//! 监测状态机：预热、连击阈值、切断、持续压制、自动解除。

use crate::engine::config::{Config, RuleLevel};
use crate::engine::evaluate::evaluate;
use crate::engine::model::{Issue, ProbeResult, Severity};
use crate::engine::platform::Platform;
use crate::engine::probe::probe;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum Event {
    Checking,
    Result { result: ProbeResult, issues: Vec<Issue> },
    Cut { reason: String },
    Restored { auto: bool },
    Log(String),
}

/// 上次切断留下的防火墙规则，程序崩了下次启动要能清掉。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockedFile {
    #[serde(default)]
    pub programs: Vec<String>,
    #[serde(default)]
    pub pids: Vec<u32>,
    #[serde(default)]
    pub since: String,
}

pub struct Guard {
    pub cfg: Config,
    pub cut: bool,
    /// 运行时的「封锁保护」开关。false = 用户在托盘里关掉了自动切断，
    /// 只影响本次运行，config.json 不变。
    pub protection: bool,
    pub bad_streak: u32,
    pub good_streak: u32,
    pub cut_ts: Option<Instant>,
    pub cut_reason: String,
    pub baseline_ip: String,
    pub started: Instant,
    pub last: Option<ProbeResult>,
    pub last_issues: Vec<Issue>,
    pub blocked_programs: Vec<String>,
    blocked_path: Option<PathBuf>,
}

impl Guard {
    pub fn new(cfg: Config, blocked_path: Option<PathBuf>) -> Self {
        let mut blocked_programs = Vec::new();
        if let Some(path) = &blocked_path {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(file) = serde_json::from_str::<BlockedFile>(&text) {
                    blocked_programs = file.programs;
                }
            }
        }
        Self {
            cfg,
            cut: false,
            protection: true,
            bad_streak: 0,
            good_streak: 0,
            cut_ts: None,
            cut_reason: String::new(),
            baseline_ip: String::new(),
            started: Instant::now(),
            last: None,
            last_issues: Vec::new(),
            blocked_programs,
            blocked_path,
        }
    }

    fn save_blocked(&self) {
        if let Some(path) = &self.blocked_path {
            let file = BlockedFile {
                programs: self.blocked_programs.clone(),
                pids: Vec::new(),
                since: String::new(),
            };
            if let Ok(text) = serde_json::to_string_pretty(&file) {
                let _ = std::fs::write(path, text);
            }
        }
    }

    /// 启动时清掉上一次运行残留的规则，免得程序崩过之后把人锁死。
    pub fn clear_stale_block(&mut self, p: &dyn Platform) -> Vec<Event> {
        let mut events = Vec::new();
        if self.blocked_programs.is_empty() {
            return events;
        }
        let prefix = self.cfg.cut_action.firewall_rule_prefix.clone();
        let programs = self.blocked_programs.clone();
        let mut count = 0usize;
        for path in &programs {
            if p.unblock_program(&prefix, path).is_ok() {
                count += 1;
            }
        }
        self.blocked_programs.clear();
        self.save_blocked();
        events.push(Event::Log(format!(
            "清掉上次运行残留的 {count} 条封锁规则，从干净状态开始。"
        )));
        events
    }

    /// 跑一轮。所有副作用都在这里面发生，返回需要通知前端的事件。
    pub fn cycle(&mut self, p: &dyn Platform) -> Vec<Event> {
        let mut events = vec![Event::Checking];

        let result = probe(p, &self.cfg);
        let mut issues = evaluate(&self.cfg, &result);

        // 出口 IP 基线：变了只提示，不当异常（节点轮换很常见）
        if result.exit_ok {
            if self.baseline_ip.is_empty() {
                self.baseline_ip = result.exit_ip.clone();
            } else if result.exit_ip != self.baseline_ip {
                issues.push(Issue::warn(format!(
                    "出口 IP 变化：{} → {}",
                    self.baseline_ip, result.exit_ip
                )));
                self.baseline_ip = result.exit_ip.clone();
            }
        }

        let crit_count = issues.iter().filter(|i| i.severity == Severity::Crit).count();
        let warm = self.started.elapsed().as_secs() < self.cfg.warmup_sec;

        // 硬信号：代理通道没了 / 梯子进程没了。这两件事没得商量，不用等第二次。
        let hard = (self.cfg.rules.proxy_present == RuleLevel::Crit && result.mode == "none")
            || (self.cfg.rules.tonbo_process == RuleLevel::Crit && !result.tonbo_ok);

        if self.cut {
            events.extend(self.enforce(p));
            if crit_count == 0 {
                self.good_streak = self.good_streak.saturating_add(1);
                events.extend(self.maybe_restore(p));
            } else {
                self.good_streak = 0;
            }
        } else if crit_count > 0 {
            self.good_streak = 0;
            if warm {
                let first = issues
                    .iter()
                    .find(|i| i.severity == Severity::Crit)
                    .map(|i| i.message.clone())
                    .unwrap_or_default();
                events.push(Event::Log(format!("预热期内只记录不切断：{first}")));
                self.bad_streak = 0;
            } else {
                self.bad_streak = self.bad_streak.saturating_add(1);
                let threshold = self.cfg.fail_threshold.max(1);
                if hard {
                    events.push(Event::Log("代理通道已经不在了，立刻切断。".to_string()));
                    events.extend(self.cut_now(p, &issues));
                } else if self.bad_streak >= threshold {
                    events.extend(self.cut_now(p, &issues));
                } else {
                    let first = issues
                        .iter()
                        .find(|i| i.severity == Severity::Crit)
                        .map(|i| i.message.clone())
                        .unwrap_or_default();
                    events.push(Event::Log(format!(
                        "第 {}/{} 次异常：{first}",
                        self.bad_streak, threshold
                    )));
                }
            }
        } else {
            self.bad_streak = 0;
            self.good_streak = 0;
        }

        self.last = Some(result.clone());
        self.last_issues = issues.clone();
        events.push(Event::Result { result, issues });
        events
    }

    fn claude_pids(&self, p: &dyn Platform) -> Vec<u32> {
        let me = std::process::id();
        p.list_processes()
            .into_iter()
            // 无论如何不能结束自己
            .filter(|proc| proc.pid != me)
            .filter(|proc| self.cfg.is_claude_process(&proc.name))
            .map(|proc| proc.pid)
            .collect()
    }

    fn cut_now(&mut self, p: &dyn Platform, issues: &[Issue]) -> Vec<Event> {
        let mut events = Vec::new();
        let reason = issues
            .iter()
            .filter(|i| i.severity == Severity::Crit)
            .map(|i| i.message.clone())
            .collect::<Vec<_>>()
            .join("；");

        if self.cfg.dry_run {
            events.push(Event::Log(format!("演练模式（dry_run=true），本应切断：{reason}")));
            return events;
        }
        if !self.protection {
            events.push(Event::Log(format!("封锁保护已关闭，跳过切断：{reason}")));
            return events;
        }

        self.cut = true;
        self.cut_ts = Some(Instant::now());
        self.cut_reason = reason.clone();
        self.good_streak = 0;

        events.push(Event::Log("=== 执行切断 ===".to_string()));
        events.push(Event::Log(format!("原因：{reason}")));

        let action = self.cfg.cut_action.clone();

        // 先封网，再杀进程：这样 Claude 自动重启也连不出去
        if action.firewall_block {
            let mut paths = p.claude_exe_paths(&self.cfg.claude_process_names);
            if paths.is_empty() {
                paths = self.blocked_programs.clone();
            }
            if paths.is_empty() {
                events.push(Event::Log(
                    "拿不到 Claude 的 exe 路径，防火墙这一步跳过（只能杀进程）。".to_string(),
                ));
            }
            for path in paths {
                match p.block_program(&action.firewall_rule_prefix, &path) {
                    Ok(msg) => {
                        events.push(Event::Log(msg));
                        if !self.blocked_programs.contains(&path) {
                            self.blocked_programs.push(path);
                        }
                    }
                    Err(msg) => events.push(Event::Log(msg)),
                }
            }
            self.save_blocked();
        }

        if action.kill_process {
            let pids = self.claude_pids(p);
            if pids.is_empty() {
                events.push(Event::Log("没有找到正在运行的 Claude 进程。".to_string()));
            } else {
                let killed: Vec<u32> = pids.into_iter().filter(|pid| p.kill_pid(*pid)).collect();
                if !killed.is_empty() {
                    let ids: Vec<String> = killed.iter().map(|p| p.to_string()).collect();
                    events.push(Event::Log(format!("已结束 Claude 进程：{}", ids.join(","))));
                }
            }
        }

        events.push(Event::Cut { reason });
        events
    }

    /// 封锁期间，继续压住新冒出来的 Claude 进程。
    fn enforce(&mut self, p: &dyn Platform) -> Vec<Event> {
        let mut events = Vec::new();
        if self.cfg.dry_run || !self.protection || !self.cfg.cut_action.kill_process {
            return events;
        }
        let mut killed = Vec::new();
        for pid in self.claude_pids(p) {
            if p.kill_pid(pid) {
                killed.push(pid);
            }
        }
        if !killed.is_empty() {
            let ids: Vec<String> = killed.iter().map(|p| p.to_string()).collect();
            events.push(Event::Log(format!(
                "封锁期内又拦下 Claude 进程：{}",
                ids.join(",")
            )));
        }
        events
    }

    fn maybe_restore(&mut self, p: &dyn Platform) -> Vec<Event> {
        let mut events = Vec::new();
        let need = self.cfg.restore_after_good.max(1);
        if self.good_streak < need {
            return events;
        }
        let elapsed = self
            .cut_ts
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX);
        if elapsed < self.cfg.restore_cooldown_sec {
            if self.good_streak == need {
                events.push(Event::Log(format!(
                    "链路连续 {need} 次正常，等冷却期走完再自动解除。"
                )));
            }
            return events;
        }
        events.extend(self.restore(p, true));
        events
    }

    pub fn restore(&mut self, p: &dyn Platform, auto: bool) -> Vec<Event> {
        let mut events = Vec::new();
        let prefix = self.cfg.cut_action.firewall_rule_prefix.clone();
        let programs = self.blocked_programs.clone();
        let mut count = 0usize;
        for path in &programs {
            if p.unblock_program(&prefix, path).is_ok() {
                count += 1;
            }
        }
        self.blocked_programs.clear();
        self.save_blocked();
        self.cut = false;
        self.bad_streak = 0;
        self.good_streak = 0;
        self.cut_ts = None;
        self.cut_reason.clear();
        if auto {
            events.push(Event::Log(format!("链路已恢复，自动解除封锁（清掉 {count} 条规则）。")));
        } else {
            events.push(Event::Log(format!("封锁已解除（清掉 {count} 条规则）。")));
        }
        events.push(Event::Restored { auto });
        events
    }

    /// 重新打开「封锁保护」：自动切断立刻生效，出站锁定由调用方重建。
    pub fn enable_protection(&mut self) {
        self.protection = true;
        self.bad_streak = 0;
    }

    /// 关掉「封锁保护」= 原来的「解除封锁（应急）」：清掉已生效的封锁，
    /// 本次运行内不再切断（重启程序或再勾上就恢复）。
    pub fn disable_protection(&mut self, p: &dyn Platform) -> Vec<Event> {
        self.protection = false;
        self.restore(p, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::model::{Process, Severity};
    use crate::engine::platform::FakePlatform;
    use std::time::Duration;

    fn platform_ok() -> FakePlatform {
        FakePlatform {
            proxy: Some("127.0.0.1:7890".into()),
            processes: vec![
                Process { name: "sing-box-windows-64.exe".into(), pid: 4412 },
                Process { name: "Claude.exe".into(), pid: 9001 },
            ],
            exe_paths: vec![r"C:\Program Files\Claude\Claude.exe".into()],
            admin: true,
            ..Default::default()
        }
        .with_exit_ip("1.2.3.4", "US")
        .with_claude_ok(200)
    }

    fn platform_dead() -> FakePlatform {
        let mut p = FakePlatform {
            processes: vec![
                Process { name: "explorer.exe".into(), pid: 100 },
                Process { name: "Tonbo.exe".into(), pid: 4412 },
                Process { name: "Claude.exe".into(), pid: 9001 },
            ],
            // 网卡还在（Up），只是隧道死了：这种要按 fail_threshold 连击来判
            adapters: vec![crate::engine::parse::Adapter {
                name: "Tonbo".into(),
                desc: "Wintun Userspace Tunnel".into(),
                status: "Up".into(),
                luid: 0,
            }],
            exe_paths: vec![r"C:\Program Files\Claude\Claude.exe".into()],
            admin: true,
            ..Default::default()
        };
        for url in [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://api.ipify.org?format=json",
            "https://claude.ai/",
        ] {
            p.http.insert(
                url.to_string(),
                Err(crate::engine::platform::FetchError::Other("timed out".into())),
            );
        }
        p
    }

    fn guard(warm: bool) -> Guard {
        let mut g = Guard::new(Config::default(), None);
        if !warm {
            g.started = Instant::now() - Duration::from_secs(999);
        }
        g
    }

    fn has_cut(events: &[Event]) -> bool {
        events.iter().any(|e| matches!(e, Event::Cut { .. }))
    }

    fn has_restored(events: &[Event]) -> bool {
        events.iter().any(|e| matches!(e, Event::Restored { .. }))
    }

    #[test]
    fn warmup_never_cuts() {
        let p = platform_dead();
        let mut g = guard(true);
        let e1 = g.cycle(&p);
        let e2 = g.cycle(&p);
        assert!(!g.cut);
        assert!(!has_cut(&e1) && !has_cut(&e2));
        assert_eq!(g.bad_streak, 0);
    }

    #[test]
    fn cuts_on_second_consecutive_failure() {
        let p = platform_dead();
        let mut g = guard(false);
        let first = g.cycle(&p);
        assert!(!g.cut, "第一次不动手");
        assert_eq!(g.bad_streak, 1);
        assert!(!has_cut(&first));

        let second = g.cycle(&p);
        assert!(g.cut);
        assert!(has_cut(&second));
        let target = r"C:\Program Files\Claude\Claude.exe".to_string();
        assert_eq!(g.blocked_programs, vec![target.clone()]);
        assert_eq!(*p.blocked.lock().unwrap(), vec![target]);
        assert!(g.cut_reason.contains("出口探测失败"));
    }

    #[test]
    fn missing_channel_cuts_on_first_cycle() {
        let mut p = platform_dead();
        p.adapters.clear();
        let mut g = guard(false);
        let events = g.cycle(&p);
        assert!(g.cut, "通道没了要立刻切，不等 fail_threshold");
        assert!(has_cut(&events));
    }

    #[test]
    fn missing_proxy_process_cuts_on_first_cycle() {
        let mut p = platform_dead();
        p.processes
            .retain(|proc| !proc.name.to_ascii_lowercase().contains("tonbo"));
        let mut g = guard(false);
        let events = g.cycle(&p);
        assert!(g.cut, "梯子进程没了要立刻切");
        assert!(has_cut(&events));
    }

    #[test]
    fn never_kills_itself() {
        let mut p = platform_dead();
        // 只有「自己」以 Claude 的名字出现：切断时也必须跳过
        p.processes
            .retain(|proc| !proc.name.eq_ignore_ascii_case("Claude.exe"));
        p.processes.push(Process {
            name: "Claude.exe".into(),
            pid: std::process::id(),
        });
        p.adapters.clear(); // 没有通道 → 第一轮就切
        let mut g = guard(false);
        let events = g.cycle(&p);
        assert!(has_cut(&events));
        assert!(
            p.killed.lock().unwrap().is_empty(),
            "切断时不能把自己杀掉：{:?}",
            *p.killed.lock().unwrap()
        );
    }

    #[test]
    fn keeps_suppressing_while_cut() {
        let p = platform_dead();
        let mut g = guard(false);
        g.cycle(&p);
        g.cycle(&p);
        p.killed.lock().unwrap().clear();
        g.cycle(&p);
        assert!(
            !p.killed.lock().unwrap().is_empty(),
            "封锁期内新冒出来的 Claude 也要压住"
        );
    }

    #[test]
    fn auto_restores_after_enough_good_checks() {
        let dead = platform_dead();
        let ok = platform_ok();
        let mut g = guard(false);
        g.cfg.restore_cooldown_sec = 0;
        g.cycle(&dead);
        g.cycle(&dead);
        assert!(g.cut);

        let e1 = g.cycle(&ok);
        assert!(g.cut, "才正常 1 次，不能放开");
        assert_eq!(g.good_streak, 1);
        assert!(!has_restored(&e1));

        g.cycle(&ok);
        let e3 = g.cycle(&ok);
        assert!(!g.cut, "3 次正常 + 冷却走完应该自动放开");
        assert!(has_restored(&e3));
        assert!(g.blocked_programs.is_empty());
        assert_eq!(
            *ok.unblocked.lock().unwrap(),
            vec![r"C:\Program Files\Claude\Claude.exe".to_string()]
        );
    }

    #[test]
    fn cooldown_blocks_early_restore() {
        let dead = platform_dead();
        let ok = platform_ok();
        let mut g = guard(false);
        g.cfg.restore_cooldown_sec = 3600;
        g.cycle(&dead);
        g.cycle(&dead);
        for _ in 0..6 {
            g.cycle(&ok);
        }
        assert!(g.cut, "冷却期没过完不许放开");
        assert!(g.good_streak >= g.cfg.restore_after_good);
    }

    #[test]
    fn failure_while_cut_resets_good_streak() {
        let dead = platform_dead();
        let ok = platform_ok();
        let mut g = guard(false);
        g.cycle(&dead);
        g.cycle(&dead);
        g.cycle(&ok);
        g.cycle(&ok);
        assert_eq!(g.good_streak, 2);
        g.cycle(&dead);
        assert_eq!(g.good_streak, 0);
        assert!(g.cut);
    }

    #[test]
    fn dry_run_never_cuts() {
        let dead = platform_dead();
        let mut g = guard(false);
        g.cfg.dry_run = true;
        for _ in 0..4 {
            g.cycle(&dead);
        }
        assert!(!g.cut);
        assert!(dead.blocked.lock().unwrap().is_empty());
        assert!(dead.killed.lock().unwrap().is_empty());
    }

    #[test]
    fn threshold_one_cuts_immediately() {
        let dead = platform_dead();
        let mut g = guard(false);
        g.cfg.fail_threshold = 1;
        g.cycle(&dead);
        assert!(g.cut);
    }

    #[test]
    fn recuts_after_restore() {
        let dead = platform_dead();
        let ok = platform_ok();
        let mut g = guard(false);
        g.cfg.restore_cooldown_sec = 0;
        g.cycle(&dead);
        g.cycle(&dead);
        g.cycle(&ok);
        g.cycle(&ok);
        g.cycle(&ok);
        assert!(!g.cut);
        g.cycle(&dead);
        g.cycle(&dead);
        assert!(g.cut, "恢复之后再异常要重新切");
    }

    #[test]
    fn healthy_never_cuts() {
        let ok = platform_ok();
        let mut g = guard(false);
        for _ in 0..5 {
            let events = g.cycle(&ok);
            assert!(!has_cut(&events));
        }
        assert!(!g.cut);
        assert!(g.last_issues.is_empty(), "{:?}", g.last_issues);
    }

    #[test]
    fn stale_rules_are_cleared_on_start() {
        let p = platform_ok();
        let dir = std::env::temp_dir().join("claudeball-test-blocked");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blocked.json");
        std::fs::write(
            &path,
            r#"{"programs": ["C:\\old\\Claude.exe"], "pids": [], "since": ""}"#,
        )
        .unwrap();

        let mut g = Guard::new(Config::default(), Some(path.clone()));
        assert_eq!(g.blocked_programs.len(), 1);
        let events = g.clear_stale_block(&p);
        assert!(g.blocked_programs.is_empty());
        assert_eq!(
            *p.unblocked.lock().unwrap(),
            vec![r"C:\old\Claude.exe".to_string()]
        );
        assert!(events.iter().any(|e| matches!(e, Event::Log(m) if m.contains("残留"))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ip_change_is_only_a_warning() {
        let ok = platform_ok();
        let mut g = guard(false);
        g.baseline_ip = "9.9.9.9".to_string();
        let events = g.cycle(&ok);
        let issues = events
            .iter()
            .find_map(|e| match e {
                Event::Result { issues, .. } => Some(issues.clone()),
                _ => None,
            })
            .expect("每轮都要给出结果");
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].severity, Severity::Warn);
        assert!(issues[0].message.contains("出口 IP 变化"));
        assert!(!g.cut, "IP 变了不该切断");
    }

    #[test]
    fn protection_off_never_cuts_and_can_turn_back_on() {
        let p = platform_dead();
        let mut g = guard(false);

        g.disable_protection(&p);
        for _ in 0..4 {
            g.cycle(&p);
        }
        assert!(!g.cut, "关闭封锁保护后不该再切断");
        assert!(p.blocked.lock().unwrap().is_empty(), "也不该写防火墙规则");

        // 重新打开：连击从头算，第二次才切
        g.enable_protection();
        assert!(!has_cut(&g.cycle(&p)), "重新打开后要重新数连击");
        assert!(has_cut(&g.cycle(&p)));
        assert!(g.cut);
    }

    #[test]
    fn disable_protection_clears_an_active_cut() {
        let p = platform_dead();
        let mut g = guard(false);
        g.cycle(&p);
        g.cycle(&p);
        assert!(g.cut);

        let events = g.disable_protection(&p);
        assert!(!g.cut);
        assert!(g.blocked_programs.is_empty());
        assert!(events.iter().any(|e| matches!(e, Event::Restored { .. })));
    }
}
