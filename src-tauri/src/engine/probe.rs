//! 一轮探测：代理模式、进程、出口 IP、Claude 可达性、是否绕过代理。

use crate::engine::config::{Config, RuleLevel};
use crate::engine::model::ProbeResult;
use crate::engine::parse::{pick_tun_adapters, public_connections};
use crate::engine::platform::{FetchError, Fetcher, HttpResponse, Platform};
use std::sync::mpsc;
use std::sync::Arc;

/// 把 `127.0.0.1:7890` 补成 `http://127.0.0.1:7890`。
pub fn normalize_proxy(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    }
}

/// 当前的代理通道。
pub struct Channel {
    pub proxy_url: String,
    /// system / tun / none
    pub mode: String,
    pub detail: String,
    /// 选中 TUN 网卡的 LUID（WFP 出站锁定用）；非 tun 模式为 0。
    pub tun_luid: u64,
}

/// 判断代理通道：手动覆盖 > 系统代理 > 已连接的 TUN 网卡。
/// 很便宜（注册表 + 一次 Win32 网卡枚举），监视线程可以高频调用。
pub fn detect_channel(p: &dyn Platform, cfg: &Config) -> Channel {
    let override_url = normalize_proxy(&cfg.proxy_override);
    if !override_url.is_empty() {
        return Channel {
            proxy_url: override_url.clone(),
            mode: "system".into(),
            detail: format!("手动指定 {override_url}"),
            tun_luid: 0,
        };
    }
    if let Some(sys) = p.read_system_proxy() {
        let url = normalize_proxy(&sys);
        return Channel {
            proxy_url: url.clone(),
            mode: "system".into(),
            detail: format!("系统代理 {url}"),
            tun_luid: 0,
        };
    }
    let adapters = p.list_adapters();
    match pick_tun_adapters(&adapters).first() {
        Some(a) => Channel {
            proxy_url: String::new(),
            mode: "tun".into(),
            detail: format!("TUN 网卡 {}", a.name),
            tun_luid: a.luid,
        },
        None => {
            let names: Vec<&str> = adapters
                .iter()
                .filter(|a| a.is_up())
                .map(|a| a.name.as_str())
                .collect();
            let detail = if names.is_empty() {
                "没有已连接的网卡".to_string()
            } else {
                format!("已连接的网卡：{}（没有匹配到 TUN/VPN）", names.join("、"))
            };
            Channel {
                proxy_url: String::new(),
                mode: "none".into(),
                detail,
                tun_luid: 0,
            }
        }
    }
}

#[derive(Default)]
struct ExitOutcome {
    ok: bool,
    ip: String,
    country: String,
    error: String,
    tls: String,
}

/// 几个出口探测地址同时试，**谁先成功就用谁**。
///
/// 拿到第一个带 IP 的响应就返回，剩下的请求线程在后台自己超时结束，
/// 不再拖住这一轮——某个地址卡住不会让整轮等满 `timeout_sec`。
fn probe_exit_racing(
    fetcher: &Arc<dyn Fetcher>,
    urls: &[String],
    use_proxy: Option<&str>,
    timeout_secs: u64,
) -> ExitOutcome {
    let mut out = ExitOutcome::default();
    let (tx, rx) = mpsc::channel::<(String, Result<HttpResponse, FetchError>)>();
    for url in urls {
        let tx = tx.clone();
        let fetcher = Arc::clone(fetcher);
        let url = url.clone();
        let proxy: Option<String> = use_proxy.map(|s| s.to_string());
        std::thread::spawn(move || {
            let res = fetcher.fetch(&url, proxy.as_deref(), timeout_secs);
            // 已经拿到成功结果时接收端可能已经关了，发送失败无所谓
            let _ = tx.send((url, res));
        });
    }
    drop(tx);
    for _ in 0..urls.len() {
        let Ok((url, res)) = rx.recv() else { break };
        if absorb(&mut out, &url, res) {
            break;
        }
    }
    out
}

/// 顺序版：平台没给抓取句柄时用（stub 平台）。
fn probe_exit_sequential(
    p: &dyn Platform,
    urls: &[String],
    use_proxy: Option<&str>,
    timeout_secs: u64,
) -> ExitOutcome {
    let mut out = ExitOutcome::default();
    for url in urls {
        let res = p.fetch(url, use_proxy, timeout_secs);
        if absorb(&mut out, url, res) {
            break;
        }
    }
    out
}

/// 收下一条探测结果。返回 true 表示已经拿到出口 IP，可以停了。
fn absorb(out: &mut ExitOutcome, url: &str, res: Result<HttpResponse, FetchError>) -> bool {
    match res {
        Ok(resp) => {
            let info = crate::engine::parse::parse_trace(&resp.body);
            match info.get("ip") {
                Some(ip) if !ip.is_empty() => {
                    out.ok = true;
                    out.ip = ip.clone();
                    out.country = info
                        .get("loc")
                        .or_else(|| info.get("country"))
                        .map(|c| c.to_ascii_uppercase())
                        .unwrap_or_default();
                    out.error.clear();
                    return true;
                }
                _ => {
                    if out.error.is_empty() {
                        out.error = format!("探测地址 {url} 的返回里没有 IP");
                    }
                }
            }
        }
        Err(FetchError::Tls(msg)) => {
            out.tls = msg.clone();
            if out.error.is_empty() {
                out.error = format!("TLS 校验失败：{msg}");
            }
        }
        Err(FetchError::Other(msg)) => {
            if out.error.is_empty() {
                out.error = msg;
            }
        }
    }
    false
}

pub fn probe(p: &dyn Platform, cfg: &Config) -> ProbeResult {
    let mut result = ProbeResult { admin: p.is_admin(), ..Default::default() };

    // 1) 通道判断和进程列表互不依赖，一起跑
    let (procs, channel) = std::thread::scope(|scope| {
        let procs = scope.spawn(|| p.list_processes());
        let channel = detect_channel(p, cfg);
        (procs.join().unwrap_or_default(), channel)
    });

    result.mode = channel.mode;
    result.mode_detail = channel.detail;
    result.proxy_url = channel.proxy_url;
    result.tun_luid = channel.tun_luid;

    // 2) 进程
    for proc in &procs {
        if cfg.matches_tonbo(&proc.name) {
            result.tonbo_ok = true;
            if !result.tonbo_names.contains(&proc.name) {
                result.tonbo_names.push(proc.name.clone());
            }
        }
        if cfg.is_claude_process(&proc.name) {
            result.claude_pids.push(proc.pid);
            // 出站锁定要按 exe 路径装过滤器，顺便在这一轮里把路径收集好
            if let Some(path) = p.exe_path_of(proc.pid) {
                if !result.claude_paths.contains(&path) {
                    result.claude_paths.push(path);
                }
            }
        }
    }

    let proxy_url = result.proxy_url.clone();
    let use_proxy: Option<&str> = if result.mode == "system" && !proxy_url.is_empty() {
        Some(proxy_url.as_str())
    } else {
        None
    };

    // 3) 通道没了 + 严格模式：一个网络请求都不发，直接判死。
    //    TUN 一断，直连探测暴露的就是真实 IP。
    if result.mode == "none" && cfg.rules.proxy_present == RuleLevel::Crit {
        let msg = "没有可用的代理通道（系统代理和 TUN 网卡都不在），已跳过网络探测，避免真实 IP 直连暴露";
        result.exit_error = msg.to_string();
        result.claude_error = msg.to_string();
        return result;
    }

    // 4) 出口探测和 Claude 可达性并发跑。
    //    出口探测是「谁先成功就用谁」，不会因为某个地址卡住把整轮拖满；
    //    Claude 可达性只有一条请求，等它自己的超时。
    let timeout = cfg.timeout_sec;
    let (exit, claude) = match p.fetcher() {
        Some(fetcher) => {
            let claude_thread = if cfg.check_claude_reachable {
                let fetcher = Arc::clone(&fetcher);
                let url = cfg.claude_probe_url.clone();
                let proxy: Option<String> = use_proxy.map(|s| s.to_string());
                Some(std::thread::spawn(move || {
                    fetcher.fetch(&url, proxy.as_deref(), timeout)
                }))
            } else {
                None
            };
            let exit = probe_exit_racing(&fetcher, &cfg.ip_probe_urls, use_proxy, timeout);
            (exit, claude_thread.and_then(|handle| handle.join().ok()))
        }
        // 平台没提供抓取句柄（stub）：顺序来，行为等同以前
        None => {
            let exit = probe_exit_sequential(p, &cfg.ip_probe_urls, use_proxy, timeout);
            let claude = if cfg.check_claude_reachable {
                Some(p.fetch(&cfg.claude_probe_url, use_proxy, timeout))
            } else {
                None
            };
            (exit, claude)
        }
    };

    result.exit_ok = exit.ok;
    result.exit_ip = exit.ip;
    result.exit_country = exit.country;
    result.exit_error = exit.error;
    result.tls_error = exit.tls;

    // 只要服务器有回应就算通，403/429 都不算断
    if let Some(res) = claude {
        match res {
            Ok(resp) => {
                result.claude_ok = true;
                result.claude_status = Some(resp.status);
            }
            Err(FetchError::Tls(msg)) => {
                if result.tls_error.is_empty() {
                    result.tls_error = msg.clone();
                }
                result.claude_error = format!("TLS 校验失败：{msg}");
            }
            Err(FetchError::Other(msg)) => result.claude_error = msg,
        }
    }

    // 5) Claude 是否绕过代理。系统代理模式下它应该只连 127.0.0.1
    if result.mode == "system" && !result.claude_pids.is_empty() {
        let conns = p.netstat();
        result.claude_bypass = public_connections(&conns, &result.claude_pids);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::model::{Conn, Process};
    use crate::engine::parse::Adapter;
    use crate::engine::platform::FakePlatform;

    fn with_proxy() -> FakePlatform {
        FakePlatform {
            proxy: Some("127.0.0.1:7890".into()),
            processes: vec![
                Process { name: "sing-box-windows-64.exe".into(), pid: 4412 },
                Process { name: "Claude.exe".into(), pid: 9001 },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn proxy_normalisation() {
        assert_eq!(normalize_proxy("127.0.0.1:7890"), "http://127.0.0.1:7890");
        assert_eq!(normalize_proxy("http://127.0.0.1:7890"), "http://127.0.0.1:7890");
        assert_eq!(normalize_proxy("  "), "");
    }

    #[test]
    fn system_proxy_mode_detected() {
        let p = with_proxy().with_exit_ip("1.2.3.4", "US").with_claude_ok(403);
        let r = probe(&p, &Config::default());
        assert_eq!(r.mode, "system");
        assert_eq!(r.proxy_url, "http://127.0.0.1:7890");
        assert!(r.tonbo_ok);
        assert_eq!(r.claude_pids, vec![9001]);
        assert!(r.exit_ok);
        assert_eq!(r.exit_ip, "1.2.3.4");
        assert_eq!(r.exit_country, "US");
        assert!(r.claude_ok, "403 也算通");
        assert_eq!(r.claude_status, Some(403));
        assert!(r.tls_error.is_empty());
    }

    #[test]
    fn claude_exe_paths_are_collected() {
        let mut p = with_proxy().with_exit_ip("1.2.3.4", "US").with_claude_ok(200);
        p.exe_paths = vec![r"C:\Program Files\Claude\Claude.exe".into()];
        let r = probe(&p, &Config::default());
        assert_eq!(
            r.claude_paths,
            vec![r"C:\Program Files\Claude\Claude.exe".to_string()],
            "出站锁定要拿到 Claude 的 exe 路径"
        );
    }

    #[test]
    fn override_wins_over_system_proxy() {
        let mut p = with_proxy().with_exit_ip("1.2.3.4", "US").with_claude_ok(200);
        p.proxy = None;
        let mut cfg = Config::default();
        cfg.proxy_override = "127.0.0.1:1080".into();
        let r = probe(&p, &cfg);
        assert_eq!(r.mode, "system");
        assert_eq!(r.proxy_url, "http://127.0.0.1:1080");
        assert!(r.exit_ok);
    }

    #[test]
    fn tun_mode_via_adapter() {
        let mut p = with_proxy().with_exit_ip("5.6.7.8", "JP").with_claude_ok(200);
        p.proxy = None;
        p.adapters = vec![
            Adapter { name: "以太网".into(), desc: "Realtek".into(), status: "Up".into(), luid: 1 },
            Adapter { name: "tun0".into(), desc: "Wintun Userspace Tunnel".into(), status: "Up".into(), luid: 4242 },
        ];
        let r = probe(&p, &Config::default());
        assert_eq!(r.mode, "tun");
        assert_eq!(r.tun_luid, 4242, "要选中 tun 网卡的 LUID");
        assert!(r.mode_detail.contains("tun0"));
        assert!(r.exit_ok);
    }

    #[test]
    fn no_channel_skips_all_network_probes() {
        let mut p = FakePlatform::default();
        // 就算直连能通，严格模式下也不能去探测——否则暴露的就是真实 IP
        p.http.insert(
            "https://1.1.1.1/cdn-cgi/trace".into(),
            FakePlatform::ok("ip=9.9.9.9\nloc=CN\n"),
        );
        let r = probe(&p, &Config::default());
        assert_eq!(r.mode, "none");
        assert!(!r.exit_ok);
        assert!(!r.claude_ok);
        assert!(r.exit_error.contains("跳过网络探测"), "{}", r.exit_error);
    }

    #[test]
    fn no_channel_still_probes_when_rule_is_off() {
        let mut cfg = Config::default();
        cfg.rules.proxy_present = crate::engine::config::RuleLevel::Off;
        let mut p = FakePlatform::default();
        p.http.insert(
            "https://1.1.1.1/cdn-cgi/trace".into(),
            FakePlatform::ok("ip=9.9.9.9\nloc=CN\n"),
        );
        let r = probe(&p, &cfg);
        assert_eq!(r.mode, "none");
        assert!(r.exit_ok, "规则关掉时保持旧行为：直连也能探测");
    }

    #[test]
    fn exit_probe_falls_through_to_second_url() {
        let mut p = with_proxy().with_claude_ok(200);
        p.http.insert(
            "https://www.cloudflare.com/cdn-cgi/trace".into(),
            FakePlatform::ok("ip=7.7.7.7\nloc=SG\n"),
        );
        let r = probe(&p, &Config::default());
        assert!(r.exit_ok);
        assert_eq!(r.exit_ip, "7.7.7.7");
        assert_eq!(r.exit_country, "SG");
    }

    #[test]
    fn exit_probe_does_not_wait_for_the_slowest_url() {
        // 一个地址秒回，另一个要 800ms：整轮应该跟快的走
        // （要有代理通道，否则严格模式下会跳过网络探测）
        let mut p = FakePlatform {
            proxy: Some("127.0.0.1:7890".into()),
            ..Default::default()
        };
        p.http.insert(
            "https://1.1.1.1/cdn-cgi/trace".into(),
            FakePlatform::ok("ip=1.2.3.4\nloc=US\n"),
        );
        p.http.insert(
            "https://www.cloudflare.com/cdn-cgi/trace".into(),
            FakePlatform::ok("ip=5.6.7.8\nloc=JP\n"),
        );
        p.delay.insert(
            "https://www.cloudflare.com/cdn-cgi/trace".into(),
            std::time::Duration::from_millis(800),
        );

        let started = std::time::Instant::now();
        let r = probe(&p, &Config::default());
        let elapsed = started.elapsed();

        assert!(r.exit_ok);
        assert_eq!(r.exit_ip, "1.2.3.4", "用先回来的那个");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "不该等最慢的探测：{elapsed:?}"
        );
    }

    #[test]
    fn tls_failure_is_recorded() {
        let mut p = with_proxy();
        for url in [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://api.ipify.org?format=json",
        ] {
            p.http.insert(
                url.to_string(),
                Err(FetchError::Tls("invalid peer certificate".into())),
            );
        }
        p.http.insert(
            "https://claude.ai/".into(),
            Err(FetchError::Tls("invalid peer certificate".into())),
        );
        let r = probe(&p, &Config::default());
        assert!(!r.exit_ok);
        assert!(!r.tls_error.is_empty());
        assert!(r.exit_error.contains("TLS"));
    }

    #[test]
    fn bypass_only_checked_in_system_mode() {
        let conns = vec![Conn {
            proto: "TCP".into(),
            local: "192.168.1.9:52134".into(),
            foreign: "160.79.104.10:443".into(),
            state: "ESTABLISHED".into(),
            pid: 9001,
        }];
        let mut p = with_proxy().with_exit_ip("1.2.3.4", "US").with_claude_ok(200);
        p.conns = conns.clone();
        let r = probe(&p, &Config::default());
        assert_eq!(r.claude_bypass, vec!["160.79.104.10:443".to_string()]);

        let mut p2 = p.clone();
        p2.proxy = None;
        p2.adapters = vec![Adapter {
            name: "tun0".into(),
            desc: "Wintun".into(),
            status: "Up".into(),
            luid: 7,
        }];
        let r2 = probe(&p2, &Config::default());
        assert_eq!(r2.mode, "tun");
        assert!(r2.claude_bypass.is_empty(), "TUN 模式下不查这个");
    }
}
