//! 判定：把一轮探测结果翻译成「有哪些异常、各自多严重」。

use crate::engine::config::Config;
use crate::engine::model::{Issue, ProbeResult};

fn push(issues: &mut Vec<Issue>, level: crate::engine::config::RuleLevel, message: String) {
    if level.is_warn() {
        issues.push(Issue::warn(message));
    } else {
        issues.push(Issue::crit(message));
    }
}

pub fn evaluate(cfg: &Config, r: &ProbeResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    // 代理通道：严格模式下通道没了就是硬异常（探测也已经被跳过）
    let level = cfg.rules.proxy_present;
    if !level.is_off() && r.mode == "none" {
        if level.is_warn() || r.exit_ok {
            issues.push(Issue::warn(
                "没识别出系统代理或 TUN 网卡，但出口探测是通的。\
                 如果是 TUN 模式，把它的网卡名加进 config.json 的 tun_adapter_keywords。"
                    .to_string(),
            ));
        } else {
            issues.push(Issue::crit(format!(
                "没有可用的代理通道：{}。已跳过网络探测，避免真实 IP 直连暴露。",
                r.mode_detail
            )));
        }
    }

    // 梯子进程：默认是硬异常，进程没了就说明隧道没人维护
    let level = cfg.rules.tonbo_process;
    if !level.is_off() && !r.tonbo_ok {
        let keywords = cfg.tonbo_process_keywords.join("/");
        if level.is_warn() {
            issues.push(Issue::warn(format!(
                "没匹配到 tonbo 进程（关键字：{keywords}）。\
                 如果它明明在跑，把进程名补进 config.json 的 tonbo_process_keywords。"
            )));
        } else {
            issues.push(Issue::crit(format!(
                "tonbo 进程没在跑（关键字：{keywords}）。"
            )));
        }
    }

    // 出口探测本身
    let level = cfg.rules.exit_probe;
    if !level.is_off() && !r.exit_ok {
        let reason = if r.exit_error.is_empty() { "未知原因" } else { &r.exit_error };
        push(&mut issues, level, format!("出口探测失败：{reason}"));
    }

    // 出口地区白名单
    let level = cfg.rules.country;
    if !level.is_off() && r.exit_ok {
        let allowed = cfg.allowed_countries_upper();
        if !allowed.is_empty() && !r.exit_country.is_empty() {
            let got = r.exit_country.to_ascii_uppercase();
            if !allowed.contains(&got) {
                push(
                    &mut issues,
                    level,
                    format!(
                        "出口地区不符：当前 {got}，允许 {}。流量可能已经从别的节点出去了。",
                        allowed.join("/")
                    ),
                );
            }
        }
    }

    // 固定出口 IP
    let level = cfg.rules.expected_ip;
    if !level.is_off() && r.exit_ok {
        let want = cfg.expected_exit_ip.trim();
        if !want.is_empty() && r.exit_ip != want {
            push(
                &mut issues,
                level,
                format!("出口 IP 不符：当前 {}，期望 {want}。", r.exit_ip),
            );
        }
    }

    // Claude 端可达性
    let level = cfg.rules.claude_reachable;
    if !level.is_off() && cfg.check_claude_reachable && !r.claude_ok {
        let reason = if r.claude_error.is_empty() { "未知原因" } else { &r.claude_error };
        push(&mut issues, level, format!("Claude 端不可达：{reason}"));
    }

    // Claude 绕过代理直连公网
    let level = cfg.rules.claude_bypass;
    if !level.is_off() && !r.claude_bypass.is_empty() {
        let shown: Vec<String> = r.claude_bypass.iter().take(5).cloned().collect();
        push(
            &mut issues,
            level,
            format!("Claude 存在绕过代理的公网连接：{}", shown.join("、")),
        );
    }

    // TLS 证书
    let level = cfg.rules.tls;
    if !level.is_off() && !r.tls_error.is_empty() {
        push(
            &mut issues,
            level,
            format!("TLS 证书校验失败，可能存在中间人：{}", r.tls_error),
        );
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::RuleLevel;
    use crate::engine::model::Severity;

    fn good() -> ProbeResult {
        ProbeResult {
            mode: "system".into(),
            mode_detail: "系统代理".into(),
            proxy_url: "http://127.0.0.1:7890".into(),
            tonbo_ok: true,
            tonbo_names: vec!["sing-box-windows-64.exe".into()],
            claude_pids: vec![9001],
            claude_bypass: vec![],
            exit_ok: true,
            exit_ip: "1.2.3.4".into(),
            exit_country: "US".into(),
            exit_error: String::new(),
            claude_ok: true,
            claude_status: Some(200),
            claude_error: String::new(),
            tls_error: String::new(),
            admin: true,
            tun_luid: 0,
            claude_paths: Vec::new(),
        }
    }

    fn crits(issues: &[Issue]) -> usize {
        issues.iter().filter(|i| i.severity == Severity::Crit).count()
    }

    #[test]
    fn healthy_has_no_issues() {
        assert!(evaluate(&Config::default(), &good()).is_empty());
    }

    #[test]
    fn everything_down_is_critical() {
        let mut r = good();
        r.mode = "none".into();
        r.tonbo_ok = false;
        r.exit_ok = false;
        r.exit_ip.clear();
        r.exit_country.clear();
        r.exit_error = "timed out".into();
        r.claude_ok = false;
        r.claude_error = "timed out".into();
        let issues = evaluate(&Config::default(), &r);
        assert!(crits(&issues) >= 3, "{issues:?}");
        assert!(issues.iter().any(|i| i.message.contains("tonbo")));
    }

    #[test]
    fn unknown_mode_but_exit_ok_is_only_a_warning() {
        let mut r = good();
        r.mode = "none".into();
        let issues = evaluate(&Config::default(), &r);
        assert_eq!(crits(&issues), 0);
        assert!(!issues.is_empty());
    }

    #[test]
    fn missing_process_is_critical_by_default() {
        let mut r = good();
        r.tonbo_ok = false;
        assert_eq!(crits(&evaluate(&Config::default(), &r)), 1);
    }

    #[test]
    fn missing_process_can_be_downgraded_to_warning() {
        let mut cfg = Config::default();
        cfg.rules.tonbo_process = RuleLevel::Warn;
        let mut r = good();
        r.tonbo_ok = false;
        let issues = evaluate(&cfg, &r);
        assert_eq!(crits(&issues), 0);
        assert!(!issues.is_empty());
    }

    #[test]
    fn country_whitelist() {
        let mut cfg = Config::default();
        cfg.allowed_countries = vec!["US".into(), "JP".into()];
        let mut r = good();
        r.exit_country = "JP".into();
        assert!(evaluate(&cfg, &r).is_empty());

        r.exit_country = "HK".into();
        assert_eq!(crits(&evaluate(&cfg, &r)), 1);
    }

    #[test]
    fn expected_ip_pinning() {
        let mut cfg = Config::default();
        cfg.expected_exit_ip = "104.28.211.7".into();
        let mut r = good();
        assert_eq!(crits(&evaluate(&cfg, &r)), 1);
        r.exit_ip = "104.28.211.7".into();
        assert!(evaluate(&cfg, &r).is_empty());
    }

    #[test]
    fn bypass_is_warn_by_default_but_can_be_escalated() {
        let mut r = good();
        r.claude_bypass = vec!["160.79.104.10:443".into()];
        let issues = evaluate(&Config::default(), &r);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Warn);

        let mut cfg = Config::default();
        cfg.rules.claude_bypass = RuleLevel::Crit;
        assert_eq!(crits(&evaluate(&cfg, &r)), 1);
    }

    #[test]
    fn tls_error_is_critical() {
        let mut r = good();
        r.tls_error = "CERTIFICATE_VERIFY_FAILED".into();
        assert_eq!(crits(&evaluate(&Config::default(), &r)), 1);
    }

    #[test]
    fn disabled_rules_stay_quiet() {
        let mut cfg = Config::default();
        cfg.rules.country = RuleLevel::Off;
        cfg.rules.tls = RuleLevel::Off;
        cfg.allowed_countries = vec!["US".into()];
        let mut r = good();
        r.exit_country = "HK".into();
        r.tls_error = "x".into();
        assert!(evaluate(&cfg, &r).is_empty());
    }

    #[test]
    fn clash_reachable_off_skips_check() {
        let mut cfg = Config::default();
        cfg.check_claude_reachable = false;
        let mut r = good();
        r.claude_ok = false;
        r.claude_error = "timeout".into();
        assert!(evaluate(&cfg, &r).is_empty());
    }
}
