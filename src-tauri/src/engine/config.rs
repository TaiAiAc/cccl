//! 配置读写。字段名和老的 Python 版 `config.json` 完全一致，可以直接沿用。

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// 单条判定的强度：`true` = 切断，`"warn"` = 只提示，`false` = 关闭。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLevel {
    Off,
    Warn,
    Crit,
}

impl Default for RuleLevel {
    fn default() -> Self {
        RuleLevel::Crit
    }
}

impl RuleLevel {
    pub fn is_off(self) -> bool {
        matches!(self, RuleLevel::Off)
    }

    pub fn is_warn(self) -> bool {
        matches!(self, RuleLevel::Warn)
    }
}

impl Serialize for RuleLevel {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            RuleLevel::Off => s.serialize_bool(false),
            RuleLevel::Warn => s.serialize_str("warn"),
            RuleLevel::Crit => s.serialize_bool(true),
        }
    }
}

impl<'de> Deserialize<'de> for RuleLevel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RuleLevel;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("true / false / \"warn\"")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<RuleLevel, E> {
                Ok(if v { RuleLevel::Crit } else { RuleLevel::Off })
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<RuleLevel, E> {
                match v.trim().to_ascii_lowercase().as_str() {
                    "warn" => Ok(RuleLevel::Warn),
                    "off" | "false" | "no" => Ok(RuleLevel::Off),
                    "crit" | "on" | "true" | "yes" => Ok(RuleLevel::Crit),
                    other => Err(E::unknown_variant(other, &["true", "false", "\"warn\""])),
                }
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CutAction {
    pub firewall_block: bool,
    pub kill_process: bool,
    pub firewall_rule_prefix: String,
}

impl Default for CutAction {
    fn default() -> Self {
        Self {
            firewall_block: true,
            kill_process: true,
            firewall_rule_prefix: "ClaudeBall-Block".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Rules {
    pub proxy_present: RuleLevel,
    pub tonbo_process: RuleLevel,
    pub exit_probe: RuleLevel,
    pub country: RuleLevel,
    pub expected_ip: RuleLevel,
    pub claude_reachable: RuleLevel,
    pub claude_bypass: RuleLevel,
    pub tls: RuleLevel,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            proxy_present: RuleLevel::Crit,
            tonbo_process: RuleLevel::Crit,
            exit_probe: RuleLevel::Crit,
            country: RuleLevel::Crit,
            expected_ip: RuleLevel::Crit,
            claude_reachable: RuleLevel::Crit,
            claude_bypass: RuleLevel::Warn,
            tls: RuleLevel::Crit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 配置格式版本。旧版本没有这个字段，加载时会自动升级。
    pub config_version: u32,
    pub interval_sec: u64,
    pub fail_threshold: u32,
    pub timeout_sec: u64,
    pub warmup_sec: u64,
    pub restore_after_good: u32,
    pub restore_cooldown_sec: u64,
    pub tonbo_process_keywords: Vec<String>,
    pub tun_adapter_keywords: Vec<String>,
    pub claude_process_names: Vec<String>,
    pub allowed_countries: Vec<String>,
    pub expected_exit_ip: String,
    pub proxy_override: String,
    pub calibrated: bool,
    pub check_claude_reachable: bool,
    pub ip_probe_urls: Vec<String>,
    pub claude_probe_url: String,
    pub cut_action: CutAction,
    pub dry_run: bool,
    /// 只允许 Claude 从隧道网卡出去（WFP 出站锁定）。关掉就完全不碰 lock。
    pub enforce_tunnel_only: bool,
    pub rules: Rules,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 2,
            interval_sec: 3,
            fail_threshold: 2,
            timeout_sec: 3,
            warmup_sec: 5,
            restore_after_good: 3,
            restore_cooldown_sec: 60,
            tonbo_process_keywords: vec![
                "tonbo".into(),
                "clash".into(),
                "mihomo".into(),
                "v2ray".into(),
                "sing-box".into(),
                "xray".into(),
                "tun2socks".into(),
            ],
            tun_adapter_keywords: vec![
                "tonbo".into(),
                "tun".into(),
                "tap-windows".into(),
                "wireguard".into(),
                "wintun".into(),
                "tunnel".into(),
                "vpn".into(),
            ],
            claude_process_names: vec!["claude".into()],
            allowed_countries: Vec::new(),
            expected_exit_ip: String::new(),
            proxy_override: String::new(),
            calibrated: false,
            check_claude_reachable: true,
            ip_probe_urls: vec![
                "https://1.1.1.1/cdn-cgi/trace".into(),
                "https://www.cloudflare.com/cdn-cgi/trace".into(),
                "https://api.ipify.org?format=json".into(),
            ],
            claude_probe_url: "https://claude.ai/".into(),
            cut_action: CutAction::default(),
            dry_run: false,
            enforce_tunnel_only: true,
            rules: Rules::default(),
        }
    }
}

impl Config {
    /// 从磁盘读；文件不存在或解析失败就返回默认值（并顺手写一份出来）。
    /// 老版本的配置会在这里升级到更快的新默认节奏。
    pub fn load(path: &Path) -> Self {
        let Ok(text) = fs::read_to_string(path) else {
            let cfg = Config::default();
            cfg.save(path);
            return cfg;
        };
        let mut cfg = match serde_json::from_str::<Config>(&text) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!("[ClaudeBall] config.json 解析失败，改用默认配置：{err}");
                let cfg = Config::default();
                cfg.save(path);
                return cfg;
            }
        };
        let has_version = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .map(|v| v.get("config_version").is_some())
            .unwrap_or(false);
        if !has_version {
            if cfg.upgrade_old_defaults() {
                cfg.save(path);
                eprintln!("[ClaudeBall] 配置已升级到 v2：检查间隔 3 秒、探测超时 3 秒。");
            }
        }
        cfg
    }

    /// 把老默认值换成新默认值；用户自己改过的值（不是老默认值）保持不动。
    /// 返回是否发生了变化。
    pub fn upgrade_old_defaults(&mut self) -> bool {
        let mut changed = self.config_version < 2;
        if self.interval_sec == 15 {
            self.interval_sec = 3;
            changed = true;
        }
        if self.timeout_sec == 8 {
            self.timeout_sec = 3;
            changed = true;
        }
        if self.warmup_sec == 20 {
            self.warmup_sec = 5;
            changed = true;
        }
        self.config_version = 2;
        changed
    }

    pub fn save(&self, path: &Path) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            if let Some(dir) = path.parent() {
                let _ = fs::create_dir_all(dir);
            }
            let _ = fs::write(path, text);
        }
    }

    /// 进程名是否命中「梯子」关键字（小写子串匹配）。
    pub fn matches_tonbo(&self, name: &str) -> bool {
        let low = name.to_ascii_lowercase();
        self.tonbo_process_keywords
            .iter()
            .any(|k| !k.is_empty() && low.contains(&k.to_ascii_lowercase()))
    }

    /// 进程名是否是「Claude」（小写前缀匹配）。
    /// 注意排除本程序自己：`ClaudeBall.exe` 也以 "claude" 开头，认成 Claude 的话
    /// 切断时会把自己杀掉、出站锁定会把自己封掉。
    pub fn is_claude_process(&self, name: &str) -> bool {
        let low = name.to_ascii_lowercase();
        if low.starts_with(&crate::engine::APP_NAME.to_ascii_lowercase()) {
            return false;
        }
        self.claude_process_names
            .iter()
            .any(|p| !p.is_empty() && low.starts_with(&p.to_ascii_lowercase()))
    }

    pub fn allowed_countries_upper(&self) -> Vec<String> {
        self.allowed_countries
            .iter()
            .filter(|c| !c.trim().is_empty())
            .map(|c| c.trim().to_ascii_uppercase())
            .collect()
    }
}

/// 应用根目录：优先用 exe 所在目录，开发时回退到项目根。
pub fn app_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if !cfg!(debug_assertions) || dir.join("config.json").exists() {
                return dir.to_path_buf();
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_keys_fall_back_to_defaults() {
        let text = r#"{"interval_sec": 5, "tonbo_process_keywords": ["sing-box-windows-64"]}"#;
        let cfg: Config = serde_json::from_str(text).unwrap();
        assert_eq!(cfg.interval_sec, 5);
        assert_eq!(cfg.fail_threshold, 2);
        assert_eq!(cfg.restore_after_good, 3);
        assert_eq!(cfg.restore_cooldown_sec, 60);
        assert_eq!(cfg.tonbo_process_keywords, vec!["sing-box-windows-64".to_string()]);
        assert!(cfg.check_claude_reachable);
        assert!(cfg.enforce_tunnel_only, "没写这个字段时默认开启出站锁定");
    }

    #[test]
    fn old_defaults_are_upgraded() {
        let mut cfg: Config =
            serde_json::from_str(r#"{"interval_sec": 15, "timeout_sec": 8, "warmup_sec": 20}"#)
                .unwrap();
        assert!(cfg.upgrade_old_defaults());
        assert_eq!(cfg.interval_sec, 3);
        assert_eq!(cfg.timeout_sec, 3);
        assert_eq!(cfg.warmup_sec, 5);
        assert_eq!(cfg.config_version, 2);
    }

    #[test]
    fn custom_settings_survive_upgrade() {
        let mut cfg: Config =
            serde_json::from_str(r#"{"interval_sec": 10, "timeout_sec": 5, "warmup_sec": 1}"#)
                .unwrap();
        cfg.upgrade_old_defaults();
        assert_eq!(cfg.interval_sec, 10);
        assert_eq!(cfg.timeout_sec, 5);
        assert_eq!(cfg.warmup_sec, 1);
    }

    #[test]
    fn rule_level_accepts_bool_and_string() {
        let text = r#"{"rules": {"country": false, "claude_bypass": "warn", "tls": true}}"#;
        let cfg: Config = serde_json::from_str(text).unwrap();
        assert_eq!(cfg.rules.country, RuleLevel::Off);
        assert_eq!(cfg.rules.claude_bypass, RuleLevel::Warn);
        assert_eq!(cfg.rules.tls, RuleLevel::Crit);
        // 没写的走默认：claude_bypass 默认就是 warn
        assert_eq!(Rules::default().claude_bypass, RuleLevel::Warn);
    }

    #[test]
    fn rule_level_round_trips() {
        let rules = Rules::default();
        let text = serde_json::to_string(&rules).unwrap();
        let back: Rules = serde_json::from_str(&text).unwrap();
        assert_eq!(back.claude_bypass, RuleLevel::Warn);
        assert_eq!(back.tls, RuleLevel::Crit);
        assert!(text.contains("\"claude_bypass\":\"warn\""));
        assert!(text.contains("\"tls\":true"));
    }

    #[test]
    fn name_matching() {
        let mut cfg = Config::default();
        cfg.tonbo_process_keywords = vec!["sing-box-windows-64".into(), "tonbo".into()];
        assert!(cfg.matches_tonbo("sing-box-windows-64.exe"));
        assert!(cfg.matches_tonbo("Tonbo.exe"));
        assert!(!cfg.matches_tonbo("chrome.exe"));

        cfg.claude_process_names = vec!["claude".into()];
        assert!(cfg.is_claude_process("Claude.exe"));
        assert!(cfg.is_claude_process("claude desktop.exe"));
        assert!(!cfg.is_claude_process("chromedriver.exe"));
        // 本程序自己也以 "claude" 开头，绝不能被当成 Claude
        assert!(!cfg.is_claude_process("ClaudeBall.exe"), "不能把自己当成 Claude");
        assert!(!cfg.is_claude_process("claudeball.exe"));
    }

    #[test]
    fn countries_are_normalised() {
        let mut cfg = Config::default();
        cfg.allowed_countries = vec![" us ".into(), "".into(), "jp".into()];
        assert_eq!(cfg.allowed_countries_upper(), vec!["US".to_string(), "JP".to_string()]);
    }
}
