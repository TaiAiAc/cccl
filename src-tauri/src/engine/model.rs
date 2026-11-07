//! 数据模型：进程、网络连接、探测结果、判定问题。

use serde::{Deserialize, Serialize};

/// tasklist 里的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub name: String,
    pub pid: u32,
}

/// netstat 里的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub proto: String,
    pub local: String,
    pub foreign: String,
    pub state: String,
    pub pid: u32,
}

impl Conn {
    /// 远端主机部分（去掉端口）。
    pub fn foreign_host(&self) -> String {
        split_endpoint(&self.foreign).0
    }

    /// 本地端口（如果是监听行的话）。
    pub fn local_port(&self) -> Option<u16> {
        split_endpoint(&self.local).1.parse().ok()
    }
}

/// 把 `127.0.0.1:443` / `[::1]:443` / `*:*` 拆成 (host, port)。
pub fn split_endpoint(s: &str) -> (String, String) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let host = rest[..idx].to_string();
            let port = rest[idx + 1..].trim_start_matches(':').to_string();
            return (host, port);
        }
    }
    match s.rfind(':') {
        Some(i) => (s[..i].to_string(), s[i + 1..].to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// 私有/回环地址判断。空串和 `*` 也当私有，避免误报。
pub fn is_private_ip(ip: &str) -> bool {
    let ip = ip.trim().trim_matches(|c| c == '[' || c == ']');
    if ip.is_empty() || ip == "*" || ip == "::" || ip == "::1" || ip == "0.0.0.0" {
        return true;
    }
    if ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip.starts_with("fe80")
        || ip.starts_with("::ffff:127")
    {
        return true;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(v) = second.parse::<u16>() {
                return (16..=31).contains(&v);
            }
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Crit,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub message: String,
}

impl Issue {
    pub fn crit(message: impl Into<String>) -> Self {
        Self { severity: Severity::Crit, message: message.into() }
    }

    pub fn warn(message: impl Into<String>) -> Self {
        Self { severity: Severity::Warn, message: message.into() }
    }
}

/// 一轮探测的全部结果。前端直接拿它渲染。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub mode: String,
    pub mode_detail: String,
    pub proxy_url: String,
    pub tonbo_ok: bool,
    pub tonbo_names: Vec<String>,
    pub claude_pids: Vec<u32>,
    pub claude_bypass: Vec<String>,
    pub exit_ok: bool,
    pub exit_ip: String,
    pub exit_country: String,
    pub exit_error: String,
    pub claude_ok: bool,
    pub claude_status: Option<u16>,
    pub claude_error: String,
    pub tls_error: String,
    pub admin: bool,
    /// 本轮识别到的 TUN 网卡 LUID（没有就是 0），出站锁定用。
    pub tun_luid: u64,
    /// 本轮看到的 Claude exe 路径，出站锁定用。
    pub claude_paths: Vec<String>,
}

impl Default for ProbeResult {
    fn default() -> Self {
        Self {
            mode: "none".into(),
            mode_detail: "未发现代理通道".into(),
            proxy_url: String::new(),
            tonbo_ok: false,
            tonbo_names: Vec::new(),
            claude_pids: Vec::new(),
            claude_bypass: Vec::new(),
            exit_ok: false,
            exit_ip: String::new(),
            exit_country: String::new(),
            exit_error: String::new(),
            claude_ok: false,
            claude_status: None,
            claude_error: String::new(),
            tls_error: String::new(),
            admin: false,
            tun_luid: 0,
            claude_paths: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_split() {
        assert_eq!(split_endpoint("127.0.0.1:7890"), ("127.0.0.1".into(), "7890".into()));
        assert_eq!(split_endpoint("[::1]:443"), ("::1".into(), "443".into()));
        assert_eq!(split_endpoint("*:*"), ("*".into(), "*".into()));
        assert_eq!(split_endpoint("0.0.0.0:0"), ("0.0.0.0".into(), "0".into()));
    }

    #[test]
    fn private_ranges() {
        for ip in ["127.0.0.1", "192.168.1.5", "10.2.3.4", "172.16.0.1", "0.0.0.0",
                   "169.254.1.1", "*", "::1"] {
            assert!(is_private_ip(ip), "{ip} 应该是私有");
        }
        for ip in ["172.32.0.1", "8.8.8.8", "104.28.211.7"] {
            assert!(!is_private_ip(ip), "{ip} 应该是公网");
        }
    }
}
