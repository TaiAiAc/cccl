//! 纯文本解析与打分：tasklist / netstat / CDN trace / 进程打分 / 网卡挑选。
//! 全部是纯函数，不碰系统，方便单测。

use crate::engine::model::{is_private_ip, split_endpoint, Conn, Process};
use std::collections::HashMap;

/// 进程名里出现这些词，基本可以断定是代理客户端。
pub const PROXY_NAME_HINTS: &[&str] = &[
    "tonbo", "clash", "mihomo", "v2ray", "v2raya", "xray", "sing-box", "singbox",
    "shadowsocks", "ssr", "trojan", "nekoray", "verge", "flclash", "hiddify",
    "karing", "surge", "quantumult", "wireguard", "openvpn", "tailscale", "warp",
    "proxy", "vpn", "tun2socks", "naive", "hysteria", "tuic", "mieru", "netch",
];

/// 代理客户端几乎必占的本地监听端口。故意不放 8080/8888，那些太容易被别的程序占用。
pub const COMMON_PROXY_PORTS: &[u16] = &[
    7890, 7891, 7892, 7897, 7898, 1080, 1081, 1087, 10808, 10809, 2080, 20170,
    20171, 20172, 9910, 6152, 8889, 8877,
];

/// 虚拟网卡的名称/描述里出现这些词，就是 TUN 类的。
pub const TUN_DESC_HINTS: &[&str] = &[
    "tun", "tap", "wintun", "wireguard", "vpn", "tunnel", "tonbo", "clash",
    "mihomo", "singbox", "sing-box",
];

/// 按 CSV 规则拆一行（tasklist 会输出带引号的字段）。
pub fn split_csv_row(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// 解析 `tasklist /FO CSV /NH` 的输出。
pub fn parse_tasklist(text: &str) -> Vec<Process> {
    let mut procs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cols = split_csv_row(line);
        if cols.len() < 2 {
            continue;
        }
        let name = cols[0].trim().to_string();
        if name.is_empty() || name.eq_ignore_ascii_case("image name") || name == "映像名称" {
            continue;
        }
        let pid_raw = cols[1].trim().replace(',', "");
        if let Ok(pid) = pid_raw.parse::<u32>() {
            procs.push(Process { name, pid });
        }
    }
    procs
}

/// 解析 `netstat -ano -p tcp` 的输出。
pub fn parse_netstat(text: &str) -> Vec<Conn> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let proto = parts[0].to_ascii_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let (local, foreign) = (parts[1].to_string(), parts[2].to_string());
        let (state, pid_raw) = if proto == "TCP" {
            if parts.len() < 5 {
                continue;
            }
            (parts[3].to_ascii_uppercase(), parts[4])
        } else {
            (String::new(), parts[3])
        };
        if let Ok(pid) = pid_raw.parse::<u32>() {
            rows.push(Conn { proto, local, foreign, state, pid });
        }
    }
    rows
}

/// 从 netstat 结果里挑出「绑在本地地址上的 TCP 监听」，按进程归组。
pub fn listening_ports(conns: &[Conn]) -> HashMap<u32, Vec<u16>> {
    let mut map: HashMap<u32, Vec<u16>> = HashMap::new();
    for conn in conns {
        if conn.proto != "TCP" || conn.state != "LISTENING" {
            continue;
        }
        let (host, _) = split_endpoint(&conn.local);
        let host_ok = matches!(host.as_str(), "127.0.0.1" | "0.0.0.0" | "::" | "::1" | "");
        if !host_ok {
            continue;
        }
        if let Some(port) = conn.local_port() {
            map.entry(conn.pid).or_default().push(port);
        }
    }
    for ports in map.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }
    map
}

/// 某个进程正在建立的、目标为公网 IP 的 TCP 连接（说明它绕过了本地代理）。
pub fn public_connections(conns: &[Conn], pids: &[u32]) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    for conn in conns {
        if conn.proto != "TCP" || !pids.contains(&conn.pid) {
            continue;
        }
        if conn.state != "ESTABLISHED" && conn.state != "SYN_SENT" {
            continue;
        }
        let host = conn.foreign_host();
        if is_private_ip(&host) {
            continue;
        }
        let item = conn.foreign.clone();
        if !hits.contains(&item) {
            hits.push(item);
        }
    }
    hits
}

/// 解析 cloudflare `/cdn-cgi/trace`（key=value）或 ipify（JSON）。
pub fn parse_trace(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return map;
    }
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(ip) = v.get("ip").and_then(|x| x.as_str()) {
                map.insert("ip".to_string(), ip.to_string());
            }
            if let Some(c) = v.get("country").and_then(|x| x.as_str()) {
                map.insert("loc".to_string(), c.to_ascii_uppercase());
            }
        }
        return map;
    }
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCandidate {
    pub name: String,
    pub pid: u32,
    pub ports: Vec<u16>,
    pub score: i32,
    pub why: Vec<String>,
}

/// 给「可能是梯子」的进程打分，按分数倒序（同分按名字排，保证结果稳定）。
pub fn rank_proxy_processes(
    procs: &[Process],
    listening: &HashMap<u32, Vec<u16>>,
    exclude_pids: &[u32],
) -> Vec<ProxyCandidate> {
    let mut scored: Vec<ProxyCandidate> = Vec::new();
    for proc in procs {
        if exclude_pids.contains(&proc.pid) {
            continue;
        }
        let ports = match listening.get(&proc.pid) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => continue,
        };
        let low = proc.name.to_ascii_lowercase();
        let mut score = 0;
        let mut why = Vec::new();
        if PROXY_NAME_HINTS.iter().any(|h| low.contains(h)) {
            score += 3;
            why.push("进程名像代理客户端".to_string());
        }
        let hit: Vec<String> = ports
            .iter()
            .filter(|p| COMMON_PROXY_PORTS.contains(p))
            .map(|p| p.to_string())
            .collect();
        if !hit.is_empty() {
            score += 2;
            why.push(format!("监听常见代理端口 {}", hit.join("/")));
        }
        if ports.len() >= 3 {
            score += 1;
            why.push("同时监听多个端口".to_string());
        }
        if score >= 2 {
            scored.push(ProxyCandidate {
                name: proc.name.clone(),
                pid: proc.pid,
                ports,
                score,
                why,
            });
        }
    }
    scored.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
    });
    scored
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub name: String,
    pub desc: String,
    pub status: String,
    /// 网卡 LUID（WFP 的「本地接口」条件用它）。PowerShell 回退拿不到，记 0。
    pub luid: u64,
}

impl Adapter {
    /// 网卡是否处于「已连接」状态。
    /// 注意不能用 `contains("connected")` 判断，`Disconnected` 里也含这个词。
    pub fn is_up(&self) -> bool {
        let s = self.status.trim().to_ascii_lowercase();
        if s.contains("disconnect") || s.contains("断开") || s.contains("禁用") {
            return false;
        }
        ["up", "已启用", "已连接", "connected"]
            .iter()
            .any(|w| s.contains(w))
    }
}

/// 从网卡列表里挑出 TUN / VPN 类的。只有「已连接」的算，
/// 断开的适配器还在列表里，说明隧道已经没了。
pub fn pick_tun_adapters(adapters: &[Adapter]) -> Vec<Adapter> {
    let mut hits: Vec<Adapter> = adapters
        .iter()
        .filter(|a| a.is_up())
        .filter(|a| {
            let blob = format!("{} {}", a.name, a.desc).to_ascii_lowercase();
            TUN_DESC_HINTS.iter().any(|h| blob.contains(h))
        })
        .cloned()
        .collect();
    hits.sort_by(|a, b| a.name.cmp(&b.name));
    hits
}

/// 解析 PowerShell 输出的 `name|desc|status` 三列。
pub fn parse_adapters(text: &str) -> Vec<Adapter> {
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.trim().split('|').collect();
        if parts.len() == 3 && !parts[0].trim().is_empty() {
            out.push(Adapter {
                name: parts[0].trim().to_string(),
                desc: parts[1].trim().to_string(),
                status: parts[2].trim().to_string(),
                luid: 0,
            });
        }
    }
    out
}

/// 解析 PowerShell 输出的 `pid|path`。
pub fn parse_exe_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some((_pid, path)) = line.trim().split_once('|') {
            let path = path.trim().trim_matches('"').to_string();
            if !path.is_empty() && !out.contains(&path) {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parsing() {
        let text = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\n\
                    \"Tonbo.exe\",\"4412\",\"Console\",\"1\",\"46,120 K\"\n\
                    \"Claude.exe\",\"9001\",\"Console\",\"1\",\"312,004 K\"\n";
        let procs = parse_tasklist(text);
        assert_eq!(procs.len(), 3);
        assert_eq!(procs[1], Process { name: "Tonbo.exe".into(), pid: 4412 });
        assert_eq!(procs[2].pid, 9001);
    }

    #[test]
    fn csv_with_quoted_comma() {
        let rows = split_csv_row("\"a,b\",\"1\"");
        assert_eq!(rows, vec!["a,b".to_string(), "1".to_string()]);
    }

    #[test]
    fn netstat_parsing() {
        let text = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    127.0.0.1:52133        127.0.0.1:7890         ESTABLISHED     9001\n  TCP    192.168.1.9:52134      160.79.104.10:443      ESTABLISHED     9001\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900\n  TCP    127.0.0.1:52140        104.18.32.7:443        TIME_WAIT       9001\n";
        let conns = parse_netstat(text);
        assert_eq!(conns.len(), 4);
        assert_eq!(conns[1].foreign_host(), "160.79.104.10");
        assert_eq!(conns[1].pid, 9001);
        assert_eq!(conns[2].state, "LISTENING");
    }

    #[test]
    fn listening_grouping() {
        let text = "  TCP    127.0.0.1:7890        0.0.0.0:0              LISTENING       4412\n  TCP    127.0.0.1:7891        0.0.0.0:0              LISTENING       4412\n  TCP    192.168.1.9:139        0.0.0.0:0              LISTENING       4\n";
        let map = listening_ports(&parse_netstat(text));
        assert_eq!(map.get(&4412).unwrap(), &vec![7890u16, 7891]);
        assert!(map.get(&4).is_none(), "绑在具体网卡 IP 上的监听不算");
    }

    #[test]
    fn public_conns_filter() {
        let text = "  TCP    127.0.0.1:52133        127.0.0.1:7890         ESTABLISHED     9001\n  TCP    192.168.1.9:52134      160.79.104.10:443      ESTABLISHED     9001\n  TCP    127.0.0.1:52140        104.18.32.7:443        TIME_WAIT       9001\n";
        let hits = public_connections(&parse_netstat(text), &[9001]);
        assert_eq!(hits, vec!["160.79.104.10:443".to_string()]);
    }

    #[test]
    fn trace_parsing() {
        let text = "fl=1f2\nh=1.1.1.1\nip=104.28.211.7\nloc=JP\ncolo=NRT\n";
        let map = parse_trace(text);
        assert_eq!(map.get("ip").unwrap(), "104.28.211.7");
        assert_eq!(map.get("loc").unwrap(), "JP");

        let json = parse_trace(r#"{"ip": "8.8.8.8", "country": "us"}"#);
        assert_eq!(json.get("ip").unwrap(), "8.8.8.8");
        assert_eq!(json.get("loc").unwrap(), "US");
    }

    #[test]
    fn ranking_prefers_named_proxy() {
        let procs = vec![
            Process { name: "Tonbo.exe".into(), pid: 4412 },
            Process { name: "chrome.exe".into(), pid: 900 },
            Process { name: "node.exe".into(), pid: 800 },
            Process { name: "python.exe".into(), pid: 777 },
        ];
        let mut listening = HashMap::new();
        listening.insert(4412u32, vec![7890u16, 7891]);
        listening.insert(800u32, vec![8080u16]);
        listening.insert(777u32, vec![7890u16]);
        let ranked = rank_proxy_processes(&procs, &listening, &[777]);
        assert_eq!(ranked[0].name, "Tonbo.exe");
        assert!(ranked[0].score >= 5);
        assert!(ranked.iter().all(|c| c.pid != 777), "要排除自己");
        assert!(ranked.iter().all(|c| c.name != "node.exe"), "只有一个弱端口不算");
        assert!(ranked.iter().all(|c| c.name != "chrome.exe"), "没监听的不算");
    }

    #[test]
    fn tun_adapter_picking() {
        let adapters = vec![
            Adapter { name: "以太网".into(), desc: "Realtek PCIe GbE Family Controller".into(), status: "Up".into(), luid: 1 },
            Adapter { name: "Tonbo".into(), desc: "Wintun Userspace Tunnel".into(), status: "Up".into(), luid: 99 },
            Adapter { name: "WLAN".into(), desc: "Intel(R) Wi-Fi 6 AX201".into(), status: "Disconnected".into(), luid: 2 },
        ];
        let hits = pick_tun_adapters(&adapters);
        assert_eq!(hits[0].name, "Tonbo");
        assert_eq!(hits[0].luid, 99);
        assert!(hits.iter().all(|a| a.name != "以太网"));
    }

    #[test]
    fn disconnected_tun_is_not_a_channel() {
        let adapters = vec![Adapter {
            name: "Tonbo".into(),
            desc: "Wintun Userspace Tunnel".into(),
            status: "Disconnected".into(),
            luid: 99,
        }];
        assert!(pick_tun_adapters(&adapters).is_empty(), "断开的适配器不算通道");
        assert!(!adapters[0].is_up(), "Disconnected 不能被当成 connected");
        assert!(Adapter {
            name: "Tonbo".into(),
            desc: String::new(),
            status: "Up".into(),
            luid: 0,
        }
        .is_up());
    }

    #[test]
    fn adapter_and_exe_parsing() {
        let text = "Tonbo|Wintun Userspace Tunnel|Up\n以太网|Realtek|Up\n";
        let adapters = parse_adapters(text);
        assert_eq!(adapters.len(), 2);
        assert_eq!(adapters[0].desc, "Wintun Userspace Tunnel");
        assert_eq!(adapters[0].luid, 0, "PowerShell 回退拿不到 LUID");

        let paths = parse_exe_paths("9001|C:\\Program Files\\Claude\\Claude.exe\n");
        assert_eq!(paths, vec![r"C:\Program Files\Claude\Claude.exe".to_string()]);
    }
}
