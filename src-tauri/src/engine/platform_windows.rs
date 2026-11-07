//! Windows 平台实现：tasklist / netstat / 注册表 / PowerShell / netsh / taskkill。
//!
//! 这个文件用的是 Windows 专有 API，无法在别的系统上编译验证，所以刻意写得直白。

use crate::engine::model::{Conn, Process};
use crate::engine::parse::{parse_adapters, parse_exe_paths, parse_netstat, parse_tasklist, Adapter};
use crate::engine::platform::{FetchError, Fetcher, HttpResponse, Platform};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// 不弹黑框。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// PowerShell 里先切到 UTF-8 输出，免得上游是中文系统时路径变乱码。
const PS_UTF8: &str = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; ";

/// 转成以 NUL 结尾的宽字符串，给 Win32 的 W 系列 API 用。
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn run_hidden(program: &str, args: &[&str]) -> (i32, String) {
    match Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) => (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
        ),
        Err(err) => (-1, err.to_string()),
    }
}

/// 用原始命令行跑 netsh —— netsh 要求 `program="C:\路径 带空格\x.exe"` 这种写法，
/// 交给 Command 自动加引号会把整个 token 包起来，netsh 解析不了。
fn run_raw(program: &str, raw: &str) -> (i32, String) {
    match Command::new(program)
        .raw_arg(raw)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) => (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
        ),
        Err(err) => (-1, err.to_string()),
    }
}

/// 稳定的小哈希，用来给防火墙规则起名（同一个路径每次算出来一样）。
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.to_ascii_lowercase().bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn rule_name(prefix: &str, path: &str) -> String {
    format!("{prefix}-{:016x}", fnv1a(path))
}

/// 把宽字符串指针读成 String。
unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// 用 `GetAdaptersAddresses` 直接读网卡：一次调用约 1ms，
/// 而 PowerShell 起一次要一秒多，来不及做快速监视。
fn list_adapters_native() -> Vec<Adapter> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    const AF_UNSPEC: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const ERROR_SUCCESS: u32 = 0;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;

    for _ in 0..3 {
        // 用 u64 分配，保证满足 IP_ADAPTER_ADDRESSES_LH 的对齐要求
        let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if ret == ERROR_BUFFER_OVERFLOW {
            continue; // size 已被更新成需要的大小，重来一次
        }
        if ret != ERROR_SUCCESS {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut current = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            let name = unsafe { wide_to_string(adapter.FriendlyName) };
            let desc = unsafe { wide_to_string(adapter.Description) };
            let status = if adapter.OperStatus == IfOperStatusUp {
                "Up"
            } else {
                "Disconnected"
            };
            // NET_LUID_LH 是 union，取 .Value 是 unsafe 读
            let luid = unsafe { adapter.Luid.Value };
            if !name.is_empty() {
                out.push(Adapter {
                    name,
                    desc,
                    status: status.to_string(),
                    luid,
                });
            }
            current = adapter.Next;
        }
        return out;
    }
    Vec::new()
}

/// 找一个进程的 exe 完整路径。直接调 Win32，几毫秒；
/// PowerShell CIM 要一秒多，赶不上「立刻切断」。
fn exe_path_of(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(handle) };
    if ok == 0 || len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

fn claude_exe_paths_powershell(names: &[String]) -> Vec<String> {
    let conds: Vec<String> = names
        .iter()
        .map(|n| n.trim().replace('\'', ""))
        .filter(|n| !n.is_empty())
        .map(|n| format!("$_.Name -like '{n}*'"))
        .collect();
    if conds.is_empty() {
        return Vec::new();
    }
    let script = format!(
        "{PS_UTF8}Get-CimInstance Win32_Process | Where-Object {{ {} }} | \
         ForEach-Object {{ $_.ProcessId.ToString() + '|' + $_.ExecutablePath }}",
        conds.join(" -or ")
    );
    let (code, out) = run_hidden(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    );
    if code != 0 || out.is_empty() {
        return Vec::new();
    }
    parse_exe_paths(&out)
        .into_iter()
        .filter(|p| std::path::Path::new(p).exists() && !is_self_exe(p))
        .collect()
}

/// 本程序的 exe 完整路径（小写），用来把自己从「Claude 进程」里摘出去。
fn own_exe_lower() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// 路径是否就是本程序自己。`ClaudeBall.exe` 的名字也以 claude 开头，
/// 不过滤掉的话切断会杀掉自己、出站锁定会封掉自己。
fn is_self_exe(path: &str) -> bool {
    let own = own_exe_lower();
    !own.is_empty() && path.trim().to_ascii_lowercase() == own
}

fn list_adapters_powershell() -> Vec<Adapter> {
    let script = format!(
        "{PS_UTF8}Get-NetAdapter | ForEach-Object {{ \
         $_.Name + '|' + $_.InterfaceDescription + '|' + $_.Status.ToString() }}"
    );
    let (code, out) = run_hidden(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    );
    if code != 0 || out.is_empty() {
        return Vec::new();
    }
    parse_adapters(&out)
}

/// 找 Claude 桌面端的启动目标。
///
/// 商店/MSIX 安装的 Claude 不在 PATH 上、exe 还藏在带版本号的 WindowsApps 目录里，
/// 只能按 AUMID 走 `shell:AppsFolder` 拉起来；常规安装则用几个常见路径兜底。
fn claude_app_target() -> Option<String> {
    let script = "Get-StartApps | Where-Object { $_.AppID -like '*!*' -and $_.Name -like 'Claude*' } \
                  | Select-Object -First 1 -ExpandProperty AppID";
    let (code, out) = run_hidden(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    );
    if code == 0 {
        let id = out.trim();
        if !id.is_empty() {
            return Some(format!(r"shell:AppsFolder\{id}"));
        }
    }

    let mut candidates = Vec::new();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        candidates.push(format!(r"{local}\Programs\Claude\Claude.exe"));
    }
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        candidates.push(format!(r"{program_files}\Claude\Claude.exe"));
    }
    candidates
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

/// 真正的 HTTP 抓取：不依赖 self，`Platform::fetch` 和后台探测线程共用。
fn fetch_http(
    url: &str,
    proxy: Option<&str>,
    timeout_secs: u64,
) -> Result<HttpResponse, FetchError> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .try_proxy_from_env(false);
    if let Some(p) = proxy {
        let parsed = ureq::Proxy::new(p)
            .map_err(|e| FetchError::Other(format!("代理地址无效 {p}：{e}")))?;
        builder = builder.proxy(parsed);
    }
    let agent = builder.build();
    let ua = format!("ClaudeBall/{}", crate::engine::APP_VER);

    match agent.get(url).set("User-Agent", &ua).call() {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.into_string().unwrap_or_default();
            Ok(HttpResponse { status, body })
        }
        // 4xx / 5xx：服务器有回应就算「通」，403/429 只是被拒
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Ok(HttpResponse { status: code, body })
        }
        Err(ureq::Error::Transport(transport)) => {
            let msg = transport.to_string();
            if msg.to_ascii_lowercase().contains("certificate") {
                Err(FetchError::Tls(msg))
            } else {
                Err(FetchError::Other(msg))
            }
        }
    }
}

/// 给后台探测线程用的抓取句柄。
struct HttpFetcher;

impl Fetcher for HttpFetcher {
    fn fetch(
        &self,
        url: &str,
        proxy: Option<&str>,
        timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError> {
        fetch_http(url, proxy, timeout_secs)
    }
}

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for WindowsPlatform {
    fn list_processes(&self) -> Vec<Process> {
        let (code, out) = run_hidden("tasklist", &["/FO", "CSV", "/NH"]);
        if code != 0 || out.is_empty() {
            return Vec::new();
        }
        parse_tasklist(&out)
    }

    fn netstat(&self) -> Vec<Conn> {
        let (code, out) = run_hidden("netstat", &["-ano", "-p", "tcp"]);
        if code != 0 || out.is_empty() {
            return Vec::new();
        }
        parse_netstat(&out)
    }

    fn read_system_proxy(&self) -> Option<String> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .ok()?;
        let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        if enable == 0 {
            return None;
        }
        let server: String = key.get_value("ProxyServer").ok()?;
        let server = server.trim().to_string();
        if server.is_empty() {
            return None;
        }
        if !server.contains('=') {
            return Some(server);
        }
        // 形如 http=127.0.0.1:7890;https=127.0.0.1:7890;socks=127.0.0.1:7891
        let (mut http, mut https, mut socks) = (None, None, None);
        for seg in server.split(';') {
            if let Some((k, v)) = seg.split_once('=') {
                let v = v.trim().to_string();
                match k.trim().to_ascii_lowercase().as_str() {
                    "https" => https = Some(v),
                    "http" => http = Some(v),
                    "socks" => socks = Some(v),
                    _ => {}
                }
            }
        }
        https.or(http).or(socks)
    }

    fn list_adapters(&self) -> Vec<Adapter> {
        // 先走 Win32 API：毫秒级，监视线程可以每几百毫秒查一次。
        let native = list_adapters_native();
        if !native.is_empty() {
            return native;
        }
        // 极少数情况下 API 拿不到（比如被安全软件拦），退回 PowerShell。
        list_adapters_powershell()
    }

    fn fetch(
        &self,
        url: &str,
        proxy: Option<&str>,
        timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError> {
        fetch_http(url, proxy, timeout_secs)
    }

    fn fetcher(&self) -> Option<Arc<dyn Fetcher>> {
        // 抓取不依赖 self 的任何状态，后台线程直接用这个句柄
        Some(Arc::new(HttpFetcher))
    }

    fn claude_exe_paths(&self, names: &[String]) -> Vec<String> {
        let wanted: Vec<String> = names
            .iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        if wanted.is_empty() {
            return Vec::new();
        }

        // 先走 Win32：tasklist 拿 pid，OpenProcess 拿路径，几毫秒出结果
        let me = std::process::id();
        let mut out = Vec::new();
        for proc in self.list_processes() {
            // 绝不能把自己当成 Claude：ClaudeBall.exe 也以 "claude" 开头
            if proc.pid == me {
                continue;
            }
            let low = proc.name.to_ascii_lowercase();
            if !wanted.iter().any(|n| low.starts_with(n)) {
                continue;
            }
            if let Some(path) = exe_path_of(proc.pid) {
                if std::path::Path::new(&path).exists() && !is_self_exe(&path) && !out.contains(&path)
                {
                    out.push(path);
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
        claude_exe_paths_powershell(names)
    }

    fn exe_path_of(&self, pid: u32) -> Option<String> {
        exe_path_of(pid)
    }

    fn block_program(&self, prefix: &str, path: &str) -> Result<String, String> {
        // 兜底：任何情况下都不封自己
        if is_self_exe(path) {
            return Err("拒绝封禁 ClaudeBall 自己".to_string());
        }
        let name = rule_name(prefix, path);
        // 先删后加，保证规则不会重复堆叠
        let _ = run_raw(
            "netsh",
            &format!("advfirewall firewall delete rule name=\"{name}\""),
        );
        let raw = format!(
            "advfirewall firewall add rule name=\"{name}\" dir=out action=block \
             program=\"{path}\" enable=yes profile=any"
        );
        let (code, out) = run_raw("netsh", &raw);
        if code == 0 {
            Ok(format!("已封禁 {path}"))
        } else {
            let detail = out.trim().replace('\r', " ").replace('\n', " ");
            Err(format!(
                "封禁 {path} 失败：{}",
                if detail.is_empty() { "需要管理员权限" } else { &detail }
            ))
        }
    }

    fn unblock_program(&self, prefix: &str, path: &str) -> Result<String, String> {
        let name = rule_name(prefix, path);
        let (code, out) = run_raw(
            "netsh",
            &format!("advfirewall firewall delete rule name=\"{name}\""),
        );
        // 规则本来就不存在时 netsh 会返回非 0，这里不算失败
        if code == 0 {
            Ok(format!("已解除封锁 {path}"))
        } else {
            Ok(format!(
                "解除 {path} 时 netsh 返回 {code}：{}",
                out.trim().replace('\r', " ").replace('\n', " ")
            ))
        }
    }

    fn kill_pid(&self, pid: u32) -> bool {
        // 兜底：杀掉自己等于自尽
        if pid == std::process::id() {
            return false;
        }
        let pid = pid.to_string();
        let (code, _) = run_hidden("taskkill", &["/F", "/T", "/PID", &pid]);
        code == 0
    }

    fn notify(&self, message: &str) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, MB_ICONINFORMATION, MB_OK,
        };
        let text = to_wide(message);
        let caption = to_wide("ClaudeBall");
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                caption.as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }

    fn launch_claude_app(&self) -> Result<String, String> {
        let target = claude_app_target().ok_or_else(|| {
            "没找到 Claude 桌面端：确认已安装（商店版或常规安装都行）".to_string()
        })?;
        // ClaudeBall 自己是管理员，直接 spawn 出来的子进程也是管理员。
        // 让 explorer.exe 代劳：它跑在普通权限下，商店应用也只能这么拉。
        match Command::new("explorer.exe")
            .arg(&target)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            Ok(_) => Ok("已启动 Claude 桌面端".to_string()),
            Err(err) => Err(format!("启动 Claude 桌面端失败：{err}")),
        }
    }

    fn is_admin(&self) -> bool {
        // `net session` 需要管理员令牌，返回 0 就是提权了。只算一次。
        static ADMIN: OnceLock<bool> = OnceLock::new();
        *ADMIN.get_or_init(|| {
            let (code, _) = run_hidden("net", &["session"]);
            code == 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_name_is_stable_and_unique() {
        let a = rule_name("ClaudeBall-Block", r"C:\Program Files\Claude\Claude.exe");
        let b = rule_name("ClaudeBall-Block", r"c:\program files\claude\claude.exe");
        let c = rule_name("ClaudeBall-Block", r"C:\Users\tech\AppData\Local\Claude\Claude.exe");
        assert_eq!(a, b, "大小写不同要算出同一个名字");
        assert_ne!(a, c);
        assert!(a.len() < 60);
        assert!(a.starts_with("ClaudeBall-Block-"));
    }

    #[test]
    fn native_exe_path_lookup_works() {
        let path = exe_path_of(std::process::id()).expect("自己的 exe 路径应该能拿到");
        assert!(std::path::Path::new(&path).exists(), "{path}");
    }

    #[test]
    fn native_adapter_list_works() {
        let adapters = list_adapters_native();
        assert!(!adapters.is_empty(), "Win32 网卡枚举应该能拿到网卡");
        assert!(adapters.iter().any(|a| a.is_up()), "至少有一块网卡是 Up");
    }
}
