//! 出站锁定：给 Claude 进程装一组 WFP 过滤器，只许从隧道网卡出去。
//!
//! 每个 Claude exe 路径、V4/V6 各一套规则：
//!   1. permit  出接口 = TUN 网卡 LUID       权重 1000
//!   2. permit  目标 = 127.0.0.0/8 / ::1     权重 900（系统代理模式要用）
//!   3. permit  目标 = 代理 IP               权重 900（代理不在本机时要用）
//!   4. block   其余全部                     权重 100
//!
//! 隧道一断，第 1 条的条件自然不成立，第 4 条立刻生效——零检测延迟，
//! 连接和断开都不需要我们的代码参与。这跟 guard.rs 里「探测到异常再切断」是两回事。
//!
//! 过滤器挂在动态会话（`FWPM_SESSION_FLAG_DYNAMIC`）上：进程一退出 / 崩溃，
//! 会话销毁，所有过滤器自动消失，不会留下把人锁死的规则。
//!
//! 规则只按 exe 路径匹配 Claude，Tonbo 自己走物理网卡，完全不受影响。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 代理地址（只认 IP；主机名解析不了，宁可不放行）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyIp {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl ProxyIp {
    /// 回环地址由「回环 permit」覆盖，不需要单独加一条代理规则。
    pub fn is_loopback(&self) -> bool {
        match self {
            ProxyIp::V4(o) => o[0] == 127,
            ProxyIp::V6(a) => {
                a[..15].iter().all(|b| *b == 0) && a[15] == 1
            }
        }
    }
}

/// 从代理 URL 里抠出 IP：`http://127.0.0.1:7890`、`socks5://u:p@1.2.3.4:1080`、
/// `http://[::1]:8080` 都要能认。认不出（空串、主机名、乱写）返回 None。
pub fn parse_proxy_ip(proxy_url: &str) -> Option<ProxyIp> {
    let mut rest = proxy_url.trim();
    if rest.is_empty() {
        return None;
    }
    if let Some((_scheme, tail)) = rest.split_once("://") {
        rest = tail;
    }
    // 去掉路径 / 查询 / 锚点
    if let Some(idx) = rest.find(&['/', '?', '#'][..]) {
        rest = &rest[..idx];
    }
    // 去掉 user:pass@
    if let Some(idx) = rest.rfind('@') {
        rest = &rest[idx + 1..];
    }
    if rest.is_empty() {
        return None;
    }
    let host = if let Some(stripped) = rest.strip_prefix('[') {
        // [::1]:8080
        stripped.split_once(']')?.0
    } else if rest.matches(':').count() > 1 {
        // 没加方括号的裸 IPv6，视为没有端口
        rest
    } else {
        rest.split_once(':').map(|(h, _)| h).unwrap_or(rest)
    };
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return Some(ProxyIp::V4([127, 0, 0, 1]));
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => Some(ProxyIp::V4(v4.octets())),
        Ok(std::net::IpAddr::V6(v6)) => Some(ProxyIp::V6(v6.octets())),
        Err(_) => None,
    }
}

/// 锁的内部状态。句柄存成 usize（`*mut c_void` 不是 Send/Sync），用时再转回 HANDLE。
struct LockState {
    #[cfg(windows)]
    engine: usize,
    available: bool,
    reason: String,
    disabled: bool,
    /// 当前装的是哪一套规则
    installed: bool,
    /// 上一次见到的 TUN LUID。隧道消失（本轮 LUID=0）时保留，见 update()。
    luid: u64,
    proxy: Option<ProxyIp>,
    paths: Vec<String>,
    filter_ids: Vec<u64>,
    persist: Option<PathBuf>,
}

impl LockState {
    fn merge_paths(&mut self, app_paths: &[String]) -> bool {
        let mut changed = false;
        for path in app_paths {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            // 绝不能锁自己：ClaudeBall.exe 的名字也以 claude 开头
            if is_self_exe(path) {
                continue;
            }
            // Windows 路径大小写不敏感，去重也按大小写不敏感来
            if self.paths.iter().any(|p| p.eq_ignore_ascii_case(path)) {
                continue;
            }
            self.paths.push(path.to_string());
            changed = true;
        }
        changed
    }
}

/// 上次发现的 Claude exe 路径，下次启动时在 Claude 还没跑起来之前就能先把规则装好。
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct PersistFile {
    #[serde(default)]
    paths: Vec<String>,
}

fn load_persisted(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<PersistFile>(&text) {
        Ok(file) => file.paths,
        Err(err) => {
            eprintln!("[ClaudeBall] {} 解析失败：{err}", path.display());
            Vec::new()
        }
    }
}

fn save_persisted(path: &Path, paths: &[String]) {
    let file = PersistFile { paths: paths.to_vec() };
    if let Ok(text) = serde_json::to_string_pretty(&file) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, text);
    }
}

/// 路径是不是本程序自己。锁自己会让程序再也出不了网（探测全失败），
/// 而且 `claudeball.exe` 的名字天然会被当成 "claude*" 进程。
fn is_self_exe(path: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    path.trim().eq_ignore_ascii_case(&exe.to_string_lossy())
}

pub struct EgressLock {
    state: Mutex<LockState>,
}

impl EgressLock {
    /// 打开 WFP 引擎、建自己的 sublayer。失败（一般是非管理员）只记原因，
    /// 不 panic：退回到旧的行为，程序照常跑。
    pub fn new(persist: Option<PathBuf>) -> Self {
        let mut paths = persist
            .as_ref()
            .map(|p| load_persisted(p))
            .unwrap_or_default();
        // 旧版本可能把 claudeball.exe 自己写进过持久化文件，启动时先剔掉
        let before = paths.len();
        paths.retain(|p| !is_self_exe(p));
        if paths.len() != before {
            if let Some(path) = &persist {
                save_persisted(path, &paths);
            }
        }

        let mut state = LockState {
            #[cfg(windows)]
            engine: 0,
            available: false,
            reason: String::new(),
            disabled: false,
            installed: false,
            luid: 0,
            proxy: None,
            paths,
            filter_ids: Vec::new(),
            persist,
        };

        #[cfg(windows)]
        {
            match unsafe { open_engine() } {
                Ok(engine) => match unsafe { ensure_sublayer(engine) } {
                    Ok(()) => {
                        state.engine = engine as usize;
                        state.available = true;
                    }
                    Err(err) => {
                        unsafe { close_engine(engine) };
                        state.reason = err;
                    }
                },
                Err(err) => state.reason = err,
            }
        }
        #[cfg(not(windows))]
        {
            state.reason = "当前平台不支持 WFP 出站锁定".to_string();
        }

        Self { state: Mutex::new(state) }
    }

    /// 每轮探测后调用。只有 LUID / 代理 IP / 路径集合变化时才重建过滤器。
    pub fn update(&self, tun_luid: u64, app_paths: &[String], proxy_url: &str) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        #[cfg(windows)]
        update_locked(&mut *state, tun_luid, app_paths, proxy_url);
        #[cfg(not(windows))]
        {
            let _ = (tun_luid, app_paths, proxy_url, &mut state);
        }
    }

    /// 删掉全部过滤器，但保留路径记忆和 LUID（下一轮 update 会重新装上）。
    pub fn release_all(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        #[cfg(windows)]
        {
            if state.engine != 0 {
                unsafe {
                    delete_filters(state.engine as HANDLE, &mut state.filter_ids)
                };
            }
        }
        state.installed = false;
    }

    /// 应急：删过滤器，并且本次运行内不再装。
    pub fn disable(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.disabled = true;
        }
        self.release_all();
    }

    /// 反向操作：解除之后重新打开。下一轮 update 会重建过滤器。
    pub fn enable(&self) {
        if let Ok(mut state) = self.state.lock() {
            if state.disabled {
                state.disabled = false;
                state.installed = false;
            }
        }
    }

    /// 出站锁定是不是被应急关掉了。
    pub fn disabled(&self) -> bool {
        self.state.lock().map(|s| s.disabled).unwrap_or(false)
    }

    pub fn available(&self) -> bool {
        self.state.lock().map(|s| s.available).unwrap_or(false)
    }

    /// 打开失败的原因，给日志用。
    pub fn reason(&self) -> String {
        self.state
            .lock()
            .map(|s| s.reason.clone())
            .unwrap_or_default()
    }
}

impl Drop for EgressLock {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if let Ok(state) = self.state.get_mut() {
                if state.engine != 0 {
                    let engine = state.engine as windows_sys::Win32::Foundation::HANDLE;
                    unsafe {
                        delete_filters(engine, &mut state.filter_ids);
                        close_engine(engine);
                    }
                    state.engine = 0;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows 实现
// ---------------------------------------------------------------------------

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
#[cfg(windows)]
use windows_sys::core::GUID;

/// 自己的 sublayer，固定 GUID（加过一次再用返回 183，当成功）。
#[cfg(windows)]
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6c1a7b40_9d2e_4f83_a5b1_7e2c4d680913);
#[cfg(windows)]
const SUBLAYER_WEIGHT: u16 = 0x8000;
#[cfg(windows)]
const ERROR_ALREADY_EXISTS: u32 = 183;
/// WFP 自己也可能用 FWP_E_* 这种 HRESULT 形式的错误码报告「已存在」
#[cfg(windows)]
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

#[cfg(windows)]
const WEIGHT_INTERFACE: u64 = 1000;
#[cfg(windows)]
const WEIGHT_LOOPBACK: u64 = 900;
#[cfg(windows)]
const WEIGHT_PROXY: u64 = 900;
#[cfg(windows)]
const WEIGHT_BLOCK: u64 = 100;

#[cfg(windows)]
unsafe fn open_engine() -> Result<HANDLE, String> {
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    // 动态会话：句柄一关（进程退出或崩溃），本会话建的对象全部自动删除
    let session = wfp::FWPM_SESSION0 {
        flags: wfp::FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };

    let mut engine: HANDLE = std::ptr::null_mut();
    let status = wfp::FwpmEngineOpen0(
        std::ptr::null(),
        RPC_C_AUTHN_WINNT, // 本地连接，这个参数会被忽略
        std::ptr::null(),
        &session,
        &mut engine,
    );
    if status != 0 || engine.is_null() {
        return Err(format!(
            "FwpmEngineOpen0 失败（STATUS=0x{status:08X}），出站锁定不可用（通常是没有管理员权限）"
        ));
    }
    Ok(engine)
}

#[cfg(windows)]
unsafe fn close_engine(engine: HANDLE) {
    let _ = wfp::FwpmEngineClose0(engine);
}

#[cfg(windows)]
unsafe fn ensure_sublayer(engine: HANDLE) -> Result<(), String> {
    let name: Vec<u16> = "ClaudeBall 出站锁定"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let sublayer = wfp::FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: wfp::FWPM_DISPLAY_DATA0 {
            name: name.as_ptr() as *mut u16,
            description: std::ptr::null_mut(),
        },
        flags: 0,
        providerKey: std::ptr::null_mut(),
        providerData: wfp::FWP_BYTE_BLOB::default(),
        weight: SUBLAYER_WEIGHT,
    };
    let status = wfp::FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut());
    if status == 0 || status == ERROR_ALREADY_EXISTS || status == FWP_E_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(format!("FwpmSubLayerAdd0 失败（STATUS=0x{status:08X}）"))
    }
}

#[cfg(windows)]
unsafe fn delete_filters(engine: HANDLE, ids: &mut Vec<u64>) {
    for id in ids.drain(..) {
        let status = wfp::FwpmFilterDeleteById0(engine, id);
        if status != 0 {
            // 比如网卡/引擎状态变了，删不掉也无所谓：动态会话退出时照样清干净
            eprintln!("[ClaudeBall] 删除 WFP 过滤器 {id} 失败（STATUS=0x{status:08X}）");
        }
    }
}

#[cfg(windows)]
fn update_locked(state: &mut LockState, tun_luid: u64, app_paths: &[String], proxy_url: &str) {
    if state.disabled || !state.available || state.engine == 0 {
        return;
    }

    let paths_changed = state.merge_paths(app_paths);

    // 回环代理不需要单独的 permit：127.0.0.0/8 / ::1 那条已经覆盖了
    let proxy = parse_proxy_ip(proxy_url).filter(|p| !p.is_loopback());

    // 隧道暂时不在（tun_luid == 0）时刻意保留上一次的 LUID：
    // 旧网卡的 permit 自然匹配不上，block 已经生效；这期间重建只会把 permit 弄丢。
    let target_luid = if tun_luid != 0 { tun_luid } else { state.luid };

    let need_rebuild = !state.installed
        || target_luid != state.luid
        || proxy != state.proxy
        || paths_changed;
    if !need_rebuild {
        return;
    }

    state.luid = target_luid;
    state.proxy = proxy;

    let engine = state.engine as HANDLE;
    unsafe { delete_filters(engine, &mut state.filter_ids) };
    state.installed = true;

    let paths = state.paths.clone();
    for path in &paths {
        if is_self_exe(path) {
            continue;
        }
        if let Err(err) = unsafe { add_path_filters(engine, path, state.luid, state.proxy, &mut state.filter_ids) } {
            eprintln!("[ClaudeBall] {err}");
            state.reason = err;
        }
    }
    eprintln!(
        "[ClaudeBall] 出站锁定已更新：{} 个程序，{} 条过滤器，TUN LUID={}",
        paths.len(),
        state.filter_ids.len(),
        if state.luid == 0 { "（暂无）".to_string() } else { state.luid.to_string() }
    );

    if paths_changed {
        if let Some(persist) = &state.persist {
            save_persisted(persist, &state.paths);
        }
    }
}

/// 给一个 exe 路径加全套规则，过滤器 id 追加进 `ids`。
#[cfg(windows)]
unsafe fn add_path_filters(
    engine: HANDLE,
    path: &str,
    luid: u64,
    proxy: Option<ProxyIp>,
    ids: &mut Vec<u64>,
) -> Result<(), String> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut app_ptr: *mut wfp::FWP_BYTE_BLOB = std::ptr::null_mut();
    let status = wfp::FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut app_ptr);
    if status != 0 || app_ptr.is_null() {
        return Err(format!(
            "取 app id 失败（{path}），STATUS=0x{status:08X}，这个路径先跳过"
        ));
    }
    let app = &*app_ptr;
    let name: Vec<u16> = format!("ClaudeBall 出站锁定 · {path}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut result = Ok(());
    for v4 in [true, false] {
        let layer = if v4 {
            wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4
        } else {
            wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6
        };

        // 1) 出接口 = TUN 网卡
        if luid != 0 {
            let mut luid_value = luid;
            let mut conds = vec![app_condition(app), interface_condition(&mut luid_value)];
            match add_filter(engine, layer, &name, wfp::FWP_ACTION_PERMIT, WEIGHT_INTERFACE, &mut conds) {
                Ok(id) => ids.push(id),
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }

        // 2) 本机回环（系统代理）
        if v4 {
            let mut addr = wfp::FWP_V4_ADDR_AND_MASK {
                addr: u32::from_ne_bytes([127, 0, 0, 0]),
                mask: u32::from_ne_bytes([255, 0, 0, 0]),
            };
            let mut conds = vec![app_condition(app), v4_mask_condition(&mut addr)];
            match add_filter(engine, layer, &name, wfp::FWP_ACTION_PERMIT, WEIGHT_LOOPBACK, &mut conds) {
                Ok(id) => ids.push(id),
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        } else {
            let mut addr = wfp::FWP_V6_ADDR_AND_MASK {
                addr: [0; 16],
                prefixLength: 128,
            };
            addr.addr[15] = 1; // ::1
            let mut conds = vec![app_condition(app), v6_mask_condition(&mut addr)];
            match add_filter(engine, layer, &name, wfp::FWP_ACTION_PERMIT, WEIGHT_LOOPBACK, &mut conds) {
                Ok(id) => ids.push(id),
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }

        // 3) 代理 IP（非回环才需要）
        match (v4, proxy) {
            (true, Some(ProxyIp::V4(octets))) => {
                let mut addr = wfp::FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_ne_bytes(octets),
                    mask: u32::from_ne_bytes([255, 255, 255, 255]),
                };
                let mut conds = vec![app_condition(app), v4_mask_condition(&mut addr)];
                match add_filter(engine, layer, &name, wfp::FWP_ACTION_PERMIT, WEIGHT_PROXY, &mut conds) {
                    Ok(id) => ids.push(id),
                    Err(err) => {
                        result = Err(err);
                        break;
                    }
                }
            }
            (false, Some(ProxyIp::V6(octets))) => {
                let mut addr = wfp::FWP_V6_ADDR_AND_MASK {
                    addr: octets,
                    prefixLength: 128,
                };
                let mut conds = vec![app_condition(app), v6_mask_condition(&mut addr)];
                match add_filter(engine, layer, &name, wfp::FWP_ACTION_PERMIT, WEIGHT_PROXY, &mut conds) {
                    Ok(id) => ids.push(id),
                    Err(err) => {
                        result = Err(err);
                        break;
                    }
                }
            }
            _ => {}
        }

        // 4) 其余全部 block
        let mut conds = vec![app_condition(app)];
        match add_filter(engine, layer, &name, wfp::FWP_ACTION_BLOCK, WEIGHT_BLOCK, &mut conds) {
            Ok(id) => ids.push(id),
            Err(err) => {
                result = Err(err);
                break;
            }
        }
    }

    wfp::FwpmFreeMemory0(&mut (app_ptr as *mut core::ffi::c_void));
    result
}

#[cfg(windows)]
fn app_condition(app: &wfp::FWP_BYTE_BLOB) -> wfp::FWPM_FILTER_CONDITION0 {
    wfp::FWPM_FILTER_CONDITION0 {
        fieldKey: wfp::FWPM_CONDITION_ALE_APP_ID,
        matchType: wfp::FWP_MATCH_EQUAL,
        conditionValue: wfp::FWP_CONDITION_VALUE0 {
            r#type: wfp::FWP_BYTE_BLOB_TYPE,
            Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                byteBlob: app as *const wfp::FWP_BYTE_BLOB as *mut wfp::FWP_BYTE_BLOB,
            },
        },
    }
}

#[cfg(windows)]
fn interface_condition(luid: &mut u64) -> wfp::FWPM_FILTER_CONDITION0 {
    wfp::FWPM_FILTER_CONDITION0 {
        fieldKey: wfp::FWPM_CONDITION_IP_LOCAL_INTERFACE,
        matchType: wfp::FWP_MATCH_EQUAL,
        conditionValue: wfp::FWP_CONDITION_VALUE0 {
            r#type: wfp::FWP_UINT64,
            Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                uint64: luid as *mut u64,
            },
        },
    }
}

#[cfg(windows)]
fn v4_mask_condition(addr: &mut wfp::FWP_V4_ADDR_AND_MASK) -> wfp::FWPM_FILTER_CONDITION0 {
    wfp::FWPM_FILTER_CONDITION0 {
        fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: wfp::FWP_MATCH_EQUAL,
        conditionValue: wfp::FWP_CONDITION_VALUE0 {
            r#type: wfp::FWP_V4_ADDR_MASK,
            Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                v4AddrMask: addr as *mut wfp::FWP_V4_ADDR_AND_MASK,
            },
        },
    }
}

#[cfg(windows)]
fn v6_mask_condition(addr: &mut wfp::FWP_V6_ADDR_AND_MASK) -> wfp::FWPM_FILTER_CONDITION0 {
    wfp::FWPM_FILTER_CONDITION0 {
        fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: wfp::FWP_MATCH_EQUAL,
        conditionValue: wfp::FWP_CONDITION_VALUE0 {
            r#type: wfp::FWP_V6_ADDR_MASK,
            Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                v6AddrMask: addr as *mut wfp::FWP_V6_ADDR_AND_MASK,
            },
        },
    }
}

/// 条件数组、权重和被指针引用的值都必须在这次调用期间保持存活——都在这里。
#[cfg(windows)]
unsafe fn add_filter(
    engine: HANDLE,
    layer: GUID,
    name: &[u16],
    action: u32,
    weight: u64,
    conds: &mut [wfp::FWPM_FILTER_CONDITION0],
) -> Result<u64, String> {
    let mut weight_value = weight;

    let mut filter = wfp::FWPM_FILTER0::default();
    filter.displayData = wfp::FWPM_DISPLAY_DATA0 {
        name: name.as_ptr() as *mut u16,
        description: std::ptr::null_mut(),
    };
    filter.layerKey = layer;
    filter.subLayerKey = SUBLAYER_KEY;
    filter.weight = wfp::FWP_VALUE0 {
        r#type: wfp::FWP_UINT64,
        Anonymous: wfp::FWP_VALUE0_0 {
            uint64: &mut weight_value as *mut u64,
        },
    };
    filter.numFilterConditions = conds.len() as u32;
    filter.filterCondition = conds.as_mut_ptr();
    filter.action = wfp::FWPM_ACTION0 {
        r#type: action,
        Anonymous: wfp::FWPM_ACTION0_0::default(),
    };
    filter.Anonymous = wfp::FWPM_FILTER0_0 { rawContext: 0 };
    filter.reserved = std::ptr::null_mut();
    filter.filterId = 0;
    filter.effectiveWeight = wfp::FWP_VALUE0::default();

    let mut id: u64 = 0;
    let status = wfp::FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut id);
    if status != 0 {
        let kind = if action == wfp::FWP_ACTION_BLOCK { "block" } else { "permit" };
        return Err(format!("加 {kind} 过滤器失败（STATUS=0x{status:08X}）"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_ip_parsing() {
        assert_eq!(parse_proxy_ip("127.0.0.1:7890"), Some(ProxyIp::V4([127, 0, 0, 1])));
        assert_eq!(
            parse_proxy_ip("http://127.0.0.1:7890"),
            Some(ProxyIp::V4([127, 0, 0, 1]))
        );
        assert_eq!(
            parse_proxy_ip("socks5://user:pw@10.1.2.3:1080"),
            Some(ProxyIp::V4([10, 1, 2, 3]))
        );
        assert_eq!(
            parse_proxy_ip("https://1.2.3.4:443/一些路径?x=1"),
            Some(ProxyIp::V4([1, 2, 3, 4]))
        );
        assert_eq!(parse_proxy_ip("1.2.3.4"), Some(ProxyIp::V4([1, 2, 3, 4])), "没有端口也行");
        assert_eq!(parse_proxy_ip("http://localhost:3128"), Some(ProxyIp::V4([127, 0, 0, 1])));
    }

    #[test]
    fn proxy_ipv6_parsing() {
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(parse_proxy_ip("http://[::1]:8080"), Some(ProxyIp::V6(loopback)));
        assert_eq!(parse_proxy_ip("::1"), Some(ProxyIp::V6(loopback)), "裸 IPv6 也要认");

        let mut remote = [0u8; 16];
        remote[0] = 0x20;
        remote[1] = 0x01;
        remote[15] = 0x09;
        assert_eq!(
            parse_proxy_ip("socks5://[2001::9]:1080"),
            Some(ProxyIp::V6(remote))
        );
    }

    #[test]
    fn proxy_loopback_detection() {
        assert!(ProxyIp::V4([127, 0, 0, 1]).is_loopback());
        assert!(ProxyIp::V4([127, 5, 6, 7]).is_loopback(), "整个 127/8 都是回环");
        assert!(!ProxyIp::V4([10, 0, 0, 1]).is_loopback());
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert!(ProxyIp::V6(v6).is_loopback());
        assert!(!ProxyIp::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_loopback());
    }

    #[test]
    fn invalid_proxy_urls() {
        for url in ["", "   ", "http://", "proxy.example.com:8080", "不是地址", "http://:8080"] {
            assert_eq!(parse_proxy_ip(url), None, "{url:?} 不该解析出 IP");
        }
    }

    #[test]
    fn v4_address_byte_order() {
        // FWP 的 addr 是网络字节序：先按本机字节序解释，再按本机字节序写回内存，
        // 内存里就正好是 127.0.0.0。
        let addr = u32::from_ne_bytes([127, 0, 0, 0]);
        assert_eq!(addr.to_ne_bytes(), [127, 0, 0, 0]);
        assert_eq!(u32::from_ne_bytes([10, 1, 2, 3]).to_ne_bytes(), [10, 1, 2, 3]);
    }

    #[test]
    fn lock_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EgressLock>();
    }

    #[test]
    fn persistent_paths_round_trip() {
        let dir = std::env::temp_dir().join("claudeball-test-lock");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("claude-paths.json");
        let paths = vec![r"C:\A\Claude.exe".to_string(), r"C:\B\Claude.exe".to_string()];
        save_persisted(&path, &paths);
        assert_eq!(load_persisted(&path), paths);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn path_merge_dedupes_case_insensitively() {
        let mut state = empty_state();
        state.paths = vec![r"C:\Program Files\Claude\Claude.exe".to_string()];
        let changed = state.merge_paths(&[
            r"c:\program files\claude\claude.exe".to_string(),
            r"C:\Other\Claude.exe".to_string(),
            "  ".to_string(),
        ]);
        assert!(changed);
        assert_eq!(state.paths.len(), 2, "{:?}", state.paths);
        assert!(!state.merge_paths(&state.paths.clone()), "没有新路径就返回 false");
    }

    fn empty_state() -> LockState {
        LockState {
            #[cfg(windows)]
            engine: 0,
            available: false,
            reason: String::new(),
            disabled: false,
            installed: false,
            luid: 0,
            proxy: None,
            paths: Vec::new(),
            filter_ids: Vec::new(),
            persist: None,
        }
    }

    #[test]
    fn self_exe_is_never_locked() {
        let me = std::env::current_exe()
            .expect("拿到自己的 exe 路径")
            .to_string_lossy()
            .to_string();
        assert!(is_self_exe(&me));
        assert!(is_self_exe(&me.to_ascii_uppercase()), "路径比较不区分大小写");

        let mut state = empty_state();
        let changed = state.merge_paths(&[me, r"C:\Program Files\Claude\Claude.exe".to_string()]);
        assert!(changed, "另一个真实路径还是要加进来");
        assert_eq!(state.paths.len(), 1, "自己不能进锁定名单：{:?}", state.paths);
        assert!(!state.paths[0].eq_ignore_ascii_case(
            &std::env::current_exe().unwrap().to_string_lossy()
        ));
    }

    #[cfg(windows)]
    #[test]
    fn wfp_constants_and_layout() {
        // 这些常量写错了不会编译报错，只会让规则条件完全错掉，所以逐个钉死
        assert_eq!(wfp::FWP_ACTION_BLOCK, 4097);
        assert_eq!(wfp::FWP_ACTION_PERMIT, 4098);
        assert_eq!(wfp::FWP_MATCH_EQUAL, 0);
        assert_eq!(wfp::FWP_UINT64, 4);
        assert_eq!(wfp::FWP_BYTE_BLOB_TYPE, 12);
        assert_eq!(wfp::FWP_V4_ADDR_MASK, 256);
        assert_eq!(wfp::FWP_V6_ADDR_MASK, 257);

        // 结构体布局：GUID 16 字节 + 对齐
        assert_eq!(std::mem::size_of::<GUID>(), 16);
        assert_eq!(std::mem::size_of::<wfp::FWPM_ACTION0>(), 20);
        assert_eq!(
            std::mem::size_of::<wfp::FWP_CONDITION_VALUE0>(),
            std::mem::size_of::<usize>() * 2,
            "4 字节类型 + 对齐到指针的联合体"
        );
    }

    /// 真开一次 WFP 引擎，拿测试程序自己的 exe 路径加一条 block 再删掉。
    /// 非管理员直接跳过（CI / 普通用户跑 cargo test 时不会失败）。
    #[cfg(windows)]
    #[test]
    fn wfp_filter_roundtrip() {
        let engine = match unsafe { open_engine() } {
            Ok(engine) => engine,
            Err(err) => {
                eprintln!("[跳过] 没有 WFP 权限：{err}");
                return;
            }
        };
        if let Err(err) = unsafe { ensure_sublayer(engine) } {
            eprintln!("[跳过] 建 sublayer 失败：{err}");
            unsafe { close_engine(engine) };
            return;
        }

        let path = std::env::current_exe()
            .expect("拿到自己的 exe 路径")
            .to_string_lossy()
            .to_string();

        let mut ids = Vec::new();
        let result = unsafe { add_path_filters(engine, &path, 0, None, &mut ids) };
        match result {
            Ok(()) => {
                // 没有 LUID、没有代理：每层 2 条（回环 permit + block），V4/V6 各一套
                assert_eq!(ids.len(), 4, "过滤器数量和预期不符");
                assert!(!ids.is_empty());
            }
            Err(err) => assert!(false, "WFP 过滤器往返失败：{err}"),
        }

        unsafe { delete_filters(engine, &mut ids) };
        assert!(ids.is_empty(), "删完要清空记录");

        // 重复加一次，确认删掉之后还能再加（sublayer 的 183 分支）
        assert!(unsafe { ensure_sublayer(engine) }.is_ok());
        unsafe { close_engine(engine) };
    }

    #[test]
    fn lock_can_be_disabled_and_enabled_again() {
        // 非管理员时 new() 只是记下原因，不会 panic，这个测试在哪都能跑
        let lock = EgressLock::new(None);
        assert!(!lock.disabled(), "默认是开着的");
        lock.disable();
        assert!(lock.disabled(), "应急解除后要记住本次运行不再装");
        lock.enable();
        assert!(!lock.disabled(), "重新勾上封锁保护后要能再装");
    }
}
