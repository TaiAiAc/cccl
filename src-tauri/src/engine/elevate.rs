//! 启动时自提权。
//!
//! 两层硬保护（netsh 防火墙规则、WFP 出站锁定）都要管理员令牌。非管理员时
//! 它们会静默失效，只剩「杀进程」那一层，灯却照样是绿的——很误导。
//! 所以 `main()` 第一件事就是：有令牌就继续，没有就用 UAC 重新拉起自己再退出。
//!
//! 用户点了「否」不阻塞使用：照常以普通权限跑，只打日志。
//! 开发时（debug 构建）默认不提权，除非设了 `CLAUDEBALL_ELEVATE=1`；
//! 任何情况都可以用 `CLAUDEBALL_NO_ELEVATE=1` 强制跳过。

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// 单实例锁的名字（提权后的进程才有）。
    const SINGLE_INSTANCE_MUTEX: &str = "ClaudeBall-SingleInstance-v1";

    /// 当前进程是不是管理员令牌。
    ///
    /// 用令牌查询而不是 `net session`：后者依赖 LanmanServer 服务，服务停着时
    /// 即使是管理员也会返回失败——那会让自提权无限重启，一直弹 UAC。
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
            let mut len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut std::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 抢一个命名互斥体当单实例锁：已经有了就返回 false。
    ///
    /// 自提权会先起一个普通进程、再被它拉起一个管理员进程；不拦一下的话
    /// 双击两次就会有两盏灯、两份托盘图标。锁要在提权之后才建，
    /// 否则普通权限的父进程会先把名额占掉。
    pub fn claim_single_instance() -> bool {
        use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name = wide(SINGLE_INSTANCE_MUTEX);
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
            if handle.is_null() {
                // mutual exclusion 建不出来就不拦，宁可多开也别打不开
                return true;
            }
            // 句柄故意不关：进程退出时系统自动回收
            std::io::Error::last_os_error().raw_os_error()
                != Some(ERROR_ALREADY_EXISTS as i32)
        }
    }

    /// 只查询不占用：已经有实例在跑时，第二次双击可以立刻退出，不用先弹一次 UAC。
    pub fn instance_running() -> bool {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::OpenMutexW;

        // SYNCHRONIZE。windows-sys 0.60 只把它定义在 FileSystem 下面，
        // 为这一个常量开那个 feature 不值当
        const SYNCHRONIZE: u32 = 0x0010_0000;

        let name = wide(SINGLE_INSTANCE_MUTEX);
        unsafe {
            let handle = OpenMutexW(SYNCHRONIZE, 0, name.as_ptr());
            if handle.is_null() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    /// 有管理员令牌 → 什么都不做；没有 → 用 UAC 重新拉起自己，然后退出当前进程。
    pub fn ensure_elevated() {
        if is_elevated() {
            return;
        }
        if std::env::var_os("CLAUDEBALL_NO_ELEVATE").is_some() {
            eprintln!("[ClaudeBall] CLAUDEBALL_NO_ELEVATE 已设置，跳过自提权。");
            return;
        }
        if cfg!(debug_assertions) && std::env::var_os("CLAUDEBALL_ELEVATE").is_none() {
            eprintln!(
                "[ClaudeBall] debug 构建默认不自提权（设 CLAUDEBALL_ELEVATE=1 可打开）。\
                 netsh 封锁和 WFP 出站锁定需要管理员。"
            );
            return;
        }

        let Ok(exe) = std::env::current_exe() else {
            eprintln!("[ClaudeBall] 拿不到自身路径，无法自提权。");
            return;
        };
        let verb = wide("runas");
        let file = wide(&exe.to_string_lossy());
        let dir = exe.parent().map(|d| wide(&d.to_string_lossy()));

        let ret = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                dir.as_ref().map(|d| d.as_ptr()).unwrap_or(std::ptr::null()),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW 返回值 <= 32 才是错误码
        let code = ret as isize;
        if code > 32 {
            // 提权后的新进程已经起来了，本进程功成身退
            std::process::exit(0);
        }
        eprintln!(
            "[ClaudeBall] 自动提权被拒或失败（ShellExecuteW={code}），本次以普通权限运行：\
             netsh 封锁和 WFP 出站锁定不可用，只剩杀进程。\
             请右键 exe 选「以管理员身份运行」，或用 启动-管理员.bat。"
        );
    }
}

#[cfg(windows)]
pub use imp::{claim_single_instance, ensure_elevated, instance_running, is_elevated};

#[cfg(not(windows))]
pub fn ensure_elevated() {}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(not(windows))]
pub fn claim_single_instance() -> bool {
    true
}

#[cfg(not(windows))]
pub fn instance_running() -> bool {
    false
}
