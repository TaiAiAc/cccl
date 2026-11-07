//! 平台抽象：把「跟操作系统打交道」的全部动作收在一个 trait 里。
//! 真实现见 `platform_windows`，测试用的假实现在文件末尾。

use crate::engine::model::{Conn, Process};
use crate::engine::parse::Adapter;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone)]
pub enum FetchError {
    /// 证书校验失败，通常意味着可能存在中间人。
    Tls(String),
    /// 连不上、超时之类。
    Other(String),
}

impl FetchError {
    pub fn message(&self) -> &str {
        match self {
            FetchError::Tls(m) | FetchError::Other(m) => m,
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, FetchError::Tls(_))
    }
}

/// 能送进后台线程的「发请求」句柄。
///
/// 探测线程要求 `'static`，借不到 `&dyn Platform`，所以平台对象负责把发请求
/// 需要的那一小份状态搬成一个独立句柄。出口探测靠它做到「谁先成功就用谁」，
/// 不用等最慢的那个请求超时。
pub trait Fetcher: Send + Sync {
    fn fetch(
        &self,
        url: &str,
        proxy: Option<&str>,
        timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError>;
}

pub trait Platform: Send + Sync {
    /// `tasklist /FO CSV /NH` 的结果。
    fn list_processes(&self) -> Vec<Process>;

    /// `netstat -ano -p tcp` 的结果。
    fn netstat(&self) -> Vec<Conn>;

    /// 系统代理，形如 `http://127.0.0.1:7890`。没开就 None。
    fn read_system_proxy(&self) -> Option<String>;

    /// 所有网卡。
    fn list_adapters(&self) -> Vec<Adapter>;

    /// `proxy` 为 None 时强制直连（忽略环境变量里的代理）。
    fn fetch(
        &self,
        url: &str,
        proxy: Option<&str>,
        timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError>;

    /// 后台探测线程用的 `'static` 句柄。返回 None 时探测退化成顺序执行。
    fn fetcher(&self) -> Option<Arc<dyn Fetcher>> {
        None
    }

    /// Claude 各个进程的 exe 完整路径（防火墙规则要用）。
    fn claude_exe_paths(&self, names: &[String]) -> Vec<String>;

    /// 单个进程的 exe 完整路径。探测时逐个 Claude 进程查，比整表扫一遍便宜。
    fn exe_path_of(&self, pid: u32) -> Option<String>;

    /// 加一条出站阻断规则，返回给人看的说明。
    fn block_program(&self, prefix: &str, path: &str) -> Result<String, String>;

    /// 删掉对应的阻断规则。
    fn unblock_program(&self, prefix: &str, path: &str) -> Result<String, String>;

    fn kill_pid(&self, pid: u32) -> bool;

    /// 启动 Claude 桌面端，返回给人看的说明。
    fn launch_claude_app(&self) -> Result<String, String> {
        Err("当前平台不支持启动 Claude 桌面端".to_string())
    }

    /// 弹一个提示框。托盘点击没有控制台，光写日志用户看不见。
    fn notify(&self, _message: &str) {}

    fn is_admin(&self) -> bool;

    /// 给前端展示用的运行日志。
    fn log(&self, _message: &str) {}
}

/// 测试专用的假平台：所有系统调用都由字段喂进来。
#[cfg(test)]
#[derive(Default, Clone)]
pub struct FakePlatform {
    pub processes: Vec<Process>,
    pub conns: Vec<Conn>,
    pub proxy: Option<String>,
    pub adapters: Vec<Adapter>,
    pub http: std::collections::HashMap<String, Result<HttpResponse, FetchError>>,
    /// 每个地址的假延迟，用来验证「不等最慢的那个」
    pub delay: std::collections::HashMap<String, std::time::Duration>,
    pub exe_paths: Vec<String>,
    pub admin: bool,
    pub block_should_fail: bool,
    pub blocked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    pub unblocked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    pub killed: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
}

#[cfg(test)]
impl FakePlatform {
    pub fn ok(body: &str) -> Result<HttpResponse, FetchError> {
        Ok(HttpResponse { status: 200, body: body.to_string() })
    }

    pub fn with_exit_ip(mut self, ip: &str, country: &str) -> Self {
        for url in [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://api.ipify.org?format=json",
        ] {
            self.http.insert(
                url.to_string(),
                FakePlatform::ok(&format!("ip={ip}\nloc={country}\n")),
            );
        }
        self
    }

    pub fn with_claude_ok(mut self, status: u16) -> Self {
        self.http.insert(
            "https://claude.ai/".to_string(),
            Ok(HttpResponse { status, body: String::new() }),
        );
        self
    }
}

/// 假平台的抓取句柄：探测开始时把 http 表拷一份，线程里查表。
#[cfg(test)]
struct FakeFetcher {
    http: std::collections::HashMap<String, Result<HttpResponse, FetchError>>,
    delay: std::collections::HashMap<String, std::time::Duration>,
}

#[cfg(test)]
impl Fetcher for FakeFetcher {
    fn fetch(
        &self,
        url: &str,
        _proxy: Option<&str>,
        _timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError> {
        if let Some(delay) = self.delay.get(url) {
            std::thread::sleep(*delay);
        }
        match self.http.get(url) {
            Some(resp) => resp.clone(),
            None => Err(FetchError::Other(format!("no route to {url}"))),
        }
    }
}

#[cfg(test)]
impl Platform for FakePlatform {
    fn list_processes(&self) -> Vec<Process> {
        self.processes.clone()
    }

    fn netstat(&self) -> Vec<Conn> {
        self.conns.clone()
    }

    fn read_system_proxy(&self) -> Option<String> {
        self.proxy.clone()
    }

    fn list_adapters(&self) -> Vec<Adapter> {
        self.adapters.clone()
    }

    fn fetch(
        &self,
        url: &str,
        _proxy: Option<&str>,
        _timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError> {
        match self.http.get(url) {
            Some(resp) => resp.clone(),
            None => Err(FetchError::Other(format!("no route to {url}"))),
        }
    }

    fn fetcher(&self) -> Option<Arc<dyn Fetcher>> {
        Some(Arc::new(FakeFetcher {
            http: self.http.clone(),
            delay: self.delay.clone(),
        }))
    }

    fn claude_exe_paths(&self, _names: &[String]) -> Vec<String> {
        self.exe_paths.clone()
    }

    fn exe_path_of(&self, _pid: u32) -> Option<String> {
        self.exe_paths.first().cloned()
    }

    fn block_program(&self, _prefix: &str, path: &str) -> Result<String, String> {
        if self.block_should_fail {
            return Err(format!("封禁 {path} 失败：需要管理员权限"));
        }
        self.blocked.lock().unwrap().push(path.to_string());
        Ok(format!("已封禁 {path}"))
    }

    fn unblock_program(&self, _prefix: &str, path: &str) -> Result<String, String> {
        self.unblocked.lock().unwrap().push(path.to_string());
        Ok(format!("已解除 {path}"))
    }

    fn kill_pid(&self, pid: u32) -> bool {
        self.killed.lock().unwrap().push(pid);
        true
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}
