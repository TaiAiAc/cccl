//! 非 Windows 平台的占位实现。只是为了代码能在别的系统上编译通过、
//! 好让引擎的单元测试能跑起来；真正的实现见 `platform_windows.rs`。

use crate::engine::model::{Conn, Process};
use crate::engine::parse::Adapter;
use crate::engine::platform::{FetchError, HttpResponse, Platform};

#[allow(dead_code)]
pub struct StubPlatform;

impl StubPlatform {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }
}

impl Platform for StubPlatform {
    fn list_processes(&self) -> Vec<Process> {
        Vec::new()
    }

    fn netstat(&self) -> Vec<Conn> {
        Vec::new()
    }

    fn read_system_proxy(&self) -> Option<String> {
        None
    }

    fn list_adapters(&self) -> Vec<Adapter> {
        Vec::new()
    }

    fn fetch(
        &self,
        _url: &str,
        _proxy: Option<&str>,
        _timeout_secs: u64,
    ) -> Result<HttpResponse, FetchError> {
        Err(FetchError::Other("当前平台不支持网络探测".into()))
    }

    fn claude_exe_paths(&self, _names: &[String]) -> Vec<String> {
        Vec::new()
    }

    fn exe_path_of(&self, _pid: u32) -> Option<String> {
        None
    }

    fn block_program(&self, _prefix: &str, _path: &str) -> Result<String, String> {
        Err("当前平台不支持防火墙".into())
    }

    fn unblock_program(&self, _prefix: &str, _path: &str) -> Result<String, String> {
        Err("当前平台不支持防火墙".into())
    }

    fn kill_pid(&self, _pid: u32) -> bool {
        false
    }

    fn is_admin(&self) -> bool {
        false
    }
}
