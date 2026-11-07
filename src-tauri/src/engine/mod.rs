//! 监测引擎：除了 `platform_windows` 之外都是纯逻辑，不依赖 Tauri，可以单独 `cargo test`。

pub mod config;
pub mod elevate;
pub mod evaluate;
pub mod guard;
pub mod lock;
pub mod model;
pub mod parse;
pub mod platform;
pub mod probe;

#[cfg(windows)]
pub mod platform_windows;
#[cfg(not(windows))]
pub mod platform_stub;

pub const APP_NAME: &str = "ClaudeBall";
pub const APP_VER: &str = "1.0.0";
