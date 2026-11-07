// 桌面红绿灯外壳：窗口、托盘、把引擎事件转成前端能用的状态。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;

use engine::config::{app_dir, Config, RuleLevel};
use engine::elevate::ensure_elevated;
use engine::guard::{Event, Guard};
use engine::lock::EgressLock;
use engine::model::{Issue, ProbeResult, Severity};
use engine::platform::Platform;
use engine::probe::detect_channel;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Position, State, Wry};

#[cfg(windows)]
use engine::platform_windows::WindowsPlatform as RealPlatform;
#[cfg(not(windows))]
use engine::platform_stub::StubPlatform as RealPlatform;

const TRAY_ID: &str = "main";

/// 前端拿到的完整状态。
#[derive(Clone, serde::Serialize)]
pub struct StatusPayload {
    /// checking / ok / warn / bad / cut
    pub state: String,
    pub label: String,
    pub detail: String,
    pub issues: Vec<Issue>,
    pub cut: bool,
    pub mode: String,
    pub exit_ip: String,
    pub country: String,
    pub tonbo_ok: bool,
    pub admin: bool,
    pub claude_procs: usize,
    pub interval: u64,
    /// 托盘的「封锁保护」开关是否打开
    pub protected: bool,
}

impl Default for StatusPayload {
    fn default() -> Self {
        Self {
            state: "checking".into(),
            label: "启动中".into(),
            detail: "正在初始化".into(),
            issues: Vec::new(),
            cut: false,
            mode: "none".into(),
            exit_ip: String::new(),
            country: String::new(),
            tonbo_ok: false,
            admin: false,
            claude_procs: 0,
            interval: 15,
            protected: true,
        }
    }
}

fn build_payload(
    result: &ProbeResult,
    issues: &[Issue],
    cut: bool,
    cut_reason: &str,
    interval: u64,
    protected: bool,
) -> StatusPayload {
    let has_crit = issues.iter().any(|i| i.severity == Severity::Crit);
    let state = if cut {
        "cut"
    } else if has_crit {
        "bad"
    } else if !issues.is_empty() {
        "warn"
    } else {
        "ok"
    };

    let first = issues.first().map(|i| i.message.clone()).unwrap_or_default();
    let (label, detail) = match state {
        "cut" => (
            "已切断 Claude 联网".to_string(),
            if cut_reason.is_empty() {
                "链路异常，已封掉出网。恢复正常后会自动放开。".to_string()
            } else {
                cut_reason.to_string()
            },
        ),
        "bad" => ("异常".to_string(), first),
        "warn" => ("在守着".to_string(), first),
        _ => (
            "正常".to_string(),
            format!("{} · 每 {interval} 秒检查", result.mode_detail),
        ),
    };

    StatusPayload {
        state: state.to_string(),
        label,
        detail,
        issues: issues.to_vec(),
        cut,
        mode: result.mode.clone(),
        exit_ip: result.exit_ip.clone(),
        country: result.exit_country.clone(),
        tonbo_ok: result.tonbo_ok,
        admin: result.admin,
        claude_procs: result.claude_pids.len(),
        interval,
        protected,
    }
}

/// 让监测线程能被「立即检测」叫醒。
#[derive(Default)]
struct Waker {
    flag: Mutex<bool>,
    cv: Condvar,
}

impl Waker {
    fn poke(&self) {
        if let Ok(mut flag) = self.flag.lock() {
            *flag = true;
        }
        self.cv.notify_all();
    }

    /// 最多睡 ms 毫秒；被 poke 叫醒返回 true。
    fn wait_slice(&self, ms: u64) -> bool {
        let Ok(mut flag) = self.flag.lock() else {
            std::thread::sleep(Duration::from_millis(ms));
            return false;
        };
        if *flag {
            *flag = false;
            return true;
        }
        match self.cv.wait_timeout(flag, Duration::from_millis(ms)) {
            Ok((mut guard, _)) => {
                let poked = *guard;
                *guard = false;
                poked
            }
            Err(_) => false,
        }
    }

    /// 睡 secs 秒，期间被 poke 就提前醒。
    fn wait(&self, secs: u64) {
        let Ok(mut flag) = self.flag.lock() else {
            std::thread::sleep(Duration::from_secs(secs));
            return;
        };
        if !*flag {
            if let Ok((guard, _)) = self
                .cv
                .wait_timeout(flag, Duration::from_secs(secs.max(1)))
            {
                flag = guard;
            } else {
                return;
            }
        }
        *flag = false;
    }
}

struct AppState {
    guard: Mutex<Guard>,
    status: Mutex<StatusPayload>,
    waker: Arc<Waker>,
    platform: Arc<RealPlatform>,
    /// WFP 出站锁定：Claude 只能从隧道网卡出去
    lock: Arc<EgressLock>,
    pos_path: PathBuf,
    /// 托盘里的「封锁保护」勾选项，切换和同步勾选状态用
    protection_item: Mutex<Option<CheckMenuItem<Wry>>>,
}

#[tauri::command]
fn get_status(state: State<AppState>) -> StatusPayload {
    state
        .status
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default()
}

#[tauri::command]
fn check_now(state: State<AppState>) {
    state.waker.poke();
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

fn tray_tooltip(payload: &StatusPayload) -> String {
    let mut text = format!("ClaudeBall — {}", payload.label);
    if !payload.exit_ip.is_empty() {
        text.push_str(&format!(" · {} {}", payload.country, payload.exit_ip));
    }
    if !payload.protected {
        text.push_str(" · 封锁保护已关闭");
    }
    text
}

// ---- 托盘图标：只显示当前那一盏灯，红灯会呼吸 ----

const TRAY_ICON_SIZE: u32 = 32;
const TRAY_CENTER: f32 = 16.0;
/// 深色灯圈的外沿
const TRAY_BEZEL_R: f32 = 14.8;
/// 灯泡半径
const TRAY_LAMP_R: f32 = 11.7;
/// 红黄绿的亮灯颜色，和桌面上的灯一致
const TRAY_LAMP_COLORS: [[f32; 3]; 3] = [
    [255.0, 59.0, 48.0],
    [255.0, 204.0, 0.0],
    [52.0, 199.0, 89.0],
];

fn mix(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    let t = t.clamp(0.0, 1.0);
    [
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    ]
}

/// 按状态现场画一张 32×32 的托盘图标（RGBA）：只有当前状态的那一盏灯。
/// ok → 绿灯；checking / warn → 黄灯；bad / cut → 红灯。
/// `pulse` 只在红灯时给值（0~1），用来做呼吸效果；其他灯传 None。
fn tray_icon(state: &str, pulse: Option<f32>) -> Image<'static> {
    let color = match state {
        "ok" => TRAY_LAMP_COLORS[2],
        "warn" | "checking" => TRAY_LAMP_COLORS[1],
        _ => TRAY_LAMP_COLORS[0],
    };
    // 呼吸：亮度、光晕强度、光晕范围一起起伏
    let (brightness, glow_alpha, glow_span) = match pulse {
        Some(p) => {
            let p = p.clamp(0.0, 1.0);
            (0.74 + 0.36 * p, 0.26 + 0.64 * p, 3.2 + 3.2 * p)
        }
        None => (1.0, 0.55, 4.2),
    };

    let mut buf = vec![0u8; (TRAY_ICON_SIZE * TRAY_ICON_SIZE * 4) as usize];

    for y in 0..TRAY_ICON_SIZE {
        for x in 0..TRAY_ICON_SIZE {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            let dx = px - TRAY_CENTER;
            let dy = py - TRAY_CENTER;
            let dist = (dx * dx + dy * dy).sqrt();

            let bezel_cover = (TRAY_BEZEL_R + 0.5 - dist).clamp(0.0, 1.0);
            // 灯圈外的柔光（让红灯呼吸时能透出来）
            let halo = if dist > TRAY_BEZEL_R {
                let h = (1.0 - (dist - TRAY_BEZEL_R) / (glow_span * 0.8)).clamp(0.0, 1.0);
                (h * h * glow_alpha * 0.6).clamp(0.0, 0.7)
            } else {
                0.0
            };

            if bezel_cover <= 0.0 {
                if halo <= 0.003 {
                    continue;
                }
                let offset = ((y * TRAY_ICON_SIZE + x) * 4) as usize;
                buf[offset] = color[0] as u8;
                buf[offset + 1] = color[1] as u8;
                buf[offset + 2] = color[2] as u8;
                buf[offset + 3] = (halo * 255.0) as u8;
                continue;
            }

            // ---- 深色灯圈：上亮下暗，外沿一圈高光 ----
            let t = ((py - 1.2) / 29.6).clamp(0.0, 1.0);
            let mut rgb = mix([72.0, 79.0, 88.0], [13.0, 16.0, 20.0], t);
            let rim = 1.0 - ((TRAY_BEZEL_R - dist) / 1.6).clamp(0.0, 1.0);
            if py < TRAY_CENTER {
                let top = 1.0 - py / TRAY_CENTER;
                rgb = mix(rgb, [128.0, 138.0, 150.0], rim * top * 0.55);
            } else {
                rgb = mix(rgb, [0.0, 0.0, 0.0], rim * 0.4);
            }

            // 灯泡和灯圈之间的暗槽 + 光晕
            let gap = dist - TRAY_LAMP_R;
            if gap > 0.0 {
                if gap < 2.2 {
                    rgb = mix(rgb, [5.0, 6.0, 8.0], (1.0 - gap / 2.2) * 0.8);
                }
                let g = (1.0 - gap / glow_span.max(0.1)).clamp(0.0, 1.0);
                let g = g * g * glow_alpha * 0.8;
                for c in 0..3 {
                    rgb[c] = (rgb[c] + color[c] * g).min(255.0);
                }
            }

            // ---- 灯泡本体 ----
            let lamp_cover = (TRAY_LAMP_R + 0.5 - dist).clamp(0.0, 1.0);
            if lamp_cover > 0.0 {
                let mut lamp = [
                    (color[0] * brightness).min(255.0),
                    (color[1] * brightness).min(255.0),
                    (color[2] * brightness).min(255.0),
                ];
                // 左上角高光
                let hx = px - (TRAY_CENTER - TRAY_LAMP_R * 0.32);
                let hy = py - (TRAY_CENTER - TRAY_LAMP_R * 0.32);
                let hd = (hx * hx + hy * hy).sqrt() / (TRAY_LAMP_R * 0.95);
                if hd < 1.0 {
                    lamp = mix(lamp, [255.0, 255.0, 255.0], (1.0 - hd).powf(1.7) * 0.8);
                }
                // 下缘变暗，像玻璃灯泡
                let shade = ((py - (TRAY_CENTER - TRAY_LAMP_R)) / (TRAY_LAMP_R * 2.0))
                    .clamp(0.0, 1.0);
                lamp = mix(
                    lamp,
                    [lamp[0] * 0.5, lamp[1] * 0.5, lamp[2] * 0.5],
                    shade * 0.55,
                );
                // 灯泡边缘压暗一圈
                let edge = ((dist - (TRAY_LAMP_R - 1.3)) / 1.3).clamp(0.0, 1.0);
                lamp = mix(
                    lamp,
                    [lamp[0] * 0.55, lamp[1] * 0.55, lamp[2] * 0.55],
                    edge * 0.45,
                );
                rgb = mix(rgb, lamp, lamp_cover);
            }

            let offset = ((y * TRAY_ICON_SIZE + x) * 4) as usize;
            buf[offset] = rgb[0].clamp(0.0, 255.0) as u8;
            buf[offset + 1] = rgb[1].clamp(0.0, 255.0) as u8;
            buf[offset + 2] = rgb[2].clamp(0.0, 255.0) as u8;
            buf[offset + 3] = (bezel_cover * 255.0) as u8;
        }
    }

    Image::new_owned(buf, TRAY_ICON_SIZE, TRAY_ICON_SIZE)
}

/// 盯着当前状态刷新托盘图标。红灯时约 10fps 做呼吸，其他颜色只在状态变化时换一次。
fn spawn_tray_animation(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last_static: Option<String> = None;
        let started = std::time::Instant::now();
        loop {
            let state = app
                .try_state::<AppState>()
                .and_then(|s| s.status.lock().ok().map(|p| p.state.clone()))
                .unwrap_or_default();
            let red = state == "bad" || state == "cut";

            if let Some(tray) = app.tray_by_id(TRAY_ID) {
                if red {
                    // 1.6 秒一次呼吸
                    let phase =
                        (started.elapsed().as_secs_f32() * std::f32::consts::TAU / 1.6).sin()
                            * 0.5
                            + 0.5;
                    let _ = tray.set_icon(Some(tray_icon(&state, Some(phase))));
                    last_static = None;
                } else if last_static.as_deref() != Some(state.as_str()) {
                    let _ = tray.set_icon(Some(tray_icon(&state, None)));
                    last_static = Some(state);
                }
            }

            std::thread::sleep(Duration::from_millis(if red { 100 } else { 250 }));
        }
    });
}


fn spawn_monitor(app: AppHandle) {
    std::thread::spawn(move || loop {
        let round_started = std::time::Instant::now();

        let (platform, cfg, waker) = {
            let state = app.state::<AppState>();
            let locked = state.guard.lock();
            let cfg = match locked {
                Ok(guard) => guard.cfg.clone(),
                Err(err) => err.into_inner().cfg.clone(),
            };
            (Arc::clone(&state.platform), cfg, Arc::clone(&state.waker))
        };

        let events = {
            let state = app.state::<AppState>();
            // 先绑定到局部变量，guard 在 state 之前释放
            let locked = state.guard.lock();
            match locked {
                Ok(mut guard) => guard.cycle(platform.as_ref() as &dyn Platform),
                Err(err) => err.into_inner().cycle(platform.as_ref() as &dyn Platform),
            }
        };

        let mut latest: Option<StatusPayload> = None;
        for event in events {
            match event {
                Event::Checking => {}
                Event::Log(message) => {
                    let _ = app.emit("log", message);
                }
                Event::Cut { reason } => {
                    let _ = app.emit("cut", reason);
                }
                Event::Restored { auto } => {
                    let _ = app.emit("restored", auto);
                }
                Event::Result { result, issues } => {
                    let state = app.state::<AppState>();
                    let (cut, cut_reason, interval, enforce, protected) = state
                        .guard
                        .lock()
                        .map(|g| {
                            (
                                g.cut,
                                g.cut_reason.clone(),
                                g.cfg.interval_sec,
                                g.cfg.enforce_tunnel_only,
                                g.protection,
                            )
                        })
                        .unwrap_or((false, String::new(), 15, false, true));
                    // 每轮把最新的 TUN LUID / Claude 路径 / 代理带给出站锁定。
                    // 什么都没变时 update 内部直接返回，不会反复重建过滤器。
                    if enforce {
                        state
                            .lock
                            .update(result.tun_luid, &result.claude_paths, &result.proxy_url);
                    }
                    latest = Some(build_payload(
                        &result, &issues, cut, &cut_reason, interval, protected,
                    ));
                }
            }
        }

        if let Some(payload) = latest {
            let state = app.state::<AppState>();
            if let Ok(mut slot) = state.status.lock() {
                *slot = payload.clone();
            }
            let _ = app.emit("status", payload.clone());
            if let Some(tray) = app.tray_by_id(TRAY_ID) {
                let _ = tray.set_tooltip(Some(tray_tooltip(&payload)));
            }
        }

        // 下一轮：通道一没就提前叫醒，不用干等 interval
        let elapsed = round_started.elapsed().as_secs();
        let wait = cfg.interval_sec.saturating_sub(elapsed).max(1);
        wait_next_round(&waker, platform.as_ref() as &dyn Platform, &cfg, wait);
    });
}

/// 等到下一轮。等待期间每 300ms 看一眼代理通道，通道没了就立刻返回，
/// 让下一轮 cycle 马上切断——VPN 一断，真实 IP 随时会出去，不能干等。
fn wait_next_round(waker: &Waker, platform: &dyn Platform, cfg: &Config, secs: u64) {
    if cfg.rules.proxy_present != RuleLevel::Crit {
        waker.wait(secs);
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(secs.max(1));
    let mut missing = 0u32;
    while std::time::Instant::now() < deadline {
        if waker.wait_slice(300) {
            return; // 手动点了「立即检测」
        }
        if detect_channel(platform, cfg).mode == "none" {
            missing += 1;
            if missing >= 3 {
                return; // 连续约 1 秒没有通道，立刻跑下一轮
            }
        } else {
            missing = 0;
        }
    }
}

fn read_position(path: &PathBuf) -> Option<(i32, i32)> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let x = value.get("x")?.as_i64()? as i32;
    let y = value.get("y")?.as_i64()? as i32;
    Some((x, y))
}

fn save_position(path: &PathBuf, x: i32, y: i32) {
    let value = serde_json::json!({ "x": x, "y": y });
    let _ = std::fs::write(path, value.to_string());
}

/// 托盘勾选框「封锁保护」：按当前状态取反。勾选状态以实际状态为准，
/// 不依赖菜单自己有没有切。
fn toggle_protection(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let current = state.guard.lock().map(|g| g.protection).unwrap_or(true);
    set_protection(app, !current);
}

/// 打开/关闭封锁保护。两种方向都只影响本次运行，config.json 不动。
///
/// - 关掉（原来的「解除封锁（应急）」）：删 WFP 过滤器、清 netsh 规则、
///   退出切断状态，本次运行不再自动切断。
/// - 打开：重新允许装 WFP 过滤器，切断规则立刻生效。
fn set_protection(app: &AppHandle, on: bool) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let platform = Arc::clone(&state.platform);

    // WFP 出站锁定：关掉时删过滤器并拒绝再装；打开时允许下一轮 update 重建
    if on {
        state.lock.enable();
    } else {
        state.lock.disable();
    }

    let mut messages: Vec<String> = Vec::new();
    {
        // Tauri State 的借用坑：临时量会在 block 结束时晚于 state 析构，
        // 先把 lock() 的结果绑到局部变量再处理
        let locked = state.guard.lock();
        let mut guard = locked.unwrap_or_else(|err| err.into_inner());
        if on {
            guard.enable_protection();
            messages.push("封锁保护已恢复：出站锁定会重新装上，异常按规则切断。".to_string());
        } else {
            for event in guard.disable_protection(platform.as_ref() as &dyn Platform) {
                if let Event::Log(message) = event {
                    messages.push(message);
                }
            }
            messages.push("封锁保护已关闭：本次运行不再切断、不再装出站锁定。".to_string());
        }
    }

    if let Ok(slot) = state.protection_item.lock() {
        if let Some(item) = slot.as_ref() {
            let _ = item.set_checked(on);
        }
    }

    for message in messages {
        let _ = app.emit("log", message);
    }
    state.waker.poke();
}

/// 托盘「启动 Claude 桌面端」：切断状态下不放行——拉起来下一秒就会被 enforce 杀掉。
fn launch_claude_app(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let cut = state.guard.lock().map(|g| g.cut).unwrap_or(false);
    if cut {
        let message = "现在是切断状态，先等链路恢复自动解除，再启动 Claude 桌面端。";
        state.platform.notify(message);
        let _ = app.emit("log", message.to_string());
        return;
    }
    match state.platform.launch_claude_app() {
        Ok(message) => {
            let _ = app.emit("log", message);
        }
        Err(message) => {
            // 拉不起来多半是没装 / 不在 PATH 里，弹框比日志有用
            state.platform.notify(&message);
            let _ = app.emit("log", message);
        }
    }
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let check = MenuItem::with_id(app, "check", "立即检测", true, None::<&str>)?;
    let launch = MenuItem::with_id(app, "launch-claude", "启动 Claude 桌面端", true, None::<&str>)?;
    // 勾选 = 封锁保护开着。取消勾选 = 原来的「解除封锁（应急）」，再勾上就恢复。
    let protect = CheckMenuItem::with_id(
        app,
        "protection",
        "封锁保护（切断 + 出站锁定）",
        true,
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &check,
            &launch,
            &protect,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    // 勾选状态跟 Guard 里的真实状态对齐（比如上一次切到关掉了）
    if let Some(state) = app.try_state::<AppState>() {
        let on = state.guard.lock().map(|g| g.protection).unwrap_or(true);
        let _ = protect.set_checked(on && !state.lock.disabled());
        if let Ok(mut slot) = state.protection_item.lock() {
            *slot = Some(protect.clone());
        }
    }

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("ClaudeBall — 启动中")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "check" => {
                if let Some(state) = app.try_state::<AppState>() {
                    state.waker.poke();
                }
            }
            "launch-claude" => launch_claude_app(app),
            "protection" => toggle_protection(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                if let Some(state) = tray.app_handle().try_state::<AppState>() {
                    state.waker.poke();
                }
            }
        });

    // 托盘图标不用默认的圆球，只显示当前那盏灯（启动时是黄灯）
    builder = builder.icon(tray_icon("checking", None));
    builder.build(app)?;
    Ok(())
}

fn main() {
    // 第一件事：没管理员令牌就用 UAC 重新拉起自己（提权后的新进程会从头再跑一遍）。
    // 必须在 Tauri/WebView2 起来之前做，否则会白白初始化一次窗口。
    // 已经有实例在跑就立刻退出，连 UAC 都不弹
    if engine::elevate::instance_running() {
        eprintln!("[ClaudeBall] 已经有一个 ClaudeBall 在跑了，本次退出。");
        return;
    }
    ensure_elevated();
    // 单实例锁放在提权之后：普通权限的父进程拉起管理员进程后会退出，
    // 谁先占名额谁就是那个活下来的实例
    if !engine::elevate::claim_single_instance() {
        eprintln!("[ClaudeBall] 已经有一个 ClaudeBall 在跑了，本次退出。");
        return;
    }
    #[cfg(windows)]
    if !engine::elevate::is_elevated() {
        eprintln!(
            "[ClaudeBall] 没有管理员权限：netsh 封锁和 WFP 出站锁定不可用，只剩杀进程。"
        );
    }

    let dir = app_dir();
    let config_path = dir.join("config.json");
    let pos_path = dir.join("window-position.json");
    let blocked_path = dir.join("blocked.json");

    let cfg = Config::load(&config_path);
    let platform = Arc::new(RealPlatform::new());
    let mut guard = Guard::new(cfg, Some(blocked_path));
    let interval = guard.cfg.interval_sec;

    // 上次要是崩在切断状态，这里把残留规则清掉，免得把人锁死
    let stale = guard.clear_stale_block(platform.as_ref() as &dyn Platform);
    for event in stale {
        if let Event::Log(message) = event {
            eprintln!("[ClaudeBall] {message}");
        }
    }

    // 出站锁定：在监视线程起来之前就装好，从启动第一秒起 Claude 就只能走隧道。
    // 打开 WFP 引擎失败（非管理员）只打日志，退回原来的检测+切断行为。
    let lock = Arc::new(EgressLock::new(Some(dir.join("claude-paths.json"))));
    if !lock.available() {
        eprintln!("[ClaudeBall] 出站锁定不可用：{}", lock.reason());
    } else if guard.cfg.enforce_tunnel_only {
        let channel = detect_channel(platform.as_ref() as &dyn Platform, &guard.cfg);
        let paths = platform.claude_exe_paths(&guard.cfg.claude_process_names);
        lock.update(channel.tun_luid, &paths, &channel.proxy_url);
    }

    let state = AppState {
        guard: Mutex::new(guard),
        status: Mutex::new(StatusPayload {
            interval,
            ..Default::default()
        }),
        waker: Arc::new(Waker::default()),
        platform: Arc::clone(&platform),
        lock,
        pos_path: pos_path.clone(),
        protection_item: Mutex::new(None),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![get_status, check_now, quit_app])
        .setup(move |app| {
            let handle = app.handle().clone();

            if let Some(window) = app.get_webview_window("main") {
                if let Some((x, y)) = read_position(&pos_path) {
                    let _ = window.set_position(Position::Physical(PhysicalPosition::new(x, y)));
                }
                let save_path = pos_path.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::Moved(pos) = event {
                        save_position(&save_path, pos.x, pos.y);
                    }
                });
            } else {
                eprintln!("[ClaudeBall] 找不到 main 窗口");
            }

            if let Err(err) = setup_tray(&handle) {
                // 托盘建不出来不该让整个程序挂掉，灯还在
                eprintln!("[ClaudeBall] 托盘图标创建失败：{err}");
            }

            spawn_tray_animation(handle.clone());
            spawn_monitor(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("ClaudeBall 启动失败");
}
