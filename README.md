# ClaudeBall

Claude 网络环境哨兵的 Tauri + Rust 版本。一个浮在桌面上的小信号灯，只干一件事：
盯着 Claude 走的那条链路（tonbo）。链路一出问题就封掉 Claude 的出网并结束进程，
链路恢复了自动放开。没有按钮，不用管它。

## 灯的意思

| 灯 | 状态 | 说明 |
| --- | --- | --- |
| 绿灯常亮 | 正常 | 出口探测和 Claude 可达性都正常 |
| 黄灯闪 | 检查中 | 启动后的第一轮探测（之后不再每轮闪黄） |
| 黄灯闪 | 在守着 | 有提示但没到切断的程度（比如出口 IP 变了、Claude 有直连） |
| 红灯常亮 | 已切断 | 代理通道/梯子进程消失，或连续 2 次异常：已封网 + 结束 Claude 进程 |
| 红灯常亮 | 异常 | 单次异常，还没到阈值 |

通道消失（TUN 网卡断开/系统代理关掉）是硬信号：**大约 1~2 秒内变红并切断**，
不会等 `fail_threshold`，也不会在这时候去做出口探测（那会把真实 IP 送出去）。

## 红灯之后

切断不是终点，程序每一轮还在做这些事（节奏和平时一样：`interval_sec = 3` 秒一轮；
通道一直不在时看门狗会让它 1～2 秒就转一轮）：

1. **照常探测**，判断链路有没有恢复。通道不在的那一轮不发网络请求（避免真实 IP 直连）。
2. **继续压住 Claude**：这期间新冒出来的 `claude.exe` 每个都会被结束（`enforce`）。
3. **灯保持红色「已切断」**，并显示原因。
4. **自动解除的条件**：连续 3 次（`restore_after_good`）没有任何异常，
   并且距切断已经过了 60 秒（`restore_cooldown_sec`）——两个条件都满足才会放开。
   链路一恢复就满足的话，也要等满冷却期。

它**不会**帮你把 Claude 重新启动起来（进程已经被杀了），也不会「立即重测」——
它本来就一直在按间隔测。想催的话，点托盘「立即检测」或灯本身（左键单击）。

## 出站锁定（WFP）

除了上面「检测到异常再切断」，还有一层更硬的保护：用 Windows Filtering Platform
给 Claude 的 exe 装过滤器，只放行三种出站连接——

1. 出接口是 Tonbo 的 TUN 网卡；
2. 目标是本机回环 `127.0.0.0/8` / `::1`（系统代理模式）；
3. 目标是系统代理的远程 IP（代理不在本机时）。

其余全部 block。**隧道一断，第 1 条自然不成立，block 立刻生效**，不依赖 3 秒一轮
的探测，所以断开的瞬间 Claude 一个包都出不去。Tonbo 自己不受影响（过滤只按
Claude 的 exe 路径匹配）。

过滤器挂在 WFP 的**动态会话**上：程序退出或崩溃时 Windows 自动删掉，不会留下锁死
的规则。不想要这一层就把 `enforce_tunnel_only` 改成 `false`，它就完全不碰 WFP。

## 怎么操作

左键拖动灯换位置（位置会记住，下次启动还在原地）。左键单击立刻检查一次。
右键菜单在**托盘图标**上：立即检测 / 启动 Claude 桌面端 / 封锁保护（勾选开关）/ 退出。
灯本身没有菜单。

「启动 Claude 桌面端」认两种安装：商店/MSIX 版按 AUMID 走
`shell:AppsFolder\Claude_xxx!Claude`（exe 藏在带版本号的 WindowsApps 目录里，不能写死路径），
常规安装则依次试 `%LOCALAPPDATA%\Programs\Claude\Claude.exe`、
`%ProgramFiles%\Claude\Claude.exe`。两种都由 `explorer.exe` 代劳拉起，
所以是**普通权限**，不会被 ClaudeBall 自己的管理员身份带高。
切断状态下它不会启动，而是弹个框说明原因——那时候拉起来下一秒就会被 `enforce` 杀掉；
找不到桌面端时也会弹框告诉你。

**封锁保护**是个勾选项：

- **勾着**（默认）= 正常状态：按规则检测、切断、装出站锁定。
- **取消勾选** = 原来的「解除封锁（应急）」：删掉 WFP 出站锁定、清掉 netsh 封锁规则、
  退出切断状态，本次运行不再自动切断。真被锁死、按菜单也点不动的时候用。
- **再勾上** = 立刻恢复：出站锁定下一轮重新装上，切断规则重新生效。

开关只影响本次运行，`config.json` 不会被改。关掉期间托盘提示里会带
「封锁保护已关闭」，避免误以为还在保护。

## 先装什么

1. **Rust**：https://rustup.rs 下载 rustup-init.exe 一路回车。装完 `cargo --version` 有输出。
2. **Node.js 18+**：https://nodejs.org 下 LTS 版。
3. **WebView2**：Win10 19045 一般已经有了；没有的话打包时会自动提示装。

## 构建

在 `ClaudeBall` 目录里：

```
npm install
npm run dev      # 开发模式，改代码热加载
npm run build    # 出安装包
```

`npm run build` 的产物：

```
src-tauri\target\release\ClaudeBall.exe          直接能跑的单文件
src-tauri\target\release\bundle\msi\*.msi        安装包
src-tauri\target\release\bundle\nsis\*-setup.exe 安装包
```

第一次构建要编译整个 Tauri 依赖树，**大概 5–15 分钟**，之后就快了。

## 为什么需要管理员权限

切断用的是 `netsh advfirewall` 加一条出站阻断规则，出站锁定用的是 WFP，
两者都必须有管理员权限。**程序启动时会自己用 UAC 重新拉起自己**
（`engine/elevate.rs`，用令牌查询判断，不依赖 `net session`）：

- 直接双击 `ClaudeBall.exe` → 弹 UAC，点是，直接就是管理员，完整功能。
- 点「否」也不会打不开：照常以普通权限运行，只是 netsh 和 WFP 两层不可用、只剩杀进程，
  程序会在日志里说明。
- `启动-管理员.bat` 和右键「以管理员身份运行」仍然可用（效果一样，只是多一层）。
- 开发模式（debug 构建）默认**不**自提权，要用管理员就在启动前设 `CLAUDEBALL_ELEVATE=1`；
  任何情况都可以用 `CLAUDEBALL_NO_ELEVATE=1` 强制跳过自提权。

想让每次开机都自动跑，把 `启动-管理员.bat` 的快捷方式丢进
`shell:startup`（Win+R 输入这个就能打开启动文件夹）。

## 配置

首次运行会在 exe 旁边生成 `config.json`，字段和 Python 版完全一样：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `interval_sec` | 3 | 检查间隔 |
| `timeout_sec` | 3 | 单次网络探测超时 |
| `fail_threshold` | 2 | 连续几次网络异常才切断（通道/进程消失会立刻切，不看这个） |
| `restore_after_good` | 3 | 连续几次正常才自动解除 |
| `restore_cooldown_sec` | 60 | 切断后至少锁多少秒 |
| `allowed_countries` | `[]` | 出口地区白名单，例 `["JP","US"]` |
| `expected_exit_ip` | `""` | 固定出口 IP |
| `proxy_override` | `""` | 手动指定探测代理，例 `127.0.0.1:7890` |
| `dry_run` | `false` | 改 `true` 就只记录不动手 |
| `enforce_tunnel_only` | `true` | WFP 出站锁定：Claude 只许从隧道网卡出去；`false` 关掉这一层 |

`rules` 里每条判定可以写 `true`（切断）/ `"warn"`（只提示）/ `false`（关闭）。

默认关键字已经覆盖 `sing-box`、`tonbo`、`clash`、`v2ray`、`tun` 这些，
所以你现在的 sing-box + tun0 应该开箱就认得出来。

## 和 Python 版的区别

- **没有自动识别 tonbo 的按钮**。默认关键字已经覆盖常见客户端；
  真认不出来就在 `config.json` 里补 `tonbo_process_keywords` / `tun_adapter_keywords`。
- 判定是严格的：**代理通道或梯子进程一消失就立刻切断**，不等 `fail_threshold`。
  通道没了的时候连出口探测都不做——那时候直连出去的就是真实 IP。
  如果某块没被认出来的网卡导致误切，把网卡名加进 `tun_adapter_keywords`
  （状态栏/日志里会列出检测到的网卡名）。
- 解除封锁和重新封锁都是托盘里的同一个勾选项，随时切换、不用重启。
  关掉时它会同时删掉 WFP 过滤器和 netsh 规则，并且本次运行不再自动切断。
  WFP 那层是动态会话，程序一退出就没了，最坏情况下重新启动程序也能恢复。
  不要用 `netsh advfirewall firewall delete rule name=all`，那会删掉所有规则。
- 启动时自动用 UAC 提权，不用再记得走 `启动-管理员.bat`。

## 应急

先把托盘菜单里「封锁保护」的勾取消掉（等于以前的「解除封锁（应急）」），
它会删掉 WFP 过滤器、清掉 netsh 规则、退出切断状态，并且本次运行不再切断。
链路正常之后再勾回去就恢复保护，不用重启。

要是连托盘都点不到（或者程序已经不在了），WFP 那一层什么都不用做——
动态会话在程序退出时自动清空。

netsh 那层用管理员身份开个命令行，先列出规则：

```
netsh advfirewall firewall show rule name=all | findstr /C:"ClaudeBall-Block"
```

再按名字逐条删掉：

```
netsh advfirewall firewall delete rule name="ClaudeBall-Block-<那一串哈希>"
```

程序正常退出时不会留规则；非正常退出的话，下次启动会自动清掉
`blocked.json` 里记录的残留规则。

## 验证情况（说实话）

在 Linux 沙箱里能验的都验了：

- `engine/` 下的纯逻辑（解析、打分、判定、状态机、代理地址解析）有 **73 个单元测试**，
  `cargo test` 全过。这部分包括切断、自动解除、冷却期、演练模式、残留清理，
  封锁保护开关（关掉后不再切断、能重新打开、能清掉正在生效的封锁），
  以及出口探测「谁先成功就用谁」（有故意慢 800ms 的地址时整轮不等它）。
- Win32 网卡枚举（`GetAdaptersAddresses`）有在 Windows 上实际跑的测试。
- WFP 过滤器有一条「打开引擎 → 建 sublayer → 给自己的 exe 加 block → 删掉」的
  往返测试；非管理员时自动跳过。
- `ui/style.css` 过了 postcss 解析，`ui/main.js` 过了 `node --check`。
- 图标是脚本生成的真 PNG/ICO。

**Win10 19045 上实机验过的**：release 能构建并运行；双击非管理员启动会自己弹 UAC
并变成管理员进程；重复启动不会多开、也不会重复弹 UAC；托盘勾选切换的逻辑由单元测试覆盖。

**还需要真机确认的**：`tauri build` 能出包（已在 Win10 19045 上出过 MSI/NSIS），
`platform_windows.rs` 里 netsh/taskkill 那几步在管理员权限下的实际效果，
以及管理员 + Tonbo TUN 连上时：Claude 正常联网 → Tonbo 断开 Claude 立刻没网 →
托盘取消勾选「封锁保护」恢复 → 重新勾上 → 重连 Tonbo 3 秒内自动恢复保护。
