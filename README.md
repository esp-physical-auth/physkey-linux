<h1 align="center">
  <br>
  <img src="assets/logo.svg" alt="logo" width="180">
  <br>
  physkey-linux
  <br>
  <span style="font-size:0.7em;color:#888;">Passkey (FIDO2) · ESP32-C5 · 系统级接入</span>
  <br><br>
</h1>

![Rust](https://img.shields.io/badge/rust-2024%20edition-000000?logo=rust)
![License](https://img.shields.io/badge/license-GPL%20v3-blue)
![Backend](https://img.shields.io/badge/backend-ESP32--C5--BLE-orange)

**physkey-linux** 是一个把 **ESP32-C5 变成真正 FIDO2 硬件安全密钥** 的桥接守护进程。
它在 Linux 内核里注册一个虚拟 UHID 设备，浏览器通过标准 USB-HID 通道看到一把合规的
FIDO2 密钥；所有密钥生成和 P-256 签名操作则经 Nordic UART Service (NUS) 蓝牙协议，
安全地转发给 ESP32 硬件执行——**私钥永不离开设备**。

---

## ⚠️ 安全声明

physkey-linux 不是软件模拟器：

- **密钥生成、P-256 签名、凭证存储** 全部在 ESP32-C5 硬件内完成
- 主机上运行的是 **CTAP2 编解码器 + 蓝牙传输层**，永远看不到私钥
- 通过 **CA 证书链 + 挑战响应** 防止蓝牙中间人攻击
- 这把虚拟密钥对浏览器来说和 YubiKey、Solo 等硬件密钥无差别

但请注意：ESP32 不是安全芯片 (Secure Element / TPM)，它能提供"私钥永不导出"的边界，
但无法实现专用安全芯片的防物理克隆、侧信道防护等能力。对于高价值账户，依然推荐
TPM 级别的硬件密钥。

---

## 架构

```
┌────────────────────────────────────────────────────────────────┐
│                    浏览器 WebAuthn                              │
│         Chrome / Firefox / Edge / Brave / Vivaldi               │
└──────────────────────────┬─────────────────────────────────────┘
                           │ CTAP2 over USB-HID
                           ▼
┌────────────────────────────────────────────────────────────────┐
│  physkey-linux daemon (用户态)                                  │
│                                                                │
│   ┌──────────────────┐    ┌───────────────────┐               │
│   │ soft-fido2       │    │  BLE NUS 协议栈   │               │
│   │ Authenticator    │◄──►│  btleplug + tokio  │               │
│   │ (CTAP2 编解码)   │    │                   │               │
│   └────────┬─────────┘    └─────────┬─────────┘               │
│            │                         │                         │
│   ┌────────▼─────────────────────────▼──────────┐             │
│   │   CredentialStorage + CredentialKeyProvider   │             │
│   │        (凭证元数据 + 密钥操作抽象层)         │             │
│   └────────────────────┬─────────────────────────┘             │
│                        │ NUS 文本协议                          │
└────────────────────────┼──────────────────────────────────────┘
                         │ 蓝牙
                         ▼
          ┌─────────────────────────────┐
          │  ESP32-C5 硬件              │
          │  (私钥永不导出)             │
          │                             │
          │  WA_REG    密钥生成         │
          │  WA_SIGNHASH  P-256 签名    │
          │  WA_LIST / WA_META  凭证   │
          │  GETCERT / AUTH  信任链     │
          │  AUTHPASS  解锁口令        │
          └─────────────────────────────┘
```

### 数据通路

```
浏览器: navigator.credentials.create()
  → CTAP2 MakeCredential (CBOR)
  → 虚拟 UHID (/dev/uhid)
  → physkey-linux 解包
  → WA_REG esp32 user\n  (BLE)
  → ESP32 生成 P-256 密钥对
  → 返回 内部 ID + 公钥
  → 用 WA_SETMETA 把 rp_id / user 等元数据写回 ESP32
  → physkey-linux 组装 CTAP2 MakeCredential 响应
  → 浏览器收到 OK ✅
```

```
浏览器: navigator.credentials.get()
  → CTAP2 GetAssertion
  → physkey-linux 按 web credential id 查 ESP32
  → WA_WEBSIGNHASH <id> <sha256>
  → ESP32 内部签名 → 返回 64 字节 raw (r||s)
  → physkey-linux 转 DER 编码，组装 CTAP2 响应
  → 浏览器验证签名 ✅
```

---

## 功能清单

| 功能 | 状态 | 说明 |
|------|------|------|
| FIDO2 / WebAuthn 完整合规 | ✅ | soft-fido2 引擎，CTAP1 + CTAP2 |
| Passkey (resident credential) | ✅ | `rk=true`，支持自动填充 |
| 硬件密钥生成（P-256 ES256） | ✅ | 私钥锁死在 ESP32 |
| 硬件签名 | ✅ | SHA-256 摘要 + P-256 raw 签名 |
| 凭证全存储在设备端 | ✅ | 本地不落盘（方案 A1） |
| 用户确认（User Presence） | ✅ | D-Bus 桌面通知，支持超时 |
| 内置 PIN / UV | ✅ | 可配置 enforcement 策略 |
| PIN 重试 / UV 锁定 | ✅ | 默认 8 次 |
| 凭证管理（列举/删除） | ✅ | CTAP2 credMgmt 命令 |
| 信任链校验 | ✅ | CA 证书 + 挑战响应 |
| 多浏览器兼容 | ✅ | 任何支持 UHID 的浏览器 |
| 多 daemons 互斥 | ✅ | 实例锁 + 同一 backend 状态目录互斥 |
| Agent 自动化代理 | ⚗️ 实验性 | 策略控制的 WebAuthn 代理 |

### 已知限制

- **仅支持 P-256 (ES256)**，FIDO2 的唯一强制算法
- **不支持其他后端**：pass / TPM / local 在本构建中已屏蔽
- **需要蓝牙适配器**（`btleplug` 支持 BlueZ，不支持 Windows / macOS）
- **Flatpak / Snap 沙盒应用** 可能无法直接访问 `/dev/uhid`，需配合 credentialsd

---

## 快速开始

### 先决条件

```bash
# 内核模块
sudo modprobe uhid
echo uhid | sudo tee /etc/modules-load.d/fido.conf

# 权限：把自己加入 fido 组
sudo groupadd -f fido
sudo usermod -aG fido $USER

# udev 规则
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | sudo tee /etc/udev/rules.d/90-passless.rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# 蓝牙：确保有适配器且运行中的 BlueZ
bluetoothctl list     # 应有 Controller
systemctl status bluetooth
```

**注销并重新登录**，让新组生效。

### 从源码编译

```bash
# 进入 workspace 根目录
cd physkey-linux/

# 编译（默认 feature 集：ESP32 BLE 桥接，无 agent / tpm）
cargo build --release -p passless-rs

# 带 agent 功能（策略控制的自动化认证）
cargo build --release -p passless-rs --features agent

# 只编译核心协议库（Android JNI 集成用）
cargo build --release -p esp32-fido-core --features jni
```

**注意**：Rust 2024 edition 需要 Rust ≥ 1.85。如果编译 agent feature，需要额外依赖 `libdbus-1-dev`（`zbus` 运行时通过 BlueZ DBus 代理蓝牙交互）。

编译产物位置：
- 守护进程二进制：`target/release/passless`
- ESP32 协议库：`target/release/libesp32_fido_core.so`（Android 交叉编译产物由 Gradle 任务负责，见 physkey-android README）

### 安装

```bash
# 一键安装：二进制 + systemd + udev + sysusers
make install

# 单独步骤
make install-binary     # 二进制 → ~/.cargo/bin
make install-systemd     # systemd user service → ~/.config/systemd/user
make install-udev       # udev 规则 → /etc/udev/rules.d
make install-sysusers   # 创建 fido 组
make install-modules    # 自动加载 uhid 模块
```

### 启动守护进程

```bash
# 前台运行（调试用）
cargo run -p passless-rs --release

# 或直接运行已编译的二进制
./target/release/passless

# 作为 systemd user service
systemctl --user enable --now passless
journalctl --user -u passless -f
```

### ESP32 设备端

需要一台烧录了 **FIDO2 NUS 固件** 的 ESP32-C5 / ESP32-C3 / ESP32-S3。
固件必须实现以下协议（Nordic UART Service，文本行协议）：

```
RX: 6e400002-b5a3-f393-e0a9-e50e24dcca9e
TX: 6e400003-b5a3-f393-e0a9-e50e24dcca9e

# 命令（长度前缀 4 位 hex + 20 字节分片写入）
AUTHPASS <password>              → OK / ERR
GETCERT                          → CERT:<base64 len-prefixed>
AUTH <nonce_b64>                 → OK SIG:<sig_b64>
WA_REG <rp> [user]               → OK CRED:<id_hex> + PUBKEY:<pub_b64>
WA_PUB <id_hex>                  → OK PUBKEY:<pub_b64>
WA_SIGNHASH <id_hex> <sha256b64> → OK SIG:<sig_b64>
WA_WEBSIGNHASH <webid_b64> <sha256b64> → OK SIG:<sig_b64>
WA_LIST                          → 每行 "id_hex\trp\tuser" + OK
WA_META <id_hex>                 → key=value...
WA_WEBMETA <webid_b64>           → key=value...
WA_SETMETA <id_hex> <kvs>        → OK / ERR
WA_SETMETA_WEB <webid_b64> <kvs> → OK / ERR
WA_DEL <id_hex>                  → OK / ERR
WA_WEBDEL <webid_b64>            → OK / ERR
WA_COUNT                         → OK N credentials
```

设备名默认 `ATRI-TOTP`，可用 `--esp32-device-name` 覆盖。

### 验证

```bash
# 查看守护进程日志
passless -v          # verbose 模式
journalctl --user -u passless -f

# 浏览器里打开
# https://webauthn.io/  → 注册 passkey → 会看到"ATRI-TOTP"设备弹窗
# https://demo.yubico.com/webauthn
# 或直接用 Yubikey Manager / FIDO2 tools 查询设备信息

# 本地 client 命令（另开终端，守护进程要在运行）
passless client devices           # 列出所有 FIDO2 设备
passless client info              # 显示 AAGUID、能力矩阵等
passless client list              # 列出设备上所有凭证
```

---

## 配置

配置文件路径：`~/.config/physkey-linux/config.toml`

```bash
passless config print > ~/.config/physkey-linux/config.toml   # 生成默认模板
```

### 完整示例

```toml
# ===== 设备端 =====
backend_type = "esp32"                                    # 本构建唯一有效值

[esp32]
device_name = "ATRI-TOTP"                                 # BLE 广播名
ca_pubkey = ""                                            # CA 公钥 (P-256 未压缩点, base64)
                                                          # 留空使用内置默认值

# ===== 安全加固 =====
[security]
check_mlock = true                  # 尝试 mlock 防止凭证换出
disable_core_dumps = true           # RLIMIT_CORE + prctl PR_SET_DUMPABLE
constant_signature_counter = true   # 固定签名计数器，帮助 RP 检测克隆
always_uv = true                    # 每次都触发 UV 确认
user_verification_registration = true
user_verification_authentication = true
notification_timeout = 30           # 弹窗超时秒数

# ===== PIN / UV =====
[pin]
enforcement = "optional"            # never | optional | required
min_length = 4                      # PIN 最小长度 (4-63)
max_retries = 8                     # PIN 重试上限
max_uv_retries = 8                  # UV 重试上限，用光用 `uv-reset` 恢复
auto_lock_timeout = 0               # 0 = 禁用

# ===== Agent 代理（实验性） =====
[agents]
enabled = false                     # 默认关闭
```

### 信任链 CA

ESP32 端必须有 CA 签发的设备证书（P-256），physkey-linux 会：

1. 读 ESP32 的 `GETCERT` 响应
2. 用 `ca_pubkey` 验签证书 payload
3. 生成随机 nonce，发 `AUTH <nonce>`
4. 用证书里的设备公钥验签响应
5. **验签不过就拒绝连接**，防止蓝牙中间人

`ca_pubkey` 留空时使用内置默认值（与项目内 CA 脚本生成的默认 CA 一致）。
如果你自己建 CA，把 P-256 未压缩点 base64 填进去即可：

```bash
openssl pkey -in ca.key -pubout -raw | base64
```

### 用户确认模式

默认弹 D-Bus 桌面通知。无图形环境时可自动批准（仅限受控环境）：

```bash
PASSLESS_INTERACTION_MODE=automatic passless
```

systemd service 里设置：

```ini
Environment=PASSLESS_INTERACTION_MODE=automatic
```

> ⚠️ `automatic` 会静默批准所有 UP/UV 请求，只在完全受控的部署中使用。

---

## CLI 速查

```bash
# ===== 守护进程 =====
passless                         # 前台运行
passless --backend-type esp32    # 显式指定后端
passless --esp32-device-name MY-KEY --verbose

# ===== Client（守护进程运行中才能用） =====
passless client devices                       # 枚举 FIDO2 设备
passless client info                          # 查看本守护进程伪装的设备信息
passless client list                          # 列出全部凭证
passless client list -d github.com            # 按 RP 过滤
passless client show <credential_id_hex>      # 查看单条详情
passless client delete <credential_id_hex>    # 删除凭证
passless client pin set 1234                  # 设置 PIN
passless client pin change 1234 5678          # 修改 PIN
passless client pin uv-reset                  # 恢复 UV 重试计数
passless client reset --yes-i-really-want-to-reset-my-device --yes-i-really-want-to-reset-my-device  # ⚠️ 清空全部凭证
```

---

## 安全加固

physkey-linux 默认开启：

| 措施 | 位置 | 目的 |
|------|------|------|
| `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` | `config.rs` | 阻止 core dump 泄漏凭证 |
| `mlock` 探测 | `config.rs` | 内存锁定，防止换出 |
| 单实例锁 | `main.rs` | 同 backend 状态目录只能一个 daemon 运行 |
| 操作锁（`Mutex<()>`） | `main.rs:83` | CTAP 请求串行化，防并发 race |
| RP ID 校验 | `authenticator.rs:489` | 拒绝对无效/越界 RP ID 的枚举 |
| PIN / UV 重试限制 | `authenticator.rs` | 默认各 8 次 |
| ESP32 信任链校验 | `esp32.rs:146` | CA 验签 + 挑战响应 |
| 启动解锁一次、后续复用 | `esp32.rs:243` | 设备密码只输一次，中途掉线自动清缓存 |

### 权限设计

- 守护进程以 **普通用户** 运行，**不要求 root**
- 仅需 `/dev/uhid` 的读写权限（通过 fido 组 + udev 规则）
- 蓝牙适配器的访问由 BlueZ 管理（通常默认允许当前会话用户）

---

## 调试

```bash
# 1) 看 UHID 模块
lsmod | grep uhid

# 2) 手动权限测试
sudo chmod 666 /dev/uhid         # 临时绕过 udev（仅调试）

# 3) 直接跑守护进程看日志
RUST_LOG=debug passless --verbose

# 4) 蓝牙扫描（验证设备在广播）
bluetoothctl scan on
# 等看到 ATRI-TOTP 后 Ctrl+C

# 5) 浏览器层面：用 FIDO2 调试工具
# https://www.google.com/servicelogin/webauthndebugtool

# 6) systemd journal
journalctl --user -u passless -f -o cat

# 7) 单元测试
cargo test --all-features
```

常见错误：

| 报错 | 原因 | 解决 |
|------|------|------|
| `Failed to create UHID device` | uhid 模块未加载或权限不够 | `modprobe uhid` + udev 规则 |
| `BLE 设备 'ATRI-TOTP' 未找到` | 设备没开 / 名不对 / 蓝牙适配器坏了 | `bluetoothctl scan on` 确认 |
| `设备证书验签失败` | ESP32 证书不是内置 CA 签发的 | 用同一 CA 重新签发，或填 `ca_pubkey` |
| `AUTH 响应异常` | ESP32 固件版本不匹配 | 确认固件实现了完整协议 |

---

## 项目结构

```
physkey-linux/
├── cmd/passless/src/           # 主 crate
│   ├── main.rs                 # 入口：UHID 创建、后端路由、shutdown
│   ├── authenticator.rs        # AuthenticatorService + WebAuthn 回调
│   ├── esp32.rs                # BLE 连接 + CredentialKeyProvider + 信任链
│   ├── storage/
│   │   ├── mod.rs              # CredentialStorage trait
│   │   └── esp32/mod.rs        # ESP32 存储适配器（凭证全在设备端）
│   ├── worker.rs               # UHID worker 调度
│   ├── pin_storage/            # Local / Pass / TPM PIN 存储
│   ├── commands/               # CLI 子命令实现
│   └── agent/                  # 实验性 agent 系统（策略 + 审计 + 浏览器代理）
├── passless-core/              # 公共类型：配置、错误、协议
├── passless-uhid/              # UHID 封装
├── passless-config-doc/        # 配置文档生成
├── contrib/
│   ├── systemd/passless.service
│   ├── udev/90-passless.rules
│   ├── sysusers.d/passless.conf
│   └── modules-load.d/fido.conf
└── Makefile
```

---

## 致谢

本项目基于 [passless](https://github.com/pando85/passless) 修改，核心 FIDO2 引擎
[soft-fido2](https://github.com/pando85/soft-fido2) 提供 CTAP 编解码、认证模拟
和密钥抽象。感谢这些开源项目及其贡献者。