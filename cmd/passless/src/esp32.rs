//! ESP32-C5 BLE FIDO2 桥
//!
//! 把 passless / soft-fido2 的密钥操作转发给一台运行自定义 NUS 文本协议的
//! ESP32 硬件。架构：
//!
//! ```text
//! 浏览器 WebAuthn
//!   ↕ USB-HID (soft-fido2)
//! passless (本模块)
//!   ↕ BLE / Nordic UART Service (文本协议)
//! ESP32-C5  (私钥永不导出，只负责生成与签名)
//! ```
//!
//! ESP32 端协议（NUS RX 写入指令，TX 通知返回，UTF-8 文本）：
//! ```text
//! AUTHPASS <pw>                      -> OK auth ok
//! WA_REG <rp> [user]                 -> OK <id_hex> <pub_b64>
//! WA_PUB <id_hex>                    -> OK PUBKEY:<pub_b64>
//! WA_SIGNHASH <id_hex> <b64hash32>   -> OK SIG:<sig_b64>
//! WA_DEL <id_hex>                    -> OK deleted
//! ```
//!
//! 关于签名：soft-fido2 的 `sign()` 拿到的是 **CTAP 层已拼好的完整待签消息**，
//! 而 ESP32 的 `wa_sign_hash` 接收的是 **32 字节 SHA-256 摘要**且不再二次哈希。
//! 因此这里的 `sign()` 负责先对 message 做 SHA-256，再发 `WA_SIGNHASH`。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use base64::Engine as _;
use futures::stream::StreamExt;
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
use soft_fido2::{
    CredentialKey, CredentialKeyError, CredentialKeyProvider, CredentialKeyProviderId,
    GeneratedCredentialKey,
};
use soft_fido2_ctap::sec_bytes::SecBytes;
use tokio::sync::Mutex as AsyncMutex;

/// ESP32 的 BLE 广播名（见 main/ble_totp.h: BLE_DEVICE_NAME）
const DEFAULT_DEVICE_NAME: &str = "ATRI-TOTP";

/// Nordic UART Service UUID
const NUS_SERVICE_UUID: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
/// RX 特征（写入指令）
const NUS_RX_UUID: &str = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
/// TX 特征（订阅通知）
const NUS_TX_UUID: &str = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";

/// 自定义 provider 的稳定 ID（序列化进 CredentialKey）
const ESP32_PROVIDER_ID: &[u8] = b"esp32-nus-v1";

/// 单次 BLE 命令超时
const CMD_TIMEOUT: Duration = Duration::from_secs(20);

fn provider_id() -> CredentialKeyProviderId {
    CredentialKeyProviderId::new(ESP32_PROVIDER_ID)
}

/// 内部 BLE 连接（异步）。所有方法串行化以保证请求/响应配对。
pub struct BleLink {
    peripheral: Peripheral,
    rx: Characteristic,
    tx: Characteristic,
    notify: Arc<AsyncMutex<futures::stream::BoxStream<'static, Vec<u8>>>>,
}

/// 共享的 ESP32 连接句柄：storage 与 key provider 复用同一连接。
/// 内含 tokio 运行时、设备名、连接缓存与密码回调。
pub struct Esp32Link {
    device_name: String,
    link: Mutex<Option<Arc<BleLink>>>,
    rt: tokio::runtime::Runtime,
    pass_prompt: Mutex<Option<Box<dyn Fn() -> Result<String, String> + Send + Sync>>>,
    /// 启动时输过一次密码并解锁成功后置 true。
    /// 之后所有需要解锁的操作都直接复用，不再弹窗（"启动输一次，自动批准"）。
    unlocked: Mutex<bool>,
    /// 根 CA 公钥（P-256 未压缩点 base64，65 字节），用于信任链校验。
    ca_pubkey_b64: String,
    /// 部署标识确认回调（对齐 web/authnkey 的“这是你自己部署的设备吗”弹窗）。
    /// 返回 true = 用户确认；false/None = 拒绝（断开连接）。
    deploy_prompt: Mutex<Option<Box<dyn Fn(&str) -> bool + Send + Sync>>>,
    /// 最近一次验签通过的部署标识（内嵌于证书），供上层 UI 提示确认。
    deployment_id: Mutex<Option<String>>,
}

impl Esp32Link {
    pub fn new(
        device_name: Option<String>,
        pass_prompt: Option<Box<dyn Fn() -> Result<String, String> + Send + Sync>>,
    ) -> Result<Arc<Self>, String> {
        Self::new_with_ca(device_name, pass_prompt, None)
    }

    pub fn new_with_ca(
        device_name: Option<String>,
        pass_prompt: Option<Box<dyn Fn() -> Result<String, String> + Send + Sync>>,
        ca_pubkey_b64: Option<String>,
    ) -> Result<Arc<Self>, String> {
        Self::new_full(device_name, pass_prompt, ca_pubkey_b64, None)
    }

    pub fn new_full(
        device_name: Option<String>,
        pass_prompt: Option<Box<dyn Fn() -> Result<String, String> + Send + Sync>>,
        ca_pubkey_b64: Option<String>,
        deploy_prompt: Option<Box<dyn Fn(&str) -> bool + Send + Sync>>,
    ) -> Result<Arc<Self>, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .map_err(|e| format!("build tokio runtime: {e}"))?;
        Ok(Arc::new(Self {
            device_name: device_name.unwrap_or_else(|| DEFAULT_DEVICE_NAME.to_string()),
            link: Mutex::new(None),
            rt,
            pass_prompt: Mutex::new(pass_prompt),
            unlocked: Mutex::new(false),
            ca_pubkey_b64: ca_pubkey_b64
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| passless_core::config::DEFAULT_ESP32_CA_PUBKEY_B64.to_string()),
            deploy_prompt: Mutex::new(deploy_prompt),
            deployment_id: Mutex::new(None),
        }))
    }

    /// 建立（或复用）BLE 连接。
    fn ensure_link(&self) -> Result<Arc<BleLink>, CredentialKeyError> {
        if let Some(link) = self.link.lock().unwrap().clone() {
            return Ok(link);
        }
        let dev = self.device_name.clone();
        let link = self
            .rt
            .block_on(async { BleLink::connect(&dev).await })
            .map_err(|e| {
                warn!("[esp32] 连接失败: {e}");
                CredentialKeyError::TransientFailure(e)
            })?;
        let link = Arc::new(link);
        // 信任链校验：验签设备证书 + 挑战响应，防中间人。
        if let Err(e) = self.verify_device(&link) {
            warn!("[esp32] 设备身份校验失败，拒绝连接: {e:?}");
            // 丢弃连接（drop 在 runtime 上下文中执行）
            let _g = self.rt.enter();
            drop(link);
            return Err(e);
        }
        *self.link.lock().unwrap() = Some(link.clone());
        Ok(link)
    }

    /// 信任链校验（SSL/TLS 式三级链，全程离线，对齐 web/totp.html）：
    ///   1. GETCERT 取设备证书链，用【内置根 CA 公钥】验签：
    ///      两段链：根CA公钥→验中间CA证书→取中间CA公钥→验设备证书
    ///      单段：直接用内置根 CA 公钥验设备证书
    ///   2. AUTH <nonce> 让设备用私钥签名随机数，用设备公钥验签（确认持有私钥）
    ///   3. 打印/日志展示部署标识，供上层 UI 提示用户确认
    fn verify_device(&self, link: &BleLink) -> Result<(), CredentialKeyError> {
        use p256::ecdsa::{signature::Verifier as _, Signature as EcSig, VerifyingKey};

        // 1) 取证书
        let cert_resp = self
            .rt
            .block_on(async { link.command("GETCERT\n").await })
            .map_err(CredentialKeyError::TransientFailure)?;
        let cert_b64 = cert_resp
            .split("CERT:")
            .nth(1)
            .ok_or_else(|| CredentialKeyError::PermanentFailure(
                "设备未安装证书（需先用电脑 CA 签发 SETCERT）".to_string(),
            ))?
            .trim();

        // GETCERT 可能返回两段：“设备证书|中间CA证书”（三级链）。
        // 必须【先按 '|' 拆段】再逐段 base64 解码（不能整串解码，否则 '|' 非法）。
        let parts: Vec<&str> = cert_b64.split('|').filter(|s| !s.is_empty()).collect();
        let device_cert = base64::engine::general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("设备证书 b64 解码失败: {e}")))?;
        let user_ca_cert: Option<Vec<u8>> = if parts.len() >= 2 {
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(parts[1])
                    .map_err(|e| CredentialKeyError::PermanentFailure(format!("中间 CA 证书 b64 解码失败: {e}")))?,
            )
        } else {
            None
        };

        // 拆设备证书（len(2)||payload||slen(2)||sig）
        let (payload, sig) = split_cert(&device_cert)
            .ok_or_else(|| CredentialKeyError::PermanentFailure("设备证书长度越界".into()))?;

        // 解析 payload（兼容 0x01/0x02），取出 deployment_id 与设备公钥
        let (deployment_id, pub_off) = parse_cert_payload(payload)
            .ok_or_else(|| CredentialKeyError::PermanentFailure("证书 payload 格式异常".into()))?;
        if payload.len() < pub_off + 81 {
            return Err(CredentialKeyError::PermanentFailure("证书 payload 异常".into()));
        }
        let device_pub = &payload[pub_off..pub_off + 65]; // 0x04||X||Y

        // 选验证公钥（全程离线，仅用内置根 CA 公钥）：
        //   - 两段链：根CA公钥→验中间CA证书→取中间CA公钥
        //   - 单段：直接用内置根 CA 公钥
        let verify_pub_raw: Vec<u8> = if let Some(uca) = &user_ca_cert {
            // 1) 用根 CA 公钥验中间 CA 证书
            let root_raw = base64::engine::general_purpose::STANDARD
                .decode(&self.ca_pubkey_b64)
                .map_err(|e| CredentialKeyError::PermanentFailure(format!("根 CA 公钥 b64 解码失败: {e}")))?;
            if root_raw.len() < 65 || root_raw[0] != 0x04 {
                return Err(CredentialKeyError::PermanentFailure("根 CA 公钥格式异常".into()));
            }
            let root_key = VerifyingKey::from_sec1_bytes(&root_raw[..65])
                .map_err(|e| CredentialKeyError::PermanentFailure(format!("根 CA 公钥无效: {e}")))?;
            let (uca_payload, uca_sig) = split_cert(uca)
                .ok_or_else(|| CredentialKeyError::PermanentFailure("中间 CA 证书长度越界".into()))?;
            let uca_sig_obj = EcSig::from_slice(uca_sig)
                .map_err(|e| CredentialKeyError::PermanentFailure(format!("中间 CA 证书签名解析失败: {e}")))?;
            root_key.verify(uca_payload, &uca_sig_obj).map_err(|_| {
                CredentialKeyError::PermanentFailure("中间 CA 证书验签失败：非本根 CA 签发".into())
            })?;
            let (uca_id, uca_pub_off) = parse_cert_payload(uca_payload).ok_or_else(|| {
                CredentialKeyError::PermanentFailure("中间 CA 证书 payload 异常".into())
            })?;
            if uca_payload.len() < uca_pub_off + 65 {
                return Err(CredentialKeyError::PermanentFailure("中间 CA 证书 payload 异常".into()));
            }
            let user_ca_pub = uca_payload[uca_pub_off..uca_pub_off + 65].to_vec();
            info!("[esp32] 中间 CA 证书验签通过（根 CA 可信），用户标识='{uca_id}'");
            user_ca_pub
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(&self.ca_pubkey_b64)
                .map_err(|e| CredentialKeyError::PermanentFailure(format!("根 CA 公钥 b64 解码失败: {e}")))?
        };

        if verify_pub_raw.len() < 65 || verify_pub_raw[0] != 0x04 {
            return Err(CredentialKeyError::PermanentFailure("验证公钥格式异常".into()));
        }
        let verify_key = VerifyingKey::from_sec1_bytes(&verify_pub_raw[..65])
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("验证公钥无效: {e}")))?;
        // ESP32 签名是 raw r||s（P1363），p256 的 Signature::from_slice 接受 raw。
        let ca_sig = EcSig::from_slice(sig)
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("证书签名解析失败: {e}")))?;
        verify_key
            .verify(payload, &ca_sig)
            .map_err(|_| CredentialKeyError::PermanentFailure(
                "设备证书验签失败：非可信 CA 签发（可能被伪造/中间人）".into(),
            ))?;
        info!("[esp32] 设备证书验签通过，部署标识='{deployment_id}'");
        // 供上层 UI 提示用户确认设备归属
        *self.deployment_id.lock().unwrap() = Some(deployment_id.clone());

        // 1.5) 部署标识确认（对齐 web/authnkey：\"这是你自己部署的设备吗\"）
        //      在挑战-响应之前询问，拒绝则不继续。回调可能阻塞（弹窗），故
        //      先释放 deployment_id 锁再调用。
        let confirmed = {
            let cb = self.deploy_prompt.lock().unwrap();
            match cb.as_ref() {
                Some(f) => f(&deployment_id),
                None => true, // 未提供回调：不弹窗（非交互场景），仅日志
            }
        };
        if !confirmed {
            warn!("[esp32] 用户拒绝确认部署标识 '{deployment_id}'，断开连接");
            return Err(CredentialKeyError::PermanentFailure(
                "用户未确认设备归属（部署标识），已拒绝连接".into(),
            ));
        }

        // 2) 挑战-响应
        let mut nonce = [0u8; 32];
        getrandom_fill(&mut nonce);
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let auth_resp = self
            .rt
            .block_on(async { link.command(&format!("AUTH {nonce_b64}\n")).await })
            .map_err(CredentialKeyError::TransientFailure)?;
        let sig_b64 = auth_resp
            .split("SIG:")
            .nth(1)
            .ok_or_else(|| CredentialKeyError::PermanentFailure(format!(
                "AUTH 响应异常: {auth_resp}")
            ))?
            .trim();
        let dev_sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("设备签名 b64 解码失败: {e}")))?;
        let dev_key = VerifyingKey::from_sec1_bytes(device_pub)
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("设备公钥无效: {e}")))?;
        let dev_sig_obj = EcSig::from_slice(&dev_sig)
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("设备签名解析失败: {e}")))?;
        dev_key
            .verify(&nonce, &dev_sig_obj)
            .map_err(|_| CredentialKeyError::PermanentFailure(
                "挑战响应验签失败：设备可能未持有对应私钥".into(),
            ))?;
        info!("[esp32] 挑战响应验签通过（设备身份可信）");
        Ok(())
    }

    /// 丢弃缓存的连接（传输出错时调用，下次重连）。
    fn drop_link(&self) {
        *self.link.lock().unwrap() = None;
    }

    /// 确保设备已解锁（发送 AUTHPASS）。
    ///
    /// 行为：**仅在首次（本次进程内）弹窗索取密码；解锁成功后将状态缓存**，
    /// 之后所有操作都直接复用，不再弹窗（即"启动输一次，自动批准"）。
    /// 若设备中途重启导致丢失解锁状态，命令返回 ERR 时会清除缓存并重试一次。
    fn ensure_unlocked(&self, link: &BleLink) -> Result<(), CredentialKeyError> {
        if *self.unlocked.lock().unwrap() {
            return Ok(());
        }
        let pw = {
            let prompt = self.pass_prompt.lock().unwrap();
            match prompt.as_ref() {
                Some(f) => f().map_err(|_e| CredentialKeyError::AuthorizationDenied)?,
                None => return Err(CredentialKeyError::AuthorizationDenied),
            }
        };
        let resp = self
            .rt
            .block_on(async { link.command(&format!("AUTHPASS {pw}\n")).await })
            .map_err(CredentialKeyError::TransientFailure)?;
        if resp.starts_with("OK") {
            *self.unlocked.lock().unwrap() = true;
            info!("[esp32] 设备已解锁（后续操作自动批准）");
            Ok(())
        } else {
            Err(CredentialKeyError::AuthorizationDenied)
        }
    }

    /// 执行一条命令（自动保证连接与解锁）。返回去掉终止行前的全部响应文本。
    pub fn call(&self, cmd: &str, need_unlock: bool) -> Result<String, CredentialKeyError> {
        let link = self.ensure_link()?;
        if need_unlock {
            self.ensure_unlocked(&link)?;
        }
        let result = match self.rt.block_on(async { link.command(cmd).await }) {
            Ok(r) => {
                if r.starts_with("ERR") {
                    Err(CredentialKeyError::PermanentFailure(r))
                } else {
                    Ok(r)
                }
            }
            Err(e) => {
                self.drop_link();
                // 连接失效，解锁状态也随之失效，下次重连需重新解锁
                *self.unlocked.lock().unwrap() = false;
                Err(CredentialKeyError::TransientFailure(e))
            }
        };
        // 仅当确实是“未解锁”类错误时才清解锁缓存；
        // 注意："ERR not found or locked" 是“找不到凭证”，不是未解锁，
        // 不能用 contains("locked") 做宽泛匹配，否则每次读失败都会误清缓存、
        // 导致下次操作重新弹密码框。
        if let Ok(ref r) = result {
            if r.contains("engine locked") || r.contains("ERR locked") || r.contains("not unlocked") {
                *self.unlocked.lock().unwrap() = false;
            }
        }
        // ★ 关键：BleLink 内部含 bluez-async 的 MessageStream，其 Drop 会调用
        //   `tokio::spawn`，必须在 Tokio runtime 上下文中执行。若在本函数返回时
        //   由非 runtime 线程自然析构会 panic（"there is no reactor running"）。
        //   这里显式进入 runtime 再释放最后一个 Arc 引用。
        let _rt_guard = self.rt.enter();
        drop(link);
        drop(_rt_guard);
        result
    }
}

impl BleLink {
    /// 扫描并连接指定名字的设备，打开 NUS 通知。
    async fn connect(device_name: &str) -> Result<Self, String> {
        let manager = Manager::new()
            .await
            .map_err(|e| format!("init BLE manager: {e}"))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| format!("list adapters: {e}"))?;
        let adapter: &Adapter = adapters
            .first()
            .ok_or_else(|| "no Bluetooth adapter found".to_string())?;

        info!("[esp32] 扫描 BLE，寻找设备 '{}' ...", device_name);
        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|e| format!("start scan: {e}"))?;

        let mut found: Option<Peripheral> = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            let peripherals = adapter.peripherals().await.map_err(|e| e.to_string())?;
            for p in peripherals {
                let props = match p.properties().await {
                    Ok(Some(props)) => props,
                    _ => continue,
                };
                let name = props.local_name.unwrap_or_default();
                if name == device_name {
                    found = Some(p);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let _ = adapter.stop_scan().await;

        let peripheral = found.ok_or_else(|| format!("BLE 设备 '{device_name}' 未找到"))?;
        if !peripheral.is_connected().await.map_err(|e| e.to_string())? {
            peripheral
                .connect()
                .await
                .map_err(|e| format!("connect: {e}"))?;
        }
        info!("[esp32] 已连接 '{}'", device_name);

        // 显式触发服务发现（btleplug/BlueZ 上仅靠 characteristics() 拿不到特征，
        // 必须先 discover_services()）。失败则重试几次。
        let mut discovered = false;
        for _ in 0..5 {
            match peripheral.discover_services().await {
                Ok(()) if !peripheral.characteristics().is_empty() => {
                    discovered = true;
                    break;
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
        if !discovered {
            // 最后再轮询等待一次，给慢设备一点缓冲
            let mut tries = 0;
            while peripheral.characteristics().is_empty() && tries < 20 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                tries += 1;
            }
        }
        let chars = peripheral.characteristics();
        debug!("[esp32] 发现 {} 个特征", chars.len());
        for c in chars.iter() {
            debug!("[esp32]   特征 {}", c.uuid);
        }
        let uuid = |s: &str| uuid::Uuid::parse_str(s).unwrap();
        let rx = chars
            .iter()
            .find(|c| c.uuid == uuid(NUS_RX_UUID))
            .ok_or_else(|| "NUS RX 特征未找到".to_string())?
            .clone();
        let tx = chars
            .iter()
            .find(|c| c.uuid == uuid(NUS_TX_UUID))
            .ok_or_else(|| "NUS TX 特征未找到".to_string())?
            .clone();

        peripheral
            .subscribe(&tx)
            .await
            .map_err(|e| format!("subscribe TX: {e}"))?;
        let stream = peripheral
            .notifications()
            .await
            .map_err(|e| format!("open notifications: {e}"))?;
        let notify = Arc::new(AsyncMutex::new(
            stream.map(|n| n.value).boxed(),
        ));

        Ok(Self {
            peripheral,
            rx,
            tx,
            notify,
        })
    }

    /// 发送一条文本命令，收集响应直到出现以 `OK`/`ERR` 开头的终止行。
    /// ESP32 可能把多行响应（中间含 '\n'）拆成多个通知发来，因此需要累积。
    /// 终止行出现后，仍在短时间内继续收尾（把紧随其后的数据行如 `PUBKEY:` 收全），
    /// 收尾期间到达的字节同样要参与切行，绝不丢弃。
    async fn command(&self, cmd: &str) -> Result<String, String> {
        debug!("[esp32] >> {}", cmd);
        // ESP32 端采用【长度前缀 + 分片】协议（同 web/totp.html）：
        //   命令体 = cmd + '\n'，前加 4 位十六进制长度（长度=命令体字节数）
        //   然后按 20 字节分片写入，避免超出 BLE MTU 导致 "Failed to initiate write"。
        let body = if cmd.ends_with('\n') {
            cmd.to_string()
        } else {
            format!("{cmd}\n")
        };
        let body_bytes = body.as_bytes();
        let len_hex = format!("{:04x}", body_bytes.len());
        let mut frame = Vec::with_capacity(4 + body_bytes.len());
        frame.extend_from_slice(len_hex.as_bytes());
        frame.extend_from_slice(body_bytes);

        // 按 20 字节分片（不在 UTF-8 多字节字符中间切开）
        const CHUNK: usize = 20;
        let mut i = 0usize;
        while i < frame.len() {
            let mut end = (i + CHUNK).min(frame.len());
            while end > i && end < frame.len() && (frame[end] & 0xC0) == 0x80 {
                end -= 1;
            }
            let chunk = &frame[i..end];
            // 单次写带退避重试
            let mut write_err = None;
            for attempt in 0..5 {
                match self
                    .peripheral
                    .write(&self.rx, chunk, WriteType::WithoutResponse)
                    .await
                {
                    Ok(()) => {
                        write_err = None;
                        break;
                    }
                    Err(e) => {
                        write_err = Some(format!("BLE write: {e}"));
                        debug!("[esp32] write 重试 {}/5: {e}", attempt + 1);
                        tokio::time::sleep(Duration::from_millis(60 * (attempt + 1) as u64)).await;
                    }
                }
            }
            if let Some(e) = write_err {
                return Err(e);
            }
            i = end;
            if i < frame.len() {
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }

        let mut stream = self.notify.lock().await;
        let mut lines: Vec<String> = Vec::new();
        let mut tail: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + CMD_TIMEOUT;

        // 把 tail 里完整行切出并压入 lines（tail 保留未完结的部分）
        let drain_lines = |tail: &mut Vec<u8>, lines: &mut Vec<String>| {
            while let Some(pos) = tail.iter().position(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(&tail[..pos]).trim().to_string();
                tail.drain(..=pos);
                if !line.is_empty() {
                    lines.push(line);
                }
            }
        };

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("等待响应超时: {cmd}"));
            }

            // 已收到终止行（任意行以 OK/ERR 开头）？ESP32 把长响应（如 WA_REG 的
            // OK CRED + PUBKEY）拆成多个 BLE 通知分片发来，固定等待时间不可靠。
            // 改为"静默检测"：继续收，直到连续 500ms 没有新分片才认为收完。
            let got_terminal = lines
                .iter()
                .any(|l| l.starts_with("OK") || l.starts_with("ERR"));
            if got_terminal {
                match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
                    Ok(Some(chunk)) => {
                        tail.extend_from_slice(&chunk);
                        drain_lines(&mut tail, &mut lines);
                        // 有新数据，回到循环开头重新开始静默计时
                        continue;
                    }
                    _ => {
                        // 静默：tail 里若还有未带换行的收尾内容，一并并入
                        if !tail.is_empty() {
                            let leftover = String::from_utf8_lossy(&tail).trim().to_string();
                            if !leftover.is_empty() {
                                lines.push(leftover);
                            }
                        }
                        let full = lines.join("\n");
                        debug!("[esp32] << {full}");
                        return Ok(full.trim().to_string());
                    }
                }
            }

            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(chunk)) => {
                    tail.extend_from_slice(&chunk);
                    drain_lines(&mut tail, &mut lines);
                }
                Ok(None) => return Err("BLE 通知流已关闭".to_string()),
                Err(_) => return Err(format!("等待响应超时: {cmd}")),
            }
        }
    }
}

/// 把 ID 转成小写 hex
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 解析 hex 字符串为字节
fn bytes_of_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex 长度必须为偶数".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

/// ESP32 硬件密钥提供者。
///
/// - `generate`  → `WA_REG`（设备生成 P-256 密钥对，私钥留在设备）
/// - `sign`      → 对 message 做 SHA-256 后发 `WA_SIGNHASH`
/// - `delete`    → `WA_DEL`
pub struct Esp32CredentialKeyProvider {
    /// 与 storage 共享的连接句柄
    shared: Arc<Esp32Link>,
}

impl Esp32CredentialKeyProvider {
    /// 创建 provider。`pass_prompt` 在需要解锁时被调用以获取密码（可弹窗）。
    pub fn new(
        device_name: Option<String>,
        pass_prompt: Option<Box<dyn Fn() -> Result<String, String> + Send + Sync>>,
    ) -> Result<Self, String> {
        let shared = Esp32Link::new(device_name, pass_prompt)?;
        Ok(Self { shared })
    }

    /// 创建 provider（带部署标识确认回调）。
    pub fn new_with_deploy_prompt(
        device_name: Option<String>,
        pass_prompt: Option<Box<dyn Fn() -> Result<String, String> + Send + Sync>>,
        deploy_prompt: Option<Box<dyn Fn(&str) -> bool + Send + Sync>>,
    ) -> Result<Self, String> {
        let shared = Esp32Link::new_full(device_name, pass_prompt, None, deploy_prompt)?;
        Ok(Self { shared })
    }

    /// 用已有的共享连接创建 provider（与 storage 复用）。
    pub fn with_shared(shared: Arc<Esp32Link>) -> Self {
        Self { shared }
    }

    /// 执行一条命令（自动保证连接与解锁）。
    fn call(&self, cmd: &str, need_unlock: bool) -> Result<String, CredentialKeyError> {
        self.shared.call(cmd, need_unlock)
    }
}

impl CredentialKeyProvider for Esp32CredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        provider_id()
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        // ESP32 端只实现 P-256 (ES256)
        algorithm == -7
    }

    fn generate(
        &self,
        algorithm: i32,
    ) -> Result<GeneratedCredentialKey, CredentialKeyError> {
        if algorithm != -7 {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }
        // WA_REG 返回两行: "OK CRED:<id_hex>" + "PUBKEY:<pub_b64>"
        let resp = self.call("WA_REG esp32 user\n", true)?;
        info!("[esp32] WA_REG 原始响应: {resp:?}");
        let mut id_hex: Option<String> = None;
        let mut pub_b64: Option<String> = None;
        for line in resp.lines() {
            if let Some(v) = line.strip_prefix("OK CRED:") {
                id_hex = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("PUBKEY:") {
                pub_b64 = Some(v.trim().to_string());
            }
        }
        info!(
            "[esp32] 解析结果: id_hex={:?} pub_b64_len={:?}",
            id_hex,
            pub_b64.as_ref().map(|s| s.len())
        );
        let id_hex = id_hex.ok_or_else(|| {
            CredentialKeyError::PermanentFailure(format!("WA_REG 缺少凭证 ID: {resp}"))
        })?;
        if let Some(pb) = pub_b64.as_deref() {
            if pb.is_empty() {
                return Err(CredentialKeyError::PermanentFailure(format!(
                    "WA_REG 公钥为空: {resp}"
                )));
            }
        }

        let id = bytes_of_hex(&id_hex).map_err(CredentialKeyError::PermanentFailure)?;
        let pub_point = if let Some(pb) = pub_b64 {
            use base64::Engine as _;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&pb)
                .map_err(|e| {
                    CredentialKeyError::PermanentFailure(format!(
                        "公钥 b64 解码失败 (len={}): {e}",
                        pb.len()
                    ))
                })?;
            info!("[esp32] 公钥解码后 {} 字节 (首字节={:02x})", decoded.len(), decoded.first().copied().unwrap_or(0));
            decoded
        } else {
            // 设备未在 WA_REG 里回公钥：单独再取一次
            let r = self.call(&format!("WA_PUB {id_hex}\n"), true)?;
            let pb = r
                .split("PUBKEY:")
                .nth(1)
                .ok_or_else(|| CredentialKeyError::PermanentFailure(format!("WA_PUB 响应异常: {r}")))?
                .trim();
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(pb)
                .map_err(|e| CredentialKeyError::PermanentFailure(format!("公钥 b64 解码失败: {e}")))?
        };

        // COSE_Key (ES256)：soft-fido2 的 GeneratedCredentialKey.cose_public_key
        // 实际期望的是【未压缩 SEC1 点 65 字节 (0x04||x||y)】，而非 CBOR 编码。
        // 参见 TPM provider：直接返回 0x04||x||y。上层 build_cose_public_key 会
        // 自行编码为 COSE_Key。
        let cose = pub_point;

        Ok(GeneratedCredentialKey {
            key: CredentialKey::new(provider_id(), 1, SecBytes::from_slice(&id)),
            cose_public_key: cose,
        })
    }

    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> Result<Vec<u8>, CredentialKeyError> {
        if algorithm != -7 {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }
        if key.provider != provider_id() {
            return Err(CredentialKeyError::UnsupportedProvider);
        }
        let id = key.material.as_slice();
        if id.is_empty() {
            return Err(CredentialKeyError::InvalidKeyMaterial);
        }
        use base64::Engine as _;
        // soft-fido2 给的是完整待签消息；ESP32 端对摘要签名 => 先算 SHA-256
        let digest = Sha256::digest(message);
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(digest);

        // key.material 可能有两种来源：
        //   - 注册后立即签名：material = WA_REG 返回的 16 字节内部 id（走 WA_SIGNHASH）
        //   - 从 storage 读回后签名：material = 32 字节 web credential id（走 WA_WEBSIGNHASH）
        // ESP32 端两种 id 均可定位，故按长度自适应选择命令。
        let (cmd, tag) = if id.len() == 16 {
            (
                format!("WA_SIGNHASH {} {}\n", hex_of(id), hash_b64),
                "WA_SIGNHASH",
            )
        } else {
            let webid_b64 = base64::engine::general_purpose::STANDARD.encode(id);
            (
                format!("WA_WEBSIGNHASH {} {}\n", webid_b64, hash_b64),
                "WA_WEBSIGNHASH",
            )
        };
        let resp = self.call(&cmd, true)?;
        let sig_b64 = resp
            .split("OK SIG:")
            .nth(1)
            .ok_or_else(|| CredentialKeyError::PermanentFailure(format!("{tag} 响应异常: {resp}")))?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.trim())
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("签名 b64 解码失败: {e}")))?;
        if sig.len() != 64 {
            return Err(CredentialKeyError::PermanentFailure(format!(
                "签名长度异常: {} (期望 64)",
                sig.len()
            )));
        }
        // ESP32 的 wa_sign_hash 返回 raw (r||s) 64 字节；
        // WebAuthn/COSE (ES256) 要求 DER 编码的 ECDSA 签名，故此处转 DER。
        use p256::ecdsa::signature::SignatureEncoding as _;
        let der = p256::ecdsa::Signature::from_slice(&sig)
            .map_err(|e| CredentialKeyError::PermanentFailure(format!("签名解析失败: {e}")))?
            .to_der()
            .to_vec();
        debug!("[esp32] 签名 raw 64B -> DER {}B", der.len());
        Ok(der)
    }

    fn delete(&self, key: &CredentialKey) -> Result<(), CredentialKeyError> {
        if key.provider != provider_id() {
            return Err(CredentialKeyError::UnsupportedProvider);
        }
        let id = key.material.as_slice();
        if id.is_empty() {
            return Err(CredentialKeyError::InvalidKeyMaterial);
        }
        // 同 sign：16 字节走内部 id（WA_DEL），32 字节走 webid（WA_WEBDEL）
        let cmd = if id.len() == 16 {
            format!("WA_DEL {}\n", hex_of(id))
        } else {
            use base64::Engine as _;
            let webid_b64 = base64::engine::general_purpose::STANDARD.encode(id);
            format!("WA_WEBDEL {webid_b64}\n")
        };
        self.call(&cmd, true)?;
        Ok(())
    }
}

// ---- 信任链校验辅助 ----

/// 拆分证书：len(2) || payload || slen(2) || sig(64)，返回 (payload, sig)。
fn split_cert(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    if cert.len() < 4 {
        return None;
    }
    let plen = ((cert[0] as usize) << 8) | cert[1] as usize;
    if cert.len() < 2 + plen + 2 {
        return None;
    }
    let payload = &cert[2..2 + plen];
    let slen = ((cert[2 + plen] as usize) << 8) | cert[3 + plen] as usize;
    if cert.len() < 4 + plen + slen {
        return None;
    }
    let sig = &cert[4 + plen..4 + plen + slen];
    Some((payload, sig))
}

/// 解析证书 payload（兼容 0x01/0x02/0x10），返回 (deployment_id, subject_pub 偏移)。
///   0x02/0x10 || id_len(1) || deployment_id(id_len) || pub(65) || issue_time(8) || serial(8)
///   0x01 || pub(65) || issue_time(8) || serial(8)
fn parse_cert_payload(payload: &[u8]) -> Option<(String, usize)> {
    if payload.is_empty() {
        return None;
    }
    match payload[0] {
        0x02 | 0x10 => {
            if payload.len() < 2 {
                return None;
            }
            let id_len = payload[1] as usize;
            if payload.len() < 2 + id_len + 81 {
                return None;
            }
            let id = String::from_utf8_lossy(&payload[2..2 + id_len]).to_string();
            Some((id, 2 + id_len))
        }
        0x01 => Some((String::new(), 1)),
        _ => None,
    }
}

/// 填充随机字节（用于挑战 nonce）。
fn getrandom_fill(buf: &mut [u8]) {
    use rand::RngCore as _;
    rand::thread_rng().fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0x00u8, 0x1f, 0xab, 0xff];
        assert_eq!(hex_of(&b), "001fabff");
        assert_eq!(bytes_of_hex("001fabff").unwrap(), b);
    }

    #[test]
    fn cert_payload_v2_parse() {
        // 0x02 || len=5 || "abcde" || pub(65) || time(8) || serial(8)
        let mut p = vec![0x02u8, 5];
        p.extend_from_slice(b"abcde");
        p.extend(std::iter::repeat(0x04u8).take(65));
        p.extend(std::iter::repeat(0u8).take(16));
        let (id, off) = parse_cert_payload(&p).unwrap();
        assert_eq!(id, "abcde");
        assert_eq!(off, 7);
    }

    #[test]
    fn cert_payload_v1_parse() {
        let mut p = vec![0x01u8];
        p.extend(std::iter::repeat(0x04u8).take(65));
        p.extend(std::iter::repeat(0u8).take(16));
        let (id, off) = parse_cert_payload(&p).unwrap();
        assert_eq!(id, "");
        assert_eq!(off, 1);
    }
}
