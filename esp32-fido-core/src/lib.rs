//! ESP32 FIDO2 可移植核心 — 从 passless 的 esp32.rs 剥离纯逻辑层。
//!
//! 本 crate 不含任何 BLE / tokio / Linux 专属依赖，可编译到 Android / iOS /
//! 裸 metal。BLE NUS 通信通过 `Esp32Transport` trait 注入。

#[cfg(feature = "jni")]
mod jni;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEFAULT_DEVICE_NAME: &str = "ATRI-TOTP";

/// 平台无关的传输层 —— 调用方实现 NUS 文本协议收发。
/// 这样同一套核心逻辑可以跑在 Linux (btleplug) / Android (BluetoothGatt) / Web
/// (Web Bluetooth)。
pub trait Esp32Transport {
    fn send_command(&self, cmd: &str) -> Result<String, String>;
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("device returned error: {0}")]
    Device(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

// ---------------------------------------------------------------------------
// 工具函数（原样从 esp32.rs 搬运）
// ---------------------------------------------------------------------------

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn bytes_of_hex(hex: &str) -> Result<Vec<u8>, CoreError> {
    if hex.len() % 2 != 0 {
        return Err(CoreError::Protocol("hex 长度必须为偶数".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| CoreError::Protocol(format!("bad hex: {e}")))
        })
        .collect()
}

/// 拆分 ESP32 自定义证书：`len(2) || payload || slen(2) || sig`，返回 `(payload, sig)`。
pub fn split_cert(cert: &[u8]) -> Option<(&[u8], &[u8])> {
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

/// 解析证书 payload，返回 `(deployment_id, subject_pub 偏移)`。
///   0x02/0x10 || id_len(1) || deployment_id(id_len) || pub(65) || issue_time(8) || serial(8)
///   0x01 || pub(65) || issue_time(8) || serial(8)
pub fn parse_cert_payload(payload: &[u8]) -> Option<(String, usize)> {
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

/// ECDSA P-256 raw 64 字节 (r||s) → DER 编码。
pub fn raw_sig_to_der(raw: &[u8]) -> Result<Vec<u8>, CoreError> {
    if raw.len() != 64 {
        return Err(CoreError::Protocol(format!(
            "raw signature 长度应为 64，实际 {}",
            raw.len()
        )));
    }
    use p256::ecdsa::signature::SignatureEncoding as _;
    let sig = p256::ecdsa::Signature::from_slice(raw)
        .map_err(|e| CoreError::Protocol(format!("签名解析失败: {e}")))?;
    Ok(sig.to_der().to_vec())
}

// ---------------------------------------------------------------------------
// ESP32 命令构造 & 响应解析（原样搬运 + transport trait 抽象）
// ---------------------------------------------------------------------------

/// WA_REG 返回值。
pub struct WaRegResult {
    /// ESP32 内部凭证 ID（16 字节），hex 编码。
    pub id_hex: String,
    /// P-256 未压缩公钥点（65 字节，0x04||x||y）。
    /// 部分固件版本 WA_REG 不回 PUBKEY，此时为 None，调用方应 fallback 到 WA_PUB。
    pub pubkey: Option<Vec<u8>>,
}

pub fn cmd_wa_reg(rp: &str, user: Option<&str>) -> String {
    match user {
        Some(u) => format!("WA_REG {rp} {u}\n"),
        None => format!("WA_REG {rp}\n"),
    }
}

/// 对齐 passless esp32.rs 的占位 WA_REG：`WA_REG esp32 user`。
/// ESP32 内部密钥生成按槽位分配，rp 参数只是设备内部标签；
/// 真实 rp/user 通过后续 WA_SETMETA 写入覆盖。
pub const WA_REG_PLACEHOLDER_RP: &str = "esp32";
pub const WA_REG_PLACEHOLDER_USER: &str = "user";

pub fn cmd_wa_reg_placeholder() -> String {
    cmd_wa_reg(WA_REG_PLACEHOLDER_RP, Some(WA_REG_PLACEHOLDER_USER))
}

/// 解析 WA_REG 响应（含 `OK CRED:<id_hex>` 行 + 可选 `PUBKEY:<pub_b64>` 行）。
/// 固件版本差异：有的 WA_REG 回 PUBKEY，有的不回——不回时 pubkey=None，
/// 调用方应 fallback 到 WA_PUB {id_hex} 再取公钥。
pub fn parse_wa_reg_response(resp: &str) -> Result<WaRegResult, CoreError> {
    let mut id_hex: Option<String> = None;
    let mut pub_b64: Option<String> = None;
    for line in resp.lines() {
        if let Some(v) = line.strip_prefix("OK CRED:") {
            id_hex = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("PUBKEY:") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                pub_b64 = Some(trimmed.to_string());
            }
        }
    }
    let id_hex = id_hex.ok_or_else(|| {
        CoreError::Protocol(format!("WA_REG 缺少凭证 ID: {resp}"))
    })?;
    let pubkey = match pub_b64 {
        Some(pb) => {
            let pk = base64::engine::general_purpose::STANDARD
                .decode(&pb)
                .map_err(|e| CoreError::Protocol(format!("公钥 b64 解码失败: {e}")))?;
            if pk.len() != 65 {
                return Err(CoreError::Protocol(format!(
                    "公钥长度异常: {} (期望 65)",
                    pk.len()
                )));
            }
            Some(pk)
        }
        None => None,
    };
    Ok(WaRegResult { id_hex, pubkey })
}

/// 输入完整待签 message，内部 SHA256 后签名。对齐 passless sign() 调用约定。
pub fn cmd_sign_hash(key_material: &[u8], message: &[u8]) -> String {
    let digest = Sha256::digest(message);
    cmd_sign_digest(key_material, &digest)
}

/// 输入已经算好的 SHA256 摘要（32 字节），直接拼签名命令不做哈希。
/// 对 Android 桥接等场景，调用方已在本地按 CTAP2 约定算好 digest。
pub fn cmd_sign_digest(key_material: &[u8], digest: &[u8]) -> String {
    assert!(digest.len() == 32, "digest 应为 SHA256 的 32 字节摘要");
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    if key_material.len() == 16 {
        format!("WA_SIGNHASH {} {}\n", hex_of(key_material), hash_b64)
    } else {
        let webid_b64 = base64::engine::general_purpose::STANDARD.encode(key_material);
        format!("WA_WEBSIGNHASH {} {}\n", webid_b64, hash_b64)
    }
}

/// 解析 WA_SIGNHASH / WA_WEBSIGNHASH 响应，返回 DER 编码签名。
pub fn parse_sign_response(resp: &str) -> Result<Vec<u8>, CoreError> {
    let sig_b64 = resp
        .split("OK SIG:")
        .nth(1)
        .ok_or_else(|| CoreError::Protocol(format!("签名响应异常: {resp}")))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| CoreError::Protocol(format!("签名 b64 解码失败: {e}")))?;
    raw_sig_to_der(&raw)
}

pub fn cmd_delete(key_material: &[u8]) -> String {
    if key_material.len() == 16 {
        format!("WA_DEL {}\n", hex_of(key_material))
    } else {
        let webid_b64 = base64::engine::general_purpose::STANDARD.encode(key_material);
        format!("WA_WEBDEL {webid_b64}\n")
    }
}

pub fn cmd_wa_pub(id_hex: &str) -> String {
    format!("WA_PUB {id_hex}\n")
}

/// 生成 32 字节随机 credentialId（对齐 passless `generate_credential_id`）。
/// 这是对外暴露给 WebAuthn 的 credential id，存储在 ESP32 的 WA_SETMETA webid 字段里。
pub fn generate_credential_id() -> Vec<u8> {
    use rand::RngCore as _;
    let mut id = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// WA_SETMETA 字段集合（对齐 passless Esp32StorageAdapter::write）。
#[derive(Debug, Default, Clone)]
pub struct WaSetMetaFields {
    pub created: i64,
    pub sign_count: u32,
    pub alg: i32,
    pub cred_protect: u8,
    pub discoverable: u8,
    pub backup_state: u8,
    pub user_id: Vec<u8>,
    pub user_display: Vec<u8>,
    pub webid: Vec<u8>,
    pub rp: Vec<u8>,
    pub user: Vec<u8>,
}

/// 构造 `WA_SETMETA <id_hex> <kvs>` 命令（用 16B 内部 id 定位）。
pub fn cmd_wa_setmeta(id_hex: &str, fields: &WaSetMetaFields) -> String {
    use base64::Engine as _;
    let b64 = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);
    let kvs = wa_setmeta_kvs(fields);
    format!("WA_SETMETA {id_hex} {kvs}\n")
}

/// 构造 `WA_SETMETA_WEB <webid_b64> <kvs>` 命令（用 webid 定位）。
/// 注册时 WA_SETMETA 之后补发此命令 —— 双保险让固件建立 webid→内部id 的索引，
/// 确保 WA_WEBMETA / WA_WEBSIGNHASH 能正确反查。
pub fn cmd_wa_setmeta_web(webid: &[u8], fields: &WaSetMetaFields) -> String {
    use base64::Engine as _;
    let webid_b64 = base64::engine::general_purpose::STANDARD.encode(webid);
    let kvs = wa_setmeta_kvs(fields);
    format!("WA_SETMETA_WEB {webid_b64} {kvs}\n")
}

fn wa_setmeta_kvs(fields: &WaSetMetaFields) -> String {
    use base64::Engine as _;
    let b64 = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);
    format!(
        "created={} sign_count={} alg={} cred_protect={} discoverable={} backup_state={} user_id={} user_display={} webid={} rp={} user={}",
        fields.created,
        fields.sign_count,
        fields.alg,
        fields.cred_protect,
        fields.discoverable,
        fields.backup_state,
        b64(&fields.user_id),
        b64(&fields.user_display),
        b64(&fields.webid),
        b64(&fields.rp),
        b64(&fields.user),
    )
}

/// 解析 WA_PUB 响应，返回 65 字节未压缩公钥点。
pub fn parse_wa_pub_response(resp: &str) -> Result<Vec<u8>, CoreError> {
    let pub_b64 = resp
        .split("PUBKEY:")
        .nth(1)
        .ok_or_else(|| CoreError::Protocol(format!("WA_PUB 响应异常: {resp}")))?;
    let pubkey = base64::engine::general_purpose::STANDARD
        .decode(pub_b64.trim())
        .map_err(|e| CoreError::Protocol(format!("公钥 b64 解码失败: {e}")))?;
    if pubkey.len() != 65 {
        return Err(CoreError::Protocol(format!(
            "公钥长度异常: {} (期望 65)",
            pubkey.len()
        )));
    }
    Ok(pubkey)
}

// ---------------------------------------------------------------------------
// 高层封装：一个 transport 就能跑完整 FIDO2 密钥操作
// ---------------------------------------------------------------------------

pub struct Esp32FidoCore<T: Esp32Transport> {
    pub transport: T,
}

impl<T: Esp32Transport> Esp32FidoCore<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn register(&self, rp: &str, user: Option<&str>) -> Result<WaRegResult, CoreError> {
        let cmd = cmd_wa_reg(rp, user);
        let resp = self
            .transport
            .send_command(&cmd)
            .map_err(CoreError::Transport)?;
        parse_wa_reg_response(&resp)
    }

    pub fn sign(&self, key_material: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let cmd = cmd_sign_hash(key_material, message);
        let resp = self
            .transport
            .send_command(&cmd)
            .map_err(CoreError::Transport)?;
        parse_sign_response(&resp)
    }

    pub fn delete(&self, key_material: &[u8]) -> Result<(), CoreError> {
        let cmd = cmd_delete(key_material);
        let resp = self
            .transport
            .send_command(&cmd)
            .map_err(CoreError::Transport)?;
        if resp.starts_with("OK") {
            Ok(())
        } else {
            Err(CoreError::Device(resp))
        }
    }

    pub fn get_pubkey(&self, id_hex: &str) -> Result<Vec<u8>, CoreError> {
        let cmd = cmd_wa_pub(id_hex);
        let resp = self
            .transport
            .send_command(&cmd)
            .map_err(CoreError::Transport)?;
        parse_wa_pub_response(&resp)
    }
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

    #[test]
    fn sign_command_internal_id() {
        let id = [0u8; 16];
        let msg = b"hello world this is some test data";
        let cmd = cmd_sign_hash(&id, msg);
        assert!(cmd.starts_with("WA_SIGNHASH "));
        assert!(cmd.ends_with('\n'));
    }

    #[test]
    fn sign_command_webid() {
        let webid = [0u8; 32];
        let msg = b"hello world";
        let cmd = cmd_sign_hash(&webid, msg);
        assert!(cmd.starts_with("WA_WEBSIGNHASH "));
    }

    #[test]
    fn parse_wa_reg_multiline() {
        use base64::Engine as _;
        let mut pk = vec![0x04u8];
        pk.extend(std::iter::repeat(0xABu8).take(64));
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
        let resp = format!("OK CRED:00112233445566778899aabbccddeeff\nPUBKEY:{pub_b64}\n");
        let r = parse_wa_reg_response(&resp).unwrap();
        assert_eq!(r.id_hex.len(), 32);
        assert_eq!(r.pubkey.len(), 65);
    }
}