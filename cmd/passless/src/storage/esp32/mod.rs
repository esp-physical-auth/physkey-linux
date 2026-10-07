//! ESP32 BLE 存储适配器（方案 A1：凭证不落盘，全部存在 ESP32）
//!
//! 实现 `CredentialStorage` trait，所有读写都通过 NUS 文本协议转发给 ESP32：
//!   - 列表/遍历  → WA_LIST + WA_META
//!   - 按 id 读取 → WA_META <id>
//!   - 写入       → （密钥已在 WA_REG 生成）用 WA_SETMETA 补元数据
//!   - 删除       → WA_DEL <id>
//!   - 计数       → WA_COUNT
//!
//! 与 `Esp32CredentialKeyProvider` 共享同一条 BLE 连接（`Esp32Link`）。

use crate::esp32::Esp32Link;
use crate::storage::{CredentialFilter, CredentialStorage};

use soft_fido2::{Credential, CredentialBackupState, CredentialKey, Extensions, RelyingParty, User};
use soft_fido2::CredentialKeyProviderId;
use soft_fido2_ctap::SecBytes;

use log::{debug, error, warn};
use std::sync::Arc;

/// ESP32 provider 的稳定 ID（须与 esp32.rs 中的 ESP32_PROVIDER_ID 一致）
const ESP32_PROVIDER_ID: &[u8] = b"esp32-nus-v1";

fn provider_id() -> CredentialKeyProviderId {
    CredentialKeyProviderId::new(ESP32_PROVIDER_ID)
}

/// 写元数据时用哪种 key 定位 ESP32 上的凭证槽位。
#[derive(Debug, Clone, Copy)]
enum Locate {
    /// WA_REG 返回的 16 字节内部 id（WA_SETMETA）
    InternalId,
    /// 对外 web credential id（WA_SETMETA_WEB）
    WebId,
}

/// 一条从 ESP32 读回的凭证元数据（WA_META 的解析结果）
#[derive(Debug, Clone, Default)]
struct RemoteMeta {
    created: i64,
    sign_count: u32,
    alg: i32,
    cred_protect: u8,
    discoverable: u8,
    backup_state: u8,
    user_id: Vec<u8>,
    user_display: String,
}

/// 把元数据字节映射回 `CredentialBackupState`（无效值回退 NotEligible）
fn backup_state_from_u8(v: u8) -> CredentialBackupState {
    match v {
        1 => CredentialBackupState::Eligible,
        2 => CredentialBackupState::BackedUp,
        _ => CredentialBackupState::NotEligible,
    }
}

/// 把 `CredentialBackupState` 序列化为 u8
fn backup_state_to_u8(s: CredentialBackupState) -> u8 {
    match s {
        CredentialBackupState::NotEligible => 0,
        CredentialBackupState::Eligible => 1,
        CredentialBackupState::BackedUp => 2,
    }
}

/// ESP32 存储适配器。
pub struct Esp32StorageAdapter {
    shared: Arc<Esp32Link>,
    /// WA_LIST 的迭代快照（esp_id_hex, rp, user）
    iteration_items: Vec<(String, String, String)>,
    iteration_index: usize,
    /// 最近一次计数（避免频繁 BLE 往返）
    cached_count: usize,
}

impl Esp32StorageAdapter {
    pub fn new(shared: Arc<Esp32Link>) -> Self {
        Self {
            shared,
            iteration_items: Vec::new(),
            iteration_index: 0,
            cached_count: 0,
        }
    }

    /// 按【对外 web credential id（b64）】读取完整凭证。
    fn fetch_credential_by_webid(&self, webid_b64: &str) -> soft_fido2::Result<Credential> {
        let resp = self
            .shared
            .call(&format!("WA_WEBMETA {webid_b64}\n"), true)
            .map_err(|e| {
                debug!("[esp32-storage] WA_WEBMETA 失败: {e:?}");
                soft_fido2::Error::DoesNotExist
            })?;
        let mut rp = String::new();
        let mut user = String::new();
        let mut meta = RemoteMeta {
            alg: -7,
            discoverable: 1,
            ..Default::default()
        };
        for line in resp.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "rp" => rp = v.to_string(),
                    "user" => user = v.to_string(),
                    "created" => meta.created = v.parse().unwrap_or(0),
                    "sign_count" => meta.sign_count = v.parse().unwrap_or(0),
                    "alg" => meta.alg = v.parse().unwrap_or(-7),
                    "cred_protect" => meta.cred_protect = v.parse().unwrap_or(0),
                    "discoverable" => meta.discoverable = v.parse().unwrap_or(1),
                    "backup_state" => meta.backup_state = v.parse().unwrap_or(0),
                    "user_id" => meta.user_id = decode_b64(v).unwrap_or_default(),
                    "user_display" => {
                        meta.user_display =
                            String::from_utf8_lossy(&decode_b64(v).unwrap_or_default()).to_string()
                    }
                    _ => {}
                }
            }
        }
        // 用 webid 本身作为凭证 id、并用它作为 key.material（ESP32 端签名时
        // 会用 WA_WEBSIGNHASH + webid 定位，不再需要 16 字节内部 id）。
        let webid = decode_b64(webid_b64).unwrap_or_default();
        let key = CredentialKey::new(provider_id(), 1, SecBytes::from_slice(&webid));
        Ok(Credential {
            id: webid.clone(),
            rp: RelyingParty {
                id: rp,
                name: None,
            },
            user: User {
                id: meta.user_id.clone(),
                name: if user.is_empty() { None } else { Some(user) },
                display_name: if meta.user_display.is_empty() {
                    None
                } else {
                    Some(meta.user_display.clone())
                },
            },
            sign_count: meta.sign_count,
            alg: meta.alg,
            key,
            created: meta.created,
            discoverable: meta.discoverable != 0,
            backup_state: backup_state_from_u8(meta.backup_state),
            extensions: Extensions {
                cred_protect: if meta.cred_protect == 0 {
                    None
                } else {
                    Some(meta.cred_protect)
                },
                hmac_secret: None,
                cred_random: None,
            },
        })
    }

    /// 拉取全部凭证的 (id_hex, rp, user) 列表。
    fn fetch_list(&self) -> soft_fido2::Result<Vec<(String, String, String)>> {
        let resp = self
            .shared
            .call("WA_LIST\n", true)
            .map_err(|e| {
                error!("[esp32-storage] WA_LIST 失败: {e:?}");
                soft_fido2::Error::Other
            })?;
        let mut out = Vec::new();
        for line in resp.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("OK") || line.starts_with("ERR") {
                continue;
            }
            let mut parts = line.split('\t');
            let id = parts.next().unwrap_or("").to_string();
            let rp = parts.next().unwrap_or("").to_string();
            let user = parts.next().unwrap_or("").to_string();
            if !id.is_empty() {
                out.push((id, rp, user));
            }
        }
        Ok(out)
    }

    /// 读取某条凭证的完整元数据（WA_META）。
    fn fetch_meta(&self, id_hex: &str) -> soft_fido2::Result<RemoteMeta> {
        let resp = self
            .shared
            .call(&format!("WA_META {id_hex}\n"), true)
            .map_err(|e| {
                error!("[esp32-storage] WA_META {id_hex} 失败: {e:?}");
                soft_fido2::Error::DoesNotExist
            })?;
        let mut meta = RemoteMeta {
            alg: -7,
            discoverable: 1,
            ..Default::default()
        };
        for line in resp.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "created" => meta.created = v.parse().unwrap_or(0),
                    "sign_count" => meta.sign_count = v.parse().unwrap_or(0),
                    "alg" => meta.alg = v.parse().unwrap_or(-7),
                    "cred_protect" => meta.cred_protect = v.parse().unwrap_or(0),
                    "discoverable" => meta.discoverable = v.parse().unwrap_or(1),
                    "backup_state" => meta.backup_state = v.parse().unwrap_or(0),
                    "user_id" => meta.user_id = decode_b64(v).unwrap_or_default(),
                    "user_display" => {
                        meta.user_display =
                            String::from_utf8_lossy(&decode_b64(v).unwrap_or_default()).to_string()
                    }
                    _ => {}
                }
            }
        }
        Ok(meta)
    }

    /// 按 id_hex + rp + user 构造一条完整 `soft_fido2::Credential`。
    fn build_credential(
        &self,
        id_hex: &str,
        rp: &str,
        user_name: &str,
    ) -> soft_fido2::Result<Credential> {
        let id = hex_decode(id_hex).map_err(|_| soft_fido2::Error::Other)?;
        let meta = self.fetch_meta(id_hex)?;
        let key = CredentialKey::new(provider_id(), 1, SecBytes::from_slice(&id));
        Ok(Credential {
            id,
            rp: RelyingParty {
                id: rp.to_string(),
                name: None,
            },
            user: User {
                id: meta.user_id.clone(),
                name: if user_name.is_empty() {
                    None
                } else {
                    Some(user_name.to_string())
                },
                display_name: if meta.user_display.is_empty() {
                    None
                } else {
                    Some(meta.user_display.clone())
                },
            },
            sign_count: meta.sign_count,
            alg: meta.alg,
            key,
            created: meta.created,
            discoverable: meta.discoverable != 0,
            backup_state: backup_state_from_u8(meta.backup_state),
            extensions: Extensions {
                cred_protect: if meta.cred_protect == 0 {
                    None
                } else {
                    Some(meta.cred_protect)
                },
                hmac_secret: None,
                cred_random: None,
            },
        })
    }
}

impl CredentialStorage for Esp32StorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> soft_fido2::Result<Credential> {
        debug!("[esp32-storage] read_first filter={filter:?}");
        let list = self.fetch_list()?;
        self.cached_count = list.len();
        // 应用过滤
        let filtered: Vec<_> = list
            .into_iter()
            .filter(|(_, rp, _)| match &filter {
                CredentialFilter::ByRp(want) => rp == want,
                _ => true,
            })
            .collect();
        self.iteration_items = filtered.clone();
        self.iteration_index = 0;
        if self.iteration_items.is_empty() {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        self.iteration_index = 1;
        let (esp_id_hex, rp, user) = self.iteration_items[0].clone();
        self.build_credential(&esp_id_hex, &rp, &user)
    }

    fn read_next(&mut self) -> soft_fido2::Result<Credential> {
        if self.iteration_index >= self.iteration_items.len() {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        let (esp_id_hex, rp, user) = self.iteration_items[self.iteration_index].clone();
        self.iteration_index += 1;
        self.build_credential(&esp_id_hex, &rp, &user)
    }

    fn read(&mut self, id: &[u8]) -> soft_fido2::Result<Credential> {
        // id 是 soft-fido2 的对外 credential id（web id），按它查。
        let webid_b64 = b64_encode(id);
        debug!("[esp32-storage] read webid(b64)={webid_b64}");
        self.fetch_credential_by_webid(&webid_b64)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
        // 密钥已在 WA_REG（generate）时于 ESP32 生成；此处把对外 credential id
        // (webid) 与完整元数据一起写回 ESP32。
        // key.material 有两种可能：
        //   - 16 字节：WA_REG 返回的内部 id（注册后立即写，走 WA_SETMETA）
        //   - 32 字节：对外 webid（从 storage 读回后再写，走 WA_SETMETA_WEB）
        let mat = cred_ref.key.material.as_slice();
        let (id_hex, webid_b64, locate) = if mat.len() == 16 {
            (hex_encode(mat), b64_encode(cred_ref.id), Locate::InternalId)
        } else {
            // 32 字节（或其他）：视为 webid，用 webid 定位
            (
                String::new(),
                b64_encode(mat),
                Locate::WebId,
            )
        };
        debug!(
            "[esp32-storage] write meta locate={locate:?} id_hex={id_hex} webid(b64)={webid_b64}"
        );
        let cred = cred_ref.to_owned();
        let user_id_b64 = b64_encode(cred_ref.user_id);
        let display = cred_ref.user_display_name.unwrap_or("");
        let display_b64 = b64_encode(display.as_bytes());
        // 真实 RP / 用户名（b64），覆盖 WA_REG 时的占位值 "esp32"/"user"
        let rp_b64 = b64_encode(cred_ref.rp_id.as_bytes());
        let user_name_b64 = b64_encode(cred_ref.user_name.unwrap_or("").as_bytes());
        let created = cred.created;
        let backup = backup_state_to_u8(cred.backup_state);
        let rk = if *cred_ref.discoverable { 1 } else { 0 };
        let protect = cred_ref.cred_protect.copied().unwrap_or(0);
        let kvs = format!(
            "created={} sign_count={} alg={} cred_protect={} discoverable={} backup_state={} user_id={} user_display={} webid={} rp={} user={}",
            created, cred.sign_count, cred.alg, protect, rk, backup, user_id_b64, display_b64, webid_b64, rp_b64, user_name_b64
        );
        let cmd = match locate {
            Locate::InternalId => format!("WA_SETMETA {id_hex} {kvs}\n"),
            Locate::WebId => format!("WA_SETMETA_WEB {webid_b64} {kvs}\n"),
        };
        self.shared.call(&cmd, true).map_err(|e| {
            error!("[esp32-storage] WA_SETMETA 失败: {e:?}");
            soft_fido2::Error::Other
        })?;

        // 双保险：注册路径（InternalId）只发了 WA_SETMETA，
        // 补发 WA_SETMETA_WEB 让固件显式建立 webid→内部id 索引，
        // 确保 WA_WEBMETA / WA_WEBSIGNHASH 能正确反查，
        // 这样其他客户端（如 Android Authnkey）也能通过 webid 定位此凭据。
        if matches!(locate, Locate::InternalId) {
            let web_cmd = format!("WA_SETMETA_WEB {webid_b64} {kvs}\n");
            if let Err(e) = self.shared.call(&web_cmd, true) {
                warn!("[esp32-storage] WA_SETMETA_WEB 双保险失败（非致命）: {e:?}");
            }
        }

        Ok(())
    }

    fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
        // id 是对外 credential id，走 WA_WEBDEL
        let webid_b64 = b64_encode(id);
        debug!("[esp32-storage] delete webid(b64)={webid_b64}");
        self.shared
            .call(&format!("WA_WEBDEL {webid_b64}\n"), true)
            .map_err(|e| {
                warn!("[esp32-storage] WA_WEBDEL 失败: {e:?}");
                soft_fido2::Error::Other
            })?;
        Ok(())
    }

    fn count_credentials(&self) -> usize {
        match self.shared.call("WA_COUNT\n", true) {
            Ok(resp) => {
                // "OK N credentials"
                for tok in resp.split_whitespace() {
                    if let Ok(n) = tok.parse::<usize>() {
                        return n;
                    }
                }
                self.cached_count
            }
            Err(e) => {
                warn!("[esp32-storage] WA_COUNT 失败: {e:?}");
                self.cached_count
            }
        }
    }
}

/// 小写 hex 编码
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// hex 解码
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// base64 编码
fn b64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// base64 解码
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}