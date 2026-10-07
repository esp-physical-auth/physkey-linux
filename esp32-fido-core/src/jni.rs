#![cfg(feature = "jni")]

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use serde::Serialize;

#[derive(Serialize)]
struct WaRegJson {
    id_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey_b64: Option<String>,
}

fn to_js(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(js) => js.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn from_js(env: &mut JNIEnv, js: jstring) -> Option<String> {
    if js.is_null() {
        return None;
    }
    let s = unsafe { JString::from_raw(js) };
    env.get_string(&s).ok().map(|g| g.into())
}

fn from_jba(env: &mut JNIEnv, arr: jbyteArray) -> Option<Vec<u8>> {
    if arr.is_null() {
        return None;
    }
    let jba = unsafe { JByteArray::from_raw(arr) };
    let len = env.get_array_length(&jba).ok()? as usize;
    let mut buf = vec![0i8; len];
    env.get_byte_array_region(&jba, 0, &mut buf).ok()?;
    Some(buf.into_iter().map(|b| b as u8).collect())
}

fn to_jba(env: &mut JNIEnv, bytes: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdWaReg(
    mut env: JNIEnv,
    _class: JClass,
    rp: jstring,
    user: jstring,
) -> jstring {
    let rp = match from_js(&mut env, rp) {
        Some(s) => s,
        None => return to_js(&mut env, ""),
    };
    let user = from_js(&mut env, user);
    to_js(&mut env, &crate::cmd_wa_reg(&rp, user.as_deref()))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_parseWaRegResponse(
    mut env: JNIEnv,
    _class: JClass,
    resp: jstring,
) -> jstring {
    let resp = match from_js(&mut env, resp) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    match crate::parse_wa_reg_response(&resp) {
        Ok(r) => {
            use base64::Engine as _;
            let pubkey_b64 = r.pubkey.as_ref().map(|pk| {
                base64::engine::general_purpose::STANDARD.encode(pk)
            });
            let json = serde_json::to_string(&WaRegJson {
                id_hex: r.id_hex,
                pubkey_b64,
            })
            .unwrap_or_default();
            to_js(&mut env, &json)
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdSignHash(
    mut env: JNIEnv,
    _class: JClass,
    key_material: jbyteArray,
    message: jbyteArray,
) -> jstring {
    let km = match from_jba(&mut env, key_material) {
        Some(b) => b,
        None => return to_js(&mut env, ""),
    };
    let msg = match from_jba(&mut env, message) {
        Some(b) => b,
        None => return to_js(&mut env, ""),
    };
    to_js(&mut env, &crate::cmd_sign_hash(&km, &msg))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdSignDigest(
    mut env: JNIEnv,
    _class: JClass,
    key_material: jbyteArray,
    digest: jbyteArray,
) -> jstring {
    let km = match from_jba(&mut env, key_material) {
        Some(b) => b,
        None => return to_js(&mut env, ""),
    };
    let dg = match from_jba(&mut env, digest) {
        Some(b) => b,
        None => return to_js(&mut env, ""),
    };
    to_js(&mut env, &crate::cmd_sign_digest(&km, &dg))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_parseSignResponse(
    mut env: JNIEnv,
    _class: JClass,
    resp: jstring,
) -> jbyteArray {
    let resp = match from_js(&mut env, resp) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    match crate::parse_sign_response(&resp) {
        Ok(der) => to_jba(&mut env, &der),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdDelete(
    mut env: JNIEnv,
    _class: JClass,
    key_material: jbyteArray,
) -> jstring {
    let km = match from_jba(&mut env, key_material) {
        Some(b) => b,
        None => return to_js(&mut env, ""),
    };
    to_js(&mut env, &crate::cmd_delete(&km))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_rawSigToDer(
    mut env: JNIEnv,
    _class: JClass,
    raw: jbyteArray,
) -> jbyteArray {
    let raw = match from_jba(&mut env, raw) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    match crate::raw_sig_to_der(&raw) {
        Ok(der) => to_jba(&mut env, &der),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_hexOf(
    mut env: JNIEnv,
    _class: JClass,
    bytes: jbyteArray,
) -> jstring {
    let bytes = match from_jba(&mut env, bytes) {
        Some(b) => b,
        None => return to_js(&mut env, ""),
    };
    to_js(&mut env, &crate::hex_of(&bytes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_bytesOfHex(
    mut env: JNIEnv,
    _class: JClass,
    hex: jstring,
) -> jbyteArray {
    let hex = match from_js(&mut env, hex) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    match crate::bytes_of_hex(&hex) {
        Ok(b) => to_jba(&mut env, &b),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdWaPub(
    mut env: JNIEnv,
    _class: JClass,
    id_hex: jstring,
) -> jstring {
    let id_hex = match from_js(&mut env, id_hex) {
        Some(s) => s,
        None => return to_js(&mut env, ""),
    };
    to_js(&mut env, &crate::cmd_wa_pub(&id_hex))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_parseWaPubResponse(
    mut env: JNIEnv,
    _class: JClass,
    resp: jstring,
) -> jbyteArray {
    let resp = match from_js(&mut env, resp) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    match crate::parse_wa_pub_response(&resp) {
        Ok(pk) => to_jba(&mut env, &pk),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_generateCredentialId(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    let id = crate::generate_credential_id();
    to_jba(&mut env, &id)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdWaRegPlaceholder(
    mut _env: JNIEnv,
    _class: JClass,
) -> jstring {
    let cmd = crate::cmd_wa_reg_placeholder();
    unsafe { JNIEnv::new_string(&mut _env, cmd.as_str()) }
        .ok()
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdWaSetMeta(
    mut env: JNIEnv,
    _class: JClass,
    id_hex: jstring,
    created: jlong,
    sign_count: jint,
    alg: jint,
    cred_protect: i8,
    discoverable: i8,
    backup_state: i8,
    user_id: jbyteArray,
    user_display: jbyteArray,
    webid: jbyteArray,
    rp: jbyteArray,
    user: jbyteArray,
) -> jstring {
    let id_hex = match from_js(&mut env, id_hex) {
        Some(s) => s,
        None => return to_js(&mut env, ""),
    };
    let fields = crate::WaSetMetaFields {
        created: created,
        sign_count: sign_count as u32,
        alg,
        cred_protect: cred_protect as u8,
        discoverable: discoverable as u8,
        backup_state: backup_state as u8,
        user_id: from_jba(&mut env, user_id).unwrap_or_default(),
        user_display: from_jba(&mut env, user_display).unwrap_or_default(),
        webid: from_jba(&mut env, webid).unwrap_or_default(),
        rp: from_jba(&mut env, rp).unwrap_or_default(),
        user: from_jba(&mut env, user).unwrap_or_default(),
    };
    to_js(&mut env, &crate::cmd_wa_setmeta(&id_hex, &fields))
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_pl_lebihan_authnkey_rust_Esp32Core_cmdWaSetMetaWeb(
    mut env: JNIEnv,
    _class: JClass,
    webid: jbyteArray,
    created: jlong,
    sign_count: jint,
    alg: jint,
    cred_protect: i8,
    discoverable: i8,
    backup_state: i8,
    user_id: jbyteArray,
    user_display: jbyteArray,
    rp: jbyteArray,
    user: jbyteArray,
) -> jstring {
    let webid = from_jba(&mut env, webid).unwrap_or_default();
    let fields = crate::WaSetMetaFields {
        created: created,
        sign_count: sign_count as u32,
        alg,
        cred_protect: cred_protect as u8,
        discoverable: discoverable as u8,
        backup_state: backup_state as u8,
        user_id: from_jba(&mut env, user_id).unwrap_or_default(),
        user_display: from_jba(&mut env, user_display).unwrap_or_default(),
        webid: webid.clone(),
        rp: from_jba(&mut env, rp).unwrap_or_default(),
        user: from_jba(&mut env, user).unwrap_or_default(),
    };
    to_js(&mut env, &crate::cmd_wa_setmeta_web(&webid, &fields))
}