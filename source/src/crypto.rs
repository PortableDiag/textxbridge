//! The protocol's frame encryption (TextX agent-protocol §3.3).
//!
//! AES-256-GCM, a 12-byte random nonce, and the AAD `textx1|<kid>|p2a` or
//! `textx1|<kid>|a2p`, so a frame cannot be reflected back to its sender.
//! A sealed frame is `nonce ‖ ciphertext ‖ tag`; JSON carries it as
//! `{"x": base64url(frame)}`, files carry the raw bytes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub const KEY_LEN: usize = 32;
pub const KID_LEN: usize = 12;
const NONCE_LEN: usize = 12;

/// Which way a frame travels; part of the AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    PhoneToAgent,
    AgentToPhone,
}

fn aad(kid: &str, dir: Dir) -> Vec<u8> {
    let tag = match dir {
        Dir::PhoneToAgent => "p2a",
        Dir::AgentToPhone => "a2p",
    };
    format!("textx1|{kid}|{tag}").into_bytes()
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|e| format!("random: {e}"))?;
    Ok(b)
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Accepts base64url with or without padding.
pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("base64url: {e}"))
}

pub fn seal(key: &[u8], kid: &str, dir: Dir, plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "key must be 32 bytes".to_string())?;
    let nonce = random_bytes(NONCE_LEN)?;
    let aad = aad(kid, dir);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &aad })
        .map_err(|_| "encrypt failed".to_string())?;
    let mut out = nonce;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8], kid: &str, dir: Dir, frame: &[u8]) -> Result<Vec<u8>, String> {
    if frame.len() < NONCE_LEN + 16 {
        return Err("frame too short".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "key must be 32 bytes".to_string())?;
    let (nonce, ct) = frame.split_at(NONCE_LEN);
    let aad = aad(kid, dir);
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| "frame does not decrypt".to_string())
}

/// `{"x": "…"}` around a sealed JSON value.
pub fn seal_json(key: &[u8], kid: &str, dir: Dir, v: &serde_json::Value) -> Result<String, String> {
    let frame = seal(key, kid, dir, v.to_string().as_bytes())?;
    Ok(serde_json::json!({ "x": b64(&frame) }).to_string())
}

/// The inverse of `seal_json`: any failure (not JSON, no `x`, bad base64,
/// does not decrypt, not JSON inside) is one error, so a caller counts it as
/// one bad frame.
pub fn open_json(key: &[u8], kid: &str, dir: Dir, text: &str) -> Result<serde_json::Value, String> {
    let outer: serde_json::Value = serde_json::from_str(text).map_err(|_| "not JSON".to_string())?;
    let x = outer.get("x").and_then(|x| x.as_str()).ok_or("no \"x\"")?;
    let plain = open(key, kid, dir, &unb64(x)?)?;
    serde_json::from_slice(&plain).map_err(|_| "plaintext is not JSON".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_direction_is_bound() {
        let key = random_bytes(KEY_LEN).unwrap();
        let v = serde_json::json!({"type": "ping"});
        let s = seal_json(&key, "kid1", Dir::PhoneToAgent, &v).unwrap();
        assert_eq!(open_json(&key, "kid1", Dir::PhoneToAgent, &s).unwrap(), v);
        // Reflected back the other way, or under another kid: refused.
        assert!(open_json(&key, "kid1", Dir::AgentToPhone, &s).is_err());
        assert!(open_json(&key, "kid2", Dir::PhoneToAgent, &s).is_err());
    }

    #[test]
    fn a_wrong_key_or_a_flipped_bit_does_not_decrypt() {
        let key = random_bytes(KEY_LEN).unwrap();
        let other = random_bytes(KEY_LEN).unwrap();
        let mut f = seal(&key, "k", Dir::AgentToPhone, b"hi").unwrap();
        assert!(open(&other, "k", Dir::AgentToPhone, &f).is_err());
        let last = f.len() - 1;
        f[last] ^= 1;
        assert!(open(&key, "k", Dir::AgentToPhone, &f).is_err());
    }

    #[test]
    fn nonces_differ_per_frame() {
        let key = random_bytes(KEY_LEN).unwrap();
        let a = seal(&key, "k", Dir::AgentToPhone, b"same").unwrap();
        let b = seal(&key, "k", Dir::AgentToPhone, b"same").unwrap();
        assert_ne!(a[..12], b[..12]);
    }

    #[test]
    fn base64url_accepts_padding() {
        assert_eq!(unb64("aGk=").unwrap(), b"hi");
        assert_eq!(unb64("aGk").unwrap(), b"hi");
    }
}
