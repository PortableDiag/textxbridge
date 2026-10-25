//! The relay link (DESIGN X2; LANAgent's relay link spec v1, Trellis
//! 2119 #79): one outbound WebSocket to the relay, which carries every
//! phone's HTTP requests and WebSockets for this instance.
//!
//! The relay sees only the kid, the path and §3.3 ciphertext; this end
//! decrypts with the pairing key, exactly as the direct listener does.

use crate::hub::Hub;
use crate::phone::{self, Req, Session};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::Message;

/// DER SubjectPublicKeyInfo prefix for an Ed25519 key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

pub struct Identity {
    key: SigningKey,
}

impl Identity {
    /// The instance key: generated once, kept mode 600 beside the state.
    pub fn load_or_create(dir: &Path) -> Result<Identity, String> {
        let path = dir.join("relay.key");
        let seed = match std::fs::read(&path) {
            Ok(b) if b.len() == 32 => b,
            Ok(_) => return Err(format!("{}: not a 32-byte key", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                let b = crate::crypto::random_bytes(32)?;
                crate::store::write_private(&path, &b)?;
                b
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let seed: [u8; 32] = seed.try_into().map_err(|_| "bad key")?;
        Ok(Identity { key: SigningKey::from_bytes(&seed) })
    }

    pub fn spki(&self) -> Vec<u8> {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(self.key.verifying_key().as_bytes());
        der
    }

    /// The first 16 bytes of SHA-256 over the DER SPKI, lowercase hex.
    pub fn fingerprint(&self) -> String {
        Sha256::digest(self.spki())[..16].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The signature over `textx-relay-v1|<relay>|<nonce>`, raw Ed25519.
    pub fn auth(&self, relay: &str, nonce: &str) -> Value {
        let msg = format!("textx-relay-v1|{relay}|{nonce}");
        let sig = self.key.sign(msg.as_bytes());
        json!({ "t": "auth", "pub": STANDARD.encode(self.spki()), "sig": STANDARD.encode(sig.to_bytes()) })
    }
}

/// The relay's base URL for a link URL: `wss://host/textx/relay/agent` →
/// `https://host/r/<fp>`. The relay's `ready` says the same; this is for
/// before the first link is up.
pub fn base_for(relay_url: &str, fp: &str) -> Option<String> {
    let rest = relay_url.strip_prefix("wss://").map(|r| ("https", r)).or_else(|| relay_url.strip_prefix("ws://").map(|r| ("http", r)))?;
    let host = rest.1.split('/').next()?;
    Some(format!("{}://{host}/r/{fp}", rest.0))
}

/// Keep the link up for as long as the process lives.
pub fn run(hub: Arc<Hub>, url: String, id: Identity) {
    let mut backoff = 1u64;
    loop {
        hub.set_link(json!({ "state": "connecting", "url": url }));
        let started = Instant::now();
        // A panic in one attempt must not end the link for good.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| link(&hub, &url, &id)));
        let why = match attempt {
            Ok(Ok(())) => "closed".to_string(),
            Ok(Err(e)) => e,
            Err(_) => "the link thread panicked".to_string(),
        };
        // A link that held for a minute was healthy: start the backoff over.
        if started.elapsed() > Duration::from_secs(60) {
            backoff = 1;
        }
        if why.contains("4000") {
            // Another link with our key replaced this one: do not fight it fast.
            backoff = 60;
        }
        hub.set_link(json!({ "state": "down", "url": url, "error": why, "retry_s": backoff }));
        eprintln!("textxbridge: relay link {why}; again in {backoff} s");
        std::thread::sleep(Duration::from_secs(backoff));
        backoff = (backoff * 2).min(60);
    }
}

type Ws = tungstenite::WebSocket<MaybeTlsStream<TcpStream>>;

fn set_timeout(ws: &mut Ws, d: Option<Duration>) {
    let _ = match ws.get_mut() {
        MaybeTlsStream::Plain(s) => s.set_read_timeout(d),
        MaybeTlsStream::Rustls(s) => s.sock.set_read_timeout(d),
        _ => Ok(()),
    };
}

fn send(ws: &mut Ws, v: &Value) -> Result<(), String> {
    ws.send(Message::text(v.to_string())).map_err(|e| format!("send: {e}"))
}

/// Read one JSON frame, or `None` on a read timeout.
fn recv(ws: &mut Ws) -> Result<Option<Value>, String> {
    match ws.read() {
        Ok(Message::Text(t)) => Ok(serde_json::from_str(t.as_str()).ok().or(Some(json!({})))),
        Ok(Message::Close(c)) => Err(format!(
            "closed by the relay ({})",
            c.map(|c| format!("{} {}", u16::from(c.code), c.reason)).unwrap_or_default()
        )),
        Ok(_) => Ok(None),
        Err(tungstenite::Error::Io(e))
            if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
        {
            Ok(None)
        }
        Err(e) => Err(format!("read: {e}")),
    }
}

fn link(hub: &Hub, url: &str, id: &Identity) -> Result<(), String> {
    let (mut ws, _) = tungstenite::connect(url).map_err(|e| format!("connect: {e}"))?;
    set_timeout(&mut ws, Some(Duration::from_secs(10)));
    let ch = recv(&mut ws)?.ok_or("no challenge within 10 s")?;
    if ch["t"] != "challenge" {
        return Err(format!("expected a challenge, got {}", ch["t"]));
    }
    let relay = ch["relay"].as_str().unwrap_or("");
    let nonce = ch["nonce"].as_str().unwrap_or("");
    send(&mut ws, &id.auth(relay, nonce))?;
    let ready = recv(&mut ws)?.ok_or("no ready within 10 s")?;
    if ready["t"] != "ready" {
        return Err(format!("expected ready, got {}", ready["t"]));
    }
    let fp = id.fingerprint();
    if ready["fp"].as_str() != Some(fp.as_str()) {
        return Err(format!("the relay named fingerprint {} but ours is {fp}", ready["fp"]));
    }
    hub.set_link(json!({ "state": "ready", "url": url, "fp": fp, "base": ready["base"], "since": crate::proto::iso(crate::proto::now_ms()) }));
    eprintln!("textxbridge: relay link ready, base {}", ready["base"].as_str().unwrap_or(""));

    set_timeout(&mut ws, Some(Duration::from_millis(200)));
    let mut sessions: HashMap<String, Session> = HashMap::new();
    let result = (|| -> Result<(), String> {
        loop {
            if let Some(f) = recv(&mut ws)? {
                on_frame(hub, &mut ws, &mut sessions, &f)?;
            }
            let sids: Vec<String> = sessions.keys().cloned().collect();
            for sid in sids {
                let s = sessions.get_mut(&sid).expect("listed");
                if !hub.is_paired(&s.kid) {
                    send(&mut ws, &json!({ "t": "close", "sid": sid, "code": 4401, "reason": "revoked" }))?;
                    if let Some(s) = sessions.remove(&sid) {
                        s.close(hub);
                    }
                    continue;
                }
                for frame in s.pending(hub) {
                    send(&mut ws, &json!({ "t": "msg", "sid": sid, "data": frame }))?;
                }
            }
            let _ = ws.flush();
        }
    })();
    for (_, s) in sessions.drain() {
        s.close(hub);
    }
    result
}

fn on_frame(hub: &Hub, ws: &mut Ws, sessions: &mut HashMap<String, Session>, f: &Value) -> Result<(), String> {
    let sid = f["sid"].as_str().unwrap_or("").to_string();
    match f["t"].as_str().unwrap_or("") {
        "req" => {
            let body = match f["body"].as_str() {
                Some(b) => STANDARD.decode(b).or_else(|_| crate::crypto::unb64(b).map_err(|_| ())).unwrap_or_default(),
                None => vec![],
            };
            let res = phone::http(
                hub,
                &Req {
                    method: f["method"].as_str().unwrap_or(""),
                    path: f["path"].as_str().unwrap_or(""),
                    query: f["query"].as_str().unwrap_or(""),
                    authorization: f["headers"]["authorization"].as_str(),
                    device: f["headers"]["x-textx-device"].as_str(),
                    body: &body,
                },
            );
            send(
                ws,
                &json!({ "t": "res", "rid": f["rid"], "status": res.status,
                    "headers": { "content-type": res.content_type },
                    "body": if res.body.is_empty() { Value::Null } else { json!(STANDARD.encode(&res.body)) } }),
            )
        }
        "open" => {
            if f["path"].as_str() != Some("/textx/v1/ws") {
                return send(ws, &json!({ "t": "reject", "sid": sid, "status": 404 }));
            }
            match phone::ws_open(hub, f["headers"]["authorization"].as_str()) {
                Ok(mut s) => {
                    send(ws, &json!({ "t": "accept", "sid": sid }))?;
                    for frame in s.pending(hub) {
                        send(ws, &json!({ "t": "msg", "sid": sid, "data": frame }))?;
                    }
                    sessions.insert(sid, s);
                    Ok(())
                }
                Err(status) => send(ws, &json!({ "t": "reject", "sid": sid, "status": status })),
            }
        }
        "msg" => {
            let Some(s) = sessions.get_mut(&sid) else {
                return send(ws, &json!({ "t": "close", "sid": sid, "code": 4400, "reason": "no such session" }));
            };
            let step = s.on_text(hub, f["data"].as_str().unwrap_or(""));
            for frame in step.send {
                send(ws, &json!({ "t": "msg", "sid": sid, "data": frame }))?;
            }
            if let Some((code, why)) = step.close {
                send(ws, &json!({ "t": "close", "sid": sid, "code": code, "reason": why }))?;
                if let Some(s) = sessions.remove(&sid) {
                    s.close(hub);
                }
            }
            Ok(())
        }
        "close" => {
            if let Some(s) = sessions.remove(&sid) {
                s.close(hub);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, Dir};
    use crate::hub::tests::hub;
    use crate::proto;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::net::TcpListener;

    /// The wss path, offline: with the provider installed, connecting to a
    /// port that speaks no TLS fails as an error, not a panic.
    #[test]
    fn wss_fails_as_an_error_not_a_panic() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                use std::io::Write;
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            }
        });
        let h = hub();
        let dir = std::env::temp_dir().join(format!("textxbridge-id-{}", proto::ulid()));
        let id = Identity::load_or_create(&dir).unwrap();
        let r = link(&h, &format!("wss://127.0.0.1:{port}/textx/relay/agent"), &id);
        assert!(r.unwrap_err().starts_with("connect:"));
    }

    #[test]
    fn fingerprint_is_sha256_of_der_spki_first_16_bytes() {
        let dir = std::env::temp_dir().join(format!("textxbridge-id-{}", proto::ulid()));
        let id = Identity::load_or_create(&dir).unwrap();
        let again = Identity::load_or_create(&dir).unwrap();
        assert_eq!(id.fingerprint(), again.fingerprint());
        assert_eq!(id.fingerprint().len(), 32);
        assert_eq!(id.spki().len(), 44);
        assert_eq!(base_for("wss://relay.example/textx/relay/agent", "ab").unwrap(), "https://relay.example/r/ab");
    }

    /// A fake relay: checks the auth exactly as #79 says, then carries one
    /// HTTP request and one phone WebSocket over the link.
    #[test]
    fn a_phone_reaches_the_bridge_through_the_link() {
        let h = Arc::new(hub());
        let (kid, key) = h.pair("phone").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/textx/relay/agent", listener.local_addr().unwrap());
        let dir = std::env::temp_dir().join(format!("textxbridge-id-{}", proto::ulid()));
        let id = Identity::load_or_create(&dir).unwrap();
        let fp = id.fingerprint();
        {
            let h = h.clone();
            let url = url.clone();
            std::thread::spawn(move || {
                let _ = link(&h, &url, &id);
            });
        }
        let (stream, _) = listener.accept().unwrap();
        let mut ws = tungstenite::accept(stream).unwrap();
        let get = |ws: &mut tungstenite::WebSocket<TcpStream>| -> Value {
            loop {
                if let Message::Text(t) = ws.read().unwrap() {
                    return serde_json::from_str(t.as_str()).unwrap();
                }
            }
        };
        let put = |ws: &mut tungstenite::WebSocket<TcpStream>, v: Value| ws.send(Message::text(v.to_string())).unwrap();

        let nonce = crypto::b64(&[9u8; 32]);
        put(&mut ws, json!({"t": "challenge", "nonce": nonce, "relay": "relay.test"}));
        let auth = get(&mut ws);
        let der = STANDARD.decode(auth["pub"].as_str().unwrap()).unwrap();
        let fp_seen: String = Sha256::digest(&der)[..16].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(fp_seen, fp);
        let vk = VerifyingKey::from_bytes(der[12..].try_into().unwrap()).unwrap();
        let sig = Signature::from_slice(&STANDARD.decode(auth["sig"].as_str().unwrap()).unwrap()).unwrap();
        vk.verify(format!("textx-relay-v1|relay.test|{nonce}").as_bytes(), &sig).unwrap();
        put(&mut ws, json!({"t": "ready", "fp": fp, "base": format!("https://relay.test/r/{fp}")}));

        // HTTP over the link: an unknown kid, then a real POST.
        put(&mut ws, json!({"t": "req", "rid": "r1", "method": "GET", "path": "/textx/v1/messages", "query": "since=0",
            "headers": {"authorization": "Bearer nobody"}, "body": null}));
        assert_eq!(get(&mut ws)["status"], 401);
        let hello = proto::envelope("hello", json!({"protocol": 1, "device": "d1", "capabilities": []}));
        let body = crypto::seal_json(&key, &kid, Dir::PhoneToAgent, &json!([hello])).unwrap();
        put(&mut ws, json!({"t": "req", "rid": "r2", "method": "POST", "path": "/textx/v1/messages", "query": "",
            "headers": {"authorization": format!("Bearer {kid}")}, "body": STANDARD.encode(body)}));
        let res = get(&mut ws);
        assert_eq!((res["rid"].as_str(), res["status"].as_u64()), (Some("r2"), Some(200)));
        let plain = String::from_utf8(STANDARD.decode(res["body"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(crypto::open_json(&key, &kid, Dir::AgentToPhone, &plain).unwrap()["acks"][0], hello["id"]);

        // A phone WebSocket over the link: accept, the queued welcome, a message in.
        put(&mut ws, json!({"t": "open", "sid": "s1", "path": "/textx/v1/ws", "headers": {"authorization": format!("Bearer {kid}")}}));
        assert_eq!(get(&mut ws), json!({"t": "accept", "sid": "s1"}));
        // Every socket says hello first (the bound device), then talks.
        let acked = |ws: &mut tungstenite::WebSocket<TcpStream>, id: &Value| loop {
            let f = get(ws);
            let e = crypto::open_json(&key, &kid, Dir::AgentToPhone, f["data"].as_str().unwrap()).unwrap();
            if e["type"] == "ack" && &e["body"]["of"] == id {
                break;
            }
        };
        let hello2 = proto::envelope("hello", json!({"protocol": 1, "device": "d1"}));
        put(&mut ws, json!({"t": "msg", "sid": "s1", "data": crypto::seal_json(&key, &kid, Dir::PhoneToAgent, &hello2).unwrap()}));
        acked(&mut ws, &hello2["id"]);
        let m = proto::envelope("message", json!({"text": "hi from the bus"}));
        put(&mut ws, json!({"t": "msg", "sid": "s1", "data": crypto::seal_json(&key, &kid, Dir::PhoneToAgent, &m).unwrap()}));
        acked(&mut ws, &m["id"]);
        let ev = h.events_after(0, Duration::from_secs(2));
        assert_eq!(ev[0].text, "hi from the bus");
        assert_eq!(h.link_status()["state"], "ready");

        // Revoking closes the phone's session with 4401.
        h.revoke(&kid).unwrap();
        let c = get(&mut ws);
        assert_eq!((c["t"].as_str(), c["code"].as_u64()), (Some("close"), Some(4401)));
    }
}
