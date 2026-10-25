//! The phone-facing routes (protocol §3.1, §3.3), as plain functions of a
//! request, so the direct listener and the relay link serve them identically.

use crate::crypto::{self, Dir};
use crate::hub::{self, Hub};
use serde_json::{json, Value};

pub struct Req<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub authorization: Option<&'a str>,
    /// `X-TextX-Device` (LANAgent's form; the spec's is `?device=`): either works.
    pub device: Option<&'a str>,
    pub body: &'a [u8],
}

#[derive(Debug)]
pub struct Res {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Res {
    fn plain(status: u16, msg: &str) -> Res {
        Res {
            status,
            content_type: "application/json",
            body: json!({ "error": msg }).to_string().into_bytes(),
        }
    }
    fn sealed(text: String) -> Res {
        Res { status: 200, content_type: "application/json", body: text.into_bytes() }
    }
}

/// `Bearer <kid>` → kid.
pub fn kid_of(authorization: Option<&str>) -> Option<&str> {
    let v = authorization?.trim();
    let kid = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer "))?.trim();
    (!kid.is_empty()).then_some(kid)
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then_some(v)
    })
}

/// The longest a phone's GET is held (`wait`).
const MAX_WAIT_S: u64 = 25;

pub fn http(hub: &Hub, req: &Req) -> Res {
    if !req.path.starts_with("/textx/v1/") {
        return Res::plain(404, "not found");
    }
    // Before anything is read: an unknown kid is a plaintext 401 (§3.3).
    let Some(kid) = kid_of(req.authorization) else {
        return Res::plain(401, "unknown kid");
    };
    let Some(key) = hub.key_for(kid) else {
        return Res::plain(401, "unknown kid");
    };
    // A second device on a bound pairing gets `auth` on everything, not only
    // on hello (TextX › Agent Card #15): a POST proves its device with the
    // hello it starts with, any other request with `?device=`.
    let device_ok = || {
        let d = query_param(req.query, "device").or(req.device).unwrap_or("");
        !d.is_empty() && hub.bound_device(kid).as_deref() == Some(d)
    };
    match (req.method, req.path) {
        ("POST", "/textx/v1/messages") => {
            let text = String::from_utf8_lossy(req.body);
            let Ok(v) = crypto::open_json(&key, kid, Dir::PhoneToAgent, &text) else {
                return Res::plain(400, "frame does not decrypt");
            };
            let envs = match v {
                Value::Array(a) => a,
                one @ Value::Object(_) => vec![one],
                _ => return Res::plain(400, "expected an array of envelopes"),
            };
            if envs.first().and_then(|e| e["type"].as_str()) != Some("hello") {
                return Res::plain(401, "a POST batch starts with this device's hello");
            }
            let mut acks = vec![];
            for e in &envs {
                let h = hub.handle(kid, e);
                if h.close == Some(4401) {
                    return Res::plain(401, "this pairing belongs to another device");
                }
                if let Some(id) = h.ack {
                    acks.push(id);
                }
                // Errors have no socket to go back on: they queue for the next GET.
                for e in h.now.into_iter().filter(|e| e["type"] == "error") {
                    let _ = hub.enqueue(kid, e);
                }
            }
            match hub::seal_for_phone(&key, kid, &json!({ "acks": acks })) {
                Ok(t) => Res::sealed(t),
                Err(e) => Res::plain(500, &e),
            }
        }
        _ if req.method == "GET" && !device_ok() || req.path == "/textx/v1/files" && !device_ok() => {
            Res::plain(401, "this request needs ?device= with the device this pairing is bound to")
        }
        ("GET", "/textx/v1/messages") => {
            hub.polled(kid);
            let since = query_param(req.query, "since").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            // Long poll (DialX #82): `wait` seconds at most 25, so a relay's 30 s
            // ceiling holds; a missing or bad one answers at once, as before.
            let wait = query_param(req.query, "wait").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0).min(MAX_WAIT_S);
            if wait > 0 {
                hub.wait_outgoing(kid, since, std::time::Duration::from_secs(wait));
                hub.polled(kid);
            }
            let (envelopes, cursor) = hub.drain(kid, since);
            match hub::seal_for_phone(&key, kid, &json!({ "envelopes": envelopes, "cursor": cursor.to_string() })) {
                Ok(t) => Res::sealed(t),
                Err(e) => Res::plain(500, &e),
            }
        }
        ("POST", "/textx/v1/files") => {
            if req.body.len() > hub::FILE_MAX + 64 {
                return Res::plain(413, "over 5 MB");
            }
            let Ok(bytes) = crypto::open(&key, kid, Dir::PhoneToAgent, req.body) else {
                return Res::plain(400, "file does not decrypt");
            };
            match hub.store_file(kid, &bytes) {
                Ok(id) => match hub::seal_for_phone(&key, kid, &json!({ "url": hub.file_url(&id) })) {
                    Ok(t) => Res::sealed(t),
                    Err(e) => Res::plain(500, &e),
                },
                Err(e) => Res::plain(413, &e),
            }
        }
        ("GET", "/textx/v1/avatar") => match hub.avatar() {
            Some(bytes) => match crypto::seal(&key, kid, Dir::AgentToPhone, &bytes) {
                Ok(frame) => Res { status: 200, content_type: "application/octet-stream", body: frame },
                Err(e) => Res::plain(500, &e),
            },
            None => Res::plain(404, "no avatar"),
        },
        ("GET", p) if p.starts_with("/textx/v1/files/") => {
            let id = &p["/textx/v1/files/".len()..];
            match hub.read_file(id, Some(kid)) {
                Some(bytes) => match crypto::seal(&key, kid, Dir::AgentToPhone, &bytes) {
                    Ok(frame) => Res { status: 200, content_type: "application/octet-stream", body: frame },
                    Err(e) => Res::plain(500, &e),
                },
                None => Res::plain(404, "no such file"),
            }
        }
        _ => Res::plain(404, "not found"),
    }
}

/// One phone's WebSocket, whatever carries it.
pub struct Session {
    pub kid: String,
    key: Vec<u8>,
    /// Outbox position sent on this socket so far.
    sent: u64,
    eph: u64,
    bad: u8,
    /// Set once a hello on this socket matched the bound device: nothing but
    /// ack and pong is acted on before that.
    hello: bool,
}

/// The upgrade: `Err(401)` for an unknown kid (close 4401 on a socket).
pub fn ws_open(hub: &Hub, authorization: Option<&str>) -> Result<Session, u16> {
    let kid = kid_of(authorization).ok_or(401u16)?;
    let key = hub.key_for(kid).ok_or(401u16)?;
    hub.session_opened(kid);
    // Start at the current head: a typing from before this socket is stale.
    let (_, eph) = hub.ephemeral(kid, 0);
    Ok(Session { kid: kid.to_string(), key, sent: 0, eph, bad: 0, hello: false })
}

/// What a socket should do after a frame.
#[derive(Debug, Default)]
pub struct Step {
    pub send: Vec<String>,
    pub close: Option<(u16, &'static str)>,
}

impl Session {
    pub fn on_text(&mut self, hub: &Hub, text: &str) -> Step {
        let mut step = Step::default();
        if !hub.is_paired(&self.kid) {
            step.close = Some((4401, "revoked"));
            return step;
        }
        let env = match crypto::open_json(&self.key, &self.kid, Dir::PhoneToAgent, text) {
            Ok(v) => v,
            Err(_) => {
                // Dropped; three of them end the session (§3.3).
                self.bad += 1;
                if self.bad >= 3 {
                    step.close = Some((4400, "frames do not decrypt"));
                }
                return step;
            }
        };
        let kind = env["type"].as_str().unwrap_or("");
        if !self.hello && !matches!(kind, "hello" | "ack" | "pong") {
            step.send.extend(self.seal(&hub::error_env("auth", "send hello first on this connection")));
            return step;
        }
        let h = hub.handle(&self.kid, &env);
        if kind == "hello" && h.close.is_none() && h.ack.is_some() {
            self.hello = true;
        }
        if let Some(id) = h.ack {
            step.send.extend(self.seal(&crate::proto::envelope("ack", json!({ "of": id }))));
        }
        for e in &h.now {
            step.send.extend(self.seal(e));
        }
        if let Some(code) = h.close {
            step.close = Some((code, "refused"));
        }
        step
    }

    /// Envelopes queued since the last call, sealed. Unacked ones stay in the
    /// outbox and go again on the next socket.
    pub fn pending(&mut self, hub: &Hub) -> Vec<String> {
        // Anonymous until its own hello is accepted: nothing queued for the
        // phone goes to a socket that has not proved its device.
        if !self.hello {
            return vec![];
        }
        let out = hub.outgoing(&self.kid, self.sent);
        if let Some((n, _)) = out.last() {
            self.sent = *n;
        }
        let (eph, eph_n) = hub.ephemeral(&self.kid, self.eph);
        self.eph = eph_n;
        out.iter().map(|(_, e)| e).chain(eph.iter()).filter_map(|e| self.seal(e)).collect()
    }

    fn seal(&self, v: &Value) -> Option<String> {
        hub::seal_for_phone(&self.key, &self.kid, v).ok()
    }

    pub fn close(&self, hub: &Hub) {
        hub.session_closed(&self.kid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::tests::hub;
    use crate::proto;
    use std::time::Duration;

    fn phone_seal(key: &[u8], kid: &str, v: &Value) -> String {
        crypto::seal_json(key, kid, Dir::PhoneToAgent, v).unwrap()
    }

    fn phone_open(key: &[u8], kid: &str, body: &[u8]) -> Value {
        crypto::open_json(key, kid, Dir::AgentToPhone, std::str::from_utf8(body).unwrap()).unwrap()
    }

    #[test]
    fn unknown_kid_is_401_before_anything_is_read() {
        let h = hub();
        let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: "", authorization: Some("Bearer nope"), device: None, body: b"" });
        assert_eq!(r.status, 401);
        assert!(ws_open(&h, None).is_err());
    }

    #[test]
    fn http_post_then_get_drains_the_welcome() {
        let h = hub();
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        let hello = proto::envelope("hello", json!({"protocol": 1, "app": "TextX", "device": "d1", "capabilities": []}));
        let body = phone_seal(&key, &kid, &json!([hello]));
        let r = http(&h, &Req { method: "POST", path: "/textx/v1/messages", query: "", authorization: Some(&auth), device: None, body: body.as_bytes() });
        assert_eq!(r.status, 200);
        let acks = phone_open(&key, &kid, &r.body);
        assert_eq!(acks["acks"][0], hello["id"]);

        let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: "since=0&device=d1", authorization: Some(&auth), device: None, body: b"" });
        assert_eq!(h.pairings()[0]["online"], true, "a polling phone counts as online");
        let page = phone_open(&key, &kid, &r.body);
        assert_eq!(page["envelopes"][0]["type"], "welcome");
        let cursor = page["cursor"].as_str().unwrap().to_string();
        // Asking past the cursor acks it: nothing comes back again.
        let q = format!("since={cursor}&device=d1");
        let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: &q, authorization: Some(&auth), device: None, body: b"" });
        assert!(phone_open(&key, &kid, &r.body)["envelopes"].as_array().unwrap().is_empty());
    }

    /// DialX #82: `wait` holds the GET until something is queued, and no longer.
    #[test]
    fn a_long_poll_answers_when_something_is_queued_and_waits_otherwise() {
        let h = std::sync::Arc::new(hub());
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        let hello = proto::envelope("hello", json!({"protocol": 1, "app": "TextX", "device": "d1", "capabilities": []}));
        http(&h, &Req { method: "POST", path: "/textx/v1/messages", query: "", authorization: Some(&auth), device: None,
            body: phone_seal(&key, &kid, &json!([hello])).as_bytes() });
        let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: "since=0&device=d1", authorization: Some(&auth), device: None, body: b"" });
        let cursor = phone_open(&key, &kid, &r.body)["cursor"].as_str().unwrap().to_string();
        let q = format!("since={cursor}&device=d1&wait=1");
        // Nothing queued: held about a second, then an empty page.
        let t0 = std::time::Instant::now();
        let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: &q, authorization: Some(&auth), device: None, body: b"" });
        assert!(t0.elapsed() >= std::time::Duration::from_millis(900), "{:?}", t0.elapsed());
        assert!(phone_open(&key, &kid, &r.body)["envelopes"].as_array().unwrap().is_empty());
        // Something queued while held: answered at once with it.
        let q = format!("since={cursor}&device=d1&wait=20");
        let (h2, k2) = (h.clone(), kid.clone());
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            h2.enqueue(&k2, proto::envelope("tool_call", json!({"call_id": "C1", "name": "read_thread", "args": {}}))).unwrap();
        });
        let t0 = std::time::Instant::now();
        let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: &q, authorization: Some(&auth), device: None, body: b"" });
        assert!(t0.elapsed() < std::time::Duration::from_secs(3), "{:?}", t0.elapsed());
        assert_eq!(phone_open(&key, &kid, &r.body)["envelopes"][0]["type"], "tool_call");
        // A bad wait answers at once, as before.
        let q = format!("since={cursor}&device=d1&wait=soon");
        let t0 = std::time::Instant::now();
        http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: &q, authorization: Some(&auth), device: None, body: b"" });
        assert!(t0.elapsed() < std::time::Duration::from_millis(500));
    }

    /// TextX › Agent Card #15: a second device on a bound pairing gets
    /// `auth` on everything, on both paths.
    #[test]
    fn a_second_device_gets_nothing_on_either_path() {
        let h = hub();
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        h.handle(&kid, &proto::envelope("hello", json!({"device": "mine"})));
        let msg = |t: &str| proto::envelope("message", json!({"text": t}));
        let post = |body: Value| {
            let b = phone_seal(&key, &kid, &body);
            http(&h, &Req { method: "POST", path: "/textx/v1/messages", query: "", authorization: Some(&auth), device: None, body: b.as_bytes() })
        };
        // HTTP: no hello first, or another device's hello: refused, nothing acted on.
        assert_eq!(post(json!([msg("skip hello")])).status, 401);
        let other = proto::envelope("hello", json!({"device": "theirs"}));
        assert_eq!(post(json!([other, msg("after their hello")])).status, 401);
        for q in ["since=0", "since=0&device=theirs"] {
            let r = http(&h, &Req { method: "GET", path: "/textx/v1/messages", query: q, authorization: Some(&auth), device: None, body: b"" });
            assert_eq!(r.status, 401, "{q}");
        }
        // WS: a socket that never said hello is answered `auth` and nothing more.
        let mut s = ws_open(&h, Some(&auth)).unwrap();
        let step = s.on_text(&h, &phone_seal(&key, &kid, &msg("no hello on this socket")));
        let e = crypto::open_json(&key, &kid, Dir::AgentToPhone, &step.send[0]).unwrap();
        assert_eq!(e["body"]["code"], "auth");
        assert!(h.events_after(0, Duration::ZERO).is_empty(), "nothing reached the agent");
        // The bound device, properly, still works.
        let mine = proto::envelope("hello", json!({"device": "mine"}));
        assert_eq!(post(json!([mine, msg("hi")])).status, 200);
        assert_eq!(h.events_after(0, Duration::ZERO).len(), 1);
        s.close(&h);
    }

    #[test]
    fn the_avatar_is_sealed_named_in_welcome_and_only_for_the_bound_device() {
        let mut h = hub();
        let pic = std::env::temp_dir().join(format!("tx-avatar-{}.png", proto::ulid()));
        std::fs::write(&pic, b"\x89PNG fake").unwrap();
        h.cfg.avatar = Some(pic);
        assert_eq!(h.welcome_for(crate::store::App::TextX)["avatar_url"], "https://relay.example/r/abc/textx/v1/avatar");
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        h.handle(&kid, &proto::envelope("hello", json!({"device": "d1"})));
        let get = |q: &str| http(&h, &Req { method: "GET", path: "/textx/v1/avatar", query: q, authorization: Some(&auth), device: None, body: b"" });
        let r = get("device=d1");
        assert_eq!(crypto::open(&key, &kid, Dir::AgentToPhone, &r.body).unwrap(), b"\x89PNG fake");
        assert_eq!(get("device=other").status, 401);
        assert_eq!(get("").status, 401);
    }

    #[test]
    fn a_frame_sealed_the_wrong_way_does_not_decrypt() {
        let h = hub();
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        // Sealed as agent→phone, sent phone→agent: a reflected frame.
        let body = crypto::seal_json(&key, &kid, Dir::AgentToPhone, &json!([])).unwrap();
        let r = http(&h, &Req { method: "POST", path: "/textx/v1/messages", query: "", authorization: Some(&auth), device: None, body: body.as_bytes() });
        assert_eq!(r.status, 400);
    }

    #[test]
    fn files_go_up_and_come_back_only_to_their_pairing() {
        let h = hub();
        let (kid, key) = h.pair("p").unwrap();
        let (kid2, _) = h.pair("q").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        h.handle(&kid, &proto::envelope("hello", json!({"device": "d1"})));
        h.handle(&kid2, &proto::envelope("hello", json!({"device": "d2"})));
        let up = crypto::seal(&key, &kid, Dir::PhoneToAgent, b"picture bytes").unwrap();
        let r = http(&h, &Req { method: "POST", path: "/textx/v1/files", query: "device=d1", authorization: Some(&auth), device: None, body: &up });
        let url = phone_open(&key, &kid, &r.body)["url"].as_str().unwrap().to_string();
        assert!(url.starts_with("https://relay.example/r/abc/textx/v1/files/"));
        let path = &url["https://relay.example/r/abc".len()..];
        let r = http(&h, &Req { method: "GET", path, query: "device=d1", authorization: Some(&auth), device: None, body: b"" });
        assert_eq!(crypto::open(&key, &kid, Dir::AgentToPhone, &r.body).unwrap(), b"picture bytes");
        let auth2 = format!("Bearer {kid2}");
        let r = http(&h, &Req { method: "GET", path, query: "device=d2", authorization: Some(&auth2), device: None, body: b"" });
        assert_eq!(r.status, 404);
    }

    #[test]
    fn ws_acks_pongs_and_closes_after_three_bad_frames() {
        let h = hub();
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let mut s = ws_open(&h, Some(&format!("Bearer {kid}"))).unwrap();
        let hello = proto::envelope("hello", json!({"protocol": 1, "device": "d"}));
        let step = s.on_text(&h, &phone_seal(&key, &kid, &hello));
        let ack = crypto::open_json(&key, &kid, Dir::AgentToPhone, &step.send[0]).unwrap();
        assert_eq!(ack["type"], "ack");
        assert_eq!(ack["body"]["of"], hello["id"]);
        let pending = s.pending(&h);
        let welcome = crypto::open_json(&key, &kid, Dir::AgentToPhone, &pending[0]).unwrap();
        assert_eq!(welcome["type"], "welcome");
        assert!(s.pending(&h).is_empty());

        let step = s.on_text(&h, &phone_seal(&key, &kid, &proto::envelope("ping", json!({}))));
        let types: Vec<String> = step.send.iter()
            .map(|f| crypto::open_json(&key, &kid, Dir::AgentToPhone, f).unwrap()["type"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(types, ["ack", "pong"]);

        assert!(s.on_text(&h, "{\"x\":\"garbage\"}").close.is_none());
        assert!(s.on_text(&h, "not json").close.is_none());
        assert_eq!(s.on_text(&h, "{}").close.map(|c| c.0), Some(4400));
        s.close(&h);
    }

    #[test]
    fn a_welcome_unacked_on_one_socket_goes_again_on_the_next() {
        let h = hub();
        let (kid, key) = h.pair("p").unwrap();
        let key = crypto::unb64(&key).unwrap();
        let auth = format!("Bearer {kid}");
        let hello = || phone_seal(&key, &kid, &proto::envelope("hello", json!({"device": "d"})));
        let kinds = |s: &mut Session| -> Vec<String> {
            s.pending(&h).iter().map(|f| crypto::open_json(&key, &kid, Dir::AgentToPhone, f).unwrap())
                .map(|e| format!("{}:{}", e["type"].as_str().unwrap(), e["body"]["text"].as_str().unwrap_or(""))).collect()
        };
        let mut s = ws_open(&h, Some(&auth)).unwrap();
        s.on_text(&h, &hello());
        h.enqueue(&kid, proto::envelope("message", json!({"text": "reply"}))).unwrap();
        assert_eq!(kinds(&mut s), ["welcome:", "message:reply"]);
        s.close(&h);
        // A new socket gets nothing before its hello, then the unacked reply again.
        let mut s2 = ws_open(&h, Some(&auth)).unwrap();
        assert!(s2.pending(&h).is_empty());
        s2.on_text(&h, &hello());
        let again = s2.pending(&h);
        let m = again.iter().map(|f| crypto::open_json(&key, &kid, Dir::AgentToPhone, f).unwrap())
            .find(|e| e["type"] == "message").unwrap();
        // Acking it removes it for good.
        s2.on_text(&h, &phone_seal(&key, &kid, &proto::envelope("ack", json!({"of": m["id"]}))));
        s2.close(&h);
        let mut s3 = ws_open(&h, Some(&auth)).unwrap();
        s3.on_text(&h, &hello());
        assert!(!kinds(&mut s3).iter().any(|k| k.starts_with("message")));
    }
}
