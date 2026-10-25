//! The loopback API for the Hermes adapter (DESIGN, "Bridge ⇄ adapter").
//!
//! Every route but health needs the bridge key. Each request gets its own
//! thread: an MCP tool call can wait minutes for the user's tap, and
//! `/api/events` long-polls.

use crate::hub::Hub;
use crate::store::App;
use crate::{mcp, proto};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const BODY_MAX: usize = 8 * 1024 * 1024;

pub fn serve(hub: Arc<Hub>) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", hub.cfg.port);
    let server = tiny_http::Server::http(&addr).map_err(|e| format!("{addr}: {e}"))?;
    println!("textxbridge {VERSION}: adapter API on http://{addr}");
    for mut req in server.incoming_requests() {
        let hub = hub.clone();
        std::thread::spawn(move || {
            let url = req.url().to_string();
            let (path, query) = url.split_once('?').unwrap_or((&url, ""));
            let method = req.method().as_str().to_string();
            let authed = has_key(&req, &hub.cfg.api_key);
            let mut body = vec![];
            let _ = req.as_reader().take(BODY_MAX as u64 + 1).read_to_end(&mut body);
            let r = if body.len() > BODY_MAX {
                Reply::json(413, error("body over 8 MB"))
            } else {
                route(&hub, &method, path, query, authed, &body)
            };
            let mut resp = tiny_http::Response::from_data(r.body).with_status_code(r.status);
            resp.add_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], r.content_type.as_bytes()).expect("static"),
            );
            let _ = req.respond(resp);
        });
    }
    Ok(())
}

pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Reply {
    fn json(status: u16, v: Value) -> Reply {
        Reply { status, content_type: "application/json".into(), body: v.to_string().into_bytes() }
    }
}

fn has_key(req: &tiny_http::Request, key: &str) -> bool {
    req.headers().iter().any(|h| {
        let name = h.field.as_str().as_str().to_ascii_lowercase();
        let value = h.value.as_str();
        (name == "x-api-key" && value == key)
            || (name == "authorization" && value.strip_prefix("Bearer ") == Some(key))
    })
}

fn param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then_some(v)
    })
}

pub fn route(hub: &Hub, method: &str, path: &str, query: &str, authed: bool, body: &[u8]) -> Reply {
    if (method, path) == ("GET", "/api/health") {
        // No key, and the version: a caller told "that shipped" can check.
        let mut h = json!({ "status": "ok", "version": VERSION, "name": hub.cfg.name,
            "base_url": hub.cfg.base_url, "direct": hub.cfg.listen, "relay": hub.link_status() });
        if let (Some(o), Value::Object(extra)) = (h.as_object_mut(), hub.health()) {
            o.extend(extra);
        }
        return Reply::json(200, h);
    }
    if !authed {
        return Reply::json(401, error("missing or invalid bridge key"));
    }
    let body_json = || serde_json::from_slice::<Value>(body).unwrap_or(json!({}));
    match (method, path) {
        ("GET", "/api/events") => {
            let after = param(query, "after").and_then(|v| v.parse().ok()).unwrap_or(0);
            let wait = param(query, "wait").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0).min(55);
            let evs = hub.events_after(after, Duration::from_secs(wait));
            Reply::json(200, json!({ "events": evs }))
        }
        ("POST", p) if p.starts_with("/api/events/") && p.ends_with("/ack") => {
            let id = p["/api/events/".len()..p.len() - "/ack".len()].parse::<u64>().unwrap_or(0);
            Reply::json(200, json!({ "acked": hub.ack_event(id) }))
        }
        ("POST", "/api/say") => {
            let b = body_json();
            let kid = match hub.resolve(b["pairing"].as_str()) {
                Ok(k) => k,
                Err(e) => return Reply::json(404, error(&e)),
            };
            let text = b["text"].as_str().unwrap_or("");
            let attachments = b.get("attachments").filter(|a| a.is_array()).cloned();
            if text.trim().is_empty() && attachments.is_none() {
                return Reply::json(400, error("say needs text or attachments"));
            }
            let mut m = json!({ "text": hub.reveal(&kid, text) });
            for k in ["reply_to", "chips"] {
                if let Some(v) = b.get(k).filter(|v| !v.is_null()) {
                    m[k] = v.clone();
                }
            }
            if let Some(a) = attachments {
                match outgoing_attachments(hub, &kid, &a) {
                    Ok(a) => m["attachments"] = a,
                    Err(e) => return Reply::json(400, error(&e)),
                }
            }
            match hub.enqueue(&kid, proto::envelope("message", m)) {
                Ok(id) => Reply::json(200, json!({ "id": id })),
                Err(e) => Reply::json(404, error(&e)),
            }
        }
        // The model's words in a DialX call, spoken there (DESIGN X19). Answers
        // when playback ends, as dialx.say does: {played_ms, interrupted}.
        ("POST", "/api/call/say") => {
            let b = body_json();
            let kid = match hub.resolve_app(b["pairing"].as_str(), App::DialX) {
                Ok(k) => k,
                Err(e) => return Reply::json(404, error(&e)),
            };
            let Some(call_id) = b["call_id"].as_str().filter(|c| !c.is_empty()) else {
                return Reply::json(400, error("call/say needs call_id"));
            };
            let text = hub.reveal(&kid, b["text"].as_str().unwrap_or(""));
            let mut args = json!({ "call_id": call_id, "text": text });
            // More of the reply follows (a split line): DialX keeps the turn, no turn cue.
            if b["more"] == json!(true) {
                args["more"] = json!(true);
            }
            if let (Some(a), Some(f)) = (b["audio_b64"].as_str(), b["format"].as_str()) {
                if hub.speaks(&kid, f) {
                    args["audio_b64"] = json!(a);
                    args["format"] = json!(f);
                }
            }
            if text.trim().is_empty() && args.get("audio_b64").is_none() {
                return Reply::json(400, error("call/say needs text or audio"));
            }
            // A voice effect asked for this call is for fun: a line DialX will not play
            // through it goes again in Orbit's own voice, never not at all.
            let voice = hub.call_voice(call_id);
            if let Some(v) = &voice {
                args["voice"] = json!(v);
            }
            let r = hub.call_tool(&kid, "dialx.say", args.clone());
            let r = match (&voice, &r) {
                (Some(_), Ok(x)) if x["ok"] != json!(true) => {
                    // DialX applies the call's voice to every line itself: plain is "Off".
                    args["voice"] = json!("Off");
                    hub.call_tool(&kid, "dialx.say", args)
                }
                _ => r,
            };
            // A line the callee talked over (DialX stops it after 1 s) is told to the next turn.
            if let Ok(x) = &r {
                if x["result"]["interrupted"] == json!(true) {
                    hub.note_interrupted(call_id, x["result"]["played_ms"].as_u64().unwrap_or(0));
                }
            }
            match r {
                Ok(r) => Reply::json(200, r),
                Err(e) => Reply::json(502, error(&e)),
            }
        }
        ("POST", "/api/call/audio") => {
            let b = body_json();
            let Some(call_id) = b["call_id"].as_str().filter(|c| !c.is_empty()) else {
                return Reply::json(400, error("call/audio needs call_id"));
            };
            let part = b["part"].as_u64().unwrap_or(0);
            match hub.call_audio(call_id, part) {
                Ok(v) => Reply::json(200, v),
                // DialX is still joining the recording: the caller asks again.
                Err(e) if e.starts_with("not_ready") => Reply::json(503, error(&e)),
                Err(e) => Reply::json(404, error(&e)),
            }
        }
        ("POST", "/api/recording/audio") => {
            let b = body_json();
            let Some(rid) = b["recording_id"].as_str().filter(|c| !c.is_empty()) else {
                return Reply::json(400, error("recording/audio needs recording_id"));
            };
            let kid = match hub.resolve_app(b["pairing"].as_str(), App::DialX) {
                Ok(k) => k,
                Err(e) => return Reply::json(404, error(&e)),
            };
            match hub.recording_audio(&kid, rid, b["part"].as_u64().unwrap_or(0)) {
                Ok(v) => Reply::json(200, v),
                Err(e) if e.starts_with("not_ready") => Reply::json(503, error(&e)),
                Err(e) => Reply::json(404, error(&e)),
            }
        }
        ("POST", "/api/typing") => {
            let b = body_json();
            match hub.resolve(b["pairing"].as_str()).or_else(|_| hub.resolve_app(b["pairing"].as_str(), App::DialX)) {
                Ok(kid) => {
                    hub.send_live(&kid, proto::envelope("typing", json!({})));
                    Reply::json(200, json!({ "ok": true }))
                }
                Err(e) => Reply::json(404, error(&e)),
            }
        }
        ("GET", p) if p.starts_with("/api/files/") => match hub.read_file(&p["/api/files/".len()..], None) {
            Some(bytes) => Reply { status: 200, content_type: "application/octet-stream".into(), body: bytes },
            None => Reply::json(404, error("no such file")),
        },
        ("GET", "/api/pairings") => Reply::json(200, json!({ "pairings": hub.pairings() })),
        ("POST", "/api/pairings") => {
            let b = body_json();
            match hub.pair_app(b["label"].as_str().unwrap_or(""), b["app"].as_str()) {
                Ok((kid, key)) => {
                    let string = hub.pairing_string(&kid, &key).ok();
                    Reply::json(200, json!({ "kid": kid, "key": key, "pairing": string }))
                }
                Err(e) => Reply::json(400, error(&e)),
            }
        }
        ("DELETE", p) if p.starts_with("/api/pairings/") => match hub.revoke(&percent_decode(&p["/api/pairings/".len()..])) {
            Ok(kid) => Reply::json(200, json!({ "revoked": kid })),
            Err(e) => Reply::json(404, error(&e)),
        },
        ("POST", "/mcp") => {
            let (s, t) = mcp::handle(hub, body);
            Reply { status: s, content_type: "application/json".into(), body: t.into_bytes() }
        }
        _ => Reply::json(404, error("no such endpoint")),
    }
}

/// Attachments the adapter sends: `{name, mime, data_b64}` (bytes from the
/// agent). Up to 256 KB goes inline; bigger is stored and sent as a URL the
/// phone fetches with its bearer (protocol §4).
fn outgoing_attachments(hub: &Hub, kid: &str, a: &Value) -> Result<Value, String> {
    use base64::Engine;
    let mut out = vec![];
    for x in a.as_array().into_iter().flatten() {
        let name = x["name"].as_str().unwrap_or("file");
        let mime = x["mime"].as_str().unwrap_or("application/octet-stream");
        let data = x["data_b64"].as_str().ok_or("an attachment needs data_b64")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| format!("attachment {name}: {e}"))?;
        if bytes.len() > crate::hub::FILE_MAX {
            return Err(format!("attachment {name} is over 5 MB"));
        }
        if bytes.len() <= 256 * 1024 {
            out.push(json!({ "name": name, "mime": mime, "size": bytes.len(), "data_b64": data }));
        } else {
            let id = hub.store_file(kid, &bytes)?;
            out.push(json!({ "name": name, "mime": mime, "size": bytes.len(), "url": hub.file_url(&id) }));
        }
    }
    Ok(Value::Array(out))
}

/// `Phone%202` → `Phone 2` (a label in a path).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn error(msg: &str) -> Value {
    json!({ "error": msg })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::tests::hub;

    #[test]
    fn health_needs_no_key_and_reports_a_version() {
        let r = route(&hub(), "GET", "/api/health", "", false, b"");
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["version"], VERSION);
        assert_eq!(v["pairings"], 0);
    }

    #[test]
    fn everything_else_needs_the_key_and_unknown_is_404() {
        let h = hub();
        assert_eq!(route(&h, "GET", "/api/events", "", false, b"").status, 401);
        assert_eq!(route(&h, "POST", "/mcp", "", false, b"{}").status, 401);
        assert_eq!(route(&h, "GET", "/api/nope", "", true, b"").status, 404);
    }

    #[test]
    fn say_queues_a_message_for_the_one_phone() {
        let h = hub();
        let (kid, _) = h.pair("p").unwrap();
        let r = route(&h, "POST", "/api/say", "", true, br#"{"text":"done","chips":["thanks"]}"#);
        assert_eq!(r.status, 200);
        let out = h.outgoing(&kid, 0);
        assert_eq!(out[0].1["type"], "message");
        assert_eq!(out[0].1["body"]["chips"][0], "thanks");
        assert_eq!(route(&h, "POST", "/api/say", "", true, br#"{"text":"  "}"#).status, 400);
    }

    #[test]
    fn a_label_with_a_space_can_be_revoked() {
        let h = hub();
        h.pair("Phone 2").unwrap();
        assert_eq!(route(&h, "DELETE", "/api/pairings/Phone%202", "", true, b"").status, 200);
        assert_eq!(percent_decode("caf%C3%A9%2"), "café%2");
        assert_eq!(percent_decode("%é%zz"), "%é%zz");
    }

    #[test]
    fn a_big_attachment_goes_by_url() {
        use base64::Engine;
        let h = hub();
        let (kid, _) = h.pair("p").unwrap();
        let big = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 300 * 1024]);
        let small = base64::engine::general_purpose::STANDARD.encode(b"hi");
        let body = json!({"text": "", "attachments": [
            {"name": "big.bin", "data_b64": big}, {"name": "s.txt", "mime": "text/plain", "data_b64": small}]});
        assert_eq!(route(&h, "POST", "/api/say", "", true, body.to_string().as_bytes()).status, 200);
        let m = &h.outgoing(&kid, 0)[0].1["body"]["attachments"];
        assert!(m[0]["url"].as_str().unwrap().contains("/textx/v1/files/"));
        assert_eq!(m[1]["data_b64"], small);
    }
}
