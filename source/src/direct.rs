//! The direct listener (DESIGN X2): the phone routes on an address of our
//! own, for a phone on the LAN or a VPN. Off unless `listen` is set.
//!
//! One thread per connection. The request head is peeked, not read, so a
//! WebSocket upgrade can be handed whole to tungstenite; anything else is a
//! small HTTP/1.1 exchange answered with `Connection: close`.

use crate::hub::Hub;
use crate::phone::{self, Req, Session};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::CloseFrame;
use tungstenite::Message;

const HEAD_MAX: usize = 16 * 1024;
const BODY_MAX: usize = 8 * 1024 * 1024;

pub fn serve(hub: Arc<Hub>, addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("listen {addr}: {e}"))?;
    println!("textxbridge: phone routes on {addr} (/textx/v1/*)");
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let hub = hub.clone();
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            if let Err(e) = connection(&hub, stream) {
                if !e.is_empty() {
                    eprintln!("textxbridge: direct: {e}");
                }
            }
        });
    }
    Ok(())
}

fn connection(hub: &Hub, stream: TcpStream) -> Result<(), String> {
    let head = peek_head(&stream)?;
    let lower = head.to_ascii_lowercase();
    if lower.contains("\r\nupgrade: websocket") {
        websocket(hub, stream)
    } else {
        plain_http(hub, stream)
    }
}

/// Peek until the end of the head is in the buffer (or give up).
fn peek_head(stream: &TcpStream) -> Result<String, String> {
    let mut buf = vec![0u8; HEAD_MAX];
    for _ in 0..50 {
        let n = stream.peek(&mut buf).map_err(|_| String::new())?;
        if n == 0 {
            return Err(String::new());
        }
        if let Some(end) = find(&buf[..n], b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&buf[..end]).into_owned());
        }
        if n == HEAD_MAX {
            return Err("request head over 16 KB".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(String::new())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn plain_http(hub: &Hub, mut stream: TcpStream) -> Result<(), String> {
    let mut buf = vec![];
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut chunk).map_err(|_| String::new())?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > HEAD_MAX {
            return respond(&mut stream, 431, "application/json", br#"{"error":"head too large"}"#);
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("").to_string();
    let mut authorization = None;
    let mut device = None;
    let mut length = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(v.trim().to_string()),
                "x-textx-device" => device = Some(v.trim().to_string()),
                "content-length" => length = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    if length > BODY_MAX {
        return respond(&mut stream, 413, "application/json", br#"{"error":"body over 8 MB"}"#);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).map_err(|_| String::new())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let res = phone::http(
        hub,
        &Req { method: &method, path, query, authorization: authorization.as_deref(), device: device.as_deref(), body: &body },
    );
    respond(&mut stream, res.status, res.content_type, &res.body)
}

fn respond(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn websocket(hub: &Hub, stream: TcpStream) -> Result<(), String> {
    let mut session: Option<Session> = None;
    // tungstenite's callback type fixes this Result's shape.
    #[allow(clippy::result_large_err)]
    let callback = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let deny = |code: u16| {
            let mut r = ErrorResponse::new(Some(format!("{{\"error\":\"{code}\"}}")));
            *r.status_mut() = tungstenite::http::StatusCode::from_u16(code).expect("valid code");
            r
        };
        if req.uri().path() != "/textx/v1/ws" {
            return Err(deny(404));
        }
        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok());
        match phone::ws_open(hub, auth) {
            Ok(s) => {
                session = Some(s);
                Ok(resp)
            }
            Err(code) => Err(deny(code)),
        }
    };
    let mut ws = tungstenite::accept_hdr(stream, callback).map_err(|_| String::new())?;
    let Some(mut s) = session else { return Err(String::new()) };
    ws.get_mut().set_read_timeout(Some(Duration::from_millis(200))).ok();
    let result = drive(hub, &mut s, &mut ws);
    s.close(hub);
    result
}

/// The socket loop: read a frame or time out, then send what is pending.
fn drive(hub: &Hub, s: &mut Session, ws: &mut tungstenite::WebSocket<TcpStream>) -> Result<(), String> {
    for frame in s.pending(hub) {
        ws.send(Message::text(frame)).map_err(|_| String::new())?;
    }
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => {
                let step = s.on_text(hub, t.as_str());
                for f in step.send {
                    ws.send(Message::text(f)).map_err(|_| String::new())?;
                }
                if let Some((code, why)) = step.close {
                    let _ = ws.close(Some(CloseFrame { code: CloseCode::from(code), reason: why.into() }));
                    let _ = ws.flush();
                    return Ok(());
                }
            }
            Ok(Message::Close(_)) => return Ok(()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => return Ok(()),
        }
        if !hub.is_paired(&s.kid) {
            let _ = ws.close(Some(CloseFrame { code: CloseCode::from(4401), reason: "revoked".into() }));
            let _ = ws.flush();
            return Ok(());
        }
        for frame in s.pending(hub) {
            ws.send(Message::text(frame)).map_err(|_| String::new())?;
        }
        // Answers queued by tungstenite itself (pong to a ping) go out here.
        let _ = ws.flush();
    }
}
