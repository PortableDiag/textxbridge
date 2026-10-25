//! TextXBridge: the agent side of the TextX Agent Protocol for Hermes.
//!
//! House conventions: flat modules, `Result<T, String>`, a blocking HTTP
//! server, and no async runtime.

mod alias;
mod api;
mod config;
mod crypto;
mod direct;
mod guard;
mod hub;
mod mcp;
mod phone;
mod proto;
mod relay;
mod store;

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::sync::Arc;

fn main() {
    if let Err(e) = run() {
        eprintln!("textxbridge: {e}");
        std::process::exit(1);
    }
}

const HELP: &str = "TextXBridge: Hermes as an assistant in TextX

  textxbridge [--config PATH] <command>     (default config: ~/.config/textxbridge/config.toml)

  textxbridge init [--port N] [--name NAME] [--relay URL] [--listen ADDR] [--base-url URL]
                   [--description TEXT] [--avatar PNG] [--state-dir DIR]
                                 write a new config (refuses to overwrite one)
  textxbridge serve              run the bridge (default)
  textxbridge pair <label>       pair a phone: prints the textx-agent: string and a QR
  textxbridge pair --dialx <label>  pair DialX (calls) on a phone: a dialx-agent: string
  textxbridge pair --notifx <label> pair NotifX (notifications) on a phone: a notifx-agent: string
  textxbridge pairs              list paired phones (no keys)
  textxbridge revoke <label|kid> unpair a phone; its next frame is refused
  textxbridge identity          the relay fingerprint and the base URL it gives
  textxbridge key                print the bridge key (for the Hermes plugin)
  textxbridge --version";

thread_local! {
    static CONFIG: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}

fn load() -> Result<config::Config, String> {
    let path = CONFIG.with(|c| c.borrow().clone());
    config::Config::load_or_create(path.as_deref())
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--config") {
        let path = args.get(1).ok_or("--config needs a path")?.clone();
        CONFIG.with(|c| *c.borrow_mut() = Some(path.into()));
        args.drain(..2);
    }
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("serve") | None => serve(),
        Some("init") => init(&args[1..]),
        Some("identity") => {
            let cfg = load()?;
            let id = relay::Identity::load_or_create(&cfg.state_dir()?)?;
            let fp = id.fingerprint();
            println!("fingerprint {fp}");
            if let Some(url) = &cfg.relay {
                println!("base {}", relay::base_for(url, &fp).unwrap_or_default());
            }
            Ok(())
        }
        Some("key") => {
            println!("{}", load()?.api_key);
            Ok(())
        }
        Some("pair") => {
            let dialx = args[1..].iter().any(|a| a == "--dialx");
            let notifx = args[1..].iter().any(|a| a == "--notifx");
            let label = args[1..].iter().filter(|a| *a != "--dialx" && *a != "--notifx").cloned().collect::<Vec<_>>().join(" ");
            // `pair --help` once made a pairing named "--help" and printed its key.
            if label.trim().is_empty() || label.starts_with('-') || (dialx && notifx) {
                return Err("pair [--dialx | --notifx] <label>: the label names the phone, e.g. pair \"Phone\"".into());
            }
            let app = match (dialx, notifx) {
                (true, _) => json!("DialX"),
                (_, true) => json!("NotifX"),
                _ => json!(null),
            };
            let v = local("POST", "/api/pairings", Some(json!({ "label": label, "app": app })))?;
            let Some(s) = v["pairing"].as_str() else {
                return Err("paired, but there is no base_url in the config, so there is no string to show. \
                     Set base_url, then revoke and pair again."
                    .into());
            };
            let place = match (dialx, notifx) {
                (true, _) => "Scan this in DialX › Settings › Agents › Pair an agent",
                // NotifX has no scanner: the owner pastes the string, or shares it from a QR reader.
                (_, true) => "Paste the string in NotifX › Agents (or scan the QR with any reader and share it to NotifX)",
                _ => "Scan this in TextX › Settings › Assistants › Add",
            };
            println!("Paired {label:?} (kid {}). {place}:\n", v["kid"].as_str().unwrap_or(""));
            println!("{}", qr(s)?);
            println!("{s}\n\nThe key is shown only now. Anyone with this string can talk to the agent as you: \
                      send it only to the phone it is for.");
            Ok(())
        }
        Some("pairs") => {
            let v = local("GET", "/api/pairings", None)?;
            let list = v["pairings"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("no phones paired (textxbridge pair <label>)");
            }
            for p in list {
                println!(
                    "{:<16} {:<5} kid {}  {}  {}  last seen {}  queued {}",
                    p["label"].as_str().unwrap_or(""),
                    p["app"].as_str().unwrap_or("TextX"),
                    p["kid"].as_str().unwrap_or(""),
                    if p["bound"] == true { "bound" } else { "not yet used" },
                    if p["online"] == true { "online" } else { "offline" },
                    p["last_seen"].as_str().unwrap_or("never"),
                    p["queued"],
                );
            }
            Ok(())
        }
        Some("revoke") => {
            let which = arg(1).ok_or("revoke <label|kid>")?;
            let path: String = which
                .bytes()
                .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
                .collect();
            let v = local("DELETE", &format!("/api/pairings/{path}"), None)?;
            println!("revoked {}", v["revoked"].as_str().unwrap_or(which));
            Ok(())
        }
        Some("--version" | "-V") => {
            println!("textxbridge {}", api::VERSION);
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            println!("{HELP}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}; try --help")),
    }
}

fn init(args: &[String]) -> Result<(), String> {
    let path = match CONFIG.with(|c| c.borrow().clone()) {
        Some(p) => p,
        None => config::config_path()?,
    };
    if path.exists() {
        return Err(format!("{} exists; edit it, or remove it to start over", path.display()));
    }
    let mut cfg = config::Config::default();
    let mut i = 0;
    while i < args.len() {
        let val = || args.get(i + 1).cloned().ok_or(format!("{} needs a value", args[i]));
        match args[i].as_str() {
            "--port" => cfg.port = val()?.parse().map_err(|_| "--port must be a number")?,
            "--name" => cfg.name = val()?,
            "--relay" => cfg.relay = Some(val()?),
            "--listen" => cfg.listen = Some(val()?),
            "--base-url" => cfg.base_url = Some(val()?),
            "--description" => cfg.description = Some(val()?),
            "--avatar" => cfg.avatar = Some(val()?.into()),
            "--state-dir" => cfg.state_dir = Some(val()?.into()),
            other => return Err(format!("init: unknown option {other:?}")),
        }
        i += 2;
    }
    cfg.check()?;
    // With a relay and no base given, the base is the relay's /r/<fingerprint>:
    // known before the first link, so a pairing string works at once.
    if let (Some(url), None) = (cfg.relay.clone(), cfg.base_url.as_ref()) {
        let id = relay::Identity::load_or_create(&cfg.state_dir()?)?;
        cfg.base_url = relay::base_for(&url, &id.fingerprint());
    }
    cfg.save(&path)?;
    println!("config    {} (port {}, assistant {:?})", path.display(), cfg.port, cfg.name);
    if let Some(b) = &cfg.base_url {
        println!("base      {b}");
    }
    Ok(())
}

fn serve() -> Result<(), String> {
    // tungstenite's wss needs one rustls crypto provider chosen for the process.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = load()?;
    let hub = Arc::new(hub::Hub::open(cfg)?);
    if let Some(url) = hub.cfg.relay.clone() {
        let id = relay::Identity::load_or_create(&hub.cfg.state_dir()?)?;
        let h = hub.clone();
        std::thread::spawn(move || relay::run(h, url, id));
    }
    if let Some(addr) = hub.cfg.listen.clone() {
        let h = hub.clone();
        std::thread::spawn(move || {
            if let Err(e) = direct::serve(h, &addr) {
                eprintln!("textxbridge: {e}");
                std::process::exit(1);
            }
        });
    }
    api::serve(hub)
}

/// Pairing changes go through the running bridge, so one process owns the
/// state file. A bridge that is not running is started for the purpose.
fn local(method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let cfg = load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);
    let mut s = std::net::TcpStream::connect(&addr)
        .map_err(|_| format!("the bridge is not running on {addr}: start it (textxbridge serve, or its service) first"))?;
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nX-API-Key: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        cfg.api_key,
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    let (head, text) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status: u16 = head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let v: Value = serde_json::from_str(text).unwrap_or(json!({}));
    if status != 200 {
        return Err(v["error"].as_str().map(String::from).unwrap_or(format!("HTTP {status}")));
    }
    Ok(v)
}

fn qr(s: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(s.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}
