//! Everything the bridge must not lose across a restart (DESIGN X3): the
//! pairings and their keys, the envelope ids seen (the replay window), the
//! queue to each phone with its cursor, and the events the adapter has not
//! acked. One JSON file, mode 600, written whole through a temp file.

use crate::proto;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pairing {
    pub label: String,
    /// base64url of the 32-byte AES key. Never logged, never sent.
    pub key: String,
    /// The per-install id the first `hello` bound this pairing to.
    #[serde(default)]
    pub device: Option<String>,
    pub created: String,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    /// Tools the phone says it has enabled for this assistant (`hello`).
    #[serde(default)]
    pub phone_tools: Vec<String>,
    /// The carrier's MMS cap from `hello` (TextX 0.3.21), for spoken replies.
    #[serde(default)]
    pub max_attachment_bytes: Option<u64>,
    /// `DialX` or `NotifX` (set at `pair --dialx` / `--notifx`, confirmed by
    /// `hello.app`); None is TextX (DESIGN X19, X20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// DialX `hello.audio_formats`: what `dialx.say.audio_b64` may be.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audio_formats: Vec<String>,
}

/// Which app a pairing is. Each answers only its own tools, and pairing one
/// never makes "the one phone" ambiguous for another (DESIGN X19, X20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum App {
    TextX,
    DialX,
    NotifX,
}

impl App {
    pub fn name(self) -> &'static str {
        match self {
            App::TextX => "TextX",
            App::DialX => "DialX",
            App::NotifX => "NotifX",
        }
    }

    /// The app a phone tool belongs to, by its prefix (`dialx.`, `notifx.`).
    pub fn of_tool(name: &str) -> App {
        if name.starts_with("dialx.") {
            App::DialX
        } else if name.starts_with("notifx.") {
            App::NotifX
        } else {
            App::TextX
        }
    }
}

impl Pairing {
    pub fn kind(&self) -> App {
        match self.app.as_deref() {
            Some(a) if a.eq_ignore_ascii_case("dialx") => App::DialX,
            Some(a) if a.eq_ignore_ascii_case("notifx") => App::NotifX,
            _ => App::TextX,
        }
    }

    pub fn is_dialx(&self) -> bool {
        self.kind() == App::DialX
    }
}

/// One envelope waiting for the phone. `n` is the cursor position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Out {
    pub n: u64,
    pub env: Value,
}

/// Something for the Hermes adapter (DESIGN, "Bridge ⇄ adapter").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    pub pairing: String,
    pub label: String,
    /// `message` (the user, in the assistant's conversation) or `event`
    /// (an SMS in a watched thread).
    pub kind: String,
    /// `operator` or `content` (DESIGN X5).
    pub origin: String,
    pub at: String,
    pub text: String,
    #[serde(default)]
    pub attachments: Vec<Value>,
    #[serde(default)]
    pub reply_to: Option<String>,
    /// The envelope id it came in, so a reply can point at it.
    pub envelope: String,
    /// For `event`: the thread the text arrived in.
    #[serde(default)]
    pub thread_id: Option<String>,
    /// For `event`: the user let this assistant answer that thread on its own
    /// (DESIGN X15).
    #[serde(default)]
    pub auto_reply: bool,
    /// For `event` and a mention: how the user wants replies in that thread,
    /// `voice` or `both` (TextX 0.3.21 §5); None is text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_mode: Option<String>,
    /// With a reply_mode: the phone's MMS cap, so the spoken clip fits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// For `call` (DialX): the call this utterance or ending belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// For `call`: the call is over, so the reply is a report to the owner.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub call_end: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub pairings: BTreeMap<String, Pairing>,
    /// kid → envelope id → ts (ms) when first seen.
    #[serde(default)]
    pub seen: BTreeMap<String, HashMap<String, i64>>,
    #[serde(default)]
    pub outbox: BTreeMap<String, Vec<Out>>,
    #[serde(default)]
    pub next_n: BTreeMap<String, u64>,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub next_event: u64,
    /// kid → handle → number (DESIGN X12).
    #[serde(default)]
    pub aliases: BTreeMap<String, crate::alias::Book>,
    /// DialX call_id → what the agent asked for (purpose, opening) and what the
    /// phone said about it (contact, started, heard), so each turn of the call
    /// knows what the call is for (DESIGN X19).
    #[serde(default)]
    pub calls: BTreeMap<String, Value>,
    /// NotifX watch_id → the pairing and what the agent asked to watch for, so
    /// a match's turn knows what the watch is for (DESIGN X20).
    #[serde(default)]
    pub watches: BTreeMap<String, Value>,
    /// Recent NotifX matches (what, from which pairing, when ms), so one ring
    /// that two paired phones both report reaches the owner once (DESIGN X20).
    #[serde(skip)]
    pub recent_notices: Vec<(String, String, i64)>,
}

pub const OUTBOX_MAX: usize = 1000;

impl State {
    pub fn load(path: &Path) -> Result<State, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp: PathBuf = path.with_extension("json.tmp");
        let text = serde_json::to_string(self).map_err(|e| e.to_string())?;
        write_private(&tmp, text.as_bytes())?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// True the first time an id is seen for this pairing within the window.
    pub fn first_sight(&mut self, kid: &str, id: &str, now: i64) -> bool {
        let seen = self.seen.entry(kid.to_string()).or_default();
        if seen.contains_key(id) {
            return false;
        }
        seen.insert(id.to_string(), now);
        true
    }

    pub fn prune_seen(&mut self, now: i64) {
        for ids in self.seen.values_mut() {
            ids.retain(|_, t| *t >= now - proto::REPLAY_WINDOW_MS);
        }
    }

    /// Queue an envelope for the phone. The oldest is dropped past
    /// `OUTBOX_MAX`, so a phone that never comes back cannot fill the disk.
    pub fn enqueue(&mut self, kid: &str, env: Value) -> u64 {
        let n = self.next_n.entry(kid.to_string()).or_insert(0);
        *n += 1;
        let n = *n;
        let q = self.outbox.entry(kid.to_string()).or_default();
        q.push(Out { n, env });
        if q.len() > OUTBOX_MAX {
            q.remove(0);
        }
        n
    }

    /// The phone acked an envelope by id.
    pub fn ack_out(&mut self, kid: &str, id: &str) -> bool {
        let Some(q) = self.outbox.get_mut(kid) else { return false };
        let before = q.len();
        q.retain(|o| o.env.get("id").and_then(|v| v.as_str()) != Some(id));
        q.len() != before
    }

    /// `GET ?since=<cursor>` (protocol §3.1): everything up to the cursor is
    /// acked, and what follows is returned with the new cursor.
    pub fn drain(&mut self, kid: &str, since: u64, limit: usize) -> (Vec<Value>, u64) {
        let q = self.outbox.entry(kid.to_string()).or_default();
        q.retain(|o| o.n > since);
        let page: Vec<&Out> = q.iter().take(limit).collect();
        let cursor = page.last().map(|o| o.n).unwrap_or(since);
        (page.into_iter().map(|o| o.env.clone()).collect(), cursor)
    }

    pub fn push_event(&mut self, mut ev: Event) -> u64 {
        self.next_event += 1;
        ev.id = self.next_event;
        self.events.push(ev);
        self.next_event
    }

    pub fn forget_pairing(&mut self, kid: &str) {
        self.pairings.remove(kid);
        self.seen.remove(kid);
        self.outbox.remove(kid);
        self.next_n.remove(kid);
        self.events.retain(|e| e.pairing != kid);
        self.aliases.remove(kid);
        self.watches.retain(|_, w| w["pairing"].as_str() != Some(kid));
    }
}

#[cfg(unix)]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    f.sync_all().map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dedupe_is_per_pairing_and_expires_with_the_window() {
        let mut s = State::default();
        assert!(s.first_sight("a", "id1", 1_000));
        assert!(!s.first_sight("a", "id1", 2_000));
        assert!(s.first_sight("b", "id1", 2_000));
        s.prune_seen(1_000 + proto::REPLAY_WINDOW_MS + 1);
        assert!(s.first_sight("a", "id1", 3_000));
    }

    #[test]
    fn drain_acks_up_to_the_cursor_and_pages() {
        let mut s = State::default();
        for i in 0..5 {
            s.enqueue("k", json!({"id": format!("e{i}")}));
        }
        let (page, c) = s.drain("k", 0, 2);
        assert_eq!(page.len(), 2);
        assert_eq!(c, 2);
        // Asking past 2 acks 1 and 2; they are not returned again.
        let (page, c) = s.drain("k", c, 10);
        assert_eq!(page.len(), 3);
        assert_eq!(page[0]["id"], "e2");
        assert_eq!(c, 5);
        let (page, c2) = s.drain("k", c, 10);
        assert!(page.is_empty());
        assert_eq!(c2, 5);
    }

    #[test]
    fn ack_by_id_removes_one_entry() {
        let mut s = State::default();
        s.enqueue("k", json!({"id": "x"}));
        s.enqueue("k", json!({"id": "y"}));
        assert!(s.ack_out("k", "x"));
        assert!(!s.ack_out("k", "x"));
        assert_eq!(s.outbox["k"].len(), 1);
    }

    #[test]
    fn the_outbox_is_bounded() {
        let mut s = State::default();
        for i in 0..OUTBOX_MAX + 5 {
            s.enqueue("k", json!({"id": i}));
        }
        assert_eq!(s.outbox["k"].len(), OUTBOX_MAX);
        assert_eq!(s.outbox["k"][0].env["id"], 5);
    }

    #[test]
    fn save_and_load_round_trip_privately() {
        let dir = std::env::temp_dir().join(format!("textxbridge-store-{}", proto::ulid()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state.json");
        let mut s = State::default();
        s.enqueue("k", json!({"id": "x"}));
        s.first_sight("k", "seen1", 5);
        s.save(&p).unwrap();
        let t = State::load(&p).unwrap();
        assert_eq!(t.outbox["k"].len(), 1);
        assert!(t.seen["k"].contains_key("seen1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
