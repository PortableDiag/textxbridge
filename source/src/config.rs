//! Config and the API key.
//!
//! The key is generated on first run and stored mode-600. It is never printed
//! after that and never logged — an agent reads it from the file, the same way
//! every other service on this machine works.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const APP: &str = "textxbridge";
/// TrellisBridge holds 8791 (Orbit) and 8792 (Nexus); this one sits beside them.
pub const DEFAULT_PORT: u16 = 8793;

/// Every phone tool of protocol §5 (TextX 0.4.32), in its order.
pub const ALL_TOOLS: [&str; 34] = [
    "send_sms",
    "schedule_message",
    "list_threads",
    "read_thread",
    "search_messages",
    "contacts_lookup",
    "contacts_list",
    "get_attachment",
    "watch",
    "unwatch",
    "list_scheduled",
    "update_scheduled",
    "cancel_scheduled",
    "skip_next",
    "send_scheduled_now",
    "react",
    "retry_message",
    "mark_read",
    "delete_message",
    "block_number",
    // TextX 0.4.32: everything the app does (each off until the owner switches its group on)
    "update_thread",
    "customize_thread",
    "pin_message",
    "set_draft",
    "manage_tabs",
    "templates",
    "gif_search",
    "edit_message",
    "forward_message",
    "delete_thread",
    "block_rules",
    "app_settings",
    "pending_mms",
    "backup",
];

/// DialX's tools (DialX agent frames v1, `docs/agent-protocol-dialx.md` in the
/// DialX repo), without the `dialx.` prefix the phone uses (DESIGN X19).
/// `say` is not an MCP tool: the model's reply in a call is what is said.
pub const DIALX_TOOLS: [&str; 38] = [
    "list_recents",
    "list_screened",
    "contacts_lookup",
    "list_approved_contacts",
    "schedule_call",
    "list_scheduled_calls",
    "cancel_scheduled_call",
    "say",
    "hangup",
    "report_spam",
    "mark_not_spam",
    "set_expecting",
    // DialX 0.3.0: voicemail
    "list_voicemails",
    "mark_voicemail_read",
    "delete_voicemail",
    "get_voicemail_audio",
    // DialX 0.6.2: the recording of a voicemail an agent call left. Not an MCP
    // tool: the plugin fetches it for the owner's Telegram (POST /api/call/audio).
    "get_call_audio",
    // DialX 0.7.0, "Call recordings": every recorded call, the owner's too. The
    // audio is never an MCP result: dialx_send_recording has the plugin send it
    // to the owner's Telegram (POST /api/recording/audio).
    "list_recordings",
    "get_recording_audio",
    "delete_recording",
    // DialX 0.7.6, "Voice effects": the owner's voice on the owner's own calls.
    "voice_status",
    "set_voice",
    "theremin",
    // DialX's owner tools (OwnerTools.kt, the screens' own writes), offered to agents
    // by group: Recents, Screened, Contacts, Voicemail, Lists.
    "delete_recents",
    "remove_screened",
    "clear_screened",
    "list_contacts",
    "transcribe_voicemail",
    "list_spam",
    "remove_spam",
    "clear_spam",
    "import_spam_from_history",
    "list_allowed",
    "remove_allowed",
    "list_blocked",
    "block_number",
    "unblock_number",
    // DialX 0.7.17: Orbit's own audio through an effect, no call placed. Not shown to
    // the model: the result goes to the owner's Telegram (dialx_voice_preview).
    "voice_preview",
];

/// DialX tools the owner confirms on the phone (†): 4.5 minutes, as texts.
pub const DIALX_CONFIRMED: [&str; 14] = ["schedule_call", "report_spam", "mark_not_spam", "set_expecting", "delete_voicemail",
    "delete_recording", "delete_recents", "clear_screened", "remove_spam", "clear_spam", "import_spam_from_history",
    "remove_allowed", "block_number", "unblock_number"];

/// NotifX's tools (NotifX agent frames v1, `docs/agent-protocol-notifx.md` in
/// the NotifX repo), without the `notifx.` prefix the phone uses (DESIGN X20).
pub const NOTIFX_TOOLS: [&str; 12] = [
    "list_apps",
    "list_channels",
    "search",
    "get_notification",
    "list_active",
    "get_picture",
    "watch",
    "unwatch",
    "list_watches",
    "reply",
    "tap_action",
    "dismiss",
];

/// NotifX tools the owner confirms on the phone (†).
pub const NOTIFX_CONFIRMED: [&str; 2] = ["reply", "tap_action"];

/// The tools the phone confirms every time (§5 †): their calls live 4.5
/// minutes, the time the user has to tap.
pub const CONFIRMED_TOOLS: [&str; 14] = [
    "send_sms",
    "schedule_message",
    "update_scheduled",
    "send_scheduled_now",
    "react",
    "retry_message",
    "delete_message",
    "block_number",
    // TextX 0.4.32: always (edit, forward, delete_thread) or for some actions
    // (block_rules add/clear, sensitive app_settings, backup save/restore)
    "edit_message",
    "forward_message",
    "delete_thread",
    "block_rules",
    "app_settings",
    "backup",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The loopback API for the Hermes adapter (and the MCP tools).
    pub port: u16,
    /// The bridge key: what Hermes holds instead of any pairing key (DESIGN X1).
    pub api_key: String,
    /// The assistant's name and line in TextX (`welcome`).
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    /// A PNG or JPEG (≤ 2 MB, square is best) served sealed at
    /// `<base>/textx/v1/avatar` and named in `welcome.avatar_url`.
    #[serde(default)]
    pub avatar: Option<PathBuf>,
    /// What the phone dials: the relay's `https://…/r/<fingerprint>`, or this
    /// bridge's direct listener. Goes into every pairing string.
    #[serde(default)]
    pub base_url: Option<String>,
    /// The direct listener (DESIGN X2), off when unset: `host:port` for a
    /// phone on the LAN or a VPN; it serves only `/textx/v1/*`.
    #[serde(default)]
    pub listen: Option<String>,
    /// The relay to dial out to (DESIGN X2), e.g.
    /// `wss://relay.example/textx/relay/agent`; off when unset (the default: a
    /// bridge serves phones at its own `base_url`).
    #[serde(default)]
    pub relay: Option<String>,
    /// The tools this assistant calls (`welcome.capabilities`); default all.
    #[serde(default = "default_tools")]
    pub tools: Vec<String>,
    /// The DialX tools this assistant calls on a DialX pairing; default all.
    #[serde(default = "default_dialx_tools")]
    pub dialx_tools: Vec<String>,
    /// Whether this assistant answers threads the phone marks auto-reply. Off: a
    /// contact's text is never answered on the assistant's own; it only tells the
    /// owner when the text needs them (operator, 2026-10-25: "do not reply to a
    /// contact's texts unless the owner asked you to in that moment").
    #[serde(default = "default_true")]
    pub auto_reply: bool,
    /// The NotifX tools this assistant calls on a NotifX pairing; default all.
    #[serde(default = "default_notifx_tools")]
    pub notifx_tools: Vec<String>,
    /// Where state.json and files live; default the platform data dir.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

fn default_name() -> String {
    "Hermes".into()
}

fn default_tools() -> Vec<String> {
    ALL_TOOLS.iter().map(|t| t.to_string()).collect()
}

fn default_dialx_tools() -> Vec<String> {
    DIALX_TOOLS.iter().map(|t| t.to_string()).collect()
}

fn default_notifx_tools() -> Vec<String> {
    NOTIFX_TOOLS.iter().map(|t| t.to_string()).collect()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: DEFAULT_PORT,
            api_key: generate_key(),
            name: default_name(),
            description: None,
            avatar_url: None,
            avatar: None,
            base_url: None,
            listen: None,
            relay: None,
            tools: default_tools(),
            dialx_tools: default_dialx_tools(),
            auto_reply: true,
            notifx_tools: default_notifx_tools(),
            state_dir: None,
        }
    }
}

/// 32 hex characters from the OS CSPRNG.
///
/// Reading /dev/urandom directly is Unix-only, which is fine here — this
/// service binds loopback on a Linux box — but it is the line to change first
/// if that ever stops being true.
fn generate_key() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut bytes);
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn config_path() -> Result<PathBuf, String> {
    let dirs = directories::ProjectDirs::from("", "", APP)
        .ok_or_else(|| "no config directory on this platform".to_string())?;
    Ok(dirs.config_dir().join("config.toml"))
}

impl Config {
    pub fn state_dir(&self) -> Result<PathBuf, String> {
        if let Some(d) = &self.state_dir {
            return Ok(d.clone());
        }
        let dirs = directories::ProjectDirs::from("", "", APP)
            .ok_or_else(|| "no data directory on this platform".to_string())?;
        Ok(dirs.data_dir().to_path_buf())
    }

    /// Unknown tool names in the config are an error at start, not a tool
    /// that silently never works.
    pub fn check(&self) -> Result<(), String> {
        for t in &self.tools {
            if !ALL_TOOLS.contains(&t.as_str()) {
                return Err(format!("config: unknown tool {t:?} (known: {})", ALL_TOOLS.join(", ")));
            }
        }
        for t in &self.dialx_tools {
            if !DIALX_TOOLS.contains(&t.as_str()) {
                return Err(format!("config: unknown DialX tool {t:?} (known: {})", DIALX_TOOLS.join(", ")));
            }
        }
        for t in &self.notifx_tools {
            if !NOTIFX_TOOLS.contains(&t.as_str()) {
                return Err(format!("config: unknown NotifX tool {t:?} (known: {})", NOTIFX_TOOLS.join(", ")));
            }
        }
        if let Some(b) = &self.base_url {
            if !(b.starts_with("https://") || b.starts_with("http://")) {
                return Err(format!("config: base_url {b:?} must be an http(s) URL"));
            }
        }
        Ok(())
    }

    /// Load, or create on first run. A missing config is not an error.
    pub fn load_or_create(path: Option<&Path>) -> Result<Config, String> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => config_path()?,
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                cfg.save(&path)?;
                Ok(cfg)
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        set_private(path)
    }
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_hex_and_not_constant() {
        let a = generate_key();
        let b = generate_key();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        // A CSPRNG that returns the same key twice means the read failed and
        // every install would share a key — worth failing loudly over.
        assert_ne!(a, b);
    }
}
