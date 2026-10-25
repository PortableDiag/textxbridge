#!/usr/bin/env bash
# Install TextXBridge for one Hermes agent.
#
#   the bridge   holds the phone pairing keys and the relay identity, speaks the
#                TextX Agent Protocol, serves events + MCP on 127.0.0.1
#   the plugin   `textx-platform` in that Hermes: a paired phone's assistant
#                conversation becomes a chat platform; holds only the bridge key
#
# Re-running it upgrades in place: the binary is replaced; the bridge's config,
# key, pairings and queues are kept.
set -euo pipefail

usage() {
  cat <<'USAGE'
install.sh [options]

  --hermes-home DIR   Hermes data dir on this host (default $HERMES_HOME or ~/.hermes)
  --hermes-cmd "CMD"  how to run the Hermes CLI (default: hermes)
  --instance NAME     this bridge's instance name (default: from the Hermes dir)
  --port N            bridge port (default: the next free from 8793)
  --name NAME         what TextX shows for the assistant (default: Hermes)
  --base-url URL      the public https address phones dial (e.g. https://hermes.example.com),
                      served by --listen behind your TLS proxy; or a LAN/VPN address
  --listen HOST:PORT  the bridge's phone listener (default 127.0.0.1:8794 with --base-url)
  --relay URL         optional: a TextX relay to dial out to instead, if you have one
                      (any relay speaking the TextX relay link); the base comes from it
  --no-mcp            leave Hermes's mcp_servers alone
  --no-systemd        no systemd user unit; print the run command
  --no-restart        do not restart the Hermes gateway
  --bin PATH          use this textxbridge binary
  --no-plugin         the plugin is already installed (hermes plugins install)
USAGE
}

die() { echo "install: $*" >&2; exit 1; }
say() { echo "  $*"; }

INSTANCE= PORT= NAME= RELAY= LISTEN= BASE= MCP=1 SYSTEMD=1 RESTART=1 GIVEN_BIN= PLUGIN=1
HERMES_HOME_DIR=${HERMES_HOME:-$HOME/.hermes}
HERMES_CMD=hermes
while [ $# -gt 0 ]; do
  case $1 in
    --hermes-home) HERMES_HOME_DIR=$2; shift ;;
    --hermes-cmd) HERMES_CMD=$2; shift ;;
    --instance) INSTANCE=$2; shift ;;
    --port) PORT=$2; shift ;;
    --name) NAME=$2; shift ;;
    --relay) RELAY=$2; shift ;;
    --listen) LISTEN=$2; shift ;;
    --base-url) BASE=$2; shift ;;
    --no-mcp) MCP=0 ;;
    --no-systemd) SYSTEMD=0 ;;
    --no-restart) RESTART=0 ;;
    --bin) GIVEN_BIN=$2; shift ;;
    --no-plugin) PLUGIN=0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option $1" ;;
  esac
  shift
done
[ -n "$RELAY" ] || [ -n "$BASE" ] || die "say how a phone reaches this bridge: --base-url https://… (your own address, proxied to --listen) or --relay URL"
[ -n "$BASE" ] && [ -z "$LISTEN" ] && LISTEN=127.0.0.1:8794

HERE=$(cd "$(dirname "$0")" && pwd)
HERMES_HOME_DIR=$(cd "$HERMES_HOME_DIR" 2>/dev/null && pwd) || die "no Hermes dir at $HERMES_HOME_DIR (--hermes-home)"
ENV_FILE=$HERMES_HOME_DIR/.env
[ -n "$INSTANCE" ] || INSTANCE=$(basename "$HERMES_HOME_DIR" | sed 's/^\.//; s/[^A-Za-z0-9_-]/-/g')
[ -n "$INSTANCE" ] || INSTANCE=hermes
BIN_DIR=${BIN_DIR:-$HOME/.local/bin}
CONF_ROOT=${XDG_CONFIG_HOME:-$HOME/.config}/textxbridge
CONF_DIR=$CONF_ROOT/$INSTANCE
CONFIG=$CONF_DIR/config.toml
STATE_DIR=${XDG_DATA_HOME:-$HOME/.local/share}/textxbridge/$INSTANCE
umask 077

echo "TextXBridge → Hermes at $HERMES_HOME_DIR (bridge instance \"$INSTANCE\")"

# 1. The binary: the one given, else built from the bundled source.
if [ -n "$GIVEN_BIN" ]; then
  [ -x "$GIVEN_BIN" ] || die "--bin $GIVEN_BIN is not an executable"
  BIN=$GIVEN_BIN
else
  SRC=$(for d in "$HERE/source" "$HERE/.."; do [ -f "$d/Cargo.toml" ] && grep -q 'name = "textxbridge"' "$d/Cargo.toml" && echo "$d" && break; done || true)
  [ -n "$SRC" ] || die "no binary given (--bin) and no source to build one"
  command -v cargo >/dev/null || die "no cargo to build the bridge (https://rustup.rs), or pass --bin"
  say "building from source…"
  # The source's own .cargo/config.toml may move the target dir (an exfat
  # checkout builds elsewhere): ask cargo where it went.
  cargo build --release --quiet --manifest-path "$SRC/Cargo.toml"
  TDIR=$(cd "$SRC" && cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
  BIN=${TDIR:-$SRC/target}/release/textxbridge
fi
mkdir -p "$BIN_DIR"
install -m 755 "$BIN" "$BIN_DIR/textxbridge.new" && mv -f "$BIN_DIR/textxbridge.new" "$BIN_DIR/textxbridge"
TB=$BIN_DIR/textxbridge
say "binary    $TB ($("$TB" --version))"

# 2. The config: written once, then kept (its bridge key, pairings and queues with it).
mkdir -p "$CONF_DIR" "$STATE_DIR"
if [ ! -f "$CONFIG" ]; then
  if [ -z "$PORT" ]; then
    taken=$({ cat "$CONF_ROOT"/*/config.toml "$CONF_ROOT"/config.toml 2>/dev/null || true; } | sed -n 's/^port *= *\([0-9]*\).*/\1/p')
    PORT=8793
    while echo "$taken" | grep -qx "$PORT" || (command -v ss >/dev/null && ss -ltnH "sport = :$PORT" | grep -q .); do PORT=$((PORT + 1)); done
  fi
  args=(init --port "$PORT" --state-dir "$STATE_DIR")
  [ -n "$NAME" ] && args+=(--name "$NAME")
  [ -n "$RELAY" ] && args+=(--relay "$RELAY")
  [ -n "$LISTEN" ] && args+=(--listen "$LISTEN")
  [ -n "$BASE" ] && args+=(--base-url "$BASE")
  "$TB" --config "$CONFIG" "${args[@]}" | sed 's/^/  /'
else
  say "config    $CONFIG (kept)"
fi
PORT=$(sed -n 's/^port *= *\([0-9]*\).*/\1/p' "$CONFIG" | head -1)
BRIDGE_URL=http://127.0.0.1:$PORT
BRIDGE_KEY=$("$TB" --config "$CONFIG" key)

# 3. Run it: a systemd user unit per instance.
if [ "$SYSTEMD" = 1 ] && command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
  UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
  mkdir -p "$UNIT_DIR"
  sed "s|@BIN@|$TB|; s|@CONF_ROOT@|$CONF_ROOT|" "$HERE/textxbridge@.service" > "$UNIT_DIR/textxbridge@.service"
  systemctl --user daemon-reload
  systemctl --user enable --quiet "textxbridge@$INSTANCE"
  systemctl --user restart "textxbridge@$INSTANCE"
  loginctl enable-linger "$USER" 2>/dev/null || say "note: 'loginctl enable-linger $USER' failed: the bridge stops when you log out"
  say "service   textxbridge@$INSTANCE (systemctl --user status textxbridge@$INSTANCE)"
  for _ in $(seq 1 30); do curl -fsS "$BRIDGE_URL/api/health" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS "$BRIDGE_URL/api/health" >/dev/null 2>&1 || { journalctl --user -u "textxbridge@$INSTANCE" -n 20 --no-pager >&2; die "the bridge did not come up on $BRIDGE_URL"; }
  say "health    $(curl -fsS "$BRIDGE_URL/api/health")"
else
  say "run it    $TB --config $CONFIG serve   (keep it running: a service, tmux, …)"
fi

# 4. Hermes: the plugin, its env, the MCP server.
if [ "$PLUGIN" = 1 ]; then
  PLUG=$HERMES_HOME_DIR/plugins/textx
  mkdir -p "$HERMES_HOME_DIR/plugins"
  SRC_PLUG=$(for d in "$HERE/hermes-plugin/textx" "$HERE/../hermes-plugin/textx"; do [ -f "$d/plugin.yaml" ] && echo "$d" && break; done || true)
  [ -n "$SRC_PLUG" ] || die "no plugin source beside the installer"
  rm -rf "$PLUG.new" && cp -r "$SRC_PLUG" "$PLUG.new"
  find "$PLUG.new" -name __pycache__ -prune -exec rm -rf {} +
  rm -rf "$PLUG" && mv "$PLUG.new" "$PLUG"
  say "plugin    $PLUG ($(sed -n 's/^version: //p' "$PLUG/plugin.yaml"))"
fi

upsert_env() {  # NAME VALUE: replace or append one line, keep the file's mode
  touch "$ENV_FILE"
  local tmp; tmp=$(mktemp "$ENV_FILE.XXXX")
  grep -v -E "^$1=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  chmod --reference="$ENV_FILE" "$tmp" 2>/dev/null || chmod 600 "$tmp"
  mv -f "$tmp" "$ENV_FILE"
}
upsert_env TEXTXBRIDGE_KEY "$BRIDGE_KEY"
upsert_env TEXTXBRIDGE_URL "$BRIDGE_URL"
# The bridge admits only paired phones (DESIGN X5), so Hermes's own name
# allowlist (which would answer the user with a pairing prompt) is off here.
upsert_env TEXTX_ALLOW_ALL_USERS true
say "env       TEXTXBRIDGE_KEY, TEXTXBRIDGE_URL=$BRIDGE_URL, TEXTX_ALLOW_ALL_USERS=true in $ENV_FILE"

# shellcheck disable=SC2086  # HERMES_CMD is a command line
hermes_cli() { HERMES_HOME=$HERMES_HOME_DIR $HERMES_CMD "$@"; }
cp -p "$HERMES_HOME_DIR/config.yaml" "$HERMES_HOME_DIR/config.yaml.before-textxbridge" 2>/dev/null || true
hermes_cli plugins enable textx-platform >/dev/null && say "enabled   textx-platform"
if [ "$MCP" = 1 ]; then
  hermes_cli config set mcp_servers.textx.url "$BRIDGE_URL/mcp" >/dev/null
  hermes_cli config set mcp_servers.textx.headers.Authorization 'Bearer ${TEXTXBRIDGE_KEY}' >/dev/null
  # A send waits up to 5 minutes for the user's tap on the phone; Hermes's
  # default MCP call timeout is 300 s.
  hermes_cli config set mcp_servers.textx.timeout 330 >/dev/null
  hermes_cli config set mcp_servers.textx.enabled true >/dev/null
  say "mcp       mcp_servers.textx → $BRIDGE_URL/mcp (bridge key, timeout 330 s)"
fi
# Each message is a notification on the phone: no mid-turn narration, no
# "⏳ Working" notices. The typing dots show a turn is running.
for key in interim_assistant_messages long_running_notifications; do
  if ! hermes_cli config get "display.platforms.textx.$key" >/dev/null 2>&1; then
    hermes_cli config set "display.platforms.textx.$key" false >/dev/null \
      && say "display   display.platforms.textx.$key: false"
  fi
done

if [ "$RESTART" = 1 ]; then
  # A gateway run by its systemd user unit restarts through the unit, so its
  # drop-ins (restart notices) run.
  if systemctl --user cat hermes-gateway >/dev/null 2>&1; then
    systemctl --user restart hermes-gateway && say "restarted hermes-gateway (systemd user unit)"
  else
    hermes_cli gateway restart >/dev/null 2>&1 && say "restarted the Hermes gateway" \
      || say "restart the Hermes gateway yourself: hermes gateway restart"
  fi
fi

cat <<DONE

Done. Pair a phone:  $TB --config $CONFIG pair "<phone name>"
(or: hermes textx pair "<phone name>"), then in TextX: Settings › Assistants › Add, scan it.
DONE
