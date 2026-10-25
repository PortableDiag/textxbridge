"""`/textx pair` in any chat with the agent: a pairing link without a terminal.

The operator types `/textx pair` where they already talk to Hermes (Telegram,
Trellis, the CLI, or TextX itself) and gets back the `textx-agent:` link to
paste into TextX. A slash command, not a tool: the model never runs it, so no
text from anyone else can make the agent mint a pairing, and the link goes
straight back to the operator without passing through the model.

Only the operator may run it (checked here, fail closed): Telegram (Hermes's
allowlist admits only the operator's chat), the local CLI, and on TextX or
Trellis a message that plugin judged the operator's own.
"""

from __future__ import annotations

import importlib
import json
import logging
import urllib.parse
import urllib.request

from . import origins

logger = logging.getLogger(__name__)

HELP = ("/textx pair [phone name] — a link to add me in TextX on your phone\n"
        "/textx phones — the phones paired with me\n"
        "/textx revoke <phone name> — unpair one (lost phone, new phone)")


def _session(name: str) -> str:
    try:
        from gateway.session_context import get_session_env
        return get_session_env(name, "") or ""
    except Exception:
        return ""


def operator_here() -> bool:
    platform = _session("HERMES_SESSION_PLATFORM").lower()
    if platform in ("", "cli", "local", "telegram"):
        return True
    if platform == "textx":
        return origins.origin() == "operator"
    if platform == "trellis":
        try:
            guard = importlib.import_module("hermes_plugins.trellis_platform.guard")
            return guard.origin()[0] == "operator"
        except Exception:
            return False
    return False


def _call(method: str, path: str, body: dict | None = None) -> dict:
    from .adapter import _get_scoped_secret, DEFAULT_URL
    base = (_get_scoped_secret("TEXTXBRIDGE_URL", DEFAULT_URL) or DEFAULT_URL).rstrip("/")
    key = _get_scoped_secret("TEXTXBRIDGE_KEY", "")
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-API-Key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return {"error": json.loads(e.read()).get("error") or str(e)}
        except Exception:
            return {"error": str(e)}
    except OSError as e:
        return {"error": f"the TextX bridge is not answering ({e})"}


def _free_label(wanted: str) -> str:
    taken = {p.get("label") for p in _call("GET", "/api/pairings").get("pairings", [])}
    if wanted not in taken:
        return wanted
    n = 2
    while f"{wanted} {n}" in taken:
        n += 1
    return f"{wanted} {n}"


def handle(raw_args: str) -> str:
    if not operator_here():
        logger.warning("[textx] /textx refused: not the operator's own message")
        return "Only my owner can manage TextX pairings."
    parts = (raw_args or "").strip().split(maxsplit=1)
    sub = parts[0].lower() if parts else "pair"
    rest = parts[1].strip() if len(parts) > 1 else ""
    if sub == "pair":
        label = _free_label(rest or "Phone")
        v = _call("POST", "/api/pairings", {"label": label})
        if v.get("error"):
            return f"Could not make a pairing: {v['error']}"
        if not v.get("pairing"):
            _call("DELETE", f"/api/pairings/{urllib.parse.quote(label)}")
            return "The TextX bridge has no address for phones yet (its relay is not connected). Try again in a minute."
        return (f"Here is your TextX link for “{label}”. Tap it to copy, then in TextX open "
                f"Settings › Assistants › Add and tap the copied link.\n\n`{v['pairing']}`\n\n"
                "Only the first phone that uses it can: after that it is useless to anyone else. "
                f"Lost the phone? /textx revoke {label}")
    if sub in ("phones", "pairs", "list"):
        ps = _call("GET", "/api/pairings").get("pairings", [])
        if not ps:
            return "No phones paired. /textx pair adds one."
        return "\n".join(f"• {p['label']}: {'connected' if p.get('online') else 'not connected'}, "
                         f"last seen {p.get('last_seen') or 'never'}" for p in ps)
    if sub == "revoke":
        if not rest:
            return "Which phone? /textx revoke <phone name>"
        v = _call("DELETE", f"/api/pairings/{urllib.parse.quote(rest)}")
        return f"Unpaired “{rest}”." if not v.get("error") else f"Could not unpair: {v['error']}"
    return HELP


def register(ctx) -> None:
    if not hasattr(ctx, "register_command"):
        return
    try:
        ctx.register_command(name="textx", handler=handle, args_hint="pair [phone name]",
                             description="Pair a phone with TextX (/textx pair), list or revoke")
    except Exception as e:
        logger.warning("[textx] /textx not registered: %s", e)
