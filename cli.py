"""`hermes textx …`: connect this Hermes to TextX.

`hermes plugins install … --enable` puts this plugin in place; `hermes textx
setup` gets the bridge running and points Hermes at it; `hermes textx pair
<phone>` prints the string (and a QR) to add the assistant in TextX.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def register_cli(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="textx_cmd")
    s = sub.add_parser("setup", help="install and start the bridge, and point Hermes at it")
    s.add_argument("--bin", help="a textxbridge binary to use (else built from the bundled source)")
    s.add_argument("--name", help="what TextX shows for this assistant (default: Hermes)")
    s.add_argument("--base-url", help="the public https address phones dial, proxied to --listen")
    s.add_argument("--listen", help="the bridge's phone listener, as host:port (default 127.0.0.1:8794)")
    s.add_argument("--relay", help="optional: a TextX relay to dial out to instead of --base-url")
    s.add_argument("--no-restart", action="store_true", help="do not restart the Hermes gateway")
    p = sub.add_parser("pair", help="pair a phone: prints the textx-agent: string and a QR")
    p.add_argument("label", nargs="+", help="a name for the phone, e.g. 'Pixel'")
    p.add_argument("--dialx", action="store_true", help="pair DialX (agent calls) instead of TextX")
    p.add_argument("--notifx", action="store_true", help="pair NotifX (notifications) instead of TextX")
    sub.add_parser("pairs", help="list paired phones")
    r = sub.add_parser("revoke", help="unpair a phone")
    r.add_argument("which", help="its label or kid")
    sub.add_parser("status", help="the bridge's health")


def dispatch(args: argparse.Namespace) -> int:
    return {"setup": _setup, "pair": _pair, "pairs": _pairs, "revoke": _revoke,
            "status": _status}.get(getattr(args, "textx_cmd", None) or "status", _status)(args)


def _env(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    env = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes") / ".env"
    for line in env.read_text().splitlines() if env.exists() else []:
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip().strip("\"'")
    return ""


def _call(method: str, path: str, body: dict | None = None) -> dict:
    url = (_env("TEXTXBRIDGE_URL") or "http://127.0.0.1:8793").rstrip("/")
    key = _env("TEXTXBRIDGE_KEY")
    if not key:
        raise SystemExit("textx: not set up yet. Run: hermes textx setup")
    req = urllib.request.Request(url + path, method=method, headers={"X-API-Key": key, "Content-Type": "application/json"},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except Exception:  # noqa: BLE001
            msg = None
        raise SystemExit(f"textx: {msg or e}")
    except OSError as e:
        raise SystemExit(f"textx: the bridge at {url} is not answering ({e}). "
                         "Check: systemctl --user status 'textxbridge@*'")


def _setup(args: argparse.Namespace) -> int:
    installer = next((p for p in (HERE / "install.sh", HERE.parent.parent / "bundle" / "install.sh") if p.exists()), None)
    if not installer:
        print("textx: install.sh is missing from this plugin", file=sys.stderr)
        return 1
    cmd = ["bash", str(installer), "--no-plugin",
           "--hermes-home", os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes")]
    for flag in ("bin", "name", "relay", "listen", "base_url"):
        value = getattr(args, flag, None)
        if value:
            cmd += [f"--{flag.replace('_', '-')}", value]
    if args.no_restart:
        cmd.append("--no-restart")
    return subprocess.run(cmd).returncode


def _qr(text: str) -> str:
    try:
        import qrcode  # type: ignore
        q = qrcode.QRCode(border=2)
        q.add_data(text)
        q.make(fit=True)
        from io import StringIO
        out = StringIO()
        q.print_ascii(out=out, invert=True)
        return out.getvalue()
    except ImportError:
        pass
    if shutil.which("qrencode"):
        return subprocess.run(["qrencode", "-t", "ansiutf8", text], capture_output=True, text=True).stdout
    return "(no QR renderer here: run `textxbridge pair` on the bridge host for one, or paste the string)\n"


def _pair(args: argparse.Namespace) -> int:
    label = " ".join(args.label)
    dialx = getattr(args, "dialx", False)
    notifx = getattr(args, "notifx", False)
    if dialx and notifx:
        print("textx: pair one app at a time (--dialx or --notifx)")
        return 1
    v = _call("POST", "/api/pairings", {"label": label, "app": "DialX" if dialx else "NotifX" if notifx else None})
    s = v.get("pairing")
    if not s:
        print(f"textx: paired {label!r}, but the bridge has no base URL yet (relay not ready, no base_url). "
              f"Revoke it (hermes textx revoke {label!r}) and pair again once `hermes textx status` shows the relay ready.")
        return 1
    if notifx:
        # NotifX has no scanner: the owner pastes the string, or shares it from a QR reader.
        print(f"Paired {label!r}. In NotifX: Agents, paste the string (or scan the QR with any reader and share it to NotifX):\n")
    else:
        where = "DialX: Settings › Agents › Pair an agent" if dialx else "TextX: Settings › Assistants › Add"
        print(f"Paired {label!r}. In {where}, then scan:\n")
    print(_qr(s))
    print(s)
    print("\nThe key is shown only now. Anyone with this string can talk to the agent as you.")
    # A DialX or NotifX pairing is never where cron results go.
    if not dialx and not notifx and not _env("TEXTX_HOME_CHANNEL"):
        _set_env("TEXTX_HOME_CHANNEL", label)
        print(f"\nHome: {label!r} gets cron results and notifications (TEXTX_HOME_CHANNEL); "
              "restart the gateway to apply it: hermes gateway restart")
    return 0


def _set_env(name: str, value: str) -> None:
    env = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes") / ".env"
    lines = [l for l in (env.read_text().splitlines() if env.exists() else []) if not l.startswith(f"{name}=")]
    lines.append(f"{name}={value}")
    tmp = env.with_suffix(".textx-tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(env)


def _pairs(args) -> int:
    for p in _call("GET", "/api/pairings").get("pairings", []):
        print(f"{p['label']:<16} kid {p['kid']}  {'bound' if p['bound'] else 'not yet used'}  "
              f"{'online' if p['online'] else 'offline'}  last seen {p.get('last_seen') or 'never'}  "
              f"tools on the phone: {', '.join(p.get('phone_tools') or []) or 'none yet'}")
    return 0


def _revoke(args) -> int:
    v = _call("DELETE", f"/api/pairings/{urllib.request.quote(args.which)}")
    print(f"revoked {v.get('revoked')}")
    return 0


def _status(args) -> int:
    url = (_env("TEXTXBRIDGE_URL") or "http://127.0.0.1:8793").rstrip("/")
    try:
        body = urllib.request.urlopen(f"{url}/api/health", timeout=10).read().decode()
    except Exception as e:  # noqa: BLE001
        print(f"textx: the bridge at {url} is not answering ({e}). Run: hermes textx setup")
        return 1
    print(f"bridge at {url}: {body}")
    return 0
