"""Spoken replies (TextX 0.3.21 §5 reply_mode): the model writes text, and
this turns it into a short AAC clip with Hermes's own TTS (tts.provider in
config.yaml), so the voice is whatever the operator set for Hermes."""

import base64
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

MAX_SECONDS = 45  # TextX fits one MMS; longer is cut
# Speech is made inside Hermes's pre_tool_call hook, which Hermes cuts off at 30 s and
# then fails closed: the send is blocked and so is every tool for the next 60 s. On
# 2026-10-23 one Kokoro call took 35 s and a reply was lost. So TTS gets this long, and
# past it the words go as text (or the phone speaks them on a call). BUDGET covers the
# encoding too and keeps the whole hook under Hermes's 30 s.
TTS_DEADLINE = 18
BUDGET = 25


def _left(start: float) -> float:
    """Seconds of BUDGET left for an ffmpeg run; raises TimeoutError when spent."""
    left = BUDGET - (time.monotonic() - start)
    if left < 1:
        raise TimeoutError(f"over the {BUDGET} s voice budget")
    return left


def _tts(text: str, tag: str) -> Optional[str]:
    """Hermes's TTS for `text`: the audio file's path, or None if it failed or took
    longer than TTS_DEADLINE (the late file is removed when it lands)."""
    from tools.tts_tool import text_to_speech_tool
    box: dict = {}
    late = threading.Event()

    def run() -> None:
        try:
            box["r"] = json.loads(text_to_speech_tool(text))
        except Exception as e:
            box["e"] = e
        if late.is_set() and (box.get("r") or {}).get("file_path"):
            try:
                os.remove(box["r"]["file_path"])
            except OSError:
                pass

    t = threading.Thread(target=run, name="textx-tts", daemon=True)
    t.start()
    t.join(TTS_DEADLINE)
    if t.is_alive():
        late.set()
        logger.warning("[%s] TTS took over %d s: %s", tag, TTS_DEADLINE,
                       "sending text" if tag == "textx" else "the phone speaks it")
        return None
    if "e" in box:
        raise box["e"]
    r = box["r"]
    if not r.get("success"):
        logger.warning("[%s] TTS failed: %s", tag, r.get("error"))
        return None
    return r["file_path"]


def speak(text: str, max_bytes: Optional[int] = None) -> Optional[str]:
    """`text` spoken as m4a (AAC-LC, mono, 48 kbps; 32 or 16 kbps if that is
    over the phone's MMS cap), base64; None if it failed or cannot fit."""
    start = time.monotonic()
    src = None
    try:
        src = _tts(text, "textx")
        if not src:
            return None
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "reply.m4a")
            # 32 kbps sounded robotic to the operator; 45 s at 48 kbps is ~270 KB.
            for rate in ("48k", "32k", "16k"):
                subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", src, "-t", str(MAX_SECONDS), "-ac", "1",
                                "-c:a", "aac", "-b:a", rate, "-movflags", "+faststart", out],
                               check=True, timeout=_left(start), capture_output=True)
                with open(out, "rb") as f:
                    data = f.read()
                if not max_bytes or len(data) <= max_bytes:
                    return base64.b64encode(data).decode()
            logger.warning("[textx] voice reply is %d bytes, over the phone's %d: sending text", len(data), max_bytes)
            return None
    except Exception as e:
        logger.warning("[textx] voice reply failed, sending text: %s", e)
        return None
    finally:
        if src:
            try:
                os.remove(src)
            except OSError:
                pass


def voice_args(mode: str, text: str, max_bytes: Optional[int] = None) -> Optional[dict]:
    """The send_sms args for a reply in `mode` (voice or both), or None to send as text."""
    audio = speak(text, max_bytes) if text.strip() else None
    if not audio:
        return None
    att = [{"name": "reply.m4a", "mime": "audio/mp4", "data_b64": audio}]
    return {"text": "" if mode == "voice" else text, "attachments": att}


# DialX calls (DESIGN X19): Orbit's own voice on the line. "own" speaks each
# reply with Hermes's TTS and sends the clip; "phone" leaves the words to the
# phone's own TTS, which answers 2-6 s sooner.
CALL_AUDIO_MAX = 196_608  # raw bytes: DialX takes 256 KB inline, whichever way it counts


def call_voice() -> str:
    v = (os.environ.get("TEXTX_CALL_VOICE") or "own").strip().lower()
    return v if v in ("own", "phone") else "own"


def speak_call(text: str) -> Optional[str]:
    """`text` in Hermes's voice as mono mp3, base64, for dialx.say or the
    opening; None (the phone speaks the text) if it failed or is too big."""
    if not text.strip() or call_voice() != "own":
        return None
    start = time.monotonic()
    src = None
    try:
        src = _tts(text, "dialx")
        if not src:
            return None
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "say.mp3")
            for rate in ("64k", "32k"):
                subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", src, "-t", str(MAX_SECONDS), "-ac", "1",
                                "-c:a", "libmp3lame", "-b:a", rate, out],
                               check=True, timeout=_left(start), capture_output=True)
                with open(out, "rb") as f:
                    data = f.read()
                if len(data) <= CALL_AUDIO_MAX:
                    return base64.b64encode(data).decode()
            logger.warning("[dialx] spoken line is %d bytes, over %d: the phone speaks it", len(data), CALL_AUDIO_MAX)
            return None
    except Exception as e:
        logger.warning("[dialx] voice failed, the phone speaks it: %s", e)
        return None
    finally:
        if src:
            try:
                os.remove(src)
            except OSError:
                pass


# The theremin voices the operator approved (2026-10-25, three clips Orbit made with
# ffmpeg); DialX's own chain sounded nothing like them on a real call. So Orbit applies
# them to its own audio and sends it to DialX plain. The numbers are those clips'.
THEREMINS = ("Theremin", "ThereminVoice", "ThereminMix")
_TONE = "aevalsrc=0.3*sin(2*PI*(180+140*sin(2*PI*0.6*t))*t):s=44100:d={d}"
_TONE_SHAPE = "vibrato=f=5:d=0.6,tremolo=f=3:d=0.4"
_VOICE_SHAPE = "vibrato=f=6:d=1.0,tremolo=f=5:d=0.5"


def theremin(audio_b64: Optional[str], effect: str) -> Optional[str]:
    """Orbit's mp3 line (base64) through one of the approved theremins, as mono mp3
    base64 for DialX; the input unchanged if ffmpeg fails. Theremin is the tone alone
    for as long as the line; ThereminMix is the bent voice with the tone under it."""
    if not audio_b64 or effect not in THEREMINS:
        return audio_b64
    try:
        with tempfile.TemporaryDirectory() as d:
            src, out = os.path.join(d, "in.mp3"), os.path.join(d, "out.mp3")
            with open(src, "wb") as f:
                f.write(base64.b64decode(audio_b64))
            secs = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", src],
                                        capture_output=True, text=True, timeout=10).stdout.strip() or "5")
            tone = f"{_TONE.format(d=max(1.0, secs)):s},{_TONE_SHAPE}"
            if effect == "Theremin":
                cmd = ["ffmpeg", "-v", "error", "-f", "lavfi", "-t", f"{max(1.0, secs):.2f}", "-i", _TONE.format(d=max(1.0, secs)),
                       "-af", f"{_TONE_SHAPE},afade=t=out:st={max(0.0, secs - 0.5):.2f}:d=0.5", "-ac", "1", "-b:a", "64k", "-y", out]
            elif effect == "ThereminVoice":
                cmd = ["ffmpeg", "-v", "error", "-i", src, "-af", _VOICE_SHAPE, "-ac", "1", "-b:a", "64k", "-y", out]
            else:
                cmd = ["ffmpeg", "-v", "error", "-i", src, "-f", "lavfi", "-t", f"{max(1.0, secs):.2f}", "-i", tone,
                       "-filter_complex", f"[0:a]{_VOICE_SHAPE}[v];[1:a]volume=0.22[t];[v][t]amix=inputs=2:duration=first",
                       "-ac", "1", "-b:a", "64k", "-y", out]
            subprocess.run(cmd, capture_output=True, timeout=20, check=True)
            with open(out, "rb") as f:
                return base64.b64encode(f.read()).decode()
    except Exception as e:
        logger.warning("[dialx] %s effect not applied: %s", effect, e)
        return audio_b64
