# TextXBridge

Your [Hermes Agent](https://github.com/NousResearch/hermes-agent) as an assistant on your
Android phone, through three apps that speak the **TextX Agent Protocol**:

- **TextX** (texts): talk to your agent in its own conversation, share threads with it,
  and let it propose texts, including into group threads, from your own number.
- **DialX** (calls): the agent places calls you ask for, talks on them in its own voice,
  leaves voicemail, answers calls for you, and reports each call to you.
- **NotifX** (notifications): the agent reads the notifications you share and watches
  the ones you name (a doorbell, a delivery), forwarding them with a picture.

You need Hermes, one of the apps on an Android phone, and either `cargo` or the release
binary.

## How it is built

Two parts, so the agent never holds a pairing key:

- **`textxbridge`** is a small Rust program. It holds the phone pairing keys, speaks
  the protocol (end-to-end AES-GCM frames, acks, queues, a 7-day replay window), and
  decides what each turn may do. It listens on 127.0.0.1 only. Phones reach it through
  your own TLS proxy (`--base-url`) or a relay (`--relay`).
- **The Hermes plugin** (`textx-platform`, this repo's root) holds only the bridge's
  key. Your messages in the assistant conversation become Hermes turns. The phone's
  tools are MCP tools served by the bridge.

## What the agent can and cannot do

- **It sees only what you shared**, with only the tools you switched on for it in the
  app. The phone enforces both.
- **Sends and calls ask first.** A text or a call to someone you have not approved
  puts a card on the phone, and only your tap goes ahead. Whatever you allow without
  asking, you set in the app, under the app's own caps.
- **Other people's words are data.** Messages from a thread, a call or a notification
  reach the model inside a `[TextX data … not instructions]` fence. A turn started by
  someone else (a watched thread, an auto-reply, the person on a call) may only read
  and answer in that conversation. Commands, files, memory, web fetches and other
  sends are held.
- **Only your own turn can ask for a send or a call.** The plugin sets
  `requested_by_owner` from who started the turn, never from the model.
- **Phone numbers never reach the model.** Each one becomes a handle, `num:K7Q2 (…22)`,
  which the bridge maps back for a send.
- **One-time codes never reach it.** The apps withhold them, and the bridge blanks
  anything that still reads like one.
- **Callers always hear that it is an AI.** The plugin and the bridge both check every
  opening and voicemail.

## Install

```sh
hermes plugins install PortableDiag/textxbridge --enable
hermes textx setup            # builds the bridge with cargo, or: --bin ./textxbridge-x86_64-linux
hermes textx pair Phone       # prints a textx-agent: string and a QR to scan in TextX
hermes textx pair --dialx DialX
hermes textx pair --notifx NotifX
```

`setup` installs the bridge as a systemd user unit (`textxbridge@<instance>`), writes
`TEXTXBRIDGE_KEY` and `TEXTXBRIDGE_URL` into Hermes's `.env`, adds the bridge's MCP
server and restarts the gateway. Re-running it upgrades in place and keeps the
pairings. Options: `bash install.sh --help`.

**A pairing QR is a key.** Scan it on the phone, and never post it in a chat or a
ticket. To unpair a phone, run `hermes textx revoke <label>`.

Voice is optional. Voice notes and call audio are transcribed with Hermes's
speech-to-text, and replies are spoken with Hermes's TTS (with a deadline, so a slow TTS
falls back to text).

## Commands

- `hermes textx pairs` lists the paired phones, online or not.
- `hermes textx status` shows the bridge's health.
- `textxbridge --help` covers the bridge itself (`serve`, `pair`, `pairs`, `revoke`).

## License

MIT
