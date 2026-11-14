# yMux remote protocol, version 1

Three parties:

- **desktop**: a running yMux. Opens an outbound WebSocket to the server. The only party that decides whether a command runs.
- **device**: the PWA served by the server, on a phone or browser.
- **server**: this project. Authenticates connections, relays frames, sends Web Push. It never runs a command, cannot read what it relays, and stores no pane content.

Everything is JSON text frames over WebSocket (`wss`). Unknown fields are ignored; unknown `t` / `op` values are answered with an error and never crash a party. Maximum frame: 256 KiB.

## 1. Encodings

- `b64u`: base64url without padding.
- Keys: ECDSA P-256. Public key = raw uncompressed SEC1 point (65 bytes) as `b64u` (WebCrypto `exportKey("raw")`).
- Signature: ECDSA P-256 with SHA-256, IEEE P1363 form (`r || s`, 64 bytes) as `b64u` (what WebCrypto `sign` returns). Verifiers accept both low-S and high-S.
- Ids (`desktop_id`, `device_id`, pane ids): lowercase UUID strings.
- Signed and MACed strings are UTF-8 bytes of exactly the string given below, no trailing newline.
- `origin`: the server's public URL reduced to `scheme://host[:port]`, lowercase, default ports omitted (what a browser's `location.origin` gives).
- **Key agreement keys**: ECDH P-256, public keys as raw uncompressed SEC1 points in `b64u`. `dk` is the desktop's, made fresh for every pairing window and carried in the QR; `ek` is the device's, made for one pairing and sent in `pair_request`. Private halves never leave their owner (the device's is non-extractable).
- **Link key** (one per paired device, known to the desktop and that device only): `K = HKDF-SHA256(ikm = ECDH(ek, dk) shared secret (the 32-byte x coordinate), salt = code, info = "ymux-remote-v1|link|<desktop_id>|<device_id>|<pubkey>|<ek>|<dk>")`, 32 bytes, used as an AES-256-GCM key. `code` is the 16 raw pairing-code bytes (section 4). Knowing the code and everything the server sees is not enough to compute `K`.
- **Sealed body**: `b64u(nonce || ciphertext || tag)` with a fresh random 12-byte nonce, AES-256-GCM under `K`, plaintext = a JSON document, additional data = `ymux-remote-v1|p2d|<desktop_id>|<device_id>` for device → desktop and `ymux-remote-v1|d2p|<desktop_id>|<device_id>` for desktop → device. A body that does not open is dropped.
- **Check number**: 6 random decimal digits chosen by the desktop for one pairing request (uniform, from the OS random source), sent to the device only inside a sealed body. It is not derived from anything an attacker can choose.

## 2. Endpoints

| Path | Who | Notes |
|---|---|---|
| `GET /` and static files | browser | the PWA |
| `GET /healthz` | anyone | `200 ok` |
| `GET /api/info` | anyone | `{"v":1,"server":"<semver>","vapid":"<b64u public key>"}` |
| `GET /ws/desktop` | desktop | must NOT carry an `Origin` header |
| `GET /ws/device` | device | `Origin` must equal the server's public URL origin |
| `GET /ws/pair` | unpaired device | same `Origin` rule |

## 3. Connection handshake

On every WebSocket the server speaks first:

```json
{"t":"challenge","nonce":"<b64u, 32 random bytes>","v":1,"server":"0.1.0","origin":"https://ymux.example.com"}
```

The client answers within 10 s or is closed.

### 3.1 Desktop

```json
{"t":"hello","role":"desktop","v":1,"desktop_id":"…","pubkey":"…","name":"My PC",
 "setup_token":"…","sig":"…"}
```

- The desktop first compares the challenge's `origin` with the origin of the address the user configured. If they differ it closes without signing and reports `origin_mismatch` to the user (the server's `YMUX_SERVER_PUBLIC_URL` and the address typed into yMux must name the same origin).
- `sig` signs `ymux-remote-v1|desktop|<desktop_id>|<origin>|<nonce>`, with the desktop's configured origin. The server verifies with its own origin, so a challenge passed through from another server does not verify.
- `setup_token` is sent only until the server has accepted this desktop once; after that it is omitted. The desktop forgets the stored token when the server address changes.
- Unknown `desktop_id`: `setup_token` must equal the server's setup token (constant-time compare); the server then stores `desktop_id → pubkey`. Known `desktop_id`: the stored pubkey must equal `pubkey` and `setup_token` is ignored.
- Reply: `{"t":"ready","devices":["<device_id>",…]}` (device ids the server has for this desktop) or `{"t":"error","code":"…"}` then close. Codes: `bad_token`, `bad_sig`, `key_mismatch`, `version`, `limit`.
- One live connection per desktop: a new authenticated connection replaces the old one.
- A device id in `ready.devices` that the desktop does not know gets a `device_remove` from the desktop. A device the desktop's config still holds but cannot use during this run (its link key could not be read from the secret store) is not unknown: it gets no `device_remove`.

### 3.2 Device

```json
{"t":"hello","role":"device","v":1,"device_id":"…","sig":"…"}
```

- `sig` signs `ymux-remote-v1|device|<device_id>|<nonce>` with the device key the server stored at pairing.
- Reply: `{"t":"ready","desktop_id":"…","desktop_online":true}` or `{"t":"error","code":"unknown_device"|"bad_sig"|"version"}` then close.
- One live connection per device: a new authenticated connection replaces the old one.
- The server then tells the desktop `{"t":"device_online","device_id":"…","conn":"<b64u 8 random bytes>"}` (and `device_offline` with the same fields when it leaves). When a desktop connects, it gets one `device_online` per already-connected device. The device gets `{"t":"desktop_online"}` / `{"t":"desktop_offline"}`. These four are hints for display only; no authorisation depends on them.

## 4. Pairing

The pairing code never reaches the server, and the link key cannot be computed from the code.

1. Desktop creates `code` = 16 random bytes and a fresh ECDH key pair (`dk`), and sends `{"t":"pair_open","ttl_s":120}`. The server opens a pairing window for that desktop (max 120 s, at most 5 requests in a window). `{"t":"pair_close"}` ends it early.
2. Desktop shows a QR for `<public_url>/#pair=<desktop_id>.<b64u code>.<dk>`. The fragment is never sent in an HTTP request. The link is shown as a QR only, not as text.
3. The PWA generates its signing key pair, its `ek` key pair (both private halves non-extractable) and a `device_id`, derives the link key (section 1), connects `/ws/pair`, receives the challenge, and sends:

```json
{"t":"pair_request","v":1,"desktop_id":"…","device_id":"…","pubkey":"…","ek":"…","name":"iPhone",
 "proof":"<b64u HMAC-SHA256(key = code, msg = \"ymux-remote-v1|pair|<desktop_id>|<device_id>|<pubkey>|<ek>\")>",
 "sig":"<signs ymux-remote-v1|pair|<device_id>|<nonce>>"}
```

4. The server checks the window, the request budget and `sig` (against the `pubkey` in the request), then forwards to the desktop: `{"t":"pair_request","device_id":"…","pubkey":"…","ek":"…","name":"…","proof":"…"}`. No window: `{"t":"error","code":"no_pairing"}`. The `name` is chosen by whoever sends the request, so the server cleans it before it is forwarded or stored (the **device name rule**): every Unicode digit and all punctuation and symbols are removed except `.` `-` `_` `'` (letters, combining marks and spaces stay), whitespace is collapsed, at most 40 characters are kept, and a name with nothing left becomes `Unnamed device`. The desktop applies the same rule again, and so does the PWA when it proposes a default name. A device name therefore can never carry a number or a quote or dash that could frame a fake instruction.
5. The desktop verifies `proof` with its `code` (constant time). On mismatch it answers `pair_result` with `ok:false` and shows nothing. On match it derives the link key, picks a check number and sends `{"t":"pair_challenge","device_id":"…","body":"<sealed {\"k\":\"pair_check\",\"check\":\"123456\"}>"}` (desktop to device sealing); the server forwards `{"t":"pair_challenge","body":"…"}` to that pairing socket. Only the device that holds the matching `ek` private key can open it. The PWA shows the 6 digits.
6. The desktop shows the user the device name, in a labelled field of its own ("chosen by the device, not verified") and never inside a sentence, and asks them to TYPE the number shown on the yMux pairing page on their phone, and to pick a capability. The instruction says: never a number from this window, a notification or a message; if the phone is not showing a number, press Reject. The number is never displayed on the desktop. Three wrong entries, a rejection or the window ending refuse the request. If a SECOND request with a valid proof arrives for the same code from a different device id or key, the desktop refuses both, closes the window and tells the user that two devices used the code. On a correct number the desktop stores the device's public key and link key and answers:

```json
{"t":"pair_result","device_id":"…","ok":true,"pubkey":"…","name":"…"}
```

7. On `ok:true` the server stores the device under that desktop (max 16 devices per desktop; the stored key is the one from the original `pair_request`, and a missing or different `pubkey` in the result turns it into `ok:false`), closes the window, and tells the PWA `{"t":"pair_result","ok":true}`. On `ok:false` the PWA gets `{"t":"pair_result","ok":false}`. The PWA then connects `/ws/device`. It treats the pairing as provisional and keeps any earlier pairing with that desktop until it has received a valid sealed `session` (section 5.1) under the new link key; a `pair_result` alone proves nothing.

Removing a device: desktop sends `{"t":"device_remove","device_id":"…"}`; the server deletes it, drops its push subscription and closes its connection. The desktop deletes the device's public key and link key.

## 5. Relay

Once both are `ready`:

- Device → server: `{"t":"cmd","body":"<sealed body>","sig":"…"}`. Server forwards to the device's desktop as `{"t":"cmd","device_id":"…","conn":"…","body":"…","sig":"…"}`. If the desktop is offline: `{"t":"error","code":"desktop_offline"}`.
- Desktop → server: `{"t":"msg","to":"<device_id>","body":"<sealed body>"}`. Server forwards `{"t":"msg","body":"…"}` to that device.

`body` is always a sealed body (section 1): the server cannot read or forge it. `sig` signs `ymux-remote-v1|cmd|` followed by the body string exactly as sent. The desktop verifies `sig` against the public key IT stored for the server-supplied `device_id`, then opens the body with that device's link key. A frame for an unknown device, with a bad signature, or that does not open is dropped and logged (rate-limited); when the device is known the desktop also answers `{"k":"reply","re":0,"ok":false,"code":"bad_sig","ref":"<b64u of the first 16 bytes of SHA-256(sig string)>"}` (sealed; at most 20 such replies per device per minute).

### 5.1 Sessions, freshness and replay

The device opens a session after `ready`, after `desktop_online`, and whenever it is told to (`reopen`, or a `bad_session` reply). Plaintext:

```json
{"k":"open","desktop_id":"…","device_id":"…","nonce":"<b64u 16 random bytes>"}
```

The desktop answers (sealed):

```json
{"k":"session","open":"<that nonce>","session":"<b64u 16 random bytes>","cap":"view"|"respond"|"prompt","name":"My PC","now_ms":<desktop clock, epoch ms>,"prev":{"session":"<the session this one revoked, or empty>","seq":<last seq accepted in it, or 0>},"v":1}
```

- Issuing a session revokes every other session of that device. A device has at most one valid session.
- The device accepts a `session` only if `open` equals the nonce of its most recent `open` AND it arrives within 10 s of sending that `open` (otherwise it sends a new `open`). It records `now_ms - <its own clock>` as the clock offset, so the offset is wrong by at most those 10 s.
- `prev` tells the device what happened to commands whose outcome it does not know: a command sent in `prev.session` with `seq` at most `prev.seq` was accepted by the desktop; one with a higher `seq` was not and, because that session is now revoked, never will be. This is exact because the desktop accepts a command only when its `seq` is the last accepted one plus one (the first of a session is 1, see below): every `seq` up to `prev.seq` was accepted, with no gap.
- Every later desktop → device plaintext carries `"session":"…"`, `"n":<int>` and `"at_ms":<desktop clock>`. `n` starts at 1 and strictly increases within the session. The device drops a body whose session is not current, whose `n` is not greater than the last accepted one, or whose `at_ms` is more than 30 000 ms behind its estimate of the desktop clock.
- A failure reply with `"re":0` may carry `"session":""` and no `n`. The device acts on it only when its `ref` (section 5) matches the signature of a command it has in flight, and then only by treating that command's outcome as unknown.
- **Unknown outcomes.** When a command gets no trustworthy reply (timeout, a matching `re:0`, the socket dropping, a plaintext server frame such as `desktop_offline`), the device does not report failure. It sends a new `open`; from the answering `session.prev` it learns whether the command was accepted, and reports "not delivered" or "delivered, result unknown" accordingly. Until then the outcome is shown as unconfirmed. A `replay` reply for a write means the command was accepted earlier (a relay forwarded the frame twice): the device treats it as delivered, result unknown, never re-sends it, and still lets the genuine reply for that `seq` replace that outcome; for a read it ignores the `replay` and keeps waiting.
- When a device's capability changes, or the desktop wants a fresh session, it sends `{"k":"reopen", …}` in the current session and revokes it; the device sends a new `open`.

A command plaintext is:

```json
{"k":"cmd","desktop_id":"…","device_id":"…","session":"…","seq":1,"ts_ms":<desktop-clock estimate, epoch ms>,"cmd":{"op":"…",…}}
```

`ts_ms` is the device's clock plus the recorded offset. The desktop runs a command only if ALL hold:

1. the frame passed the signature and opening described in section 5;
2. `desktop_id` is this desktop and `device_id` equals the server-supplied one;
3. `session` is that device's current session, and `seq` is exactly the last accepted `seq` of that session plus one (the first command of a session has `seq` 1);
4. `ts_ms` is within 30 000 ms of the desktop's clock;
5. the device's capability allows `op`;
6. the plaintext is at most 64 KiB and well-formed.

A failed check is answered `{"k":"reply","re":<seq or 0>,"ok":false,"code":"…"}` (`bad_session`, `replay`, `expired`, `forbidden`, `bad_request`) and logged. Nothing else happens. `seq` is consumed as soon as checks 1–3 pass. A `re:0` reply is matched to a command only through its `ref` (above), and then only makes that command's outcome unknown.

**Consecutive seqs.** A `seq` at most the last accepted one is `replay`. A `seq` greater than the last accepted one plus one means the relay dropped or reordered a command: the desktop revokes that device's session, answers `bad_session` (with `re` 0 and the `ref` of the frame), does not consume the number, and writes one aggregated audit line. The phone then opens a new session and learns from `prev` exactly which commands ran. A phone therefore numbers its commands 1, 2, 3, … with no number skipped (a number taken for a frame that never left is given back), sends them strictly in that order, and treats a plaintext `rate_limited` or `busy` frame from the server, which means a frame was dropped, like any other unknown outcome: it opens a new session, asks reads again in it, and settles writes only from `prev`.

### 5.2 Capabilities

`view` < `respond` < `prompt`. Each includes the ones before it.

| op | needs | request fields | reply `data` |
|---|---|---|---|
| `list` | view | — | `{"panes":[Pane…]}` |
| `peek` | view | `pane`, `lines` (1–200, default 80) | `{"lines":[…],"menu":[MenuOption…],"menu_id":"…","question":[…],"blocked":null\|"<kind>","status":"…"}` |
| `answer` | respond | `pane`, `n` (1–9), `label`, `menu_id` | `{"result":"sent"\|"stale"\|"gone"\|"failed"}` |
| `interrupt` | respond | `pane` | `{"result":"sent"\|"gone"\|"failed"}` |
| `prompt` | prompt | `pane`, `text` (1–16000 chars), `queue` (bool) | `{"result":"sent"\|"queued"\|"waiting"\|"blocked"\|"refused"\|"gone"\|"failed"}` |

- `Pane`: `{"pane":"<uuid>","ws":"<workspace label>","title":"…","kind":"claude"|"codex"|…|"","status":"working"|"waiting"|"done"|"idle"|"none","since_ms":<epoch ms or 0>,"queued":<int>}`.
- `MenuOption`: `{"n":1,"label":"…","selected":true,"input":false}`.
- `lines` are logical lines: terminal rows that are a soft-wrapped continuation are joined to the row before, so redaction sees a whole line.
- `menu_id` names one appearance of one menu on that pane (`""` when there is no menu; at most 32 chars of `[A-Za-z0-9_-]`). The desktop app binds each id to (a) the text of the whole menu block: the options and every row above them back to the first run of two blank rows, at most 60 rows; (b) the pane's input generation, a counter that advances on EVERY write to that pane's terminal from any source (local keys, paste, the prompt queue, another device, the Office view) and on every automatic answer; and (c) the agent's own status generation. `answer` types the option number only when `menu_id` is the pane's current one, all three still have the values the id was minted for, AND an option with that `n` and `label` is on screen (`stale` otherwise). An id is retired the moment it is used. Options numbered above 9 and options with `input:true` cannot be answered remotely (`failed`).
- `interrupt` sends one Escape, and only to a pane that has an agent (`gone` otherwise).
- `prompt`: C0 control characters other than tab and newline are removed from `text` on the desktop (CR and CRLF become newline). A text whose first non-blank character is `!` is `refused` (an agent CLI may run it as a shell command, outside its permission rules). With `queue:true` the text is added to the pane's prompt queue when the agent is busy (`queued`); with `queue:false` a busy agent yields `waiting`. A pane without an agent is `gone`: a prompt is never typed into a plain shell.
- There is no op for raw keys, creating or closing panes, or files.

Reply: `{"k":"reply","re":<seq>,"ok":true,"data":{…}}` or `{"k":"reply","re":<seq>,"ok":false,"code":"…"}`. Extra codes: `timeout` (the app did not answer in 5 s; the desktop's page is told that deadline and never submits a `prompt` after it, but the paste itself may already be in, so for `answer`, `interrupt` and `prompt` a device treats `timeout` as "delivered, result unknown, check the screen" and never sends the command again on its own), `unknown_op`, `busy` (8 commands are already waiting on the app), `internal` (the app's answer did not fit the protocol, or the reply would exceed the frame limit).

Unsolicited desktop → device bodies: `{"k":"panes","panes":[Pane…]}` when the list changes (at most once a second, sent to each device with a session) and `reopen`.

All text leaving the desktop (`lines`, `question`, labels, titles, names) is cleaned, redacted and clipped there: control characters and Unicode format/line-separator characters (categories Cc, Cf, Zl, Zp) are removed, then lines are clipped to 2000 chars and titles/labels to 120. Device and desktop names are cleaned the same way wherever they are displayed.

## 6. Push notifications

- Device → server (after `ready`): `{"t":"push_subscribe","sub":{"endpoint":"…","keys":{"p256dh":"…","auth":"…"}}}` or `{"t":"push_unsubscribe"}`. One subscription per device. Endpoints must be `https`.
- Desktop → server: `{"t":"notify","kind":"waiting"|"done","title":"…","body":"…","pane":"<uuid>"}`. The server sends a Web Push (VAPID, TTL 600 s) to every subscribed device of that desktop (the server cannot tell whether a page is visible; the service worker always shows a notification for a push, because iOS revokes subscriptions whose pushes show nothing). `title` ≤ 80 chars, `body` ≤ 160; longer is clipped. At most 30 notifications per desktop per 10 minutes.
- The push payload is `{"kind":…,"title":…,"body":…,"pane":…}`. It carries labels only (a pane title and a workspace label), never screen text or prompts. Notifications are the one piece of pane-derived text the server can read.
- **The device shows fixed text chosen by `kind`.** The text of a push is chosen by whoever can send one (a compromised server included), so this client displays none of it: the notification is the app name plus a fixed, localised sentence ("An agent is waiting for an answer" for `waiting`, "An agent finished" for `done`; nothing else for another `kind`). `title` and `body` stay on the wire for compatibility but are not displayed; only `pane`, when it is a lowercase UUID, is used (as the click target). The service worker takes the language from a value the page stores for it, else from the browser.
- A push endpoint answering 404/410 is deleted.

## 7. Liveness and limits

- Server pings every 30 s; a connection silent for 75 s is closed. Clients reconnect with backoff (1 s doubling to 60 s, with jitter).
- Failed handshakes: 10 per client prefix per minute, then the prefix is refused for a minute. A client prefix is the IPv4 address or the IPv6 /48.
- Unauthenticated connections: at most 64 at once, and at most 8 per client prefix.
- A device may send at most 20 `cmd` frames per second (burst 40); the excess is answered `{"t":"error","code":"rate_limited"}`. When a desktop's outgoing queue is full the server drops the frame and answers the sender `{"t":"error","code":"busy"}`; it never disconnects the desktop for that.
- Text frames only; binary frames close the connection.
- After the handshake the server answers a bad frame with `{"t":"error","code":"…"}` and keeps the connection open: `bad_request` (not JSON, a required field missing or malformed, or a relayed `body` over 200 KiB; the desktop's own limit on a command is 64 KiB, section 5.1), `unknown_type` (unknown `t`), `rate_limited` (a desktop's `notify` over the budget in section 6), `desktop_offline` (a device `cmd` while its desktop is not connected; being plaintext it only makes the device's in-flight commands unconfirmed, section 5.1), `busy` (the desktop's queue is full; same treatment). A handshake that fails is answered the same way and then closed; besides the codes in section 3 that includes `bad_request` (a malformed `pair_request`; a malformed desktop or device hello is answered `bad_sig`, or `unknown_device` when the device id is missing) and `no_pairing` (section 4).

## 8. What a compromised server can and cannot do

Assuming the PWA code the phone runs is the genuine one:

- Cannot run a command: it has neither a device private key nor a link key, and the desktop verifies every command against keys it stored itself.
- Cannot pair a device, even together with someone who photographed the QR: the desktop pairs only the device whose user typed the number that device displayed, and that number travels sealed under a key only that device can derive. The pairing QR must be scanned from your own computer's screen, and a pairing link that reached you any other way (a message, a web page) must not be opened: the number protects against a stranger holding the code, not against a user who is talked into pairing someone else's phone or a page that is not the yMux pairing page.
- Cannot learn a link key, even with the QR: the key comes from a key agreement whose private halves never leave the desktop and the phone.
- Cannot read or alter relayed screen text, menus, prompts or replies, and cannot make the phone show a result the desktop did not send: "delivered, result unknown" and "not delivered" come only from a sealed reply or a sealed `prev`, and `prev.seq` is exact because the desktop accepts only consecutive seqs (a dropped or reordered command ends the session instead of being skipped). It cannot make a command that ran look as if it had not, or the reverse.
- Cannot replay a command, and cannot deliver an `answer` to any menu other than the appearance the user saw.
- CAN delay a command by up to 30 s (less once the phone opens a new session, which it does whenever an outcome is unknown), and can withhold it entirely. A delayed `prompt` or `interrupt` still runs if the pane still has an agent; the phone then reports it as delivered, not as failed. If the phone page is closed or reloaded while a command is in flight, the phone has no record of it, and the relay may still deliver it within 30 s.
- CAN show the phone a list or screen that is up to about 40 s old (30 s of body age plus up to 10 s of clock-offset error from the session handshake), and keep it from updating.
- CAN force "could not confirm" outcomes, by withholding the replies and the new session that would settle a command, and can end a session at will by dropping a frame (the phone opens another).
- CAN rename a pairing request: the device name is unverified text chosen by the sender (or by a relay in between), which is why the desktop cleans it, shows it in a field of its own and never uses it to ask for the number.
- CAN see who is connected and when, the size and timing of messages, notification titles and bodies, and that several pairings belong to one phone (they share a push endpoint); can send fake notifications, which show only the fixed text for their `kind` (and carry no action beyond opening a pane); and can keep a phone or desktop from connecting or from holding a session.
- CAN serve a modified PWA. Modified code running on the phone can use the device key and link key while it runs, and code served during pairing could show a false number or capture the pairing. This is the limit of a web client: host the server yourself, keep it updated, and protect it like the machine it controls.

Redaction of screen text is pattern matching and best effort: it reduces what a phone shows, it does not guarantee that no secret appears.
