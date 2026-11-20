# yMux server

The relay between a running [yMux](https://github.com/YoungMins/ymux) desktop and your phone.
It serves the yMux web app (a PWA), authenticates both sides, relays their messages and sends
Web Push notifications. It never runs a command and keeps no terminal content.

Wire format: [PROTOCOL.md](PROTOCOL.md). Security notes: [SECURITY.md](SECURITY.md).

- One small static binary (Rust, no OpenSSL), the web app is embedded in it.
- TLS is **not** handled here: put it behind a reverse proxy (Caddy, nginx, ...).
- State is two small files in the data directory: `state.json` (VAPID keys, paired desktops and
  devices; written only by the running server) and `setup-token` (written only by
  `ymux-server token --rotate`; the server just reads it). Neither can overwrite the other.

## Configuration

All settings are environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `YMUX_SERVER_PUBLIC_URL` | required | The `https://` address users reach the server at, e.g. `https://remote.example.com`. Must have no path. `http://localhost[:port]` and `http://127.0.0.1[:port]` are accepted for development; the server refuses to start with anything else. Device WebSockets must come from exactly this origin. |
| `YMUX_SERVER_BIND` | `127.0.0.1:11020` | Listen address. Keep it on loopback when a proxy runs on the same host. |
| `YMUX_SERVER_DATA_DIR` | `./data` | Where `state.json` (VAPID keys, paired desktops and devices) and `setup-token` live. Written atomically, mode 0600 on Unix. |
| `YMUX_SERVER_TRUST_PROXY` | off | Set `1` to take the client address for rate limiting from the **last** hop of `X-Forwarded-For` (and only that hop). See [Behind a proxy](#behind-a-proxy-ymux_server_trust_proxy). Without it the TCP peer address is used and the header is ignored. |
| `RUST_LOG` | `ymux_server=info` | Log filter. Logs carry ids and codes only. |

## Quick start

### Deploy with Docker

You need a server with Docker and Compose, and a domain name pointing at it (or a tunnel).
TLS comes from a reverse proxy, a tunnel, or the bundled Caddy.

1. Get the code: `git clone https://github.com/YoungMins/yMux-Server && cd yMux-Server`
2. Copy the settings file and edit it: `cp .env.example .env`. Set `YMUX_SERVER_PUBLIC_URL` to
   the address you will use, e.g. `https://remote.example.com` (or `YMUX_DOMAIN` for shape B).
3. Start it, in one of two shapes:

   **A. You already have a reverse proxy or tunnel** (Nginx Proxy Manager, Synology or QNAP,
   Traefik, Cloudflare Tunnel). One container, port 11020, plain HTTP:

   ```sh
   docker compose up -d --build
   ```

   **B. You have nothing in front** and want automatic HTTPS. The server plus Caddy; ports 80 and
   443 must reach this machine:

   ```sh
   docker compose -f docker-compose.caddy.yml up -d --build
   ```

   The published image `ghcr.io/youngmins/ymux-server` exists only after the owner pushes a
   version tag. Until then `--build` builds it from this folder (a few minutes the first time).

4. Read the setup token (the logs never show it). For shape B add `-f docker-compose.caddy.yml`:

   ```sh
   docker compose exec ymux-server ymux-server token
   ```

5. Shape A only: point your proxy at `http://<this host>:11020` with **WebSocket support on**
   (see below). The port is published on `127.0.0.1` only; if the proxy runs on another machine
   set `YMUX_SERVER_PUBLISH=0.0.0.0` in `.env` and firewall the port to that machine, because it
   speaks plain HTTP and trusts `X-Forwarded-For`.
6. In yMux: **Settings -> Remote server**, enter the address and the setup token, connect, then
   **Pair a phone** (see [Connecting yMux](#connecting-ymux)).

Proxy notes for shape A:

- **Nginx Proxy Manager:** add a Proxy Host for your domain, forward to this host and port 11020,
  switch on *Websockets Support*, and request a certificate on the SSL tab.
- **Synology:** Control Panel -> Login Portal -> Advanced -> Reverse Proxy: source HTTPS on your
  domain, destination HTTP `localhost` 11020. Edit the rule, Custom Header tab, *Create ->
  WebSocket* (adds the two Upgrade headers).
- **Cloudflare Tunnel:** a public hostname for your domain with service `http://localhost:11020`
  (or `http://ymux-server:11020` when `cloudflared` runs in the same compose network). WebSockets
  work without extra settings.
- **Caddy / nginx:** the snippets in [Reverse proxy](#reverse-proxy).

Update: `git pull && docker compose up -d --build`. Once images are published, use
`docker compose pull && docker compose up -d` instead. (Shape B: add `-f docker-compose.caddy.yml`
to every command.)

Back up the `ymux-data` volume (`/data` in the container). It holds `state.json` (the server's
push keys and the registered desktops and paired phones) and `setup-token`. Lose it and every
desktop must register again and every phone must be paired again. A simple copy:

```sh
docker run --rm -v ymux-server_ymux-data:/data -v "$PWD":/backup alpine tar czf /backup/ymux-data.tgz -C /data .
```

(The volume name starts with the folder name, `docker volume ls` shows it.)

Troubleshooting, the three usual mistakes:

- **`origin_mismatch` or the phone cannot connect:** `YMUX_SERVER_PUBLIC_URL` must be exactly the
  address people type (same scheme, host and port, no path, no trailing slash). Fix `.env`, then
  `docker compose up -d`.
- **Connects, then drops at once or never goes online:** the proxy does not pass WebSocket
  upgrades on `/ws/*`. Turn the WebSocket option on (above).
- **yMux or the phone says the address is unsafe or refuses it:** you typed `http://...`. Use the
  `https://` address of the proxy. Plain `http` works only for `localhost`.

### Plain `docker run`

```sh
docker build -t ymux-server .
docker run -d --name ymux-server --restart unless-stopped \
  -e YMUX_SERVER_PUBLIC_URL=https://remote.example.com \
  -e YMUX_SERVER_TRUST_PROXY=1 \
  -v ymux-data:/data -p 127.0.0.1:11020:11020 ymux-server
docker exec ymux-server ymux-server token            # show the setup token
docker exec ymux-server ymux-server token --rotate   # replace it
```

### Binary

```sh
# the web app is embedded at build time; build web/ first (Node 22 + pnpm), or skip it
# and the server serves a placeholder page.
(cd web && pnpm install --frozen-lockfile && pnpm build)
cargo build --release

YMUX_SERVER_PUBLIC_URL=https://remote.example.com \
YMUX_SERVER_DATA_DIR=/var/lib/ymux-server \
YMUX_SERVER_TRUST_PROXY=1 \
./target/release/ymux-server
```

The first start generates the setup token and the VAPID key pair. The token is **not** printed
(deployment logs are kept and shipped); the server prints one line saying that it was created and
how to read it:

```
First run: a setup token was created. Show it with `ymux-server token` (Docker: `docker compose exec <service> ymux-server token`).
```

Run `ymux-server token` (with the same `YMUX_SERVER_DATA_DIR`) to print it. Other commands:
`ymux-server token --rotate` (takes effect for the very next registration, even while the server
runs; already registered desktops are unaffected), `ymux-server --version`. Treat the token like a
password: anyone holding it can register a desktop on your server; rotate it after you have
registered your own.

### Behind a proxy (`YMUX_SERVER_TRUST_PROXY`)

Rate limits are per **client prefix**: an IPv4 address, or an IPv6 /48. They need the real client
address, which behind a reverse proxy only the proxy knows. With `YMUX_SERVER_TRUST_PROXY=1` the
server takes the **last** address of the last `X-Forwarded-For` header and ignores everything
before it. That is only safe if your proxy **overwrites** the header with the connecting client's
address, or **appends** it as the final entry; a proxy that passes the header through untouched,
or one that is not always in front of the server, lets any client pick its own address and dodge
the limits. Caddy and the nginx example below both do the right thing. If the proxy sends no usable
header, the TCP peer (the proxy itself) is used. Do not enable this without a proxy: clients could
then forge the header.

## Reverse proxy

The server speaks plain HTTP and WebSocket; the proxy must pass WebSocket upgrades on `/ws/*`.

### Caddy

```
remote.example.com {
	reverse_proxy 127.0.0.1:11020
}
```

Caddy upgrades WebSockets automatically and sets `X-Forwarded-For`.

### nginx

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

server {
    listen 443 ssl http2;
    server_name remote.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:11020;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # replace, do not append client input
        proxy_read_timeout 120s;                          # the server pings every 30 s
    }
}
```

Do not add a path prefix: the app and its WebSockets live at the root of the host.

## Connecting yMux

1. Start the server and read the setup token with `ymux-server token`.
2. In yMux open **Settings -> Remote server**, enter the server address
   (`https://remote.example.com`) and the setup token. The desktop registers with its own key; after
   that the token is not needed again by this desktop.
3. In the same panel start pairing: yMux shows a QR code. Open it with the phone camera; the
   app opens and asks for a name. The phone then shows a 6-digit number; **type it into yMux**
   (the desktop never displays it), and choose what the device may do (view, respond, or send
   prompts).
4. Optionally add the page to the home screen and allow notifications.

The QR code's `#fragment` (a one-time code and the desktop's key-agreement key) never reaches the
server. Keep the QR to yourself: show it only to the phone, and close the window when done.

Only scan the pairing QR from **your own computer's screen**. A pairing link you received any
other way (in a message, on a web page) must not be opened. The device name shown in yMux's
pairing dialog is chosen by the phone and is not verified; type only the number shown on the yMux
pairing page on your own phone, never a number from the yMux window, a notification or a message.

### Reading the conversation

The detail screen of an agent shows its conversation (Claude Code, Codex) as chat bubbles with
rendered Markdown (tables, lists and code scroll or wrap to fit the phone), with a **Screen**
toggle in the header for the raw terminal text. It needs a yMux that knows the `chat` op
(PROTOCOL.md 5.2); an older yMux simply keeps showing the screen. The desktop reads the agent's own
transcript, and conversation sharing can be turned off in yMux's settings.

### Several computers

To follow more than one computer from one phone, connect each yMux to the same server with the
same address and setup token, then pair the phone once per computer (the app takes up to 8). Each
pairing has its own device id, signing key and link key, and one connection; the agent list shows
one section per computer, and removing a computer in the app's Settings deletes only its keys.

## Security model

(Summary of PROTOCOL.md section 8.) The server is **not** trusted to run anything:

- It cannot run a command: it has neither a device private key nor a link key, and the desktop
  verifies every command against keys it stored itself, plus a per-device session, a consecutive
  sequence number (a skipped one ends the session) and a 60 s freshness window.
- It cannot pair a device, even together with someone who photographed the QR: the link key comes
  from a key agreement (ECDH between the phone's one-time key and the desktop's key from the QR,
  then HKDF salted with the code), so the code and everything the server sees do not give it. The
  6-digit check number is random, reaches the phone only sealed under that key, and the desktop
  pairs only the device whose user types it in.
- It cannot replay commands: sessions, sequence numbers and timestamps are checked on the desktop.
- It cannot read or alter relayed screen text, menus, prompts or replies: every relayed `body` is
  sealed (AES-256-GCM) with a key only the desktop and that one device hold.
- It **can** delay a command by up to 30 s (less once the phone opens a new session) or withhold
  it, and show the phone a list or screen up to about 40 s old (30 s of body age plus up to 10 s
  of clock-offset error); a delayed `prompt` or `interrupt` still runs if the pane still has an
  agent, and the phone then reports it as delivered, not failed. If the phone page is closed or
  reloaded while a command is in flight, the phone has no record of it and the relay may still
  deliver it within 30 s.
- It **can** force "could not confirm" outcomes (by withholding what would settle a command) and
  rename a pairing request (the name is unverified, which is why yMux shows it in a labelled field
  of its own and cleans it: no digits, no quote or dash marks).
- It **can** see who is connected and when, message sizes and timing, notification titles and
  pane labels, and that several pairings belong to one phone (they share a push endpoint), send
  fake notifications (the phone shows only fixed text chosen by the notification kind, never the
  text of the push), and keep a phone or desktop from connecting or from holding a session.
- It **can** serve a modified web app that uses the device and link keys while the page is open,
  or shows a false number or captures the pairing while pairing.

So host it yourself, on a machine you trust, over HTTPS, and keep it updated.

What the server enforces: exact `Origin` rules (a desktop socket must carry none; device sockets
must match the public URL), a challenge on every connection that names the server's origin and
that a desktop must sign together with it (a challenge relayed from another server never
verifies), constant-time token comparison, a validated pairing request (`ek` must be a real P-256
point), a pairing window (at most 120 s and 5 requests, at most 3 `pair_challenge` frames of at
most 4 KiB per request, delivered only to that request's own socket), 10 failed handshakes per
client prefix per minute, at most 64 unauthenticated connections and 8 per client prefix (IPv4
address or IPv6 /48), one live connection per desktop and per device, a 256 KiB frame limit, text
frames only, bounded per-connection queues (a slow device is disconnected, but a full desktop queue
only drops the frame and answers the sender `busy`: no device or pairing socket can knock a desktop
offline), 20 `cmd` frames per second per device (burst 40, kept across reconnects, excess answered
`rate_limited`), at most one push subscription change per second per device (burst 5), presence
hints dropped rather than queued when the desktop is backed up, no
broadcast (a relayed `msg` names one device), device and desktop names stripped of control, format
and line-separator characters and clipped to 80 characters, 30 push notifications per desktop per
10 minutes, and an SSRF guard on push delivery (https only, no redirects, no HTTP proxy, the host
resolved once and connected to by those vetted addresses, anything that is not a public global
unicast address refused, at most 8 deliveries at once with at most 256 queued, one 15 s deadline
per delivery including name resolution, a response size cap). Relayed `body` content, tokens and
push keys are never stored or logged, and the setup token is never printed by the server.

Strict response headers (CSP with `frame-ancestors 'none'`, `nosniff`, `no-referrer`, HSTS on
https deployments) are set on every response.

## Updating

Docker: `git pull && docker compose build && docker compose up -d`. Binary: rebuild and restart.
`state.json` and `setup-token` are kept; the setup token, VAPID key and paired devices survive. A
setup token stored in the `state.json` of an older version is moved to `setup-token` on first start. Keep yMux desktop
and server on the same minor version; the protocol version is `1`.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test        # needs no Node: without web/dist a placeholder page is embedded
```

`fixtures/` holds one valid JSON example per protocol message plus the key agreement and link key
derivation (ECDH + HKDF) and sealed bodies (AES-256-GCM, fixed nonces), all deterministic and from the test inputs in
`fixtures/keys.json`, for other implementations to verify against; see
[fixtures/README.md](fixtures/README.md). Regenerate with
`YMUX_REGEN_FIXTURES=1 cargo test --test fixtures regenerate`.

## End-to-end test

`scripts/e2e.ps1` runs all three independently written implementations against each other on
loopback (`http://127.0.0.1:<free port>`, temp data dir): the real `ymux-server` binary, the real
yMux desktop socket loop and engine (an `#[ignore]`d test, `remote::runtime::e2e`, in the sibling
ymux checkout, with a fake page and a fake user), and the real PWA protocol/net code driven from
Node (`web/scripts/e2e-device.ts` through `vitest`). Scenario 1 (one desktop) pairs with the link
key (key agreement, then the number the phone shows typed into the desktop), opens a session, runs list, peek, answer (with
`menu_id`), interrupt and prompt, and checks every rejection: a `!` prompt (`refused`), a stale
`menu_id`, a replayed frame, a command re-sent after a new session (`bad_session`), a `ts_ms` five
minutes old (`expired`), a valid signature over a body sealed with the wrong key, a tampered body;
then a desktop reconnect, a capability drop to `view` and device removal. The desktop side counts
exactly what reached its fake page, so a rejected command that leaked through fails the run.
Scenario 2 (two desktops registered with the same setup token, one device process using the PWA's
`Fleet` with two pairings) checks that each list holds only that desktop's panes (one pane uuid is
on both with different titles), that a command, a captured frame or a body sealed for one pairing
never reaches or opens on the other, that one desktop being stopped does not slow the other, and
that removing one pairing leaves the other working.

```powershell
pwsh scripts\e2e.ps1 [-Ymux ..\ymux] [-Keep] [-Only single|fleet]   # -Ymux: the ymux checkout (default ..\ymux)
```

It needs Rust, Node 22+ and pnpm (`pnpm install` in `web/` once), builds with
`CARGO_INCREMENTAL=0`, refuses to build with under 6 GB free, and exits non-zero on any failure
(logs of a failed run are kept in the temp directory it prints). It commits nothing. Not covered:
TLS, a real browser, real Web Push, and the Tauri page itself.

## Demo mode

`scripts/demo.ps1` starts the server on `http://127.0.0.1:11020` (temp data dir; builds `web/` first
unless `-SkipWebBuild`) and two fake desktops, "Office PC" and "Home PC", that stay up until Ctrl+C.
Each has a few panes in two workspaces (one waiting with a three-option menu, one working, one done,
one idle) with about 40 lines of sample terminal text; answering turns the waiting pane into a
working one, and a queued prompt to a working pane raises its `queued` count. Each approves pairing
with capability `prompt` and renews its pairing window every 100 s and after each pairing. The script
prints both `http://127.0.0.1:11020/#pair=...` links and keeps the current ones in `demo-urls.txt` in
the temp directory it names. The fake desktops are an `#[ignore]`d test of the ymux repo
(`remote::runtime::e2e::demo_fake_desktop`): test code that no build of the app contains.

```powershell
pwsh scripts\demo.ps1 [-Ymux ..\ymux] [-Port 11020] [-SkipWebBuild]
```

## License

MIT, see [LICENSE](LICENSE).
