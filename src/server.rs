//! HTTP routes and the WebSocket protocol (PROTOCOL.md sections 2-7).
//!
//! Logs carry ids and codes only: never `body`, tokens, keys or push data.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::Instant as TInstant;
use tokio_util::sync::CancellationToken;

use crate::auth::{check_pair_request, decide_desktop, decide_device, DesktopDecision, Hello};
use crate::config::Config;
use crate::crypto::{b64u, clean_device_name, clip, is_uuid, random_bytes};
use crate::hub::{ConnHandle, Hub, Offer, Out, CHANNEL_CAP};
use crate::limits::{
    client_prefix, HandshakeLimiter, Pending, Unauth, UnauthGuard, MAX_CHALLENGE_BODY,
};
use crate::push::{PushOutcome, PushSender};
use crate::state::{PushSub, Store};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_FRAME: usize = 256 * 1024;
/// Largest relayed `body`, leaving room for the envelope inside MAX_FRAME.
const MAX_BODY: usize = 200 * 1024;
/// Push deliveries running at once.
const MAX_PUSH_IN_FLIGHT: usize = 8;
/// Push deliveries running or waiting for a slot; the rest are dropped.
const MAX_PUSH_QUEUED: usize = 256;

pub struct AppState {
    pub cfg: Config,
    pub store: Mutex<Store>,
    pub hub: Hub,
    pub limiter: Mutex<HandshakeLimiter>,
    pub unauth: Arc<Unauth>,
    pub push: Arc<dyn PushSender>,
    /// Limits deliveries running at once.
    pub push_sem: Arc<Semaphore>,
    /// Limits deliveries running or queued; a task exists only while it holds one.
    pub push_queue: Arc<Semaphore>,
    pub vapid_public: String,
}

impl AppState {
    pub fn new(cfg: Config, store: Store, push: Arc<dyn PushSender>) -> Arc<AppState> {
        Arc::new(AppState {
            vapid_public: store.state.vapid_public.clone(),
            cfg,
            store: Mutex::new(store),
            hub: Hub::default(),
            limiter: Mutex::new(HandshakeLimiter::default()),
            unauth: Arc::new(Unauth::default()),
            push,
            push_sem: Arc::new(Semaphore::new(MAX_PUSH_IN_FLIGHT)),
            push_queue: Arc::new(Semaphore::new(MAX_PUSH_QUEUED)),
        })
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async { ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "ok") }),
        )
        .route("/api/info", get(info))
        .route("/ws/desktop", get(ws_desktop))
        .route("/ws/device", get(ws_device))
        .route("/ws/pair", get(ws_pair))
        .fallback(crate::web::serve_static)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::web::security_headers,
        ))
        .with_state(state)
}

async fn info(State(s): State<Arc<AppState>>) -> Response {
    let body = json!({ "v": 1, "server": VERSION, "vapid": s.vapid_public }).to_string();
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

pub struct Running {
    pub addr: SocketAddr,
    pub state: Arc<AppState>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    pub async fn stop(self) {
        self.shutdown.cancel();
        if tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .is_err()
        {
            tracing::warn!("shutdown timed out; exiting");
        }
    }

    pub async fn wait(self) {
        let _ = self.task.await;
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

pub fn start(state: Arc<AppState>, listener: tokio::net::TcpListener) -> std::io::Result<Running> {
    let addr = listener.local_addr()?;
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let task = tokio::spawn(async move {
        let served = axum::serve(listener, app)
            .with_graceful_shutdown(async move { token.cancelled().await })
            .await;
        if let Err(e) = served {
            tracing::error!(error = %e, "server stopped");
        }
    });
    Ok(Running {
        addr,
        state,
        shutdown,
        task,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Desktop,
    Device,
    Pair,
}

/// Last hop of X-Forwarded-For: the entry the trusted proxy appended itself.
pub fn last_forwarded(value: &str) -> Option<IpAddr> {
    value.rsplit(',').next()?.trim().parse().ok()
}

/// The client prefix (IPv4 address or IPv6 /48) every per-client limit is keyed by.
fn client_key(cfg: &Config, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if cfg.trust_proxy {
        if let Some(ip) = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(last_forwarded)
        {
            return client_prefix(ip);
        }
    }
    client_prefix(peer.ip())
}

async fn ws_desktop(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    entry(s, Role::Desktop, peer, headers, ws)
}

async fn ws_device(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    entry(s, Role::Device, peer, headers, ws)
}

async fn ws_pair(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    entry(s, Role::Pair, peer, headers, ws)
}

fn entry(
    s: Arc<AppState>,
    role: Role,
    peer: SocketAddr,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // Origin rules: a desktop is not a browser; a device socket must come from our own page.
    match role {
        Role::Desktop => {
            if headers.contains_key(header::ORIGIN) {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        Role::Device | Role::Pair => {
            let ok = headers
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                .map(|o| o == s.cfg.origin)
                .unwrap_or(false);
            if !ok {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }
    let ip = client_key(&s.cfg, peer, &headers);
    if !lock(&s.limiter).allowed(ip, std::time::Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Some(guard) = s.unauth.acquire(ip) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| run(s, role, ip, guard, socket))
}

// ---------------------------------------------------------------------------
// Connection plumbing

async fn write_loop(
    mut sink: SplitSink<WebSocket, Message>,
    mut rx: mpsc::Receiver<Out>,
    write_timeout: Duration,
) {
    while let Some(out) = rx.recv().await {
        let (msg, last) = match out {
            Out::Text(s) => (Message::Text(s.into()), false),
            Out::Ping => (Message::Ping(Bytes::new()), false),
            Out::Close(code) => (
                Message::Close(Some(CloseFrame {
                    code,
                    reason: "".into(),
                })),
                true,
            ),
        };
        match tokio::time::timeout(write_timeout, sink.send(msg)).await {
            Ok(Ok(())) => {}
            _ => break,
        }
        if last {
            break;
        }
    }
}

enum Next {
    Text(String),
    Closed,
    Timeout,
}

struct Io {
    stream: SplitStream<WebSocket>,
    handle: ConnHandle,
    ping: tokio::time::Interval,
    last_rx: TInstant,
    idle: Duration,
}

impl Io {
    /// Next text frame. `fixed` is an absolute deadline; without it the
    /// connection may be silent for `idle` since the last frame of any kind.
    async fn next(&mut self, fixed: Option<TInstant>) -> Next {
        loop {
            let deadline = fixed.unwrap_or(self.last_rx + self.idle);
            tokio::select! {
                biased;
                _ = self.handle.killed() => return Next::Closed,
                _ = tokio::time::sleep_until(deadline) => return Next::Timeout,
                _ = self.ping.tick() => {
                    if !self.handle.ping() {
                        return Next::Closed;
                    }
                }
                m = self.stream.next() => match m {
                    Some(Ok(Message::Text(t))) => {
                        self.last_rx = TInstant::now();
                        return Next::Text(t.as_str().to_owned());
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                        self.last_rx = TInstant::now();
                    }
                    Some(Ok(Message::Binary(_))) => {
                        self.handle.close(1003);
                        return Next::Closed;
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Next::Closed,
                },
            }
        }
    }
}

async fn run(state: Arc<AppState>, role: Role, ip: IpAddr, guard: UnauthGuard, socket: WebSocket) {
    let t = state.cfg.timing.clone();
    let (sink, stream) = socket.split();
    let (tx, rx) = mpsc::channel(CHANNEL_CAP);
    let handle = ConnHandle::new(tx, CancellationToken::new());
    let mut writer = tokio::spawn(write_loop(sink, rx, t.write));
    let mut ping = tokio::time::interval_at(TInstant::now() + t.ping, t.ping);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut io = Io {
        stream,
        handle: handle.clone(),
        ping,
        last_rx: TInstant::now(),
        idle: t.idle,
    };
    match role {
        Role::Desktop => desktop_session(&state, ip, guard, &mut io).await,
        Role::Device => device_session(&state, ip, guard, &mut io).await,
        Role::Pair => pair_session(&state, ip, guard, &mut io).await,
    }
    handle.close(1000);
    if tokio::time::timeout(Duration::from_secs(1), &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
}

fn err_frame(code: &str) -> String {
    json!({ "t": "error", "code": code }).to_string()
}

fn challenge(nonce: &str, origin: &str) -> String {
    json!({ "t": "challenge", "nonce": nonce, "v": 1, "server": VERSION, "origin": origin })
        .to_string()
}

fn record_fail(state: &AppState, ip: IpAddr) {
    lock(&state.limiter).record_fail(ip, std::time::Instant::now());
}

fn reject(state: &AppState, io: &Io, ip: IpAddr, code: &str) {
    record_fail(state, ip);
    io.handle.send(err_frame(code));
    tracing::info!(code, "handshake rejected");
}

/// Sends the challenge and reads the first frame within the handshake timeout.
async fn read_first(state: &AppState, io: &mut Io, ip: IpAddr) -> Option<(String, String)> {
    let nonce = b64u(&random_bytes::<32>());
    io.handle.send(challenge(&nonce, &state.cfg.origin));
    let deadline = TInstant::now() + state.cfg.timing.handshake;
    match io.next(Some(deadline)).await {
        Next::Text(t) => Some((nonce, t)),
        Next::Timeout => {
            record_fail(state, ip);
            tracing::info!("handshake timeout");
            None
        }
        Next::Closed => {
            record_fail(state, ip);
            None
        }
    }
}

fn str_field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

// ---------------------------------------------------------------------------
// Desktop

async fn desktop_session(state: &Arc<AppState>, ip: IpAddr, guard: UnauthGuard, io: &mut Io) {
    let Some((nonce, text)) = read_first(state, io, ip).await else {
        return;
    };
    let hello: Hello = match serde_json::from_str(&text) {
        Ok(h) => h,
        Err(_) => return reject(state, io, ip, "bad_sig"),
    };
    let id = hello.desktop_id.clone().unwrap_or_default();
    // Decide and register under one lock: two hellos for the same new id
    // cannot both pass the "unknown" check and overwrite each other's key.
    let decision = {
        let mut store = lock(&state.store);
        let decision = decide_desktop(&store.state, &hello, &nonce, &state.cfg.origin, &|| {
            store.setup_token()
        });
        if decision == Ok(DesktopDecision::Register) {
            store.add_desktop(
                &id,
                hello.pubkey.as_deref().unwrap_or(""),
                hello.name.as_deref().unwrap_or(""),
            );
        }
        decision
    };
    match decision {
        Err(code) => return reject(state, io, ip, code),
        Ok(DesktopDecision::Register) => tracing::info!(desktop = %id, "desktop registered"),
        Ok(DesktopDecision::Known) => {}
    }
    drop(guard);

    let ready =
        json!({ "t": "ready", "devices": lock(&state.store).state.devices_of(&id) }).to_string();
    let (old, devices) = state.hub.register_desktop(&id, io.handle.clone(), ready);
    if let Some(old) = old {
        old.kill();
    }
    for (device_id, h) in &devices {
        io.handle
            .send(online_frame("device_online", device_id, &h.conn));
        h.send(json!({ "t": "desktop_online" }).to_string());
    }
    tracing::info!(desktop = %id, "desktop online");

    while let Next::Text(text) = io.next(None).await {
        desktop_frame(state, &id, &io.handle, &text);
    }
    if let Some(devs) = state.hub.unregister_desktop(&id, &io.handle.conn) {
        for h in devs {
            h.send(json!({ "t": "desktop_offline" }).to_string());
        }
    }
    tracing::info!(desktop = %id, "desktop offline");
}

fn online_frame(t: &str, device_id: &str, conn: &str) -> String {
    json!({ "t": t, "device_id": device_id, "conn": conn }).to_string()
}

/// A presence hint for a desktop, caused by a device connecting or leaving.
/// Hints are display-only, so when the desktop's queue is full the hint is
/// dropped: a device that reconnects in a loop must not disconnect the desktop.
fn hint(desktop: &ConnHandle, frame: String) {
    desktop.offer(frame);
}

fn desktop_frame(state: &Arc<AppState>, id: &str, me: &ConnHandle, text: &str) {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        me.send(err_frame("bad_request"));
        return;
    };
    match str_field(&v, "t") {
        Some("pair_open") => {
            let ttl = v.get("ttl_s").and_then(Value::as_u64).unwrap_or(120);
            state.hub.open_window(id, ttl, std::time::Instant::now());
        }
        Some("pair_close") => state.hub.close_window(id),
        Some("pair_result") => pair_result(state, id, &v),
        Some("pair_challenge") => {
            let (Some(dev), Some(body)) = (str_field(&v, "device_id"), str_field(&v, "body"))
            else {
                me.send(err_frame("bad_request"));
                return;
            };
            if body.len() > MAX_CHALLENGE_BODY || !is_uuid(dev) {
                me.send(err_frame("bad_request"));
                return;
            }
            // No window, no such request, or its three challenges used: ignored.
            state.hub.forward_challenge(id, dev, body);
        }
        Some("device_remove") => {
            if let Some(dev) = str_field(&v, "device_id") {
                let removed = lock(&state.store).remove_device(id, dev);
                if removed {
                    state.hub.kill_device(dev);
                    tracing::info!(desktop = %id, device = %dev, "device removed");
                }
            }
        }
        Some("msg") => {
            let (Some(to), Some(body)) = (str_field(&v, "to"), str_field(&v, "body")) else {
                me.send(err_frame("bad_request"));
                return;
            };
            // One addressee, a device id. There is no broadcast: "*" and any
            // other non-id is a malformed request.
            if body.len() > MAX_BODY || !is_uuid(to) {
                me.send(err_frame("bad_request"));
                return;
            }
            if let Some(h) = state.hub.device_of(id, to) {
                h.send(json!({ "t": "msg", "body": body }).to_string());
            }
        }
        Some("notify") => notify(state, id, me, &v),
        _ => {
            me.send(err_frame("unknown_type"));
        }
    }
}

fn pair_result(state: &Arc<AppState>, id: &str, v: &Value) {
    let Some(dev) = str_field(v, "device_id") else {
        return;
    };
    let Some(pending) = state.hub.take_pending(id, dev) else {
        return;
    };
    let mut accepted = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if accepted {
        // The desktop must approve the key the device presented, not another one
        // (PROTOCOL 4.6); a result that does not name it at all is not an approval.
        accepted = str_field(v, "pubkey") == Some(pending.pubkey.as_str());
    }
    if accepted {
        let name = match str_field(v, "name") {
            Some(n) => clean_device_name(n),
            None => pending.name.clone(),
        };
        accepted = lock(&state.store).add_device(id, dev, &pending.pubkey, &name);
    }
    if accepted {
        state.hub.close_window(id);
        tracing::info!(desktop = %id, device = %dev, "device paired");
    }
    let _ = pending.reply.send(accepted);
}

fn notify(state: &Arc<AppState>, id: &str, me: &ConnHandle, v: &Value) {
    let kind = match str_field(v, "kind") {
        Some(k @ ("waiting" | "done")) => k,
        _ => {
            me.send(err_frame("bad_request"));
            return;
        }
    };
    if !state.hub.notify_allowed(id, std::time::Instant::now()) {
        me.send(err_frame("rate_limited"));
        return;
    }
    let payload = json!({
        "kind": kind,
        "title": clip(str_field(v, "title").unwrap_or(""), 80),
        "body": clip(str_field(v, "body").unwrap_or(""), 160),
        "pane": clip(str_field(v, "pane").unwrap_or(""), 64),
    })
    .to_string();
    let targets: Vec<(String, PushSub)> = {
        let store = lock(&state.store);
        store
            .state
            .devices
            .iter()
            .filter(|(_, d)| d.desktop_id == id)
            .filter_map(|(dev, d)| d.push.clone().map(|p| (dev.clone(), p)))
            .collect()
    };
    dispatch_pushes(state, targets, payload);
}

/// Starts one delivery task per target, but never more than `MAX_PUSH_QUEUED`
/// at a time (running plus waiting for one of the `MAX_PUSH_IN_FLIGHT` slots).
/// The queue slot is taken before the task exists, so a flood cannot pile up
/// tasks; the excess is dropped and counted. Returns how many were dropped.
pub fn dispatch_pushes(
    state: &Arc<AppState>,
    targets: Vec<(String, PushSub)>,
    payload: String,
) -> usize {
    let payload: Arc<str> = payload.into();
    let mut dropped = 0usize;
    for (dev, sub) in targets {
        let Ok(queued) = state.push_queue.clone().try_acquire_owned() else {
            dropped += 1;
            continue;
        };
        let state = state.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            let _queued = queued;
            let Ok(_running) = state.push_sem.clone().acquire_owned().await else {
                return;
            };
            // One deadline for the whole delivery, name resolution included.
            let deadline = state.cfg.timing.push_deadline;
            let outcome =
                match tokio::time::timeout(deadline, state.push.send(&sub, payload.as_bytes()))
                    .await
                {
                    Ok(o) => o,
                    Err(_) => PushOutcome::Failed,
                };
            match outcome {
                PushOutcome::Sent => tracing::debug!(device = %dev, "push sent"),
                PushOutcome::Gone => {
                    lock(&state.store).clear_push_if(&dev, &sub.endpoint);
                    tracing::info!(device = %dev, "push subscription gone, deleted");
                }
                PushOutcome::Failed => tracing::info!(device = %dev, "push failed"),
            }
        });
    }
    if dropped > 0 {
        tracing::warn!(dropped, "push queue full, notifications dropped");
    }
    dropped
}

// ---------------------------------------------------------------------------
// Device

async fn device_session(state: &Arc<AppState>, ip: IpAddr, guard: UnauthGuard, io: &mut Io) {
    let Some((nonce, text)) = read_first(state, io, ip).await else {
        return;
    };
    let hello: Hello = match serde_json::from_str(&text) {
        Ok(h) => h,
        Err(_) => return reject(state, io, ip, "bad_sig"),
    };
    let decision = {
        let store = lock(&state.store);
        decide_device(&store.state, &hello, &nonce)
            .map(|(id, rec)| (id.to_string(), rec.desktop_id.clone()))
    };
    let (device_id, desktop_id) = match decision {
        Ok(x) => x,
        Err(code) => return reject(state, io, ip, code),
    };
    drop(guard);

    let did = desktop_id.clone();
    let (old, desktop) =
        state
            .hub
            .register_device(&device_id, &desktop_id, io.handle.clone(), move |online| {
                json!({ "t": "ready", "desktop_id": did, "desktop_online": online }).to_string()
            });
    if let Some(old) = old {
        // A newer connection of the same device replaces the older one.
        old.kill();
        if let Some(d) = &desktop {
            hint(d, online_frame("device_offline", &device_id, &old.conn));
        }
    }
    if let Some(d) = &desktop {
        hint(
            d,
            online_frame("device_online", &device_id, &io.handle.conn),
        );
    }
    tracing::info!(device = %device_id, "device online");

    while let Next::Text(text) = io.next(None).await {
        device_frame(state, &device_id, &desktop_id, &io.handle, &text);
    }
    if let Some(Some(d)) = state.hub.unregister_device(&device_id, &io.handle.conn) {
        hint(
            &d,
            online_frame("device_offline", &device_id, &io.handle.conn),
        );
    }
    tracing::info!(device = %device_id, "device offline");
}

fn device_frame(
    state: &Arc<AppState>,
    device_id: &str,
    desktop_id: &str,
    me: &ConnHandle,
    text: &str,
) {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        me.send(err_frame("bad_request"));
        return;
    };
    match str_field(&v, "t") {
        Some("cmd") => {
            if !state.hub.cmd_allowed(device_id, std::time::Instant::now()) {
                me.send(err_frame("rate_limited"));
                return;
            }
            let (Some(body), Some(sig)) = (str_field(&v, "body"), str_field(&v, "sig")) else {
                me.send(err_frame("bad_request"));
                return;
            };
            if body.len() > MAX_BODY || sig.len() > 256 {
                me.send(err_frame("bad_request"));
                return;
            }
            let Some(desktop) = state.hub.desktop(desktop_id) else {
                me.send(err_frame("desktop_offline"));
                return;
            };
            let frame = json!({
                "t": "cmd",
                "device_id": device_id,
                "conn": me.conn,
                "body": body,
                "sig": sig,
            })
            .to_string();
            // The desktop's queue belongs to the desktop: a full one drops this
            // frame and tells the sender, it never disconnects the desktop.
            match desktop.offer(frame) {
                Offer::Sent => {}
                Offer::Full => {
                    me.send(err_frame("busy"));
                }
                Offer::Gone => {
                    me.send(err_frame("desktop_offline"));
                }
            }
        }
        Some(t @ ("push_subscribe" | "push_unsubscribe")) => {
            // Each change rewrites the state file under the store lock.
            if !state.hub.sub_allowed(device_id, std::time::Instant::now()) {
                me.send(err_frame("rate_limited"));
                return;
            }
            if t == "push_unsubscribe" {
                lock(&state.store).set_push(device_id, None);
            } else {
                match parse_sub(v.get("sub")) {
                    Some(sub) => lock(&state.store).set_push(device_id, Some(sub)),
                    None => {
                        me.send(err_frame("bad_request"));
                    }
                }
            }
        }
        _ => {
            me.send(err_frame("unknown_type"));
        }
    }
}

/// Validates a Web Push subscription: https endpoint, P-256 key, 16-byte auth.
pub fn parse_sub(v: Option<&Value>) -> Option<PushSub> {
    let v = v?;
    let endpoint = str_field(v, "endpoint")?;
    let keys = v.get("keys")?;
    let p256dh = str_field(keys, "p256dh")?;
    let auth = str_field(keys, "auth")?;
    if endpoint.len() > 2048 {
        return None;
    }
    let url = url::Url::parse(endpoint).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    crate::crypto::parse_pubkey(p256dh)?;
    if crate::crypto::unb64u(auth)?.len() != 16 {
        return None;
    }
    Some(PushSub {
        endpoint: endpoint.to_string(),
        p256dh: p256dh.to_string(),
        auth: auth.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Unpaired device

async fn pair_session(state: &Arc<AppState>, ip: IpAddr, _guard: UnauthGuard, io: &mut Io) {
    let Some((nonce, text)) = read_first(state, io, ip).await else {
        return;
    };
    let hello: Hello = match serde_json::from_str(&text) {
        Ok(h) => h,
        Err(_) => return reject(state, io, ip, "bad_request"),
    };
    let req = match check_pair_request(&hello, &nonce) {
        Ok(r) => r,
        Err(code) => return reject(state, io, ip, code),
    };
    let Some(desktop) = state.hub.desktop(&req.desktop_id) else {
        return reject(state, io, ip, "no_pairing");
    };
    let (tx, mut rx) = oneshot::channel();
    let pending = Pending {
        pubkey: req.pubkey.clone(),
        name: req.name.clone(),
        reply: tx,
        handle: io.handle.clone(),
        challenges: 0,
    };
    if let Err(code) = state.hub.add_pending(
        &req.desktop_id,
        &req.device_id,
        pending,
        std::time::Instant::now(),
    ) {
        return reject(state, io, ip, code);
    }
    let forwarded = json!({
        "t": "pair_request",
        "device_id": req.device_id,
        "pubkey": req.pubkey,
        "ek": req.ek,
        "name": req.name,
        "proof": req.proof,
    })
    .to_string();
    // Pairing sockets are anyone with the QR: they may not disconnect the desktop.
    match desktop.offer(forwarded) {
        Offer::Sent => {}
        Offer::Full => {
            state.hub.take_pending(&req.desktop_id, &req.device_id);
            io.handle.send(err_frame("busy"));
            return;
        }
        Offer::Gone => {
            state.hub.take_pending(&req.desktop_id, &req.device_id);
            return reject(state, io, ip, "no_pairing");
        }
    }
    tracing::info!(desktop = %req.desktop_id, device = %req.device_id, "pair request forwarded");

    let deadline = TInstant::now() + state.cfg.timing.pair_wait;
    let ok = loop {
        tokio::select! {
            r = &mut rx => break r.unwrap_or(false),
            n = io.next(Some(deadline)) => match n {
                Next::Text(_) => continue,
                _ => {
                    state.hub.take_pending(&req.desktop_id, &req.device_id);
                    return;
                }
            },
        }
    };
    if !ok {
        record_fail(state, ip);
    }
    io.handle
        .send(json!({ "t": "pair_result", "ok": ok }).to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn xff_uses_last_hop() {
        assert_eq!(
            last_forwarded("1.2.3.4, 5.6.7.8"),
            Some("5.6.7.8".parse().unwrap())
        );
        assert_eq!(last_forwarded(" ::1 "), Some("::1".parse().unwrap()));
        assert_eq!(last_forwarded("1.2.3.4, nope"), None);
        assert_eq!(last_forwarded(""), None);
    }

    #[test]
    fn client_key_is_the_last_hop_prefix_only_behind_a_trusted_proxy() {
        let mut cfg = test_config(std::path::Path::new("."));
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.append(
            "x-forwarded-for",
            "203.0.113.1, 2001:db8:5:6:7:8:9:a".parse().unwrap(),
        );
        // Not trusted: the header is ignored.
        assert_eq!(client_key(&cfg, peer, &h), peer.ip());
        cfg.trust_proxy = true;
        assert_eq!(
            client_key(&cfg, peer, &h),
            "2001:db8:5::".parse::<IpAddr>().unwrap()
        );
        // A later header line is the proxy's; the client's earlier one is ignored.
        h.append("x-forwarded-for", "192.0.2.50".parse().unwrap());
        assert_eq!(
            client_key(&cfg, peer, &h),
            "192.0.2.50".parse::<IpAddr>().unwrap()
        );
        // No usable header: the peer itself.
        assert_eq!(client_key(&cfg, peer, &HeaderMap::new()), peer.ip());
    }

    fn test_config(dir: &std::path::Path) -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            origin: "http://127.0.0.1:1".into(),
            https: false,
            data_dir: dir.to_path_buf(),
            trust_proxy: false,
            timing: Default::default(),
        }
    }

    /// Counts what is running, blocks until released, optionally never returns.
    struct Gate {
        running: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        started: std::sync::atomic::AtomicUsize,
        release: tokio::sync::Notify,
        hang: bool,
    }

    impl PushSender for Gate {
        fn send<'a>(
            &'a self,
            _sub: &'a PushSub,
            _payload: &'a [u8],
        ) -> crate::push::BoxFut<'a, PushOutcome> {
            use std::sync::atomic::Ordering::SeqCst;
            Box::pin(async move {
                self.started.fetch_add(1, SeqCst);
                let now = self.running.fetch_add(1, SeqCst) + 1;
                self.peak.fetch_max(now, SeqCst);
                if self.hang {
                    std::future::pending::<()>().await;
                } else {
                    self.release.notified().await;
                }
                self.running.fetch_sub(1, SeqCst);
                PushOutcome::Sent
            })
        }
    }

    fn gate_state(hang: bool, deadline: Duration) -> (Arc<AppState>, Arc<Gate>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = Store::open(dir.path()).unwrap();
        let gate = Arc::new(Gate {
            running: 0.into(),
            peak: 0.into(),
            started: 0.into(),
            release: tokio::sync::Notify::new(),
            hang,
        });
        let mut cfg = test_config(dir.path());
        cfg.timing.push_deadline = deadline;
        (AppState::new(cfg, store, gate.clone()), gate, dir)
    }

    fn targets(n: usize) -> Vec<(String, PushSub)> {
        (0..n)
            .map(|i| {
                (
                    format!("dev{i}"),
                    PushSub {
                        endpoint: format!("https://push.example/{i}"),
                        p256dh: "k".into(),
                        auth: "a".into(),
                    },
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn push_queue_is_bounded_and_runs_eight_at_a_time() {
        use std::sync::atomic::Ordering::SeqCst;
        let (state, gate, _dir) = gate_state(false, Duration::from_secs(30));
        let dropped = dispatch_pushes(&state, targets(MAX_PUSH_QUEUED + 44), "{}".into());
        assert_eq!(dropped, 44, "the excess is dropped, not queued");
        assert_eq!(state.push_queue.available_permits(), 0);
        // Let the 8 slots fill; nothing else may start.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(gate.started.load(SeqCst), MAX_PUSH_IN_FLIGHT);
        // Drain: every queued delivery eventually runs, never more than 8 together.
        for _ in 0..2000 {
            gate.release.notify_waiters();
            tokio::time::sleep(Duration::from_millis(2)).await;
            if gate.started.load(SeqCst) == MAX_PUSH_QUEUED
                && state.push_queue.available_permits() == MAX_PUSH_QUEUED
            {
                break;
            }
        }
        assert_eq!(gate.started.load(SeqCst), MAX_PUSH_QUEUED);
        assert_eq!(gate.peak.load(SeqCst), MAX_PUSH_IN_FLIGHT);
        assert_eq!(state.push_queue.available_permits(), MAX_PUSH_QUEUED);
        assert_eq!(state.push_sem.available_permits(), MAX_PUSH_IN_FLIGHT);
    }

    #[tokio::test]
    async fn a_delivery_that_never_finishes_is_cut_off_by_the_deadline() {
        let (state, gate, _dir) = gate_state(true, Duration::from_millis(100));
        assert_eq!(dispatch_pushes(&state, targets(12), "{}".into()), 0);
        // 12 hung deliveries through 8 slots: all done after two deadlines.
        for _ in 0..200 {
            if state.push_queue.available_permits() == MAX_PUSH_QUEUED {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(state.push_queue.available_permits(), MAX_PUSH_QUEUED);
        assert_eq!(state.push_sem.available_permits(), MAX_PUSH_IN_FLIGHT);
        assert_eq!(gate.started.load(std::sync::atomic::Ordering::SeqCst), 12);
    }

    fn handle_with_cap(cap: usize) -> (ConnHandle, mpsc::Receiver<Out>, CancellationToken) {
        let (tx, rx) = mpsc::channel(cap);
        let kill = CancellationToken::new();
        (ConnHandle::new(tx, kill.clone()), rx, kill)
    }

    #[test]
    fn a_full_desktop_queue_drops_the_frame_and_answers_the_sender() {
        let (state, _gate, _dir) = gate_state(false, Duration::from_secs(1));
        let (desktop, mut desktop_rx, desktop_kill) = handle_with_cap(1);
        // `ready` fills the desktop's queue of one; nobody reads it.
        state.hub.register_desktop("desk", desktop, "{}".into());
        let (me, mut me_rx, me_kill) = handle_with_cap(8);
        let cmd = json!({"t":"cmd","body":"b","sig":"s"}).to_string();
        device_frame(&state, "dev", "desk", &me, &cmd);
        let Ok(Out::Text(t)) = me_rx.try_recv() else {
            panic!("the sender must be answered")
        };
        assert_eq!(serde_json::from_str::<Value>(&t).unwrap()["code"], "busy");
        assert!(!desktop_kill.is_cancelled(), "the desktop stays connected");
        assert!(!me_kill.is_cancelled());
        // Only `ready` is queued: the cmd was dropped, not delivered late.
        assert!(matches!(desktop_rx.try_recv(), Ok(Out::Text(_))));
        assert!(desktop_rx.try_recv().is_err());
        // Once the desktop drains, commands flow again.
        device_frame(&state, "dev", "desk", &me, &cmd);
        let Ok(Out::Text(t)) = desktop_rx.try_recv() else {
            panic!("delivered")
        };
        assert_eq!(serde_json::from_str::<Value>(&t).unwrap()["t"], "cmd");
        // Presence hints are dropped the same way.
        hint(&state.hub.desktop("desk").unwrap(), "{}".into());
        hint(&state.hub.desktop("desk").unwrap(), "{}".into());
        assert!(!desktop_kill.is_cancelled());
    }

    #[test]
    fn subscription_validation() {
        let ua = crate::crypto::b64u(&test_pubkey());
        let auth = crate::crypto::b64u(&[1u8; 16]);
        let ok = json!({"endpoint":"https://push.example/abc","keys":{"p256dh":ua,"auth":auth}});
        assert!(parse_sub(Some(&ok)).is_some());
        let http = json!({"endpoint":"http://push.example/abc","keys":{"p256dh":ua,"auth":auth}});
        assert!(parse_sub(Some(&http)).is_none());
        let short_auth =
            json!({"endpoint":"https://push.example/abc","keys":{"p256dh":ua,"auth":"AAAA"}});
        assert!(parse_sub(Some(&short_auth)).is_none());
        let bad_key =
            json!({"endpoint":"https://push.example/abc","keys":{"p256dh":"AAAA","auth":auth}});
        assert!(parse_sub(Some(&bad_key)).is_none());
        assert!(parse_sub(None).is_none());
        assert!(parse_sub(Some(&json!({"endpoint":5}))).is_none());
    }

    fn test_pubkey() -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::SecretKey::random(&mut rand_core::OsRng);
        sk.public_key().to_encoded_point(false).as_bytes().to_vec()
    }
}
