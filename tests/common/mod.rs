#![allow(dead_code)]
// Test helpers hand tungstenite's own error back to the test, which matches on
// it; boxing it would only make those matches noisier.
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::Sha256;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use ymux_server::config::{Config, Timing};
use ymux_server::crypto::{b64u, desktop_string, device_string, pair_string, unb64u, PREFIX};
use ymux_server::push::{BoxFut, PushOutcome, PushSender};
use ymux_server::server::{start, AppState, Running};
use ymux_server::state::{PushSub, Store};

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct MockPush {
    pub sent: Mutex<Vec<(String, Value)>>,
    pub outcome: Mutex<PushOutcome>,
}

impl PushSender for MockPush {
    fn send<'a>(&'a self, sub: &'a PushSub, payload: &'a [u8]) -> BoxFut<'a, PushOutcome> {
        Box::pin(async move {
            let v: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
            self.sent.lock().unwrap().push((sub.endpoint.clone(), v));
            *self.outcome.lock().unwrap()
        })
    }
}

pub struct Srv {
    pub running: Running,
    pub origin: String,
    /// The setup token as it was when the server started (it can be rotated since).
    pub token: String,
    pub push: Arc<MockPush>,
    pub state: Arc<AppState>,
    _dir: TempDir,
}

impl Srv {
    pub fn addr(&self) -> String {
        self.running.addr.to_string()
    }

    pub fn data_dir(&self) -> &std::path::Path {
        self._dir.path()
    }
}

pub async fn start_server(tweak: impl FnOnce(&mut Timing)) -> Srv {
    start_server_with(tweak, |_| {}).await
}

pub async fn start_server_with(
    tweak: impl FnOnce(&mut Timing),
    tweak_cfg: impl FnOnce(&mut Config),
) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin = format!("http://127.0.0.1:{port}");
    let (store, _) = Store::open(dir.path()).unwrap();
    let token = store.setup_token().unwrap();
    let mut timing = Timing::default();
    tweak(&mut timing);
    let mut cfg = Config {
        bind: listener.local_addr().unwrap(),
        origin: origin.clone(),
        https: false,
        data_dir: dir.path().to_path_buf(),
        trust_proxy: false,
        timing,
    };
    tweak_cfg(&mut cfg);
    let push = Arc::new(MockPush {
        sent: Mutex::new(Vec::new()),
        outcome: Mutex::new(PushOutcome::Sent),
    });
    let state = AppState::new(cfg, store, push.clone());
    let running = start(state.clone(), listener).unwrap();
    Srv {
        running,
        origin,
        token,
        push,
        state,
        _dir: dir,
    }
}

pub async fn connect(
    srv: &Srv,
    path: &str,
    origin: Option<&str>,
) -> Result<Ws, tungstenite::Error> {
    connect_via(srv, path, origin, None).await
}

/// Like `connect`, with an `X-Forwarded-For` header as a reverse proxy would set it.
pub async fn connect_via(
    srv: &Srv,
    path: &str,
    origin: Option<&str>,
    forwarded_for: Option<&str>,
) -> Result<Ws, tungstenite::Error> {
    let mut req = format!("ws://{}{}", srv.addr(), path)
        .into_client_request()
        .unwrap();
    if let Some(o) = origin {
        req.headers_mut().insert("Origin", o.parse().unwrap());
    }
    if let Some(f) = forwarded_for {
        req.headers_mut()
            .insert("X-Forwarded-For", f.parse().unwrap());
    }
    let (ws, _) = tokio_tungstenite::connect_async(req).await?;
    Ok(ws)
}

pub fn status_of(e: tungstenite::Error) -> u16 {
    match e {
        tungstenite::Error::Http(r) => r.status().as_u16(),
        other => panic!("expected an HTTP rejection, got {other:?}"),
    }
}

/// Next JSON text frame; None when the socket closed.
pub async fn recv(ws: &mut Ws) -> Option<Value> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Err(_) => panic!("timed out waiting for a frame"),
            Ok(None) | Ok(Some(Err(_))) => return None,
            Ok(Some(Ok(Message::Text(t)))) => {
                return Some(serde_json::from_str(t.as_str()).unwrap())
            }
            Ok(Some(Ok(Message::Close(_)))) => return None,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

pub async fn recv_t(ws: &mut Ws, t: &str) -> Value {
    let v = recv(ws)
        .await
        .unwrap_or_else(|| panic!("closed while waiting for {t}"));
    assert_eq!(v["t"], t, "got {v}");
    v
}

/// Every frame that arrives until the socket has been quiet for `quiet_ms`.
pub async fn drain(ws: &mut Ws, quiet_ms: u64) -> Vec<Value> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(quiet_ms), ws.next()).await {
            Err(_) => return out,
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return out,
            Ok(Some(Ok(Message::Text(t)))) => out.push(serde_json::from_str(t.as_str()).unwrap()),
            Ok(Some(Ok(_))) => continue,
        }
    }
}

pub async fn expect_closed(ws: &mut Ws) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Err(_) => panic!("socket did not close"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

pub async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

pub struct Keys {
    pub sk: SigningKey,
    pub pk: String,
}

pub fn keys() -> Keys {
    let sk = SigningKey::random(&mut OsRng);
    let pk = b64u(sk.verifying_key().to_encoded_point(false).as_bytes());
    Keys { sk, pk }
}

pub fn sign(k: &Keys, msg: &str) -> String {
    let s: Signature = k.sk.sign(msg.as_bytes());
    b64u(&s.to_bytes())
}

pub fn uuid(n: u8) -> String {
    format!("{n:08x}-0000-4000-8000-{n:012x}")
}

pub async fn read_challenge(ws: &mut Ws) -> String {
    let c = recv_t(ws, "challenge").await;
    assert_eq!(c["v"], 1);
    let nonce = c["nonce"].as_str().unwrap().to_string();
    assert_eq!(unb64u(&nonce).unwrap().len(), 32);
    nonce
}

/// The challenge's `origin` field (read by `read_challenge_full`).
pub async fn read_challenge_full(ws: &mut Ws) -> (String, String) {
    let c = recv_t(ws, "challenge").await;
    (
        c["nonce"].as_str().unwrap().to_string(),
        c["origin"]
            .as_str()
            .expect("challenge carries origin")
            .to_string(),
    )
}

/// A desktop hello signed for `origin` (the server's own, normally).
pub fn desktop_hello(id: &str, k: &Keys, origin: &str, nonce: &str, token: Option<&str>) -> Value {
    let mut h = json!({
        "t": "hello", "role": "desktop", "v": 1, "desktop_id": id, "pubkey": k.pk, "name": "Test PC",
        "sig": sign(k, &desktop_string(id, origin, nonce)),
    });
    if let Some(t) = token {
        h["setup_token"] = json!(t);
    }
    h
}

/// Connects a desktop and returns the socket plus the first reply to its hello.
pub async fn desktop_login(srv: &Srv, id: &str, k: &Keys, token: Option<&str>) -> (Ws, Value) {
    let mut ws = connect(srv, "/ws/desktop", None).await.unwrap();
    // Sign what the challenge says, as a desktop does after comparing it
    // with the address it was configured with.
    let (nonce, origin) = read_challenge_full(&mut ws).await;
    assert_eq!(origin, srv.origin);
    send(&mut ws, desktop_hello(id, k, &origin, &nonce, token)).await;
    let reply = recv(&mut ws).await.expect("reply");
    (ws, reply)
}

pub async fn desktop_ready(srv: &Srv, id: &str, k: &Keys, token: Option<&str>) -> Ws {
    let (ws, reply) = desktop_login(srv, id, k, token).await;
    assert_eq!(reply["t"], "ready", "{reply}");
    ws
}

pub async fn device_login(srv: &Srv, id: &str, k: &Keys) -> (Ws, Value) {
    let mut ws = connect(srv, "/ws/device", Some(&srv.origin)).await.unwrap();
    let nonce = read_challenge(&mut ws).await;
    let hello = json!({"t":"hello","role":"device","v":1,"device_id":id,"sig":sign(k, &device_string(id, &nonce))});
    send(&mut ws, hello).await;
    let reply = recv(&mut ws).await.expect("reply");
    (ws, reply)
}

/// A fresh ECDH public key as a device would send it in `ek`.
pub fn ek_pub() -> String {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = p256::SecretKey::random(&mut OsRng);
    b64u(sk.public_key().to_encoded_point(false).as_bytes())
}

pub fn proof(code: &[u8], desktop_id: &str, device_id: &str, pubkey: &str, ek: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(code).unwrap();
    mac.update(format!("{PREFIX}|pair|{desktop_id}|{device_id}|{pubkey}|{ek}").as_bytes());
    b64u(&mac.finalize().into_bytes())
}

/// Opens a pair socket, sends a `pair_request` for `device_id` and returns the
/// socket, the device keys and the `ek` sent. The request is NOT yet answered.
pub async fn pair_request(srv: &Srv, desktop_id: &str, device_id: &str) -> (Ws, Keys, String) {
    let dk = keys();
    let ek = ek_pub();
    let mut pws = connect(srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
    let nonce = read_challenge(&mut pws).await;
    send(
        &mut pws,
        json!({
            "t":"pair_request","v":1,"desktop_id":desktop_id,"device_id":device_id,"pubkey":dk.pk,"ek":ek,"name":"iPhone",
            "proof": proof(&[7u8; 16], desktop_id, device_id, &dk.pk, &ek),
            "sig": sign(&dk, &pair_string(device_id, &nonce)),
        }),
    )
    .await;
    (pws, dk, ek)
}

/// Full pairing as the test: desktop opens a window, the device requests,
/// the desktop verifies the proof and approves. Returns the device keys.
pub async fn pair_device(srv: &Srv, desktop: &mut Ws, desktop_id: &str, device_id: &str) -> Keys {
    let code = [7u8; 16];
    send(desktop, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (mut pws, dk, ek) = pair_request(srv, desktop_id, device_id).await;
    let fwd = recv_t(desktop, "pair_request").await;
    assert_eq!(fwd["device_id"], device_id);
    assert_eq!(fwd["pubkey"], dk.pk);
    assert_eq!(fwd["ek"], ek);
    assert_eq!(
        fwd["proof"],
        proof(&code, desktop_id, device_id, &dk.pk, &ek)
    );
    send(
        desktop,
        json!({"t":"pair_result","device_id":device_id,"ok":true,"pubkey":dk.pk,"name":"iPhone"}),
    )
    .await;
    let r = recv_t(&mut pws, "pair_result").await;
    assert_eq!(r["ok"], true);
    dk
}

pub async fn wait_until(mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached");
}
