mod common;

use std::time::Duration;

use common::*;
use futures_util::SinkExt;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;
use ymux_server::config::Config;
use ymux_server::push::PushOutcome;

#[tokio::test]
async fn http_endpoints_and_headers() {
    let srv = start_server(|_| {}).await;
    let base = format!("http://{}", srv.addr());
    let c = reqwest::Client::new();

    let r = c.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "ok");

    let r = c.get(format!("{base}/api/info")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    let v: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["server"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        ymux_server::crypto::unb64u(v["vapid"].as_str().unwrap())
            .unwrap()
            .len(),
        65
    );

    assert!(h["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(
        h.get("strict-transport-security").is_none(),
        "http dev server has no HSTS"
    );

    let r = c.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert_eq!(r.headers()["cache-control"], "no-cache");
    assert!(r.headers().contains_key("content-security-policy"));

    assert_eq!(
        c.get(format!("{base}/nope")).send().await.unwrap().status(),
        404
    );
    assert_eq!(
        c.post(format!("{base}/")).send().await.unwrap().status(),
        405
    );
    srv.running.stop().await;
}

#[tokio::test]
async fn desktop_registration() {
    let srv = start_server(|_| {}).await;
    let id = uuid(1);
    let k = keys();

    // Bad token, then no token.
    let (mut ws, reply) = desktop_login(&srv, &id, &k, Some("wrong")).await;
    assert_eq!(reply, json!({"t":"error","code":"bad_token"}));
    expect_closed(&mut ws).await;
    let (mut ws, reply) = desktop_login(&srv, &id, &k, None).await;
    assert_eq!(reply["code"], "bad_token");
    expect_closed(&mut ws).await;

    // Good token registers.
    let mut ws = desktop_ready(&srv, &id, &k, Some(&srv.token)).await;
    drop(ws.close(None).await);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Known desktop: token no longer needed.
    let ws2 = desktop_ready(&srv, &id, &k, None).await;
    drop(ws2);

    // Another key for the same id.
    let other = keys();
    let (mut ws, reply) = desktop_login(&srv, &id, &other, Some(&srv.token)).await;
    assert_eq!(reply["code"], "key_mismatch");
    expect_closed(&mut ws).await;

    // Bad signature (signed for a different nonce).
    let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
    let _ = read_challenge(&mut ws).await;
    send(
        &mut ws,
        desktop_hello(&uuid(2), &k, &srv.origin, "AAAA", Some(&srv.token)),
    )
    .await;
    assert_eq!(recv_t(&mut ws, "error").await["code"], "bad_sig");

    // Wrong protocol version.
    let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
    let nonce = read_challenge(&mut ws).await;
    let mut h = desktop_hello(&uuid(3), &k, &srv.origin, &nonce, Some(&srv.token));
    h["v"] = json!(2);
    send(&mut ws, h).await;
    assert_eq!(recv_t(&mut ws, "error").await["code"], "version");
    srv.running.stop().await;
}

#[tokio::test]
async fn challenge_carries_the_servers_origin() {
    let srv = start_server(|_| {}).await;
    for (path, origin) in [
        ("/ws/desktop", None),
        ("/ws/device", Some(srv.origin.as_str())),
        ("/ws/pair", Some(srv.origin.as_str())),
    ] {
        let mut ws = connect(&srv, path, origin).await.unwrap();
        let c = recv_t(&mut ws, "challenge").await;
        assert_eq!(c["origin"], srv.origin, "{path}");
        assert_eq!(c["v"], 1);
        assert_eq!(c["server"], env!("CARGO_PKG_VERSION"));
    }
    srv.running.stop().await;
}

/// A hello signed for another origin (a challenge relayed from a different
/// server) never verifies, for a new desktop or a known one, and with or
/// without a valid setup token.
#[tokio::test]
async fn hello_signed_for_another_origin_is_bad_sig() {
    let srv = start_server(|_| {}).await;
    let (id, k) = (uuid(4), keys());
    let wrong = [
        "https://evil.example".to_string(),
        srv.origin.replace("http://", "https://"),
        format!("{}/", srv.origin),
        srv.origin.to_uppercase(),
        String::new(),
    ];
    for other in &wrong {
        let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
        let nonce = read_challenge(&mut ws).await;
        send(
            &mut ws,
            desktop_hello(&id, &k, other, &nonce, Some(&srv.token)),
        )
        .await;
        assert_eq!(
            recv_t(&mut ws, "error").await["code"],
            "bad_sig",
            "{other:?}"
        );
        expect_closed(&mut ws).await;
    }
    assert!(srv.state.store.lock().unwrap().state.desktops.is_empty());

    // The same key signing for the right origin registers.
    let ws = desktop_ready(&srv, &id, &k, Some(&srv.token)).await;
    drop(ws);
    wait_until(|| srv.state.hub.desktop(&id).is_none()).await;

    // A known desktop is held to the origin as well.
    let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
    let nonce = read_challenge(&mut ws).await;
    send(
        &mut ws,
        desktop_hello(&id, &k, "https://evil.example", &nonce, None),
    )
    .await;
    assert_eq!(recv_t(&mut ws, "error").await["code"], "bad_sig");
    srv.running.stop().await;
}

/// PROTOCOL 4.6: an approval must name the key from the original request.
#[tokio::test]
async fn pair_result_must_name_the_requested_key() {
    let srv = start_server(|_| {}).await;
    let (did, dk) = (uuid(7), keys());
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    send(&mut desktop, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (i, result_key) in [Some(keys().pk), None].into_iter().enumerate() {
        let dev = uuid(8 + i as u8);
        let k = keys();
        let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
        let nonce = read_challenge(&mut pws).await;
        send(
            &mut pws,
            json!({"t":"pair_request","v":1,"desktop_id":did,"device_id":dev,"pubkey":k.pk,"ek":ek_pub(),"name":"x","proof":"p",
                   "sig": sign(&k, &ymux_server::crypto::pair_string(&dev, &nonce))}),
        )
        .await;
        recv_t(&mut desktop, "pair_request").await;
        let mut result = json!({"t":"pair_result","device_id":dev,"ok":true,"name":"x"});
        if let Some(pk) = result_key {
            result["pubkey"] = json!(pk);
        }
        send(&mut desktop, result).await;
        assert_eq!(recv_t(&mut pws, "pair_result").await["ok"], false);
    }
    assert!(srv.state.store.lock().unwrap().state.devices.is_empty());
    srv.running.stop().await;
}

#[tokio::test]
async fn names_are_cleaned_when_stored_and_forwarded() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(5), uuid(6));
    let dk = keys();
    let evil = "Eve\u{202E}lP\u{200B}C\u{FEFF}\u{2028}";
    // The desktop's own name, from its hello.
    let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
    let nonce = read_challenge(&mut ws).await;
    let mut hello = desktop_hello(&did, &dk, &srv.origin, &nonce, Some(&srv.token));
    hello["name"] = json!(evil);
    send(&mut ws, hello).await;
    recv_t(&mut ws, "ready").await;
    assert_eq!(
        srv.state.store.lock().unwrap().state.desktops[&did].name,
        "EvelPC"
    );

    // The device's name, in the request forwarded to the desktop and as stored.
    send(&mut ws, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let k = keys();
    let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
    let nonce = read_challenge(&mut pws).await;
    send(
        &mut pws,
        json!({"t":"pair_request","v":1,"desktop_id":did,"device_id":dev,"pubkey":k.pk,"ek":ek_pub(),
               "name": format!("{evil}{}", "x".repeat(200)),
               "proof":"p","sig": sign(&k, &ymux_server::crypto::pair_string(&dev, &nonce))}),
    )
    .await;
    let fwd = recv_t(&mut ws, "pair_request").await;
    let name = fwd["name"].as_str().unwrap();
    assert!(
        name.starts_with("EvelPCx") && name.chars().count() == 40,
        "{name:?}"
    );
    // A result name with format characters is cleaned too.
    send(
        &mut ws,
        json!({"t":"pair_result","device_id":dev,"ok":true,"pubkey":k.pk,"name":"Ph\u{202E}one"}),
    )
    .await;
    assert_eq!(recv_t(&mut pws, "pair_result").await["ok"], true);
    assert_eq!(
        srv.state.store.lock().unwrap().state.devices[&dev].name,
        "Phone"
    );
    srv.running.stop().await;
}

#[tokio::test]
async fn origin_rules() {
    let srv = start_server(|_| {}).await;
    // A desktop is not a browser: any Origin is refused.
    assert_eq!(
        status_of(
            connect(&srv, "/ws/desktop", Some(&srv.origin))
                .await
                .err()
                .unwrap()
        ),
        403
    );
    assert_eq!(
        status_of(
            connect(&srv, "/ws/desktop", Some("https://evil.example"))
                .await
                .err()
                .unwrap()
        ),
        403
    );
    assert!(connect(&srv, "/ws/desktop", None).await.is_ok());
    // Devices need exactly the public origin.
    for path in ["/ws/device", "/ws/pair"] {
        assert_eq!(
            status_of(connect(&srv, path, None).await.err().unwrap()),
            403,
            "{path}"
        );
        assert_eq!(
            status_of(
                connect(&srv, path, Some("https://evil.example"))
                    .await
                    .err()
                    .unwrap()
            ),
            403
        );
        assert_eq!(
            status_of(
                connect(&srv, path, Some("http://127.0.0.1:1"))
                    .await
                    .err()
                    .unwrap()
            ),
            403
        );
        let mut ws = connect(&srv, path, Some(&srv.origin)).await.unwrap();
        recv_t(&mut ws, "challenge").await;
    }
    srv.running.stop().await;
}

#[tokio::test]
async fn pairing_relay_and_removal_end_to_end() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(10), uuid(11));
    let dk = keys();
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;

    // No window yet.
    {
        let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
        let nonce = read_challenge(&mut pws).await;
        let k = keys();
        send(
            &mut pws,
            json!({"t":"pair_request","v":1,"desktop_id":did,"device_id":dev,"pubkey":k.pk,"ek":ek_pub(),"name":"x","proof":"p",
                   "sig": sign(&k, &ymux_server::crypto::pair_string(&dev, &nonce))}),
        )
        .await;
        assert_eq!(recv_t(&mut pws, "error").await["code"], "no_pairing");
    }

    // A request whose desktop rejects the proof gets ok:false and nothing is stored.
    send(&mut desktop, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    {
        let k = keys();
        let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
        let nonce = read_challenge(&mut pws).await;
        send(
            &mut pws,
            json!({"t":"pair_request","v":1,"desktop_id":did,"device_id":dev,"pubkey":k.pk,"ek":ek_pub(),"name":"x","proof":"bad",
                   "sig": sign(&k, &ymux_server::crypto::pair_string(&dev, &nonce))}),
        )
        .await;
        recv_t(&mut desktop, "pair_request").await;
        send(
            &mut desktop,
            json!({"t":"pair_result","device_id":dev,"ok":false}),
        )
        .await;
        assert_eq!(recv_t(&mut pws, "pair_result").await["ok"], false);
        assert!(srv.state.store.lock().unwrap().state.devices.is_empty());
    }

    // The real pairing.
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;
    assert!(srv
        .state
        .store
        .lock()
        .unwrap()
        .state
        .devices
        .contains_key(&dev));

    // The window closed with the success: a second request finds no pairing.
    {
        let k = keys();
        let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
        let nonce = read_challenge(&mut pws).await;
        send(
            &mut pws,
            json!({"t":"pair_request","v":1,"desktop_id":did,"device_id":uuid(12),"pubkey":k.pk,"ek":ek_pub(),"name":"x","proof":"p",
                   "sig": sign(&k, &ymux_server::crypto::pair_string(&uuid(12), &nonce))}),
        )
        .await;
        assert_eq!(recv_t(&mut pws, "error").await["code"], "no_pairing");
    }

    // Device connects: the desktop is told, with a conn id.
    let (mut device, ready) = device_login(&srv, &dev, &devk).await;
    assert_eq!(
        ready,
        json!({"t":"ready","desktop_id":did,"desktop_online":true})
    );
    let online = recv_t(&mut desktop, "device_online").await;
    assert_eq!(online["device_id"], dev);
    let conn = online["conn"].as_str().unwrap().to_string();
    assert_eq!(ymux_server::crypto::unb64u(&conn).unwrap().len(), 8);

    // Device -> desktop.
    let body = r#"{"k":"cmd","seq":1}"#;
    send(&mut device, json!({"t":"cmd","body":body,"sig":"c2ln"})).await;
    let cmd = recv_t(&mut desktop, "cmd").await;
    assert_eq!(cmd["device_id"], dev);
    assert_eq!(cmd["conn"], conn);
    assert_eq!(cmd["body"], body, "body is relayed byte for byte");
    assert_eq!(cmd["sig"], "c2ln");

    // Desktop -> device, addressed to one device id.
    send(&mut desktop, json!({"t":"msg","to":dev,"body":"one"})).await;
    assert_eq!(
        recv_t(&mut device, "msg").await,
        json!({"t":"msg","body":"one"})
    );
    // No broadcast: "*" (and anything that is not a device id) is a bad request
    // and reaches nobody.
    for to in [json!("*"), json!(""), json!("all"), json!(5), json!(null)] {
        send(&mut desktop, json!({"t":"msg","to":to,"body":"all"})).await;
        assert_eq!(
            recv_t(&mut desktop, "error").await["code"],
            "bad_request",
            "{to}"
        );
    }
    send(&mut desktop, json!({"t":"msg","body":"no addressee"})).await;
    assert_eq!(recv_t(&mut desktop, "error").await["code"], "bad_request");
    // An oversize body is still refused.
    send(
        &mut desktop,
        json!({"t":"msg","to":dev,"body":"x".repeat(201 * 1024)}),
    )
    .await;
    assert_eq!(recv_t(&mut desktop, "error").await["code"], "bad_request");
    send(&mut desktop, json!({"t":"msg","to":dev,"body":"two"})).await;
    assert_eq!(
        recv_t(&mut device, "msg").await["body"],
        "two",
        "nothing was delivered for the rejected frames"
    );
    // Unknown target and unknown frame types do not break anything.
    send(&mut desktop, json!({"t":"msg","to":uuid(99),"body":"x"})).await;
    send(&mut desktop, json!({"t":"bogus"})).await;
    assert_eq!(recv_t(&mut desktop, "error").await["code"], "unknown_type");
    send(&mut device, json!({"t":"bogus"})).await;
    assert_eq!(recv_t(&mut device, "error").await["code"], "unknown_type");

    // Desktop replaced by a reconnect: the old socket closes, the new one
    // learns about the connected device, the device keeps its connection.
    let mut desktop2 = desktop_ready(&srv, &did, &dk, None).await;
    expect_closed(&mut desktop).await;
    let online2 = recv_t(&mut desktop2, "device_online").await;
    assert_eq!(online2["conn"], conn);
    assert_eq!(
        recv_t(&mut device, "desktop_online").await,
        json!({"t":"desktop_online"})
    );
    send(&mut device, json!({"t":"cmd","body":"b","sig":"s"})).await;
    assert_eq!(recv_t(&mut desktop2, "cmd").await["body"], "b");

    // A device cannot be removed by another desktop.
    let other = keys();
    let mut intruder = desktop_ready(&srv, &uuid(20), &other, Some(&srv.token)).await;
    send(&mut intruder, json!({"t":"device_remove","device_id":dev})).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(srv
        .state
        .store
        .lock()
        .unwrap()
        .state
        .devices
        .contains_key(&dev));

    // Desktop goes away: the device is told. Then it returns.
    drop(desktop2);
    assert_eq!(
        recv_t(&mut device, "desktop_offline").await,
        json!({"t":"desktop_offline"})
    );
    send(&mut device, json!({"t":"cmd","body":"b","sig":"s"})).await;
    assert_eq!(
        recv_t(&mut device, "error").await["code"],
        "desktop_offline"
    );
    let mut desktop3 = desktop_ready(&srv, &did, &dk, None).await;
    recv_t(&mut desktop3, "device_online").await;
    recv_t(&mut device, "desktop_online").await;

    // device_remove closes the device and forgets it.
    send(&mut desktop3, json!({"t":"device_remove","device_id":dev})).await;
    expect_closed(&mut device).await;
    let (mut again, reply) = device_login(&srv, &dev, &devk).await;
    assert_eq!(reply["code"], "unknown_device");
    expect_closed(&mut again).await;
    assert!(srv.state.store.lock().unwrap().state.devices.is_empty());
    srv.running.stop().await;
}

#[tokio::test]
async fn device_hello_errors() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(30), uuid(31));
    let dk = keys();
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;

    let (_, reply) = device_login(&srv, &uuid(32), &devk).await;
    assert_eq!(reply["code"], "unknown_device");
    let (_, reply) = device_login(&srv, &dev, &keys()).await;
    assert_eq!(reply["code"], "bad_sig");
    let (_, reply) = device_login(&srv, &dev, &devk).await;
    assert_eq!(reply["t"], "ready");
    srv.running.stop().await;
}

#[tokio::test]
async fn oversize_and_binary_frames_close_the_connection() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(40), uuid(41));
    let dk = keys();
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;

    let (mut device, _) = device_login(&srv, &dev, &devk).await;
    let huge = json!({"t":"cmd","body":"x".repeat(300 * 1024),"sig":"s"}).to_string();
    let _ = device.send(Message::text(huge)).await;
    expect_closed(&mut device).await;

    let (mut device, _) = device_login(&srv, &dev, &devk).await;
    device.send(Message::binary(vec![1u8, 2, 3])).await.unwrap();
    expect_closed(&mut device).await;

    // The desktop side too.
    let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
    recv_t(&mut ws, "challenge").await;
    ws.send(Message::binary(vec![0u8])).await.unwrap();
    expect_closed(&mut ws).await;
    srv.running.stop().await;
}

#[tokio::test]
async fn handshake_timeout_closes() {
    let srv = start_server(|t| t.handshake = Duration::from_millis(300)).await;
    let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
    recv_t(&mut ws, "challenge").await;
    let start = std::time::Instant::now();
    expect_closed(&mut ws).await;
    assert!(start.elapsed() < Duration::from_secs(3));
    srv.running.stop().await;
}

#[tokio::test]
async fn idle_connection_is_closed() {
    let srv = start_server(|t| {
        t.ping = Duration::from_secs(3600);
        t.idle = Duration::from_millis(400);
    })
    .await;
    let k = keys();
    let mut ws = desktop_ready(&srv, &uuid(50), &k, Some(&srv.token)).await;
    expect_closed(&mut ws).await;
    srv.running.stop().await;
}

#[tokio::test]
async fn failed_handshakes_are_rate_limited_per_ip() {
    let srv = start_server(|_| {}).await;
    for _ in 0..10 {
        let mut ws = connect(&srv, "/ws/desktop", None).await.unwrap();
        recv_t(&mut ws, "challenge").await;
        send(&mut ws, json!({"t":"hello"})).await;
        assert_eq!(recv_t(&mut ws, "error").await["code"], "bad_sig");
    }
    assert_eq!(
        status_of(connect(&srv, "/ws/desktop", None).await.err().unwrap()),
        429
    );
    assert_eq!(
        status_of(
            connect(&srv, "/ws/device", Some(&srv.origin))
                .await
                .err()
                .unwrap()
        ),
        429
    );
    srv.running.stop().await;
}

async fn fail_one_handshake(srv: &Srv, xff: &str) {
    let mut ws = connect_via(srv, "/ws/desktop", None, Some(xff))
        .await
        .unwrap();
    recv_t(&mut ws, "challenge").await;
    send(&mut ws, json!({"t":"hello"})).await;
    assert_eq!(recv_t(&mut ws, "error").await["code"], "bad_sig");
}

fn proxied(tweak: impl FnOnce(&mut Config)) -> impl FnOnce(&mut Config) {
    move |c| {
        c.trust_proxy = true;
        tweak(c)
    }
}

/// Behind a trusted proxy the limiter keys on the LAST X-Forwarded-For hop,
/// and an IPv6 client is one client per /48.
#[tokio::test]
async fn failed_handshake_limiter_is_keyed_by_ipv6_slash_48() {
    let srv = start_server_with(|_| {}, proxied(|_| {})).await;
    // Ten failures from ten different /64s of one /48 (a client controls all of them).
    for i in 0..10 {
        fail_one_handshake(&srv, &format!("2001:db8:aa:{i:x}::{i:x}")).await;
    }
    for addr in ["2001:db8:aa:bb::1", "2001:db8:aa:ffff:ffff:ffff:ffff:ffff"] {
        assert_eq!(
            status_of(
                connect_via(&srv, "/ws/desktop", None, Some(addr))
                    .await
                    .err()
                    .unwrap()
            ),
            429,
            "{addr} shares the blocked /48"
        );
    }
    // Another /48, an IPv4 client and the proxy itself are not affected.
    for ok in ["2001:db8:ab:cc::1", "198.51.100.9"] {
        assert!(
            connect_via(&srv, "/ws/desktop", None, Some(ok))
                .await
                .is_ok(),
            "{ok}"
        );
    }
    assert!(connect(&srv, "/ws/desktop", None).await.is_ok());
    srv.running.stop().await;
}

#[tokio::test]
async fn trusted_proxy_uses_only_the_last_forwarded_hop() {
    let srv = start_server_with(|_| {}, proxied(|_| {})).await;
    // A client-forged first entry changes nothing: every failure lands on the
    // last hop (what the proxy appended), so rotating forged addresses does not
    // dodge the limiter.
    for i in 0..10 {
        fail_one_handshake(&srv, &format!("203.0.113.{i}, 192.0.2.77")).await;
    }
    assert_eq!(
        status_of(
            connect_via(&srv, "/ws/desktop", None, Some("203.0.113.200, 192.0.2.77"))
                .await
                .err()
                .unwrap()
        ),
        429
    );
    assert!(connect_via(&srv, "/ws/desktop", None, Some("192.0.2.78"))
        .await
        .is_ok());
    srv.running.stop().await;
}

#[tokio::test]
async fn forwarded_for_is_ignored_unless_the_proxy_is_trusted() {
    let srv = start_server(|_| {}).await;
    for i in 0..10 {
        fail_one_handshake(&srv, &format!("203.0.113.{i}")).await;
    }
    // All ten counted against the real peer, whatever the header said.
    assert_eq!(
        status_of(
            connect_via(&srv, "/ws/desktop", None, Some("192.0.2.1"))
                .await
                .err()
                .unwrap()
        ),
        429
    );
    srv.running.stop().await;
}

#[tokio::test]
async fn unauthenticated_connections_are_capped_in_total() {
    let srv = start_server_with(|_| {}, proxied(|_| {})).await;
    let mut held = Vec::new();
    // Eight prefixes, eight each: exactly the total of 64.
    for p in 0..8 {
        for _ in 0..8 {
            held.push(
                connect_via(&srv, "/ws/desktop", None, Some(&format!("198.51.100.{p}")))
                    .await
                    .unwrap(),
            );
        }
    }
    assert_eq!(srv.state.unauth.total(), 64);
    assert_eq!(
        status_of(
            connect_via(&srv, "/ws/desktop", None, Some("198.51.100.99"))
                .await
                .err()
                .unwrap()
        ),
        503
    );
    held.pop();
    wait_until(|| srv.state.unauth.total() < 64).await;
    assert!(
        connect_via(&srv, "/ws/desktop", None, Some("198.51.100.99"))
            .await
            .is_ok()
    );
    srv.running.stop().await;
}

#[tokio::test]
async fn unauthenticated_connections_are_capped_per_prefix() {
    let srv = start_server_with(|_| {}, proxied(|_| {})).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(
            connect_via(&srv, "/ws/desktop", None, Some("203.0.113.5"))
                .await
                .unwrap(),
        );
    }
    let refused = |r: Result<Ws, _>| status_of(r.err().unwrap());
    assert_eq!(
        refused(connect_via(&srv, "/ws/desktop", None, Some("203.0.113.5")).await),
        503
    );
    // Other prefixes still get in.
    assert!(connect_via(&srv, "/ws/desktop", None, Some("203.0.113.6"))
        .await
        .is_ok());

    // IPv6: all of a /48 (several /64s) shares the eight slots.
    let mut six = Vec::new();
    for i in 0..8 {
        six.push(
            connect_via(
                &srv,
                "/ws/device",
                Some(&srv.origin),
                Some(&format!("2001:db8:1:{i:x}::1")),
            )
            .await
            .unwrap(),
        );
    }
    assert_eq!(
        refused(
            connect_via(
                &srv,
                "/ws/pair",
                Some(&srv.origin),
                Some("2001:db8:1:9:9::9")
            )
            .await
        ),
        503
    );
    assert!(
        connect_via(&srv, "/ws/pair", Some(&srv.origin), Some("2001:db8:2:3::1"))
            .await
            .is_ok()
    );

    // A slot frees when a socket goes away.
    held.pop();
    // 7 left in the first prefix + 8 in the IPv6 /48; the probes have gone.
    wait_until(|| srv.state.unauth.total() == 7 + 8).await;
    assert!(connect_via(&srv, "/ws/desktop", None, Some("203.0.113.5"))
        .await
        .is_ok());
    srv.running.stop().await;
}

/// Authenticating releases the unauthenticated slot: a prefix full of idle
/// sockets cannot lock out a client that has already logged in.
#[tokio::test]
async fn authenticated_connections_do_not_count_as_unauthenticated() {
    let srv = start_server(|_| {}).await;
    let mut ready = Vec::new();
    for i in 0..12u8 {
        ready.push(desktop_ready(&srv, &uuid(120 + i), &keys(), Some(&srv.token)).await);
    }
    wait_until(|| srv.state.unauth.total() == 0).await;
    srv.running.stop().await;
}

/// PROTOCOL 3.2: a new authenticated connection of a device replaces the old one.
#[tokio::test]
async fn one_live_connection_per_device() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(130), uuid(131));
    let dk = keys();
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;

    let (mut first, ready) = device_login(&srv, &dev, &devk).await;
    assert_eq!(ready["t"], "ready");
    let on1 = recv_t(&mut desktop, "device_online").await;

    let (mut second, ready) = device_login(&srv, &dev, &devk).await;
    assert_eq!(ready["t"], "ready");
    // The first connection is closed; the desktop hears offline for it, then online for the new one.
    expect_closed(&mut first).await;
    let off = recv_t(&mut desktop, "device_offline").await;
    assert_eq!(off["conn"], on1["conn"]);
    let on2 = recv_t(&mut desktop, "device_online").await;
    assert_ne!(on2["conn"], on1["conn"]);

    // Only the new connection receives and sends.
    send(&mut desktop, json!({"t":"msg","to":dev,"body":"hi"})).await;
    assert_eq!(recv_t(&mut second, "msg").await["body"], "hi");
    send(&mut second, json!({"t":"cmd","body":"b","sig":"s"})).await;
    let cmd = recv_t(&mut desktop, "cmd").await;
    assert_eq!(cmd["conn"], on2["conn"]);
    // The old socket's cleanup did not unregister the new one.
    wait_until(|| srv.state.hub.device_of(&did, &dev).is_some()).await;
    srv.running.stop().await;
}

/// PROTOCOL 3.1: a new authenticated connection of a desktop replaces the old one.
#[tokio::test]
async fn one_live_connection_per_desktop() {
    let srv = start_server(|_| {}).await;
    let (did, dk) = (uuid(140), keys());
    let mut first = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    let mut second = desktop_ready(&srv, &did, &dk, None).await;
    expect_closed(&mut first).await;
    send(&mut second, json!({"t":"bogus"})).await;
    assert_eq!(recv_t(&mut second, "error").await["code"], "unknown_type");
    srv.running.stop().await;
}

/// `ymux-server token --rotate` while the server runs: it takes effect for the
/// next registration at once, and neither side loses the other's writes.
#[tokio::test]
async fn token_rotation_while_the_server_runs() {
    let srv = start_server(|_| {}).await;
    let old = srv.token.clone();
    let (first, k1) = (uuid(150), keys());
    drop(desktop_ready(&srv, &first, &k1, Some(&old)).await);
    wait_until(|| srv.state.hub.desktop(&first).is_none()).await;

    // Rotate (the CLI's whole job) between two registrations.
    let new = ymux_server::state::rotate_token(srv.data_dir()).unwrap();
    assert_ne!(new, old);

    // The old token no longer registers; the new one does.
    let (second, k2) = (uuid(151), keys());
    let (mut ws, reply) = desktop_login(&srv, &second, &k2, Some(&old)).await;
    assert_eq!(reply["code"], "bad_token");
    expect_closed(&mut ws).await;
    let ws2 = desktop_ready(&srv, &second, &k2, Some(&new)).await;
    // The desktop registered before the rotation reconnects without any token.
    let ws1 = desktop_ready(&srv, &first, &k1, None).await;
    drop((ws1, ws2));

    // The server wrote state after the rotation; the rotation survived, and
    // the registrations are all on disk.
    assert_eq!(ymux_server::state::read_token(srv.data_dir()).unwrap(), new);
    let (disk, _) = ymux_server::state::Store::open(srv.data_dir()).unwrap();
    assert!(disk.state.desktops.contains_key(&first));
    assert!(disk.state.desktops.contains_key(&second));
    assert_eq!(disk.setup_token().unwrap(), new);
    // And no setup token is in the state file at all.
    let text = std::fs::read_to_string(srv.data_dir().join("state.json")).unwrap();
    assert!(!text.contains(&new) && !text.contains(&old));
    srv.running.stop().await;
}

/// A token file that disappears refuses new registrations instead of
/// accepting an empty token; known desktops still connect.
#[tokio::test]
async fn missing_token_file_refuses_new_desktops_only() {
    let srv = start_server(|_| {}).await;
    let (id, k) = (uuid(160), keys());
    drop(desktop_ready(&srv, &id, &k, Some(&srv.token)).await);
    wait_until(|| srv.state.hub.desktop(&id).is_none()).await;
    std::fs::remove_file(srv.data_dir().join("setup-token")).unwrap();
    let (mut ws, reply) = desktop_login(&srv, &uuid(161), &keys(), Some("")).await;
    assert_eq!(reply["code"], "bad_token");
    expect_closed(&mut ws).await;
    let (mut ws, reply) = desktop_login(&srv, &uuid(162), &keys(), Some("anything")).await;
    assert_eq!(reply["code"], "bad_token");
    expect_closed(&mut ws).await;
    desktop_ready(&srv, &id, &k, None).await;
    srv.running.stop().await;
}

/// The first-run line says a token exists and how to read it, and the token
/// itself never appears in the server's output; `token` prints it, and
/// `token --rotate` replaces it.
#[test]
fn first_run_does_not_print_the_setup_token() {
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_ymux-server");
    let mut child = Command::new(bin)
        .env("YMUX_SERVER_PUBLIC_URL", "http://127.0.0.1:9")
        .env("YMUX_SERVER_BIND", "127.0.0.1:0")
        .env("YMUX_SERVER_DATA_DIR", dir.path())
        .env("RUST_LOG", "ymux_server=debug")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = child.stderr.take().unwrap();
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut out = String::new();
    // Read until the server reports it is listening (it logs that last).
    while let Some(Ok(l)) = lines.next() {
        out.push_str(&l);
        out.push('\n');
        if l.contains("listening") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let err_text = err_thread.join().unwrap();

    let token = ymux_server::state::read_token(dir.path()).expect("a token file was created");
    assert_eq!(token.len(), 43);
    assert!(out.contains("a setup token was created"), "{out}");
    assert!(out.contains("ymux-server token"), "{out}");
    assert!(out.contains("docker compose exec"), "{out}");
    assert!(
        !out.contains(&token) && !err_text.contains(&token),
        "token leaked into the output"
    );
    assert_eq!(out.lines().filter(|l| l.contains("setup token")).count(), 1);

    // `token` shows it, `token --rotate` replaces it; neither touches state.json.
    let state_before = std::fs::read(dir.path().join("state.json")).unwrap();
    let shown = Command::new(bin)
        .arg("token")
        .env("YMUX_SERVER_DATA_DIR", dir.path())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&shown.stdout).trim(), token);
    let rotated = Command::new(bin)
        .args(["token", "--rotate"])
        .env("YMUX_SERVER_DATA_DIR", dir.path())
        .output()
        .unwrap();
    let new = String::from_utf8_lossy(&rotated.stdout).trim().to_string();
    assert_eq!(new.len(), 43);
    assert_ne!(new, token);
    assert_eq!(ymux_server::state::read_token(dir.path()).unwrap(), new);
    assert_eq!(
        std::fs::read(dir.path().join("state.json")).unwrap(),
        state_before
    );

    // A second start prints no first-run line.
    let mut child = Command::new(bin)
        .env("YMUX_SERVER_PUBLIC_URL", "http://127.0.0.1:9")
        .env("YMUX_SERVER_BIND", "127.0.0.1:0")
        .env("YMUX_SERVER_DATA_DIR", dir.path())
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = String::new();
    for l in BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
    {
        out.push_str(&l);
        if l.contains("listening") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(!out.contains("setup token was created"), "{out}");
    assert!(!out.contains(&new));
}

fn sub(endpoint: &str) -> serde_json::Value {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = p256::SecretKey::random(&mut rand_core::OsRng);
    json!({"endpoint":endpoint,"keys":{
        "p256dh": ymux_server::crypto::b64u(sk.public_key().to_encoded_point(false).as_bytes()),
        "auth": ymux_server::crypto::b64u(&[3u8; 16]),
    }})
}

#[tokio::test]
async fn push_subscribe_notify_clip_and_gone() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(60), uuid(61));
    let dk = keys();
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;
    let (mut device, _) = device_login(&srv, &dev, &devk).await;
    recv_t(&mut desktop, "device_online").await;

    // http endpoints are refused.
    send(
        &mut device,
        json!({"t":"push_subscribe","sub":sub("http://push.example/x")}),
    )
    .await;
    assert_eq!(recv_t(&mut device, "error").await["code"], "bad_request");

    send(
        &mut device,
        json!({"t":"push_subscribe","sub":sub("https://push.example/x")}),
    )
    .await;
    wait_until(|| {
        srv.state.store.lock().unwrap().state.devices[&dev]
            .push
            .is_some()
    })
    .await;

    let pane = uuid(70);
    send(
        &mut desktop,
        json!({"t":"notify","kind":"waiting","title":"T".repeat(200),"body":"B".repeat(500),"pane":pane}),
    )
    .await;
    wait_until(|| !srv.push.sent.lock().unwrap().is_empty()).await;
    {
        let sent = srv.push.sent.lock().unwrap();
        let (ep, payload) = &sent[0];
        assert_eq!(ep, "https://push.example/x");
        assert_eq!(payload["kind"], "waiting");
        assert_eq!(payload["title"].as_str().unwrap().len(), 80);
        assert_eq!(payload["body"].as_str().unwrap().len(), 160);
        assert_eq!(payload["pane"], pane);
    }

    // Bad kind is rejected.
    send(
        &mut desktop,
        json!({"t":"notify","kind":"nope","title":"","body":"","pane":""}),
    )
    .await;
    assert_eq!(recv_t(&mut desktop, "error").await["code"], "bad_request");

    // 410 deletes the subscription.
    *srv.push.outcome.lock().unwrap() = PushOutcome::Gone;
    send(
        &mut desktop,
        json!({"t":"notify","kind":"done","title":"t","body":"b","pane":pane}),
    )
    .await;
    wait_until(|| {
        srv.state.store.lock().unwrap().state.devices[&dev]
            .push
            .is_none()
    })
    .await;

    // Unsubscribe path.
    send(
        &mut device,
        json!({"t":"push_subscribe","sub":sub("https://push.example/y")}),
    )
    .await;
    wait_until(|| {
        srv.state.store.lock().unwrap().state.devices[&dev]
            .push
            .is_some()
    })
    .await;
    send(&mut device, json!({"t":"push_unsubscribe"})).await;
    wait_until(|| {
        srv.state.store.lock().unwrap().state.devices[&dev]
            .push
            .is_none()
    })
    .await;
    srv.running.stop().await;
}

#[tokio::test]
async fn notify_budget_is_30_per_10_minutes() {
    let srv = start_server(|_| {}).await;
    let k = keys();
    let mut desktop = desktop_ready(&srv, &uuid(80), &k, Some(&srv.token)).await;
    for _ in 0..33 {
        send(
            &mut desktop,
            json!({"t":"notify","kind":"done","title":"t","body":"b","pane":""}),
        )
        .await;
    }
    for _ in 0..3 {
        assert_eq!(recv_t(&mut desktop, "error").await["code"], "rate_limited");
    }
    // Exactly three errors: the first 30 were accepted.
    send(&mut desktop, json!({"t":"bogus"})).await;
    assert_eq!(recv_t(&mut desktop, "error").await["code"], "unknown_type");
    srv.running.stop().await;
}

#[tokio::test]
async fn pairing_window_allows_five_requests() {
    let srv = start_server(|_| {}).await;
    let (did, k) = (uuid(90), keys());
    let mut desktop = desktop_ready(&srv, &did, &k, Some(&srv.token)).await;
    send(&mut desktop, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut sockets = Vec::new();
    for i in 0..6u8 {
        let dev = uuid(100 + i);
        let dk = keys();
        let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
        let nonce = read_challenge(&mut pws).await;
        send(
            &mut pws,
            json!({"t":"pair_request","v":1,"desktop_id":did,"device_id":dev,"pubkey":dk.pk,"ek":ek_pub(),"name":"x","proof":"p",
                   "sig": sign(&dk, &ymux_server::crypto::pair_string(&dev, &nonce))}),
        )
        .await;
        if i < 5 {
            recv_t(&mut desktop, "pair_request").await;
        } else {
            assert_eq!(recv_t(&mut pws, "error").await["code"], "no_pairing");
        }
        sockets.push(pws);
    }
    srv.running.stop().await;
}
