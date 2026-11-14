//! Pairing (`ek`, `pair_challenge`) and the limits that stop one party from
//! exhausting what belongs to another (PROTOCOL.md sections 4 and 7).

mod common;

use std::time::Duration;

use common::*;
use serde_json::{json, Value};

#[tokio::test]
async fn pair_request_ek_is_validated_and_forwarded() {
    use ymux_server::crypto::b64u;
    let srv = start_server(|_| {}).await;
    let (did, dk) = (uuid(130), keys());
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    send(&mut desktop, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let good = ek_pub();
    let bad: Vec<Option<String>> = vec![
        None,
        Some(String::new()),
        Some("***not base64***".into()),
        Some(b64u(&[4u8; 65])),
        Some(b64u(&[0u8; 65])),
        Some(b64u(&[2u8; 33])),
        Some(b64u(&[4u8; 64])),
        Some(format!("{good}AAAA")),
    ];
    for (i, ek) in bad.into_iter().enumerate() {
        let dev = uuid(150 + i as u8);
        let k = keys();
        let mut pws = connect(&srv, "/ws/pair", Some(&srv.origin)).await.unwrap();
        let nonce = read_challenge(&mut pws).await;
        let mut req = json!({
            "t":"pair_request","v":1,"desktop_id":did,"device_id":dev,"pubkey":k.pk,"name":"x","proof":"p",
            "sig": sign(&k, &ymux_server::crypto::pair_string(&dev, &nonce)),
        });
        if let Some(ek) = &ek {
            req["ek"] = json!(ek);
        }
        send(&mut pws, req).await;
        assert_eq!(
            recv_t(&mut pws, "error").await["code"],
            "bad_request",
            "{ek:?}"
        );
        expect_closed(&mut pws).await;
    }
    // None of those reached the desktop or used one of the window's five slots.
    assert!(drain(&mut desktop, 200).await.is_empty());

    let dev = uuid(170);
    let (_pws, dk2, ek) = pair_request(&srv, &did, &dev).await;
    let fwd = recv_t(&mut desktop, "pair_request").await;
    assert_eq!(
        fwd,
        json!({
            "t":"pair_request","device_id":dev,"pubkey":dk2.pk,"ek":ek,"name":"iPhone",
            "proof": proof(&[7u8; 16], &did, &dev, &dk2.pk, &ek),
        })
    );
    srv.running.stop().await;
}

#[tokio::test]
async fn pair_challenge_reaches_only_its_pairing_socket() {
    let srv = start_server(|_| {}).await;
    let (did, dk) = (uuid(131), keys());
    let mut desktop = desktop_ready(&srv, &did, &dk, Some(&srv.token)).await;
    let mut other = desktop_ready(&srv, &uuid(132), &keys(), Some(&srv.token)).await;
    send(&mut desktop, json!({"t":"pair_open","ttl_s":120})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (dev_a, dev_b) = (uuid(141), uuid(142));
    let (mut a, _, _) = pair_request(&srv, &did, &dev_a).await;
    recv_t(&mut desktop, "pair_request").await;
    let (mut b, _, _) = pair_request(&srv, &did, &dev_b).await;
    recv_t(&mut desktop, "pair_request").await;

    // To A, and to nobody else.
    send(
        &mut desktop,
        json!({"t":"pair_challenge","device_id":dev_a,"body":"sealedA"}),
    )
    .await;
    assert_eq!(
        recv_t(&mut a, "pair_challenge").await,
        json!({"t":"pair_challenge","body":"sealedA"})
    );
    assert!(drain(&mut b, 300).await.is_empty());

    // Another desktop cannot reach A's socket, and an unknown device id is ignored.
    send(
        &mut other,
        json!({"t":"pair_challenge","device_id":dev_a,"body":"forged"}),
    )
    .await;
    send(
        &mut desktop,
        json!({"t":"pair_challenge","device_id":uuid(199),"body":"nobody"}),
    )
    .await;
    assert!(drain(&mut a, 300).await.is_empty());
    assert!(drain(&mut b, 100).await.is_empty());
    assert!(drain(&mut other, 100).await.is_empty());
    assert!(
        drain(&mut desktop, 100).await.is_empty(),
        "ignored silently"
    );

    // Malformed frames are bad_request and go nowhere; 4 KiB itself is fine.
    for bad in [
        json!({"t":"pair_challenge","device_id":dev_a,"body":"x".repeat(4097)}),
        json!({"t":"pair_challenge","device_id":dev_a}),
        json!({"t":"pair_challenge","body":"x"}),
        json!({"t":"pair_challenge","device_id":"*","body":"x"}),
    ] {
        send(&mut desktop, bad).await;
        assert_eq!(recv_t(&mut desktop, "error").await["code"], "bad_request");
    }
    assert!(drain(&mut a, 200).await.is_empty());
    let max = "y".repeat(4096);
    send(
        &mut desktop,
        json!({"t":"pair_challenge","device_id":dev_a,"body":max}),
    )
    .await;
    assert_eq!(recv_t(&mut a, "pair_challenge").await["body"], max);

    // At most three per pairing request: the third arrives, the rest are ignored.
    for body in ["third", "fourth", "fifth"] {
        send(
            &mut desktop,
            json!({"t":"pair_challenge","device_id":dev_a,"body":body}),
        )
        .await;
    }
    assert_eq!(recv_t(&mut a, "pair_challenge").await["body"], "third");
    assert!(drain(&mut a, 300).await.is_empty());
    // The count is per request: B has its own three.
    send(
        &mut desktop,
        json!({"t":"pair_challenge","device_id":dev_b,"body":"forB"}),
    )
    .await;
    assert_eq!(recv_t(&mut b, "pair_challenge").await["body"], "forB");

    // Once the request is answered there is nothing left to deliver to ...
    send(
        &mut desktop,
        json!({"t":"pair_result","device_id":dev_a,"ok":false}),
    )
    .await;
    assert_eq!(
        recv_t(&mut a, "pair_result").await,
        json!({"t":"pair_result","ok":false})
    );
    send(
        &mut desktop,
        json!({"t":"pair_challenge","device_id":dev_a,"body":"late"}),
    )
    .await;
    // ... and none once the window is closed: B only learns that it ended.
    send(&mut desktop, json!({"t":"pair_close"})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(
        &mut desktop,
        json!({"t":"pair_challenge","device_id":dev_b,"body":"after close"}),
    )
    .await;
    assert_eq!(
        drain(&mut b, 300).await,
        vec![json!({"t":"pair_result","ok":false})]
    );
    assert!(drain(&mut desktop, 100).await.is_empty());
    srv.running.stop().await;
}

fn count(frames: &[Value], t: &str) -> usize {
    frames.iter().filter(|f| f["t"] == t).count()
}

#[tokio::test]
async fn device_cmd_rate_limit_is_20_per_second_burst_40() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(133), uuid(143));
    let mut desktop = desktop_ready(&srv, &did, &keys(), Some(&srv.token)).await;
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;
    let (mut device, _) = device_login(&srv, &dev, &devk).await;
    recv_t(&mut desktop, "device_online").await;

    for i in 0..100 {
        send(
            &mut device,
            json!({"t":"cmd","body":format!("b{i}"),"sig":"s"}),
        )
        .await;
    }
    let at_desktop = drain(&mut desktop, 400).await;
    let at_device = drain(&mut device, 400).await;
    let relayed = count(&at_desktop, "cmd");
    assert!(
        (40..=48).contains(&relayed),
        "burst of 40 plus a little refill, got {relayed}"
    );
    assert_eq!(count(&at_device, "error"), 100 - relayed);
    assert!(at_device.iter().all(|f| f["code"] == "rate_limited"));
    // The relayed ones are the first ones, in order.
    assert_eq!(at_desktop[0]["body"], "b0");

    // The connection stays open and the bucket refills: 250 ms is five tokens.
    tokio::time::sleep(Duration::from_millis(250)).await;
    send(&mut device, json!({"t":"cmd","body":"later","sig":"s"})).await;
    assert_eq!(recv_t(&mut desktop, "cmd").await["body"], "later");

    // The limit is per device: another device is not slowed down.
    let dev2 = uuid(144);
    let devk2 = pair_device(&srv, &mut desktop, &did, &dev2).await;
    let (mut second, _) = device_login(&srv, &dev2, &devk2).await;
    for i in 0..10 {
        send(
            &mut second,
            json!({"t":"cmd","body":format!("s{i}"),"sig":"s"}),
        )
        .await;
    }
    assert!(drain(&mut second, 300).await.is_empty());

    // Reconnecting does not hand out a fresh burst.
    for i in 0..60 {
        send(
            &mut second,
            json!({"t":"cmd","body":format!("x{i}"),"sig":"s"}),
        )
        .await;
    }
    let (mut again, ready) = device_login(&srv, &dev2, &devk2).await;
    assert_eq!(ready["t"], "ready");
    for i in 0..40 {
        send(
            &mut again,
            json!({"t":"cmd","body":format!("r{i}"),"sig":"s"}),
        )
        .await;
    }
    let errors = drain(&mut again, 400).await;
    assert!(
        errors
            .iter()
            .filter(|f| f["code"] == "rate_limited")
            .count()
            >= 35,
        "{errors:?}"
    );
    srv.running.stop().await;
}

#[tokio::test]
async fn push_subscription_changes_are_rate_limited() {
    let srv = start_server(|_| {}).await;
    let (did, dev) = (uuid(134), uuid(145));
    let mut desktop = desktop_ready(&srv, &did, &keys(), Some(&srv.token)).await;
    let devk = pair_device(&srv, &mut desktop, &did, &dev).await;
    let (mut device, _) = device_login(&srv, &dev, &devk).await;
    for _ in 0..8 {
        send(&mut device, json!({"t":"push_unsubscribe"})).await;
    }
    let frames = drain(&mut device, 300).await;
    assert_eq!(frames.len(), 3, "burst of 5, then refused: {frames:?}");
    assert!(frames.iter().all(|f| f["code"] == "rate_limited"));
    srv.running.stop().await;
}

/// A desktop that does not read while devices flood it: the frames that do not
/// fit are dropped and answered `busy` to their senders; the desktop is never
/// disconnected and works again once it reads.
#[tokio::test]
async fn full_desktop_queue_answers_busy_and_keeps_the_desktop_connected() {
    let srv = start_server(|_| {}).await;
    let did = uuid(135);
    let mut desktop = desktop_ready(&srv, &did, &keys(), Some(&srv.token)).await;
    let mut paired = Vec::new();
    for i in 0..4u8 {
        let dev = uuid(146 + i);
        paired.push((
            dev.clone(),
            pair_device(&srv, &mut desktop, &did, &dev).await,
        ));
    }
    let mut devices = Vec::new();
    for (dev, devk) in &paired {
        let (ws, _) = device_login(&srv, dev, devk).await;
        devices.push((dev.clone(), ws));
        recv_t(&mut desktop, "device_online").await;
    }
    // Large bodies, so the desktop's socket buffers fill and its queue backs up.
    let body = "A".repeat(190 * 1024);
    let (mut busy, mut limited, mut sent) = (0usize, 0usize, 0usize);
    for _ in 0..10 {
        for (_, ws) in devices.iter_mut() {
            for _ in 0..20 {
                send(ws, json!({"t":"cmd","body":body,"sig":"s"})).await;
                sent += 1;
            }
        }
        for (_, ws) in devices.iter_mut() {
            for f in drain(ws, 100).await {
                assert_eq!(f["t"], "error", "{f}");
                match f["code"].as_str().unwrap() {
                    "busy" => busy += 1,
                    "rate_limited" => limited += 1,
                    other => panic!("unexpected error {other}"),
                }
            }
        }
        if busy > 0 {
            break;
        }
    }
    assert!(busy > 0, "the desktop's queue never filled ({sent} sent)");
    // Still registered; nothing disconnected it.
    assert!(srv.state.hub.desktop(&did).is_some());
    // It reads again: it gets what was queued, and stays usable.
    let mut cmds = 0;
    loop {
        let frames = drain(&mut desktop, 500).await;
        if frames.is_empty() {
            break;
        }
        cmds += count(&frames, "cmd");
    }
    assert!(cmds > 0 && cmds + busy + limited <= sent);
    assert!(srv.state.hub.desktop(&did).is_some());
    let (dev0, ws0) = &mut devices[0];
    send(
        &mut desktop,
        json!({"t":"msg","to":dev0,"body":"still here"}),
    )
    .await;
    assert_eq!(recv_t(ws0, "msg").await["body"], "still here");
    srv.running.stop().await;
}
