//! `fixtures/` holds one valid example per PROTOCOL.md message type, with real
//! signatures, real key derivations and real AES-GCM ciphertexts, all from the
//! fixed test values in `fixtures/keys.json`, so other implementations (the
//! desktop, the PWA) can verify against them. See `fixtures/README.md`.
//!
//! The server never seals anything or derives a link key; `aes-gcm`, `hkdf`,
//! `p256` (ECDH), `hmac` and `sha2` are used here only to generate the
//! fixtures and to check them again from the recorded inputs.
//!
//! `cargo test --test fixtures` verifies them. To rewrite them (everything is
//! deterministic: RFC 6979 signatures, fixed nonces):
//! `YMUX_REGEN_FIXTURES=1 cargo test --test fixtures regenerate`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use ymux_server::auth::{
    check_pair_request, decide_desktop, decide_device, DesktopDecision, Hello,
};
use ymux_server::crypto::{
    b64u, desktop_string, device_string, pair_string, unb64u, verify_sig, PREFIX,
};
use ymux_server::state::{DeviceRec, State};

const ORIGIN: &str = "https://ymux.example.com";
const OTHER_ORIGIN: &str = "https://evil.example";
const DESKTOP_ID: &str = "0b9a7f0e-5c1d-4e55-9f7a-3d2c1b0a9e8d";
const DEVICE_ID: &str = "7c4e2a10-8b3f-4a6d-b5e1-9d0f2c3b4a51";
const PANE_ID: &str = "e3b0c442-98fc-4c14-9afb-f4c8996fb924";
const NOW_MS: u64 = 1_731_600_000_000;

/// Every sealed-body fixture and the direction it is sealed in.
const SEALED_DIRS: [(&str, &str); 8] = [
    ("sealed_pair_check.json", "d2p"),
    ("sealed_open.json", "p2d"),
    ("sealed_session.json", "d2p"),
    ("sealed_cmd.json", "p2d"),
    ("sealed_reply.json", "d2p"),
    ("sealed_panes.json", "d2p"),
    ("sealed_reopen.json", "d2p"),
    ("sealed_bad_sig_reply.json", "d2p"),
];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn key(byte: u8) -> (SigningKey, String) {
    let sk = SigningKey::from_slice(&[byte; 32]).unwrap();
    let pk = b64u(sk.verifying_key().to_encoded_point(false).as_bytes());
    (sk, pk)
}

fn sign(sk: &SigningKey, msg: &str) -> String {
    let s: Signature = sk.sign(msg.as_bytes());
    b64u(&s.to_bytes())
}

fn hmac(key: &[u8], msg: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// An ECDH P-256 key from 32 identical bytes (test keys only).
fn ecdh_key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

/// Raw uncompressed SEC1 point as b64u (what WebCrypto `exportKey("raw")` gives).
fn point(sk: &SecretKey) -> String {
    b64u(sk.public_key().to_encoded_point(false).as_bytes())
}

/// The ECDH shared secret: the 32-byte x coordinate of `sk * peer`.
fn shared_x(sk: &SecretKey, peer: &str) -> [u8; 32] {
    let peer = PublicKey::from_sec1_bytes(&unb64u(peer).unwrap()).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    (*shared.raw_secret_bytes()).into()
}

/// PROTOCOL section 1, link key: `info` string.
fn link_info(desktop_id: &str, device_id: &str, pubkey: &str, ek: &str, dk: &str) -> String {
    format!("{PREFIX}|link|{desktop_id}|{device_id}|{pubkey}|{ek}|{dk}")
}

/// HKDF-SHA256(ikm = shared x, salt = code, info), 32 bytes.
fn link_key(code: &[u8], x: &[u8; 32], info: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(Some(code), x)
        .expand(info.as_bytes(), &mut k)
        .unwrap();
    k
}

/// PROTOCOL section 5: `ref` of a `re:0` failure reply = b64u of the first 16
/// bytes of SHA-256 over the `sig` string as sent.
fn sig_ref(sig: &str) -> (Vec<u8>, String) {
    let digest = Sha256::digest(sig.as_bytes()).to_vec();
    let r = b64u(&digest[..16]);
    (digest, r)
}

/// PROTOCOL section 1, sealed body: b64u(nonce || ciphertext || tag).
fn seal(k: &[u8; 32], nonce: [u8; 12], aad: &str, plaintext: &str) -> String {
    let ct = Aes256Gcm::new_from_slice(k)
        .unwrap()
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    b64u(&out)
}

fn open(k: &[u8; 32], aad: &str, body: &str) -> Option<String> {
    let raw = unb64u(body)?;
    if raw.len() < 12 + 16 {
        return None;
    }
    let (nonce, ct) = raw.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    let pt = Aes256Gcm::new_from_slice(k)
        .ok()?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(pt).ok()
}

fn aad(direction: &str) -> String {
    format!("{PREFIX}|{direction}|{DESKTOP_ID}|{DEVICE_ID}")
}

fn read(name: &str) -> Value {
    let path = dir().join(name);
    serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

/// One sealed-body fixture. `direction` is `p2d` (device to desktop, signed
/// when sent as a `cmd`) or `d2p` (desktop to device).
fn sealed_fixture(
    what: &str,
    direction: &str,
    k: &[u8; 32],
    nonce: [u8; 12],
    plaintext: &Value,
    signer: Option<&SigningKey>,
) -> Value {
    let plaintext = plaintext.to_string();
    let aad = aad(direction);
    let body = seal(k, nonce, &aad, &plaintext);
    let mut v = json!({
        "what": what,
        "direction": direction,
        "link_key_hex": hex(k),
        "aad": aad,
        "nonce_hex": hex(&nonce),
        "plaintext": plaintext,
        "body": body,
    });
    if let Some(sk) = signer {
        let signed = format!("{PREFIX}|cmd|{body}");
        v["signed_string"] = json!(signed);
        v["sig"] = json!(sign(sk, &signed));
        v["frame"] = json!({"t":"cmd","body":body,"sig":v["sig"]});
    }
    v
}

fn all() -> Vec<(&'static str, Value)> {
    let (dsk, dpk) = key(1);
    let (vsk, vpk) = key(2);
    let (_, push_pk) = key(3);
    let nonce = b64u(&(0u8..32).collect::<Vec<_>>());
    let token = b64u(&[0xAAu8; 32]);
    let code = [0x42u8; 16];
    let conn = b64u(&[9u8; 8]);
    let session = b64u(&[5u8; 16]);
    let open_nonce = b64u(&[0x31u8; 16]);
    // Key agreement: the device's `ek` and the desktop's `dk` (from the QR).
    let (ek_sk, dk_sk) = (ecdh_key(4), ecdh_key(5));
    let (ek, dk) = (point(&ek_sk), point(&dk_sk));
    let shared = shared_x(&ek_sk, &dk);
    let info = link_info(DESKTOP_ID, DEVICE_ID, &vpk, &ek, &dk);
    let k = link_key(&code, &shared, &info);

    let proof_message = format!("{PREFIX}|pair|{DESKTOP_ID}|{DEVICE_ID}|{vpk}|{ek}");
    let proof = b64u(&hmac(&code, &proof_message));
    let pane = json!({"pane":PANE_ID,"ws":"main","title":"build","kind":"claude","status":"waiting","since_ms":NOW_MS,"queued":0});
    let prev_session = b64u(&[4u8; 16]);
    let check = "048213";

    // Plaintexts. serde_json writes object keys in sorted order and no spaces:
    // the `plaintext` strings in the files are exactly what was sealed.
    let pair_check_pt = json!({"k":"pair_check","check":check});
    let open_pt =
        json!({"k":"open","desktop_id":DESKTOP_ID,"device_id":DEVICE_ID,"nonce":open_nonce});
    let session_pt = json!({"k":"session","open":open_nonce,"session":session,"cap":"respond","name":"My PC","now_ms":NOW_MS,
        "prev":{"session":prev_session,"seq":3},"v":1});
    let cmd_pt = json!({"k":"cmd","desktop_id":DESKTOP_ID,"device_id":DEVICE_ID,"session":session,"seq":1,"ts_ms":NOW_MS + 123,
        "cmd":{"op":"answer","pane":PANE_ID,"n":1,"label":"Yes","menu_id":"m7-3fA"}});
    let reply_pt = json!({"k":"reply","session":session,"n":1,"at_ms":NOW_MS + 150,"re":1,"ok":true,"data":{"result":"sent"}});
    let panes_pt =
        json!({"k":"panes","session":session,"n":2,"at_ms":NOW_MS + 1000,"panes":[pane]});
    let reopen_pt = json!({"k":"reopen","session":session,"n":3,"at_ms":NOW_MS + 2000});

    let sealed_pair_check =
        sealed_fixture("pair_check", "d2p", &k, [0x07; 12], &pair_check_pt, None);
    let sealed_open = sealed_fixture("open", "p2d", &k, [0x01; 12], &open_pt, Some(&vsk));
    let sealed_session = sealed_fixture("session", "d2p", &k, [0x02; 12], &session_pt, None);
    let sealed_cmd = sealed_fixture("cmd (answer)", "p2d", &k, [0x03; 12], &cmd_pt, Some(&vsk));
    let sealed_reply = sealed_fixture("reply", "d2p", &k, [0x04; 12], &reply_pt, None);
    let sealed_panes = sealed_fixture("panes", "d2p", &k, [0x05; 12], &panes_pt, None);
    let sealed_reopen = sealed_fixture("reopen", "d2p", &k, [0x06; 12], &reopen_pt, None);
    // The desktop could not verify the `sig` of `sealed_cmd.json`'s frame (as if
    // it had been altered in transit) and answers with a `re:0` failure that
    // names the sig string it saw by the first 16 bytes of its SHA-256.
    let (ref_digest, ref_b64u) = sig_ref(s(&sealed_cmd["sig"]));
    let bad_sig_pt =
        json!({"k":"reply","session":"","re":0,"ok":false,"code":"bad_sig","ref":ref_b64u});
    let mut sealed_bad_sig = sealed_fixture(
        "reply (re 0, bad_sig)",
        "d2p",
        &k,
        [0x08; 12],
        &bad_sig_pt,
        None,
    );
    sealed_bad_sig["ref_sig"] = sealed_cmd["sig"].clone();
    sealed_bad_sig["ref_sha256_hex"] = json!(hex(&ref_digest));
    sealed_bad_sig["ref_first16_hex"] = json!(hex(&ref_digest[..16]));

    let hello_sig = sign(&dsk, &desktop_string(DESKTOP_ID, ORIGIN, &nonce));

    let keys = json!({
        "note": "Test keys only. Private keys are 32 identical bytes; signatures are deterministic (RFC 6979). Never use these outside tests.",
        "origin": ORIGIN,
        "desktop": {"private_hex": "01".repeat(32), "public": dpk, "desktop_id": DESKTOP_ID},
        "device": {"private_hex": "02".repeat(32), "public": vpk, "device_id": DEVICE_ID},
        "nonce": nonce,
        "setup_token": token,
        "pair_code": b64u(&code),
        "pair_code_hex": hex(&code),
        "ek": {"private_hex": "04".repeat(32), "public": ek},
        "dk": {"private_hex": "05".repeat(32), "public": dk},
        "pair_check": check,
        "session": session,
        "prev_session": prev_session,
        "open_nonce": open_nonce,
        "conn": conn,
        "pane": PANE_ID,
        "now_ms": NOW_MS,
        "signed_strings": {
            "desktop_hello": desktop_string(DESKTOP_ID, ORIGIN, &nonce),
            "device_hello": device_string(DEVICE_ID, &nonce),
            "pair_request": pair_string(DEVICE_ID, &nonce),
            "pair_proof_message": proof_message,
            "cmd": sealed_cmd["signed_string"],
        },
        "pair_proof": proof,
    });

    vec![
        ("keys.json", keys),
        (
            "challenge.json",
            json!({"t":"challenge","nonce":nonce,"v":1,"server":"0.1.0","origin":ORIGIN}),
        ),
        (
            "hello_desktop.json",
            json!({"t":"hello","role":"desktop","v":1,"desktop_id":DESKTOP_ID,"pubkey":dpk,"name":"My PC","setup_token":token,"sig":hello_sig}),
        ),
        (
            // Signed for a different server's origin: a server must answer bad_sig.
            "hello_desktop_other_origin.json",
            json!({"t":"hello","role":"desktop","v":1,"desktop_id":DESKTOP_ID,"pubkey":dpk,"name":"My PC","setup_token":token,
                   "sig":sign(&dsk,&desktop_string(DESKTOP_ID,OTHER_ORIGIN,&nonce)),
                   "signed_for_origin":OTHER_ORIGIN}),
        ),
        (
            "hello_device.json",
            json!({"t":"hello","role":"device","v":1,"device_id":DEVICE_ID,"sig":sign(&vsk,&device_string(DEVICE_ID,&nonce))}),
        ),
        (
            "ready_desktop.json",
            json!({"t":"ready","devices":[DEVICE_ID]}),
        ),
        (
            "ready_device.json",
            json!({"t":"ready","desktop_id":DESKTOP_ID,"desktop_online":true}),
        ),
        ("error.json", json!({"t":"error","code":"bad_token"})),
        (
            "device_online.json",
            json!({"t":"device_online","device_id":DEVICE_ID,"conn":conn}),
        ),
        (
            "device_offline.json",
            json!({"t":"device_offline","device_id":DEVICE_ID,"conn":conn}),
        ),
        ("desktop_online.json", json!({"t":"desktop_online"})),
        ("desktop_offline.json", json!({"t":"desktop_offline"})),
        ("pair_open.json", json!({"t":"pair_open","ttl_s":120})),
        ("pair_close.json", json!({"t":"pair_close"})),
        (
            "pair_request.json",
            json!({"t":"pair_request","v":1,"desktop_id":DESKTOP_ID,"device_id":DEVICE_ID,"pubkey":vpk,"ek":ek,"name":"iPhone","proof":proof,"sig":sign(&vsk,&pair_string(DEVICE_ID,&nonce))}),
        ),
        (
            "pair_request_forwarded.json",
            json!({"t":"pair_request","device_id":DEVICE_ID,"pubkey":vpk,"ek":ek,"name":"iPhone","proof":proof}),
        ),
        (
            "pair_challenge.json",
            json!({"t":"pair_challenge","device_id":DEVICE_ID,"body":sealed_pair_check["body"]}),
        ),
        (
            "pair_challenge_forwarded.json",
            json!({"t":"pair_challenge","body":sealed_pair_check["body"]}),
        ),
        (
            "pair_result_desktop.json",
            json!({"t":"pair_result","device_id":DEVICE_ID,"ok":true,"pubkey":vpk,"name":"iPhone"}),
        ),
        (
            "pair_result_device.json",
            json!({"t":"pair_result","ok":true}),
        ),
        (
            "device_remove.json",
            json!({"t":"device_remove","device_id":DEVICE_ID}),
        ),
        (
            "link_key.json",
            json!({
                "what": "K = HKDF-SHA256(ikm = shared_secret, salt = code, info = info), 32 bytes; used as an AES-256-GCM key. shared_secret = x coordinate of ECDH(ek private, dk public) = ECDH(dk private, ek public)",
                "code_hex": hex(&code),
                "code": b64u(&code),
                "salt_hex": hex(&code),
                "desktop_id": DESKTOP_ID,
                "device_id": DEVICE_ID,
                "pubkey": vpk,
                "ek": {"private_hex": hex(&ek_sk.to_bytes()), "public": ek},
                "dk": {"private_hex": hex(&dk_sk.to_bytes()), "public": dk},
                "shared_secret_hex": hex(&shared),
                "info": info,
                "key_hex": hex(&k),
                "key": b64u(&k),
            }),
        ),
        ("sealed_pair_check.json", sealed_pair_check.clone()),
        ("sealed_bad_sig_reply.json", sealed_bad_sig.clone()),
        ("sealed_open.json", sealed_open.clone()),
        ("sealed_session.json", sealed_session),
        ("sealed_cmd.json", sealed_cmd.clone()),
        ("sealed_reply.json", sealed_reply.clone()),
        ("sealed_panes.json", sealed_panes.clone()),
        ("sealed_reopen.json", sealed_reopen),
        (
            "cmd_device.json",
            json!({"t":"cmd","body":sealed_cmd["body"],"sig":sealed_cmd["sig"]}),
        ),
        (
            "cmd_forwarded.json",
            json!({"t":"cmd","device_id":DEVICE_ID,"conn":conn,"body":sealed_cmd["body"],"sig":sealed_cmd["sig"]}),
        ),
        (
            "msg.json",
            json!({"t":"msg","to":DEVICE_ID,"body":sealed_reply["body"]}),
        ),
        (
            "msg_forwarded.json",
            json!({"t":"msg","body":sealed_panes["body"]}),
        ),
        (
            "push_subscribe.json",
            json!({"t":"push_subscribe","sub":{"endpoint":"https://push.example.com/send/abc123","keys":{"p256dh":push_pk,"auth":b64u(&[7u8;16])}}}),
        ),
        ("push_unsubscribe.json", json!({"t":"push_unsubscribe"})),
        (
            "notify.json",
            json!({"t":"notify","kind":"waiting","title":"build","body":"needs an answer","pane":PANE_ID}),
        ),
        (
            "push_payload.json",
            json!({"kind":"waiting","title":"build","body":"needs an answer","pane":PANE_ID}),
        ),
    ]
}

#[test]
fn regenerate() {
    if std::env::var("YMUX_REGEN_FIXTURES").as_deref() != Ok("1") {
        return;
    }
    std::fs::create_dir_all(dir()).unwrap();
    for entry in std::fs::read_dir(dir()).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_some_and(|e| e == "json") {
            std::fs::remove_file(p).unwrap();
        }
    }
    for (name, v) in all() {
        std::fs::write(
            dir().join(name),
            serde_json::to_string_pretty(&v).unwrap() + "\n",
        )
        .unwrap();
    }
}

#[test]
fn every_fixture_parses_and_matches_the_generator() {
    for (name, expected) in all() {
        assert_eq!(
            read(name),
            expected,
            "{name} is stale; regenerate the fixtures"
        );
    }
}

#[test]
fn no_stray_files_in_fixtures() {
    let expected: BTreeSet<String> = all().iter().map(|(n, _)| n.to_string()).collect();
    let on_disk: BTreeSet<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    assert_eq!(on_disk, expected);
    assert!(dir().join("README.md").exists(), "fixtures/README.md");
}

#[test]
fn signatures_and_proof_verify_independently() {
    let keys = read("keys.json");
    let nonce = s(&read("challenge.json")["nonce"]).to_string();
    assert_eq!(s(&keys["nonce"]), nonce);
    assert_eq!(unb64u(&nonce).unwrap().len(), 32);
    let origin = s(&read("challenge.json")["origin"]).to_string();
    assert_eq!(origin, s(&keys["origin"]));
    let (dpk, vpk) = (s(&keys["desktop"]["public"]), s(&keys["device"]["public"]));

    // Desktop hello: bound to the origin recorded in the challenge.
    let h = read("hello_desktop.json");
    let msg = format!("ymux-remote-v1|desktop|{DESKTOP_ID}|{origin}|{nonce}");
    assert_eq!(s(&keys["signed_strings"]["desktop_hello"]), msg);
    assert!(verify_sig(dpk, msg.as_bytes(), s(&h["sig"])));
    // ... and only to it.
    for other in [OTHER_ORIGIN, "", "http://ymux.example.com"] {
        let wrong = format!("ymux-remote-v1|desktop|{DESKTOP_ID}|{other}|{nonce}");
        assert!(
            !verify_sig(dpk, wrong.as_bytes(), s(&h["sig"])),
            "{other:?}"
        );
    }
    let wrong = read("hello_desktop_other_origin.json");
    assert!(verify_sig(
        dpk,
        format!("ymux-remote-v1|desktop|{DESKTOP_ID}|{OTHER_ORIGIN}|{nonce}").as_bytes(),
        s(&wrong["sig"])
    ));
    assert!(!verify_sig(dpk, msg.as_bytes(), s(&wrong["sig"])));
    // The pre-origin form no longer verifies.
    let old = format!("ymux-remote-v1|desktop|{DESKTOP_ID}|{nonce}");
    assert!(!verify_sig(dpk, old.as_bytes(), s(&h["sig"])));

    let h = read("hello_device.json");
    let msg = format!("ymux-remote-v1|device|{DEVICE_ID}|{nonce}");
    assert!(verify_sig(vpk, msg.as_bytes(), s(&h["sig"])));

    let p = read("pair_request.json");
    let msg = format!("ymux-remote-v1|pair|{DEVICE_ID}|{nonce}");
    assert!(verify_sig(vpk, msg.as_bytes(), s(&p["sig"])));
    let code = unb64u(s(&keys["pair_code"])).unwrap();
    assert_eq!(hex(&code), s(&keys["pair_code_hex"]));
    let ek = s(&keys["ek"]["public"]);
    assert_eq!(s(&p["ek"]), ek);
    assert_eq!(unb64u(ek).unwrap().len(), 65);
    let msg = format!("ymux-remote-v1|pair|{DESKTOP_ID}|{DEVICE_ID}|{vpk}|{ek}");
    assert_eq!(s(&keys["signed_strings"]["pair_proof_message"]), msg);
    let expect = b64u(&hmac(&code, &msg));
    assert_eq!(s(&p["proof"]), expect);
    assert_eq!(s(&keys["pair_proof"]), expect);
    // The proof covers `ek`: another ek, or the old message without it, does not match.
    assert_ne!(
        b64u(&hmac(&code, &msg.replace(ek, s(&keys["dk"]["public"])))),
        expect
    );
    assert_ne!(
        b64u(&hmac(
            &code,
            &format!("ymux-remote-v1|pair|{DESKTOP_ID}|{DEVICE_ID}|{vpk}")
        )),
        expect
    );
    // The forwarded frame is the request minus what only the server needs.
    let fwd = read("pair_request_forwarded.json");
    for f in ["t", "device_id", "pubkey", "ek", "name", "proof"] {
        assert_eq!(fwd[f], p[f], "{f}");
    }
    assert_eq!(fwd.as_object().unwrap().len(), 6);
    // Pair challenge: the desktop's frame and the forwarded one carry the sealed pair_check.
    let sealed = read("sealed_pair_check.json");
    assert_eq!(read("pair_challenge.json")["body"], sealed["body"]);
    assert_eq!(read("pair_challenge.json")["device_id"], DEVICE_ID);
    assert_eq!(
        read("pair_challenge_forwarded.json"),
        json!({"t":"pair_challenge","body":sealed["body"]})
    );

    // The command frame: sig covers "ymux-remote-v1|cmd|" + the body string as sent.
    let c = read("cmd_device.json");
    let msg = format!("ymux-remote-v1|cmd|{}", s(&c["body"]));
    assert_eq!(s(&keys["signed_strings"]["cmd"]), msg);
    assert!(verify_sig(vpk, msg.as_bytes(), s(&c["sig"])));
    assert_eq!(read("cmd_forwarded.json")["sig"], c["sig"]);
    assert_eq!(read("cmd_forwarded.json")["body"], c["body"]);
    assert_eq!(read("sealed_cmd.json")["frame"], c);
    // A flipped byte must not verify.
    assert!(!verify_sig(vpk, format!("{msg}x").as_bytes(), s(&c["sig"])));
    // The open request is signed the same way.
    let o = read("sealed_open.json");
    let signed = format!("ymux-remote-v1|cmd|{}", s(&o["body"]));
    assert_eq!(s(&o["signed_string"]), signed);
    assert!(verify_sig(vpk, signed.as_bytes(), s(&o["sig"])));
}

#[test]
fn link_key_recomputes_from_either_private_key() {
    let l = read("link_key.json");
    let keys = read("keys.json");
    let code = unhex(s(&l["code_hex"]));
    assert_eq!(code.len(), 16);
    assert_eq!(b64u(&code), s(&l["code"]));
    assert_eq!(s(&l["salt_hex"]), s(&l["code_hex"]), "the salt is the code");

    // The recorded key pairs: the private scalars give the recorded points.
    let ek_sk = SecretKey::from_slice(&unhex(s(&l["ek"]["private_hex"]))).unwrap();
    let dk_sk = SecretKey::from_slice(&unhex(s(&l["dk"]["private_hex"]))).unwrap();
    let (ek, dk) = (s(&l["ek"]["public"]), s(&l["dk"]["public"]));
    assert_eq!(point(&ek_sk), ek);
    assert_eq!(point(&dk_sk), dk);
    for pk in [ek, dk] {
        let raw = unb64u(pk).unwrap();
        assert_eq!((raw.len(), raw[0]), (65, 4));
    }
    assert_eq!(l["ek"], keys["ek"]);
    assert_eq!(l["dk"], keys["dk"]);

    // The shared secret is the same from the device's side and from the desktop's.
    let from_device = shared_x(&ek_sk, dk);
    let from_desktop = shared_x(&dk_sk, ek);
    assert_eq!(from_device, from_desktop);
    assert_eq!(hex(&from_device), s(&l["shared_secret_hex"]));

    // HKDF-SHA256, salt = code, the exact info string.
    let info = format!(
        "ymux-remote-v1|link|{}|{}|{}|{ek}|{dk}",
        s(&l["desktop_id"]),
        s(&l["device_id"]),
        s(&l["pubkey"])
    );
    assert_eq!(s(&l["info"]), info);
    let k = link_key(&code, &from_device, &info);
    assert_eq!(hex(&k), s(&l["key_hex"]));
    assert_eq!(b64u(&k), s(&l["key"]));
    // The same K is what every sealed fixture used.
    for (f, _) in SEALED_DIRS {
        assert_eq!(s(&read(f)["link_key_hex"]), s(&l["key_hex"]), "{f}");
    }

    // K depends on every input: code (salt), shared secret, ids, pubkey, ek, dk.
    assert_ne!(link_key(&[0x43; 16], &from_device, &info), k, "the code");
    assert_ne!(link_key(&code, &[0u8; 32], &info), k, "the shared secret");
    for (from, to) in [
        (s(&l["device_id"]), s(&l["desktop_id"])),
        (s(&l["pubkey"]), dk),
        (ek, dk),
        (dk, ek),
    ] {
        assert_ne!(
            link_key(&code, &from_device, &info.replace(from, to)),
            k,
            "{from}"
        );
    }
    // Knowing the code and everything the relay sees (every public value and
    // frame) does not give K: the old code-only derivation is not it.
    let old = hmac(
        &code,
        &format!(
            "ymux-remote-v1|link|{}|{}|{}",
            s(&l["desktop_id"]),
            s(&l["device_id"]),
            s(&l["pubkey"])
        ),
    );
    assert_ne!(old, k);
    // A third key pair gives a different secret.
    let eve = ecdh_key(9);
    assert_ne!(shared_x(&eve, dk), from_device);
    assert_ne!(shared_x(&eve, ek), from_device);
}

#[test]
fn every_sealed_body_opens_with_its_key_and_direction_only() {
    let k: [u8; 32] = unhex(s(&read("link_key.json")["key_hex"]))
        .try_into()
        .unwrap();
    let session = s(&read("keys.json")["session"]).to_string();
    let open_nonce = s(&read("keys.json")["open_nonce"]).to_string();
    for (f, dir) in SEALED_DIRS {
        let v = read(f);
        let body = s(&v["body"]);
        let aad_ok = format!("ymux-remote-v1|{dir}|{DESKTOP_ID}|{DEVICE_ID}");
        assert_eq!(s(&v["aad"]), aad_ok, "{f}");
        let opened = open(&k, &aad_ok, body).unwrap_or_else(|| panic!("{f} does not open"));
        assert_eq!(opened, s(&v["plaintext"]), "{f}");

        // Layout: nonce (12) || ciphertext || tag (16), nonce as recorded.
        let raw = unb64u(body).unwrap();
        assert_eq!(hex(&raw[..12]), s(&v["nonce_hex"]), "{f}");
        assert_eq!(raw.len(), 12 + opened.len() + 16, "{f}");

        // The other direction's AAD, another device, a flipped bit, a short body: all dropped.
        let other = if dir == "p2d" { "d2p" } else { "p2d" };
        assert!(open(
            &k,
            &format!("ymux-remote-v1|{other}|{DESKTOP_ID}|{DEVICE_ID}"),
            body
        )
        .is_none());
        assert!(open(
            &k,
            &format!("ymux-remote-v1|{dir}|{DEVICE_ID}|{DESKTOP_ID}"),
            body
        )
        .is_none());
        assert!(open(&[0u8; 32], &aad_ok, body).is_none());
        let mut flipped = raw.clone();
        flipped[14] ^= 1;
        assert!(open(&k, &aad_ok, &b64u(&flipped)).is_none());
        assert!(open(&k, &aad_ok, &b64u(&raw[..20])).is_none());

        // The plaintext is the JSON document the protocol describes.
        let pt: Value = serde_json::from_str(&opened).unwrap();
        match pt["k"].as_str().unwrap() {
            "open" => {
                assert_eq!(pt["desktop_id"], DESKTOP_ID);
                assert_eq!(pt["device_id"], DEVICE_ID);
                assert_eq!(s(&pt["nonce"]), open_nonce);
                assert_eq!(unb64u(s(&pt["nonce"])).unwrap().len(), 16);
            }
            "pair_check" => {
                let check = s(&pt["check"]);
                assert_eq!(check, s(&read("keys.json")["pair_check"]));
                assert!(check.len() == 6 && check.bytes().all(|b| b.is_ascii_digit()));
                assert_eq!(pt.as_object().unwrap().len(), 2, "only k and check");
            }
            "session" => {
                assert_eq!(s(&pt["open"]), open_nonce, "answers that open");
                assert_eq!(s(&pt["session"]), session);
                assert_eq!(pt["cap"], "respond");
                assert_eq!(pt["now_ms"], NOW_MS);
                assert_eq!(pt["v"], 1);
                // `prev`: the session this one revoked and the last seq accepted in it.
                let prev = s(&read("keys.json")["prev_session"]).to_string();
                assert_eq!(unb64u(&prev).unwrap().len(), 16);
                assert_ne!(prev, session);
                assert_eq!(pt["prev"], json!({"session": prev, "seq": 3}));
            }
            "cmd" => {
                assert_eq!(pt["desktop_id"], DESKTOP_ID);
                assert_eq!(pt["device_id"], DEVICE_ID);
                assert_eq!(s(&pt["session"]), session);
                assert_eq!(pt["seq"], 1);
                assert!(pt["ts_ms"].as_u64().unwrap().abs_diff(NOW_MS) < 60_000);
                assert_eq!(pt["cmd"]["op"], "answer");
                assert_eq!(pt["cmd"]["menu_id"], "m7-3fA");
                assert_eq!(pt["cmd"]["n"], 1);
                assert_eq!(pt["cmd"]["label"], "Yes");
            }
            "reply" if pt["re"] == 0 => {
                // A failure the desktop cannot tie to a session: no `n`, an
                // empty session, and `ref` naming the sig string it refers to.
                assert_eq!(pt["ok"], false);
                assert_eq!(pt["code"], "bad_sig");
                assert_eq!(s(&pt["session"]), "");
                assert!(pt.get("n").is_none());
                let ref_sig = s(&v["ref_sig"]);
                assert_eq!(ref_sig, s(&read("cmd_device.json")["sig"]));
                let (digest, r) = sig_ref(ref_sig);
                assert_eq!(hex(&digest), s(&v["ref_sha256_hex"]));
                assert_eq!(hex(&digest[..16]), s(&v["ref_first16_hex"]));
                assert_eq!(s(&pt["ref"]), r);
                assert_eq!(unb64u(&r).unwrap().len(), 16);
            }
            "reply" | "panes" | "reopen" => {
                assert_eq!(s(&pt["session"]), session);
                assert!(pt["n"].as_u64().unwrap() >= 1);
                // Every unsolicited or reply body carries the desktop's clock.
                let at = pt["at_ms"].as_u64().unwrap();
                assert!((NOW_MS..NOW_MS + 60_000).contains(&at), "{f}: {at}");
            }
            other => panic!("{f}: unexpected kind {other}"),
        }
    }
    // Rising n within the session, across the unsolicited and reply bodies.
    let n = |f: &str| -> u64 {
        let pt: Value = serde_json::from_str(s(&read(f)["plaintext"])).unwrap();
        pt["n"].as_u64().unwrap()
    };
    assert!(n("sealed_reply.json") < n("sealed_panes.json"));
    assert!(n("sealed_panes.json") < n("sealed_reopen.json"));
    let at = |f: &str| -> u64 {
        let pt: Value = serde_json::from_str(s(&read(f)["plaintext"])).unwrap();
        pt["at_ms"].as_u64().unwrap()
    };
    assert!(at("sealed_reply.json") < at("sealed_panes.json"));
    assert!(at("sealed_panes.json") < at("sealed_reopen.json"));
    // The relay envelopes carry the sealed strings unchanged.
    assert_eq!(read("msg.json")["body"], read("sealed_reply.json")["body"]);
    assert_eq!(
        read("msg_forwarded.json")["body"],
        read("sealed_panes.json")["body"]
    );
    assert_eq!(read("msg.json")["to"], DEVICE_ID);
}

#[test]
fn server_auth_logic_accepts_the_fixtures() {
    let ch = read("challenge.json");
    let nonce = s(&ch["nonce"]).to_string();
    let origin = s(&ch["origin"]).to_string();
    let keys = read("keys.json");
    let token = s(&keys["setup_token"]).to_string();
    let mut st = State::fresh();
    let tok = || Some(token.clone());

    let hello: Hello = serde_json::from_value(read("hello_desktop.json")).unwrap();
    assert_eq!(
        decide_desktop(&st, &hello, &nonce, &origin, &tok),
        Ok(DesktopDecision::Register)
    );
    assert_eq!(
        decide_desktop(&st, &hello, "other-nonce", &origin, &tok),
        Err("bad_sig")
    );
    // The same hello presented to a server with another origin.
    assert_eq!(
        decide_desktop(&st, &hello, &nonce, OTHER_ORIGIN, &tok),
        Err("bad_sig")
    );
    // The hello signed for another origin is refused by this one.
    let wrong: Hello = serde_json::from_value(read("hello_desktop_other_origin.json")).unwrap();
    assert_eq!(
        decide_desktop(&st, &wrong, &nonce, &origin, &tok),
        Err("bad_sig")
    );
    assert_eq!(
        decide_desktop(&st, &wrong, &nonce, OTHER_ORIGIN, &tok),
        Ok(DesktopDecision::Register)
    );

    st.devices.insert(
        DEVICE_ID.into(),
        DeviceRec {
            desktop_id: DESKTOP_ID.into(),
            pubkey: s(&keys["device"]["public"]).into(),
            name: "iPhone".into(),
            created: 0,
            push: None,
        },
    );
    let hello: Hello = serde_json::from_value(read("hello_device.json")).unwrap();
    assert!(decide_device(&st, &hello, &nonce).is_ok());

    let hello: Hello = serde_json::from_value(read("pair_request.json")).unwrap();
    let req = check_pair_request(&hello, &nonce).unwrap();
    assert_eq!(req.device_id, DEVICE_ID);
    assert_eq!(req.proof, s(&keys["pair_proof"]));
    assert_eq!(req.ek, s(&keys["ek"]["public"]));
    // Without `ek` (the old request shape) the server refuses it.
    let mut old: Value = read("pair_request.json");
    old.as_object_mut().unwrap().remove("ek");
    let old: Hello = serde_json::from_value(old).unwrap();
    assert_eq!(check_pair_request(&old, &nonce).err(), Some("bad_request"));

    let sub = read("push_subscribe.json");
    assert!(ymux_server::server::parse_sub(sub.get("sub")).is_some());
}
