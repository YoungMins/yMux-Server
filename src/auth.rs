//! Authentication decisions as pure functions over the stored state.

use serde::Deserialize;

use crate::crypto::{
    ct_eq, desktop_string, device_string, is_uuid, pair_string, parse_pubkey, unb64u, verify_sig,
};
use crate::state::{DeviceRec, State, MAX_DESKTOPS};

pub const PROTOCOL_VERSION: u64 = 1;

/// The fields of a client `hello` / `pair_request`. Everything is optional so
/// a malformed frame becomes an error code instead of a parse failure.
#[derive(Deserialize, Default)]
pub struct Hello {
    pub t: Option<String>,
    pub role: Option<String>,
    pub v: Option<u64>,
    pub desktop_id: Option<String>,
    pub device_id: Option<String>,
    pub pubkey: Option<String>,
    pub name: Option<String>,
    pub setup_token: Option<String>,
    pub proof: Option<String>,
    pub ek: Option<String>,
    pub sig: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DesktopDecision {
    Known,
    Register,
}

fn sig_shape_ok(sig: &str) -> bool {
    unb64u(sig).map(|b| b.len() == 64).unwrap_or(false)
}

/// Desktop hello (PROTOCOL 3.1). The error is the protocol error code.
///
/// `origin` is this server's own origin; the signature must cover it.
/// `setup_token` is called at most once, only for an unknown desktop whose
/// signature already verified, and returns the current token (None: refuse).
pub fn decide_desktop(
    state: &State,
    h: &Hello,
    nonce: &str,
    origin: &str,
    setup_token: &dyn Fn() -> Option<String>,
) -> Result<DesktopDecision, &'static str> {
    if h.t.as_deref() != Some("hello") || h.role.as_deref() != Some("desktop") {
        return Err("bad_sig");
    }
    if h.v != Some(PROTOCOL_VERSION) {
        return Err("version");
    }
    let (Some(id), Some(pubkey), Some(sig)) = (
        h.desktop_id.as_deref(),
        h.pubkey.as_deref(),
        h.sig.as_deref(),
    ) else {
        return Err("bad_sig");
    };
    if !is_uuid(id) || parse_pubkey(pubkey).is_none() || !sig_shape_ok(sig) {
        return Err("bad_sig");
    }
    let msg = desktop_string(id, origin, nonce);
    match state.desktops.get(id) {
        Some(rec) => {
            if rec.pubkey != pubkey {
                return Err("key_mismatch");
            }
            if !verify_sig(&rec.pubkey, msg.as_bytes(), sig) {
                return Err("bad_sig");
            }
            Ok(DesktopDecision::Known)
        }
        None => {
            if !verify_sig(pubkey, msg.as_bytes(), sig) {
                return Err("bad_sig");
            }
            let token = h.setup_token.as_deref().unwrap_or("");
            let expected = setup_token().unwrap_or_default();
            if token.is_empty() || expected.is_empty() || !ct_eq(token, &expected) {
                return Err("bad_token");
            }
            if state.desktops.len() >= MAX_DESKTOPS {
                return Err("limit");
            }
            Ok(DesktopDecision::Register)
        }
    }
}

/// Device hello (PROTOCOL 3.2); returns the stored record on success.
pub fn decide_device<'a>(
    state: &'a State,
    h: &Hello,
    nonce: &str,
) -> Result<(&'a str, &'a DeviceRec), &'static str> {
    if h.t.as_deref() != Some("hello") || h.role.as_deref() != Some("device") {
        return Err("bad_sig");
    }
    if h.v != Some(PROTOCOL_VERSION) {
        return Err("version");
    }
    let (Some(id), Some(sig)) = (h.device_id.as_deref(), h.sig.as_deref()) else {
        return Err("unknown_device");
    };
    let Some((key, rec)) = state.devices.get_key_value(id) else {
        return Err("unknown_device");
    };
    let msg = device_string(id, nonce);
    if !verify_sig(&rec.pubkey, msg.as_bytes(), sig) {
        return Err("bad_sig");
    }
    Ok((key.as_str(), rec))
}

/// A validated `pair_request` (PROTOCOL 4, step 3), before the window check.
pub struct PairRequest {
    pub desktop_id: String,
    pub device_id: String,
    pub pubkey: String,
    pub ek: String,
    pub name: String,
    pub proof: String,
}

pub fn check_pair_request(h: &Hello, nonce: &str) -> Result<PairRequest, &'static str> {
    if h.t.as_deref() != Some("pair_request") {
        return Err("bad_request");
    }
    if h.v != Some(PROTOCOL_VERSION) {
        return Err("version");
    }
    let (Some(desktop_id), Some(device_id), Some(pubkey), Some(ek), Some(proof), Some(sig)) = (
        h.desktop_id.as_deref(),
        h.device_id.as_deref(),
        h.pubkey.as_deref(),
        h.ek.as_deref(),
        h.proof.as_deref(),
        h.sig.as_deref(),
    ) else {
        return Err("bad_request");
    };
    if !is_uuid(desktop_id) || !is_uuid(device_id) || proof.len() > 128 || !sig_shape_ok(sig) {
        return Err("bad_request");
    }
    // `ek` is an ECDH key, not a signing key, but it has the same wire form:
    // a raw uncompressed P-256 point (65 bytes) that must be on the curve.
    if parse_pubkey(ek).is_none() {
        return Err("bad_request");
    }
    if !verify_sig(pubkey, pair_string(device_id, nonce).as_bytes(), sig) {
        return Err("bad_sig");
    }
    Ok(PairRequest {
        desktop_id: desktop_id.to_string(),
        device_id: device_id.to_string(),
        pubkey: pubkey.to_string(),
        ek: ek.to_string(),
        name: crate::crypto::clean_device_name(h.name.as_deref().unwrap_or("")),
        proof: proof.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::b64u;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const DESK: &str = "11111111-1111-4111-8111-111111111111";
    const DEV: &str = "22222222-2222-4222-8222-222222222222";
    const NONCE: &str = "bm9uY2U";

    fn keypair(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
        let pk = b64u(sk.verifying_key().to_encoded_point(false).as_bytes());
        (sk, pk)
    }

    fn sign(sk: &SigningKey, msg: &str) -> String {
        let s: Signature = sk.sign(msg.as_bytes());
        b64u(&s.to_bytes())
    }

    const ORIGIN: &str = "https://ymux.example.com";

    fn state() -> State {
        State::fresh()
    }

    fn token() -> Option<String> {
        Some("TOKEN".into())
    }

    fn desktop_hello(sk: &SigningKey, pk: &str, token: &str) -> Hello {
        desktop_hello_for(sk, pk, token, ORIGIN)
    }

    fn desktop_hello_for(sk: &SigningKey, pk: &str, token: &str, origin: &str) -> Hello {
        Hello {
            t: Some("hello".into()),
            role: Some("desktop".into()),
            v: Some(1),
            desktop_id: Some(DESK.into()),
            pubkey: Some(pk.into()),
            setup_token: Some(token.into()),
            sig: Some(sign(sk, &desktop_string(DESK, origin, NONCE))),
            ..Default::default()
        }
    }

    fn decide(st: &State, h: &Hello, nonce: &str) -> Result<DesktopDecision, &'static str> {
        decide_desktop(st, h, nonce, ORIGIN, &token)
    }

    #[test]
    fn desktop_registration_rules() {
        let (sk, pk) = keypair(1);
        let mut st = state();
        assert_eq!(
            decide(&st, &desktop_hello(&sk, &pk, "TOKEN"), NONCE),
            Ok(DesktopDecision::Register)
        );
        assert_eq!(
            decide(&st, &desktop_hello(&sk, &pk, "WRONG"), NONCE),
            Err("bad_token")
        );
        assert_eq!(
            decide(&st, &desktop_hello(&sk, &pk, ""), NONCE),
            Err("bad_token")
        );
        // No readable token file: nothing registers, not even an empty token.
        assert_eq!(
            decide_desktop(&st, &desktop_hello(&sk, &pk, ""), NONCE, ORIGIN, &|| None),
            Err("bad_token")
        );
        assert_eq!(
            decide_desktop(&st, &desktop_hello(&sk, &pk, "x"), NONCE, ORIGIN, &|| None),
            Err("bad_token")
        );
        let mut h = desktop_hello(&sk, &pk, "TOKEN");
        h.v = Some(2);
        assert_eq!(decide(&st, &h, NONCE), Err("version"));
        let mut h = desktop_hello(&sk, &pk, "TOKEN");
        h.sig = Some(sign(&sk, "something else"));
        assert_eq!(decide(&st, &h, NONCE), Err("bad_sig"));
        assert_eq!(
            decide(&st, &desktop_hello(&sk, &pk, "TOKEN"), "other"),
            Err("bad_sig")
        );
        // Signed for another server's origin (a relayed challenge): refused, and
        // the token is not even looked at.
        for other in [
            "https://evil.example",
            "http://ymux.example.com",
            "https://ymux.example.com:8443",
            "",
        ] {
            let h = desktop_hello_for(&sk, &pk, "TOKEN", other);
            let looked = std::cell::Cell::new(false);
            let r = decide_desktop(&st, &h, NONCE, ORIGIN, &|| {
                looked.set(true);
                token()
            });
            assert_eq!(r, Err("bad_sig"), "{other}");
            assert!(!looked.get());
        }

        st.desktops.insert(
            DESK.into(),
            crate::state::DesktopRec {
                pubkey: pk.clone(),
                name: "x".into(),
                created: 0,
            },
        );
        // Known: token ignored (and not read), origin still enforced.
        let never = || -> Option<String> { panic!("a known desktop needs no token") };
        assert_eq!(
            decide_desktop(&st, &desktop_hello(&sk, &pk, ""), NONCE, ORIGIN, &never),
            Ok(DesktopDecision::Known)
        );
        assert_eq!(
            decide_desktop(
                &st,
                &desktop_hello_for(&sk, &pk, "", "https://evil.example"),
                NONCE,
                ORIGIN,
                &never
            ),
            Err("bad_sig")
        );
        let (sk2, pk2) = keypair(2);
        assert_eq!(
            decide(&st, &desktop_hello(&sk2, &pk2, "TOKEN"), NONCE),
            Err("key_mismatch")
        );
    }

    #[test]
    fn device_hello_rules() {
        let (sk, pk) = keypair(3);
        let mut st = state();
        let mut h = Hello {
            t: Some("hello".into()),
            role: Some("device".into()),
            v: Some(1),
            device_id: Some(DEV.into()),
            sig: Some(sign(&sk, &device_string(DEV, NONCE))),
            ..Default::default()
        };
        assert_eq!(decide_device(&st, &h, NONCE).err(), Some("unknown_device"));
        st.devices.insert(
            DEV.into(),
            DeviceRec {
                desktop_id: DESK.into(),
                pubkey: pk,
                name: "p".into(),
                created: 0,
                push: None,
            },
        );
        assert_eq!(decide_device(&st, &h, NONCE).unwrap().1.desktop_id, DESK);
        assert_eq!(decide_device(&st, &h, "x").err(), Some("bad_sig"));
        h.sig = Some(sign(&sk, &desktop_string(DEV, ORIGIN, NONCE)));
        assert_eq!(decide_device(&st, &h, NONCE).err(), Some("bad_sig"));
        h.v = Some(9);
        assert_eq!(decide_device(&st, &h, NONCE).err(), Some("version"));
    }

    #[test]
    fn pair_request_checks_sig_against_its_own_key() {
        let (sk, pk) = keypair(4);
        let mut h = Hello {
            t: Some("pair_request".into()),
            v: Some(1),
            desktop_id: Some(DESK.into()),
            device_id: Some(DEV.into()),
            pubkey: Some(pk),
            name: Some("iPhone".into()),
            proof: Some("abc".into()),
            ek: Some(keypair(5).1),
            sig: Some(sign(&sk, &pair_string(DEV, NONCE))),
            ..Default::default()
        };
        assert_eq!(check_pair_request(&h, NONCE).unwrap().name, "iPhone");
        assert_eq!(check_pair_request(&h, NONCE).unwrap().ek, keypair(5).1);
        // `ek` must be a decodable 65-byte uncompressed P-256 point.
        let good = h.ek.clone();
        for bad in [
            None,
            Some(String::new()),
            Some("not base64!".into()),
            Some(b64u(&[4u8; 65])),               // not on the curve
            Some(b64u(&[0u8; 65])),               // wrong tag
            Some(b64u(&[4u8; 64])),               // short
            Some(b64u(&[4u8; 66])),               // long
            Some(good.clone().unwrap() + "AAAA"), // trailing bytes
        ] {
            h.ek = bad.clone();
            assert_eq!(
                check_pair_request(&h, NONCE).err(),
                Some("bad_request"),
                "{bad:?}"
            );
        }
        h.ek = good;
        h.name = Some("Pho\u{202E}ne\u{200B}".into());
        assert_eq!(check_pair_request(&h, NONCE).unwrap().name, "Phone");
        h.name = Some("Pixel 8\u{201D} \u{2014} your number: 482913 \u{201C}".into());
        assert_eq!(
            check_pair_request(&h, NONCE).unwrap().name,
            "Pixel your number"
        );
        h.name = Some("4829".into());
        assert_eq!(
            check_pair_request(&h, NONCE).unwrap().name,
            "Unnamed device"
        );
        h.name = Some("iPhone".into());
        assert_eq!(check_pair_request(&h, "x").err(), Some("bad_sig"));
        h.proof = None;
        assert_eq!(check_pair_request(&h, NONCE).err(), Some("bad_request"));
    }
}
