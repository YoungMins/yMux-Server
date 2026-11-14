//! Web Push (RFC 8030 delivery, RFC 8291 aes128gcm encryption, RFC 8292 VAPID),
//! implemented on RustCrypto primitives and a rustls reqwest client: no OpenSSL.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::Sha256;

use crate::crypto::{b64u, random_bytes, unb64u};
use crate::state::{now_secs, PushSub};

pub const TTL_SECONDS: u32 = 600;
const RECORD_SIZE: u32 = 4096;
/// Largest plaintext that fits one record (4096 - header - tag - delimiter).
pub const MAX_PLAINTEXT: usize = 3993;
const RESPONSE_CAP: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PushOutcome {
    Sent,
    /// 404 / 410: the subscription is dead.
    Gone,
    Failed,
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait PushSender: Send + Sync {
    fn send<'a>(&'a self, sub: &'a PushSub, payload: &'a [u8]) -> BoxFut<'a, PushOutcome>;
}

/// RFC 8291 encryption into a single aes128gcm record (header + ciphertext).
pub fn encrypt(
    payload: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
    as_secret: &SecretKey,
    salt: &[u8; 16],
) -> Option<Vec<u8>> {
    if payload.len() > MAX_PLAINTEXT {
        return None;
    }
    let ua = PublicKey::from_sec1_bytes(ua_public).ok()?;
    let as_public = as_secret.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua.as_affine());

    let mut key_info = Vec::with_capacity(14 + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public.as_bytes());
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes())
        .expand(&key_info, &mut ikm)
        .ok()?;

    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .ok()?;
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce).ok()?;

    let mut plain = Vec::with_capacity(payload.len() + 1);
    plain.extend_from_slice(payload);
    plain.push(0x02); // last-record delimiter, no padding
    let cipher = Aes128Gcm::new_from_slice(&cek).ok()?;
    let ct = cipher.encrypt(&Nonce::from(nonce), plain.as_slice()).ok()?;

    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ct.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(65);
    body.extend_from_slice(as_public.as_bytes());
    body.extend_from_slice(&ct);
    Some(body)
}

/// `vapid t=<jwt>, k=<public key>` (RFC 8292).
pub fn vapid_header(
    key: &SigningKey,
    public_b64: &str,
    audience: &str,
    subject: &str,
    exp: u64,
) -> String {
    let header = b64u(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = serde_json::json!({ "aud": audience, "exp": exp, "sub": subject });
    let signing_input = format!("{header}.{}", b64u(claims.to_string().as_bytes()));
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!(
        "vapid t={signing_input}.{}, k={public_b64}",
        b64u(&sig.to_bytes())
    )
}

/// True for addresses a push endpoint may legitimately resolve to.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_public_v4(a),
        IpAddr::V6(a) => is_public_v6(a),
    }
}

fn is_public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // 240.0.0.0/4 reserved
}

/// Only global unicast (2000::/3) can be public, minus the special ranges
/// inside it. That alone refuses `::/96` (unspecified, loopback, IPv4-
/// compatible), `::ffff:0:0/96` (IPv4-mapped), NAT64 `64:ff9b::/96` and
/// `64:ff9b:1::/48`, unique-local, link-local, site-local and multicast.
fn is_public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    if (s[0] & 0xe000) != 0x2000 {
        return false;
    }
    if s[0] == 0x2002 {
        // 6to4 (2002::/16): public only if the embedded IPv4 address is.
        let v4 = Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
        return is_public_v4(v4);
    }
    !(s[0] == 0x2001 && s[1] < 0x0200 // 2001::/23 IETF: Teredo 2001::/32, benchmarking 2001:2::/48, ORCHID, ...
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        || (s[0] == 0x3fff && (s[1] & 0xf000) == 0)) // 3fff::/20 documentation
}

/// Resolves a domain and returns its addresses only if every one is public.
async fn resolve_public(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.ok()?.collect();
    if addrs.is_empty() || addrs.iter().any(|a| !is_public_ip(a.ip())) {
        return None;
    }
    Some(addrs)
}

pub struct WebPush {
    key: SigningKey,
    public_b64: String,
    subject: String,
}

impl WebPush {
    pub fn new(
        vapid_private_b64: &str,
        vapid_public_b64: &str,
        subject: String,
    ) -> Option<WebPush> {
        let raw = unb64u(vapid_private_b64)?;
        let key = SigningKey::from_slice(&raw).ok()?;
        Some(WebPush {
            key,
            public_b64: vapid_public_b64.to_string(),
            subject,
        })
    }

    async fn deliver(&self, sub: &PushSub, payload: &[u8]) -> PushOutcome {
        let Ok(url) = reqwest::Url::parse(&sub.endpoint) else {
            return PushOutcome::Failed;
        };
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return PushOutcome::Failed;
        }
        let port = url.port_or_known_default().unwrap_or(443);
        // No proxy, not even one from the environment: a proxy would resolve
        // the host itself and bypass the pinned, vetted addresses below.
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .https_only(true)
            .user_agent("ymux-server");
        match url.host() {
            Some(url::Host::Domain(d)) => {
                // Resolve once, vet every address, and connect to exactly those.
                let Some(addrs) = resolve_public(d, port).await else {
                    return PushOutcome::Failed;
                };
                builder = builder.resolve_to_addrs(d, &addrs);
            }
            Some(url::Host::Ipv4(a)) if is_public_v4(a) => {}
            Some(url::Host::Ipv6(a)) if is_public_v6(a) => {}
            _ => return PushOutcome::Failed,
        }
        let Ok(client) = builder.build() else {
            return PushOutcome::Failed;
        };

        let (Some(p256dh), Some(auth)) = (unb64u(&sub.p256dh), unb64u(&sub.auth)) else {
            return PushOutcome::Failed;
        };
        let as_secret = SecretKey::random(&mut OsRng);
        let salt = random_bytes::<16>();
        let Some(body) = encrypt(payload, &p256dh, &auth, &as_secret, &salt) else {
            return PushOutcome::Failed;
        };
        let audience = format!(
            "{}://{}",
            url.scheme(),
            url.host_str()
                .map(|h| match url.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                })
                .unwrap_or_default()
        );
        let auth_header = vapid_header(
            &self.key,
            &self.public_b64,
            &audience,
            &self.subject,
            now_secs() + 12 * 3600,
        );

        let resp = client
            .post(url)
            .header("Authorization", auth_header)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("TTL", TTL_SECONDS.to_string())
            .header("Urgency", "normal")
            .body(body)
            .send()
            .await;
        let mut resp = match resp {
            Ok(r) => r,
            Err(_) => return PushOutcome::Failed,
        };
        let status = resp.status().as_u16();
        // Read at most RESPONSE_CAP bytes, then drop the connection.
        let mut seen = 0usize;
        while let Ok(Some(chunk)) = resp.chunk().await {
            seen += chunk.len();
            if seen >= RESPONSE_CAP {
                break;
            }
        }
        match status {
            200..=299 => PushOutcome::Sent,
            404 | 410 => PushOutcome::Gone,
            _ => PushOutcome::Failed,
        }
    }
}

impl PushSender for WebPush {
    fn send<'a>(&'a self, sub: &'a PushSub, payload: &'a [u8]) -> BoxFut<'a, PushOutcome> {
        Box::pin(self.deliver(sub, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    fn d(s: &str) -> Vec<u8> {
        unb64u(s).unwrap()
    }

    /// RFC 8291 Appendix A.
    #[test]
    fn rfc8291_test_vector() {
        let as_private =
            SecretKey::from_slice(&d("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let ua_public = d("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        let auth = d("BTBZMqHH6r4Tts7J_aSIgg");
        let salt: [u8; 16] = d("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let body = encrypt(
            b"When I grow up, I want to be a watermelon",
            &ua_public,
            &auth,
            &as_private,
            &salt,
        )
        .unwrap();
        let expected = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
        assert_eq!(b64u(&body), expected);
    }

    /// Decrypts with the user agent's private key, as a browser would.
    #[test]
    fn round_trip_decrypts_with_the_receivers_key() {
        let ua_secret = SecretKey::random(&mut OsRng);
        let ua_public = ua_secret.public_key().to_encoded_point(false);
        let auth = random_bytes::<16>();
        let as_secret = SecretKey::random(&mut OsRng);
        let salt = random_bytes::<16>();
        let msg = br#"{"kind":"done","title":"t","body":"b","pane":"p"}"#;
        let body = encrypt(msg, ua_public.as_bytes(), &auth, &as_secret, &salt).unwrap();

        assert_eq!(&body[..16], &salt);
        assert_eq!(&body[16..20], &4096u32.to_be_bytes());
        assert_eq!(body[20], 65);
        let as_pub = &body[21..86];
        let ct = &body[86..];
        let peer = PublicKey::from_sec1_bytes(as_pub).unwrap();
        let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), peer.as_affine());
        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(ua_public.as_bytes());
        info.extend_from_slice(as_pub);
        let mut ikm = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&auth), shared.raw_secret_bytes())
            .expand(&info, &mut ikm)
            .unwrap();
        let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let (mut cek, mut nonce) = ([0u8; 16], [0u8; 12]);
        prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
            .unwrap();
        prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
            .unwrap();
        let plain = Aes128Gcm::new_from_slice(&cek)
            .unwrap()
            .decrypt(&Nonce::from(nonce), ct)
            .unwrap();
        assert_eq!(plain.last(), Some(&0x02));
        assert_eq!(&plain[..plain.len() - 1], msg);
    }

    #[test]
    fn encrypt_rejects_bad_input() {
        let sk = SecretKey::random(&mut OsRng);
        assert!(encrypt(b"x", &[1, 2, 3], &[0; 16], &sk, &[0; 16]).is_none());
        let ua = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(false);
        assert!(encrypt(
            &vec![0u8; MAX_PLAINTEXT + 1],
            ua.as_bytes(),
            &[0; 16],
            &sk,
            &[0; 16]
        )
        .is_none());
        assert!(encrypt(
            &vec![0u8; MAX_PLAINTEXT],
            ua.as_bytes(),
            &[0; 16],
            &sk,
            &[0; 16]
        )
        .is_some());
    }

    #[test]
    fn vapid_jwt_verifies() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = b64u(sk.verifying_key().to_encoded_point(false).as_bytes());
        let h = vapid_header(
            &sk,
            &pubkey,
            "https://push.example",
            "mailto:a@b.c",
            1_900_000_000,
        );
        let rest = h.strip_prefix("vapid t=").unwrap();
        let (jwt, k) = rest.split_once(", k=").unwrap();
        assert_eq!(k, pubkey);
        let (signing_input, sig) = jwt.rsplit_once('.').unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&d(&pubkey)).unwrap();
        let sig = Signature::from_slice(&d(sig)).unwrap();
        vk.verify(signing_input.as_bytes(), &sig).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&d(signing_input.split('.').nth(1).unwrap())).unwrap();
        assert_eq!(claims["aud"], "https://push.example");
        assert_eq!(claims["exp"], 1_900_000_000u64);
    }

    fn classify(list: &[&str], public: bool) {
        for s in list {
            let ip: IpAddr = s.parse().unwrap_or_else(|_| panic!("{s}"));
            assert_eq!(is_public_ip(ip), public, "{s}");
        }
    }

    #[test]
    fn ssrf_ipv4_ranges() {
        classify(
            &[
                "0.0.0.0",
                "0.1.2.3",  // 0.0.0.0/8
                "10.0.0.1", // private
                "10.255.255.255",
                "100.64.0.1", // CGNAT 100.64/10
                "100.127.255.255",
                "127.0.0.1", // loopback
                "127.255.255.254",
                "169.254.169.254", // link-local / metadata
                "172.16.0.1",
                "172.31.255.255",
                "192.0.0.8",   // IETF protocol assignments
                "192.0.2.1",   // documentation
                "192.88.99.1", // 6to4 relay anycast
                "192.168.1.1",
                "198.18.0.1", // benchmarking 198.18/15
                "198.19.255.255",
                "198.51.100.7", // documentation
                "203.0.113.7",  // documentation
                "224.0.0.1",    // multicast
                "239.255.255.250",
                "240.0.0.1",       // reserved
                "255.255.255.255", // broadcast
            ],
            false,
        );
        classify(
            &[
                "8.8.8.8",
                "1.1.1.1",
                "100.63.255.255",
                "100.128.0.1",
                "172.15.255.255",
                "172.32.0.1",
                "192.0.1.1",
                "192.169.0.1",
                "198.17.255.255",
                "198.20.0.1",
                "223.255.255.255",
                "142.250.1.1",
            ],
            true,
        );
    }

    #[test]
    fn ssrf_ipv6_ranges() {
        classify(
            &[
                "::",        // unspecified
                "::1",       // loopback
                "::8.8.8.8", // IPv4-compatible (::/96)
                "::127.0.0.1",
                "::ffff:8.8.8.8", // IPv4-mapped, even a public v4
                "::ffff:127.0.0.1",
                "::ffff:10.0.0.1",
                "64:ff9b::808:808", // NAT64 64:ff9b::/96, even a public v4
                "64:ff9b::7f00:1",
                "64:ff9b:1::1", // local-use NAT64 64:ff9b:1::/48
                "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
                "2002:7f00:1::1",   // 6to4 of 127.0.0.1
                "2002:a00:1::",     // 6to4 of 10.0.0.1
                "2002:c0a8:101::1", // 6to4 of 192.168.1.1
                "2002:a9fe:a9fe::", // 6to4 of 169.254.169.254
                "2001::1",          // Teredo 2001::/32
                "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                "2001:2::1", // benchmarking 2001:2::/48
                "2001:2:0:ffff::1",
                "2001:10::1",  // ORCHID, inside 2001::/23
                "2001:20::1",  // ORCHIDv2
                "2001:db8::1", // documentation
                "2001:db8:ffff::1",
                "3fff::1", // documentation 3fff::/20
                "3fff:fff::1",
                "100::1",  // discard-only
                "fc00::1", // unique local
                "fd12:3456::1",
                "fe80::1", // link-local
                "febf::1",
                "fec0::1", // site-local
                "ff00::1", // multicast
                "ff02::1",
                "ff0e::1",
                "4000::1", // not (yet) global unicast
                "5f00::1", // SRv6 SIDs
            ],
            false,
        );
        classify(
            &[
                "2607:f8b0:4004:c07::71",
                "2a00:1450:4001:81b::200e",
                "2001:4860:4860::8888",
                "2001:200::1",     // just above 2001::/23
                "2001:db9::1",     // just above 2001:db8::/32
                "2002:808:808::1", // 6to4 of 8.8.8.8
                "3ffe::1",         // outside 3fff::/20
                "2620:fe::fe",
            ],
            true,
        );
    }

    #[tokio::test]
    async fn refuses_loopback_and_http_endpoints() {
        let sk = SigningKey::random(&mut OsRng);
        let public = b64u(sk.verifying_key().to_encoded_point(false).as_bytes());
        let wp = WebPush::new(&b64u(&sk.to_bytes()), &public, "mailto:a@b.c".into()).unwrap();
        let ua = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(false);
        let mk = |endpoint: &str| PushSub {
            endpoint: endpoint.into(),
            p256dh: b64u(ua.as_bytes()),
            auth: b64u(&[0u8; 16]),
        };
        for ep in [
            "http://example.com/x",
            "https://127.0.0.1/x",
            "https://localhost/x",
            "https://[::1]/x",
            "https://10.0.0.5:8443/x",
            "https://user:pw@example.com/x",
            "not a url",
        ] {
            assert_eq!(wp.send(&mk(ep), b"{}").await, PushOutcome::Failed, "{ep}");
        }
    }
}
