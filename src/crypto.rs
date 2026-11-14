//! Encodings, signature verification and small helpers. Nothing here panics on
//! hostile input.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

pub const PREFIX: &str = "ymux-remote-v1";

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Constant-time equality of two strings.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Lowercase UUID text form (8-4-4-4-12).
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
    })
}

/// A raw uncompressed SEC1 P-256 point as b64u.
pub fn parse_pubkey(s: &str) -> Option<VerifyingKey> {
    let raw = unb64u(s)?;
    if raw.len() != 65 || raw[0] != 0x04 {
        return None;
    }
    VerifyingKey::from_sec1_bytes(&raw).ok()
}

/// Verifies an IEEE P1363 (r || s) ECDSA P-256 / SHA-256 signature. Both low-S
/// and high-S signatures are accepted.
pub fn verify_sig(pubkey_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
    let Some(key) = parse_pubkey(pubkey_b64u) else {
        return false;
    };
    let Some(raw) = unb64u(sig_b64u) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&raw) else {
        return false;
    };
    key.verify(msg, &sig).is_ok()
}

/// What a desktop signs: bound to the server's own origin, so a challenge
/// relayed from another server does not verify (PROTOCOL 3.1).
pub fn desktop_string(desktop_id: &str, origin: &str, nonce: &str) -> String {
    format!("{PREFIX}|desktop|{desktop_id}|{origin}|{nonce}")
}

pub fn device_string(device_id: &str, nonce: &str) -> String {
    format!("{PREFIX}|device|{device_id}|{nonce}")
}

pub fn pair_string(device_id: &str, nonce: &str) -> String {
    format!("{PREFIX}|pair|{device_id}|{nonce}")
}

/// Unicode general categories Cf, Zl and Zp, as explicit ranges (Cc is
/// `char::is_control`). Covers the bidi, zero-width and tag characters that
/// let a name spoof another one.
const FORMAT_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E), // Zl, Zp, bidi embeddings
    (0x2060, 0x206F), // word joiner, invisible operators, bidi isolates, deprecated
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// True for characters dropped from every name and notification text:
/// categories Cc, Cf, Zl, Zp (PROTOCOL 5.2).
pub fn is_stripped(c: char) -> bool {
    c.is_control()
        || FORMAT_RANGES
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&(c as u32)))
}

/// Drops Cc/Cf/Zl/Zp characters, then clips to at most `max` characters.
pub fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !is_stripped(*c)).take(max).collect()
}

/// Longest stored or forwarded device / desktop name.
pub const MAX_NAME: usize = 80;

/// A device or desktop name as it may be stored or forwarded.
pub fn clean_name(s: &str) -> String {
    clip(s, MAX_NAME)
}

/// Longest device name a pairing request may carry.
pub const MAX_DEVICE_NAME: usize = 40;
/// What a device name that cleans to nothing becomes.
pub const UNNAMED_DEVICE: &str = "Unnamed device";

/// Combining marks and the scripts whose vowel signs are marks that the
/// `Alphabetic` property misses (kept as whole blocks). A digit is never one:
/// the whole-block ranges of the Indic scripts hold their digits too, so those
/// are ruled out here and not left to the caller's order of checks.
fn is_mark_like(c: char) -> bool {
    !c.is_numeric()
        && matches!(c as u32,
            0x0300..=0x036F | 0x0483..=0x0489 | 0x0591..=0x05BD | 0x05BF | 0x05C1..=0x05C2
            | 0x05C4..=0x05C5 | 0x05C7 | 0x0610..=0x061A | 0x064B..=0x065F | 0x0670
            | 0x06D6..=0x06DC | 0x06DF..=0x06E4 | 0x06E7..=0x06E8 | 0x06EA..=0x06ED
            | 0x0900..=0x0963 | 0x0971..=0x0DFF | 0x0E00..=0x0E4E | 0x0E5C..=0x0EFF
            | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0x3099..=0x309A
            | 0xFE00..=0xFE0F | 0xFE20..=0xFE2F)
}

/// A device's self-chosen name as the desktop and the server both show it:
/// text a stranger can choose must not carry a number or punctuation that
/// frames a fake instruction. Keeps letters, marks, spaces and `. - _ '`;
/// removes every digit and all other punctuation and symbols; collapses
/// whitespace; clips to 40 characters; falls back to [`UNNAMED_DEVICE`].
pub fn clean_device_name(s: &str) -> String {
    let kept: String = s
        .chars()
        .take(MAX_DEVICE_NAME * 4)
        .filter(|c| !is_stripped(*c))
        .filter_map(|c| {
            if c.is_whitespace() {
                Some(' ')
            } else if c.is_numeric() {
                None
            } else if matches!(c, '.' | '-' | '_' | '\'') || c.is_alphabetic() || is_mark_like(c) {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    let joined = kept.split_whitespace().collect::<Vec<_>>().join(" ");
    let out: String = joined.chars().take(MAX_DEVICE_NAME).collect();
    let out = out.trim().to_string();
    if out.is_empty() {
        UNNAMED_DEVICE.to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    #[test]
    fn mark_like_is_never_a_digit_and_still_covers_vowel_signs() {
        // Devanagari, Thai, Bengali and Lao digits sit inside whole-block ranges.
        for c in [
            '\u{0966}', '\u{096F}', '\u{0E50}', '\u{0E59}', '\u{09E6}', '\u{0ED0}',
        ] {
            assert!(!is_mark_like(c), "{c:?} is a digit");
        }
        for u in 0..=0x10FFFFu32 {
            if let Some(c) = char::from_u32(u) {
                assert!(!(c.is_numeric() && is_mark_like(c)), "U+{u:04X}");
            }
        }
        // Vowel signs and combining marks stay marks.
        for c in ['\u{0301}', '\u{093F}', '\u{094D}', '\u{0E31}', '\u{064B}'] {
            assert!(is_mark_like(c), "{c:?} is a mark");
        }
    }

    #[test]
    fn device_names_cannot_frame_a_number_or_an_instruction() {
        assert_eq!(
            clean_device_name("Pixel 8\u{201D} \u{2014} your number: 482913 \u{201C}"),
            "Pixel your number"
        );
        assert_eq!(clean_device_name("iPhone"), "iPhone");
        assert_eq!(clean_device_name("Sam's phone_2.0-x"), "Sam's phone_.-x");
        assert_eq!(
            clean_device_name("\u{0664}\u{0665}\u{FF11}\u{2460}"),
            UNNAMED_DEVICE
        );
        assert_eq!(
            clean_device_name("\"\u{201C}\u{300C}!?[]()<>:;,/\\"),
            UNNAMED_DEVICE
        );
        assert_eq!(clean_device_name("  a \n\t b  "), "a b");
        assert_eq!(clean_device_name(""), UNNAMED_DEVICE);
        assert_eq!(clean_device_name("\u{1F600}"), UNNAMED_DEVICE);
        assert_eq!(
            clean_device_name(
                "한국 폰 日本語 e\u{0301} \u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}"
            ),
            "한국 폰 日本語 e\u{0301} \u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}"
        );
        assert_eq!(
            clean_device_name(&"x".repeat(100)).chars().count(),
            MAX_DEVICE_NAME
        );
    }
    use p256::ecdsa::SigningKey;

    pub fn key(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
        let pk = b64u(sk.verifying_key().to_encoded_point(false).as_bytes());
        (sk, pk)
    }

    #[test]
    fn verifies_low_and_high_s() {
        let (sk, pk) = key(7);
        let sig: Signature = sk.sign(b"hello");
        assert!(verify_sig(&pk, b"hello", &b64u(&sig.to_bytes())));
        assert!(!verify_sig(&pk, b"hellO", &b64u(&sig.to_bytes())));
        // High-S twin: s' = n - s.
        let (r, s) = sig.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        assert_ne!(high.to_bytes(), sig.to_bytes());
        assert!(verify_sig(&pk, b"hello", &b64u(&high.to_bytes())));
    }

    #[test]
    fn names_lose_control_format_and_separator_characters() {
        let cp = |u: u32| char::from_u32(u).unwrap();
        // Every code point named in the task, both ends of each range.
        let stripped = [
            0x00, 0x1F, 0x7F, 0x9F, 0x00AD, 0x0600, 0x0605, 0x061C, 0x06DD, 0x070F, 0x180E, 0x200B,
            0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202E, 0x2060, 0x2064, 0x2066,
            0x2069, 0x206F, 0xFEFF, 0xFFF9, 0xFFFA, 0xFFFB, 0xE0001, 0xE0020, 0xE007F,
        ];
        for u in stripped {
            assert!(is_stripped(cp(u)), "U+{u:04X} must be stripped");
            assert_eq!(clean_name(&format!("a{}b", cp(u))), "ab", "U+{u:04X}");
        }
        // Neighbours and ordinary text survive (including Hangul, emoji, NBSP).
        for u in [
            0x20, 0x41, 0x00A0, 0x00AE, 0x0606, 0x2027, 0x202F, 0x2070, 0xFEFE, 0xFFFC, 0xD55C,
            0x1F600,
        ] {
            assert!(!is_stripped(cp(u)), "U+{u:04X} must survive");
        }
        // An RTL override cannot reverse the rest of a name.
        assert_eq!(clean_name("evil\u{202E}gpj.exe"), "evilgpj.exe");
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        let (_, pk) = key(7);
        assert!(!verify_sig("", b"x", ""));
        assert!(!verify_sig(&pk, b"x", "AAAA"));
        assert!(!verify_sig("AAAA", b"x", "AAAA"));
        assert!(!verify_sig(&pk, b"x", &"A".repeat(86)));
        assert!(parse_pubkey(&b64u(&[4u8; 65])).is_none());
        assert!(parse_pubkey(&b64u(&[2u8; 33])).is_none());
    }

    #[test]
    fn uuid_and_clip_and_ct() {
        assert!(is_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!is_uuid("123E4567-e89b-12d3-a456-426614174000"));
        assert!(!is_uuid("123e4567e89b12d3a456426614174000"));
        assert_eq!(clip("a\nb\u{0}c한글def", 6), "abc한글d");
        // Format characters go before the clip, so they do not use up its budget.
        assert_eq!(clip("\u{200B}\u{200B}ab", 2), "ab");
        assert_eq!(clean_name(&"x".repeat(200)).len(), MAX_NAME);
        assert_eq!(
            desktop_string("d", "https://a", "n"),
            "ymux-remote-v1|desktop|d|https://a|n"
        );
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }
}
