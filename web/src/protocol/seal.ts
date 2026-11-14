// End-to-end sealing (PROTOCOL.md section 1): link key, sealed bodies, check number.
import { b64uDecode, b64uEncode, utf8 } from "./encoding";

const PREFIX = "ymux-remote-v1";

/** HKDF `info` of the link key (PROTOCOL.md section 1). `ek` and `dk` are the b64u public keys. */
export const linkKeyInfo = (desktopId: string, deviceId: string, pubkey: string, ek: string, dk: string): string =>
  `${PREFIX}|link|${desktopId}|${deviceId}|${pubkey}|${ek}|${dk}`;

/** Additional data for device -> desktop bodies. */
export const aadP2D = (desktopId: string, deviceId: string): string => `${PREFIX}|p2d|${desktopId}|${deviceId}`;
/** Additional data for desktop -> device bodies. */
export const aadD2P = (desktopId: string, deviceId: string): string => `${PREFIX}|d2p|${desktopId}|${deviceId}`;

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** The device's key-agreement pair (`ek`) for ONE pairing: ECDH P-256, private half non-extractable. */
export async function generateAgreementKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits", "deriveKey"]);
}

/** True when `dk` (b64u raw point) is a point on P-256 that WebCrypto accepts. */
export async function isAgreementPoint(dk: string): Promise<boolean> {
  const raw = b64uDecode(dk);
  if (!raw) return false;
  try {
    await crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    return true;
  } catch {
    return false;
  }
}

export interface LinkKeyInput {
  /** Private half of `ek`. The caller drops it as soon as K exists. */
  ekPrivate: CryptoKey;
  /** `ek` and `dk` as b64u raw points (the strings that go into `info`). */
  ek: string;
  dk: string;
  /** The 16 pairing-code bytes (HKDF salt). The caller owns and wipes them. */
  code: Uint8Array<ArrayBuffer>;
  desktopId: string;
  deviceId: string;
  pubkey: string;
}

/**
 * K = HKDF-SHA256(ikm = ECDH(ek, dk) x coordinate, salt = code, info = linkKeyInfo(...)) as a
 * NON-extractable AES-256-GCM key (PROTOCOL.md section 1). The shared secret never leaves
 * WebCrypto except as a byte array that is overwritten right after it is imported as the HKDF key.
 * Throws when `dk` is not a valid P-256 point.
 */
export async function deriveLinkKey(i: LinkKeyInput): Promise<CryptoKey> {
  const dkBytes = b64uDecode(i.dk);
  if (!dkBytes) throw new Error("bad dk");
  const dkKey = await crypto.subtle.importKey("raw", dkBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: dkKey }, i.ekPrivate, 256));
  try {
    const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: i.code, info: utf8(linkKeyInfo(i.desktopId, i.deviceId, i.pubkey, i.ek, i.dk)) },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    shared.fill(0);
    dkBytes.fill(0);
  }
}

/** b64u(nonce || ciphertext || tag). `nonce` is only injectable for known-answer tests. */
export async function seal(
  key: CryptoKey,
  aad: string,
  plaintext: string,
  nonce: Uint8Array<ArrayBuffer> = crypto.getRandomValues(new Uint8Array(NONCE_BYTES)),
): Promise<string> {
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: utf8(aad), tagLength: 128 }, key, utf8(plaintext)),
  );
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return b64uEncode(out);
}

/** The plaintext, or null for anything that does not open (bad encoding, key, AAD or tampering). */
export async function open(key: CryptoKey, aad: string, body: unknown): Promise<string | null> {
  const bytes = b64uDecode(body);
  if (!bytes || bytes.length < NONCE_BYTES + TAG_BYTES) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.slice(0, NONCE_BYTES), additionalData: utf8(aad), tagLength: 128 },
      key,
      bytes.slice(NONCE_BYTES),
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(pt);
  } catch {
    return null;
  }
}
