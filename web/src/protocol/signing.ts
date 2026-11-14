// Signed strings (PROTOCOL.md sections 3.2, 4, 5.1) and the WebCrypto calls behind them.
import { b64uEncode, utf8 } from "./encoding";

export const PREFIX = "ymux-remote-v1";

export const deviceHelloString = (deviceId: string, nonce: string): string =>
  `${PREFIX}|device|${deviceId}|${nonce}`;

export const pairSigString = (deviceId: string, nonce: string): string =>
  `${PREFIX}|pair|${deviceId}|${nonce}`;

export const pairProofMessage = (desktopId: string, deviceId: string, pubkey: string, ek: string): string =>
  `${PREFIX}|pair|${desktopId}|${deviceId}|${pubkey}|${ek}`;

export const cmdSigString = (body: string): string => `${PREFIX}|cmd|${body}`;

/**
 * `ref` of a command (PROTOCOL.md 5): b64u of the first 16 bytes of SHA-256 over the `sig` string
 * exactly as sent in the `cmd` frame (the b64u signature; the server's fixtures
 * `sealed_bad_sig_reply.json` record it that way). A `re:0` failure names its command by this value.
 */
export async function cmdRef(sig: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(sig)));
  return b64uEncode(d.slice(0, 16));
}

const ECDSA = { name: "ECDSA", namedCurve: "P-256" } as const;

/** Private key is non-extractable; the public key is always exportable. */
export async function generateDeviceKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDSA, false, ["sign", "verify"]);
}

/** Raw uncompressed SEC1 point (65 bytes) as b64u. */
export async function exportPublicKey(pub: CryptoKey): Promise<string> {
  return b64uEncode(new Uint8Array(await crypto.subtle.exportKey("raw", pub)));
}

/** ECDSA P-256 / SHA-256, IEEE P1363 (r||s) as b64u: what WebCrypto returns. */
export async function signString(priv: CryptoKey, s: string): Promise<string> {
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, utf8(s));
  return b64uEncode(new Uint8Array(sig));
}

/** b64u(HMAC-SHA256(key = code bytes, msg)). */
export async function hmacProof(codeBytes: Uint8Array<ArrayBuffer>, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    codeBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return b64uEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(msg))));
}
