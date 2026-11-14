// Helpers for tests only (never imported by the app): a node-crypto "desktop" for the key
// agreement, and WebCrypto keys made from fixed scalars so results are repeatable.
import { createECDH, hkdfSync } from "node:crypto";
import { b64uEncode } from "./encoding";

export const scalar = (byte: number): Buffer => Buffer.alloc(32, byte);

export interface FixedAgreement {
  /** WebCrypto ECDH private key (non-extractable). */
  priv: CryptoKey;
  /** Raw uncompressed point. */
  pub: Buffer;
  pubB64: string;
}

/** A P-256 agreement key pair whose private scalar is 32 copies of `byte`. */
export async function agreementFromScalar(byte: number): Promise<FixedAgreement> {
  const e = createECDH("prime256v1");
  e.setPrivateKey(scalar(byte));
  const pub = e.getPublicKey();
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: b64uEncode(scalar(byte)),
    x: b64uEncode(pub.subarray(1, 33)),
    y: b64uEncode(pub.subarray(33, 65)),
    ext: true,
  };
  const priv = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits", "deriveKey"]);
  return { priv, pub, pubB64: b64uEncode(pub) };
}

/** K as the desktop computes it with node crypto: ECDH(its private scalar, ek), then HKDF-SHA256. */
export function desktopLinkKey(dkScalarByte: number, ekPub: Uint8Array, code: Uint8Array, info: string): Buffer {
  const e = createECDH("prime256v1");
  e.setPrivateKey(scalar(dkScalarByte));
  const shared = e.computeSecret(ekPub);
  return Buffer.from(hkdfSync("sha256", shared, code, info, 32));
}
