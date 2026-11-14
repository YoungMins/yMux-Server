import { createDecipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import { b64uDecode, b64uEncode, utf8 } from "./encoding";
import {
  aadD2P,
  aadP2D,
  deriveLinkKey,
  generateAgreementKey,
  isAgreementPoint,
  linkKeyInfo,
  open,
  seal,
} from "./seal";
import { agreementFromScalar, desktopLinkKey } from "./testing";
import { exportPublicKey } from "./signing";

const DESKTOP = "11111111-2222-4333-8444-555555555555";
const DEVICE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PUB = "BPUBKEYPLACEHOLDER";
const code = (): Uint8Array<ArrayBuffer> => new Uint8Array(16).map((_, i) => i + 1) as Uint8Array<ArrayBuffer>;

/** Everything a derivation depends on, with a fixed device `ek` (scalar 0x07) and desktop `dk` (0x09). */
async function inputs(over: Partial<{ code: Uint8Array<ArrayBuffer>; desktopId: string; deviceId: string; pubkey: string }> = {}) {
  const ek = await agreementFromScalar(7);
  const dk = await agreementFromScalar(9);
  return {
    ekPrivate: ek.priv,
    ek: ek.pubB64,
    dk: dk.pubB64,
    code: over.code ?? code(),
    desktopId: over.desktopId ?? DESKTOP,
    deviceId: over.deviceId ?? DEVICE,
    pubkey: over.pubkey ?? PUB,
  };
}

describe("link key (ECDH + HKDF)", () => {
  it("has the info string of PROTOCOL.md section 1", () => {
    expect(linkKeyInfo(DESKTOP, DEVICE, PUB, "EK", "DK")).toBe(`ymux-remote-v1|link|${DESKTOP}|${DEVICE}|${PUB}|EK|DK`);
  });

  it("is HKDF-SHA256(ECDH(ek, dk), salt = code, info) used as a non-extractable AES-256-GCM key, as node computes it", async () => {
    const i = await inputs();
    const key = await deriveLinkKey(i);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect([...key.usages].sort()).toEqual(["decrypt", "encrypt"]);
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();

    // The "desktop" side: its own private scalar and the device's public ek, node crypto only.
    const ekPub = Buffer.from(b64uDecode(i.ek)!);
    const nodeKey = desktopLinkKey(9, ekPub, code(), linkKeyInfo(DESKTOP, DEVICE, PUB, i.ek, i.dk));
    const nonce = new Uint8Array(12).fill(9) as Uint8Array<ArrayBuffer>;
    const body = await seal(key, aadP2D(DESKTOP, DEVICE), "hello", nonce);
    const bytes = b64uDecode(body)!;
    const d = createDecipheriv("aes-256-gcm", nodeKey, Buffer.from(bytes.slice(0, 12)));
    d.setAAD(Buffer.from(`ymux-remote-v1|p2d|${DESKTOP}|${DEVICE}`));
    d.setAuthTag(Buffer.from(bytes.slice(bytes.length - 16)));
    const pt = Buffer.concat([d.update(Buffer.from(bytes.slice(12, bytes.length - 16))), d.final()]).toString("utf8");
    expect(pt).toBe("hello");
  });

  it("agrees with the desktop for a freshly generated ek (the production path)", async () => {
    const dk = await agreementFromScalar(5);
    const pair = await generateAgreementKey();
    expect(pair.privateKey.extractable).toBe(false);
    expect([...pair.privateKey.usages].sort()).toEqual(["deriveBits", "deriveKey"]);
    const ek = await exportPublicKey(pair.publicKey);
    const key = await deriveLinkKey({ ekPrivate: pair.privateKey, ek, dk: dk.pubB64, code: code(), desktopId: DESKTOP, deviceId: DEVICE, pubkey: PUB });
    const nodeKey = desktopLinkKey(5, b64uDecode(ek)!, code(), linkKeyInfo(DESKTOP, DEVICE, PUB, ek, dk.pubB64));
    const body = await seal(key, aadD2P(DESKTOP, DEVICE), "from the phone");
    const bytes = b64uDecode(body)!;
    const d = createDecipheriv("aes-256-gcm", nodeKey, Buffer.from(bytes.slice(0, 12)));
    d.setAAD(Buffer.from(`ymux-remote-v1|d2p|${DESKTOP}|${DEVICE}`));
    d.setAuthTag(Buffer.from(bytes.slice(bytes.length - 16)));
    expect(Buffer.concat([d.update(Buffer.from(bytes.slice(12, bytes.length - 16))), d.final()]).toString("utf8")).toBe("from the phone");
  });

  it("depends on the code, both ids, the signing key, ek and dk", async () => {
    const probe = async (k: CryptoKey) => seal(k, "a", "x", new Uint8Array(12) as Uint8Array<ArrayBuffer>);
    const base = await probe(await deriveLinkKey(await inputs()));
    expect(await probe(await deriveLinkKey(await inputs()))).toBe(base);
    const other = new Uint8Array(16).fill(5) as Uint8Array<ArrayBuffer>;
    expect(await probe(await deriveLinkKey(await inputs({ code: other })))).not.toBe(base);
    expect(await probe(await deriveLinkKey(await inputs({ pubkey: PUB + "x" })))).not.toBe(base);
    expect(await probe(await deriveLinkKey(await inputs({ desktopId: DEVICE, deviceId: DESKTOP })))).not.toBe(base);
    // A different ek or dk changes both the shared secret and the info string.
    const i = await inputs();
    const ek2 = await agreementFromScalar(8);
    expect(await probe(await deriveLinkKey({ ...i, ekPrivate: ek2.priv, ek: ek2.pubB64 }))).not.toBe(base);
    const dk2 = await agreementFromScalar(10);
    expect(await probe(await deriveLinkKey({ ...i, dk: dk2.pubB64 }))).not.toBe(base);
  });

  it("is NOT computable from the code and the public values alone (a wrong ek private key gives another key)", async () => {
    const i = await inputs();
    const thief = await agreementFromScalar(3);
    const probe = async (k: CryptoKey) => seal(k, "a", "x", new Uint8Array(12) as Uint8Array<ArrayBuffer>);
    expect(await probe(await deriveLinkKey({ ...i, ekPrivate: thief.priv }))).not.toBe(await probe(await deriveLinkKey(i)));
  });

  it("leaves the pairing code argument untouched (the caller wipes it) and rejects a bad dk", async () => {
    const c = code();
    await deriveLinkKey(await inputs({ code: c }));
    expect(Array.from(c)).toEqual(Array.from(code()));
    const i = await inputs();
    await expect(deriveLinkKey({ ...i, dk: b64uEncode(new Uint8Array(65).fill(4)) })).rejects.toThrow();
    await expect(deriveLinkKey({ ...i, dk: "!!" })).rejects.toThrow();
    expect(await isAgreementPoint(i.dk)).toBe(true);
    expect(await isAgreementPoint(b64uEncode(new Uint8Array(65).fill(4)))).toBe(false);
    expect(await isAgreementPoint("!!")).toBe(false);
  });
});

describe("sealed bodies", () => {
  const aad = aadP2D(DESKTOP, DEVICE);
  const key = async (): Promise<CryptoKey> => deriveLinkKey(await inputs());

  it("has the two additional-data strings of the protocol", () => {
    expect(aadP2D(DESKTOP, DEVICE)).toBe(`ymux-remote-v1|p2d|${DESKTOP}|${DEVICE}`);
    expect(aadD2P(DESKTOP, DEVICE)).toBe(`ymux-remote-v1|d2p|${DESKTOP}|${DEVICE}`);
  });
  it("round-trips in both directions, with a fresh random nonce each time", async () => {
    const k = await key();
    const text = '{"k":"cmd","x":"héllo \u{1F600}"}';
    for (const a of [aadP2D(DESKTOP, DEVICE), aadD2P(DESKTOP, DEVICE)]) {
      const a1 = await seal(k, a, text);
      const a2 = await seal(k, a, text);
      expect(a1).not.toBe(a2);
      expect(b64uDecode(a1)!.length).toBe(12 + utf8(text).length + 16);
      expect(await open(k, a, a1)).toBe(text);
      expect(await open(k, a, a2)).toBe(text);
    }
  });
  it("does not open under the other direction's AAD, a wrong key, or any tampering", async () => {
    const k = await key();
    const wrong = await deriveLinkKey(await inputs({ code: new Uint8Array(16).fill(3) as Uint8Array<ArrayBuffer> }));
    const body = await seal(k, aad, "secret");
    expect(await open(k, aad, body)).toBe("secret");
    expect(await open(k, aadD2P(DESKTOP, DEVICE), body)).toBeNull();
    expect(await open(k, aadP2D(DESKTOP, "other"), body)).toBeNull();
    expect(await open(wrong, aad, body)).toBeNull();
    const bytes = b64uDecode(body)!;
    for (const i of [0, 11, 12, bytes.length - 1]) {
      const t = bytes.slice();
      t[i] = t[i]! ^ 1;
      expect(await open(k, aad, b64uEncode(t)), `byte ${i}`).toBeNull();
    }
    expect(await open(k, aad, b64uEncode(bytes.slice(0, bytes.length - 1)))).toBeNull();
  });
  it("rejects junk without throwing", async () => {
    const k = await key();
    for (const j of [undefined, null, 5, "", "a", "!!!!", "AAAA", b64uEncode(new Uint8Array(27)), b64uEncode(new Uint8Array(28))]) {
      expect(await open(k, aad, j)).toBeNull();
    }
  });
  it("is deterministic for a given nonce (known-answer for fixtures)", async () => {
    const k = await key();
    const nonce = new Uint8Array(12).fill(1) as Uint8Array<ArrayBuffer>;
    expect(await seal(k, aad, "{}", nonce)).toBe(await seal(k, aad, "{}", nonce));
  });
});
