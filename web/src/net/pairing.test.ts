import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { deviceNameFromUA, isIos } from "../device/env";
import { b64uDecode, b64uEncode } from "../protocol/encoding";
import { parseServerFrame } from "../protocol/messages";
import { aadD2P, aadP2D, deriveLinkKey, generateAgreementKey, seal } from "../protocol/seal";
import { exportPublicKey, generateDeviceKey } from "../protocol/signing";
import { agreementFromScalar } from "../protocol/testing";
import { isValidDk, parsePairCheck, parsePairFragment, parsePairLink, runPairing } from "./pairing";

const DESKTOP = "11111111-2222-4333-8444-555555555555";
const DEVICE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

describe("pair fragment", () => {
  const code = b64uEncode(new Uint8Array(16).fill(7));
  const dk = async () => (await agreementFromScalar(9)).pubB64;

  it("parses #pair=<desktop_id>.<code>.<dk>", async () => {
    const k = await dk();
    const p = parsePairFragment(`#pair=${DESKTOP}.${code}.${k}`)!;
    expect(p.desktopId).toBe(DESKTOP);
    expect(Array.from(p.code)).toEqual(new Array(16).fill(7));
    expect(p.dk).toBe(k);
    expect(parsePairLink(`#pair=${DESKTOP}.${code}.${k}`)).toMatchObject({ ok: true });
  });
  it("a link without a valid dk is an older yMux's (update message), anything else that is broken is just bad", async () => {
    const k = await dk();
    for (const h of [
      `#pair=${DESKTOP}.${code}`,
      `#pair=${DESKTOP}.${code}.`,
      `#pair=${DESKTOP}.${code}.$$$`,
      `#pair=${DESKTOP}.${code}.${b64uEncode(new Uint8Array(65))}`, // does not start with 0x04
      `#pair=${DESKTOP}.${code}.${b64uEncode(new Uint8Array(64).fill(4))}`, // wrong length
      `#pair=${DESKTOP}.${code}.${k.slice(0, -2)}`,
    ]) {
      expect(parsePairLink(h), h).toEqual({ ok: false, reason: "old" });
      expect(parsePairFragment(h), h).toBeNull();
    }
    for (const h of [
      "",
      "#pair=",
      `#pair=${DESKTOP}`,
      `#pair=${DESKTOP}.`,
      `#pair=nope.${code}.${k}`,
      `#pair=${DESKTOP}.${b64uEncode(new Uint8Array(8))}.${k}`,
      `#pair=${DESKTOP}.${code}.${k}&x=1`,
      `#pair=${DESKTOP}.${code}.${k}.extra`,
      `#pair=${DESKTOP}.$$$.${k}`,
    ]) {
      expect(parsePairLink(h), h).toEqual({ ok: false, reason: "bad" });
    }
  });
  it("accepts only a canonical 65-byte point", async () => {
    expect(isValidDk((await agreementFromScalar(4)).pubB64)).toBe(true);
    expect(isValidDk("")).toBe(false);
    const raw = new Uint8Array(65).fill(4);
    expect(isValidDk(b64uEncode(raw))).toBe(true); // shape only: the curve check happens at import
  });
});

class FakeSocket {
  sent: string[] = [];
  closed = false;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  send(s: string): void {
    this.sent.push(s);
  }
  close(): void {
    this.closed = true;
  }
  say(o: unknown): void {
    this.onmessage?.({ data: JSON.stringify(o) });
  }
}

const wait = () => new Promise((r) => setTimeout(r, 30));
const checkBody = (check: unknown, k = "pair_check") => JSON.stringify({ k, check });

describe("runPairing", () => {
  async function start(timeoutMs?: number) {
    const kp = await generateDeviceKey();
    const pubkey = await exportPublicKey(kp.publicKey);
    const dk = await agreementFromScalar(9);
    const code = crypto.getRandomValues(new Uint8Array(16)) as Uint8Array<ArrayBuffer>;
    const agree = await generateAgreementKey();
    const ek = await exportPublicKey(agree.publicKey);
    const linkKey = await deriveLinkKey({ ekPrivate: agree.privateKey, ek, dk: dk.pubB64, code, desktopId: DESKTOP, deviceId: DEVICE, pubkey });
    const stranger = await deriveLinkKey({
      ekPrivate: agree.privateKey,
      ek,
      dk: dk.pubB64,
      code: new Uint8Array(16).fill(1) as Uint8Array<ArrayBuffer>,
      desktopId: DESKTOP,
      deviceId: DEVICE,
      pubkey,
    });
    const sock = new FakeSocket();
    const checks: string[] = [];
    let sentCb = 0;
    const result = runPairing({
      url: "wss://x/ws/pair",
      link: { desktopId: DESKTOP, code, dk: dk.pubB64 },
      deviceId: DEVICE,
      pubkey,
      ek,
      name: "Phone",
      privateKey: kp.privateKey,
      linkKey,
      onSent: () => sentCb++,
      onCheck: (c) => checks.push(c),
      timeoutMs,
      socket: () => sock as unknown as WebSocket,
    });
    const challenge = async () => {
      sock.say({ t: "challenge", nonce: "NONCE_1", v: 1, server: "0.1.0" });
      await wait();
    };
    const sealedCheck = (plain: string, key = linkKey, aad = aadD2P(DESKTOP, DEVICE)) => seal(key, aad, plain);
    return { sock, result, kp, pubkey, ek, code, linkKey, stranger, checks, sentCount: () => sentCb, challenge, sealedCheck };
  }

  it("sends proof (over ek too), ek and signature over the exact strings", async () => {
    const t = await start();
    await t.challenge();
    expect(t.sentCount()).toBe(1);
    const f = JSON.parse(t.sock.sent[0]!);
    expect(f).toMatchObject({ t: "pair_request", v: 1, desktop_id: DESKTOP, device_id: DEVICE, pubkey: t.pubkey, ek: t.ek, name: "Phone" });
    expect(b64uDecode(f.ek)!.length).toBe(65);
    const msg = `ymux-remote-v1|pair|${DESKTOP}|${DEVICE}|${t.pubkey}|${t.ek}`;
    expect(f.proof).toBe(b64uEncode(new Uint8Array(createHmac("sha256", t.code).update(msg).digest())));
    const pub = await crypto.subtle.importKey("raw", b64uDecode(t.pubkey)!, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      b64uDecode(f.sig)!,
      new TextEncoder().encode(`ymux-remote-v1|pair|${DEVICE}|NONCE_1`),
    );
    expect(ok).toBe(true);
    t.sock.say({ t: "pair_result", ok: false });
    expect(await t.result).toBe("refused");
  });

  it("shows only a check number that opens under its own link key, newest first", async () => {
    const t = await start();
    await t.challenge();
    t.sock.say({ t: "pair_challenge", body: await t.sealedCheck(checkBody("123456")) });
    await wait();
    expect(t.checks).toEqual(["123456"]);
    t.sock.say({ t: "pair_challenge", body: await t.sealedCheck(checkBody("654321")) });
    await wait();
    expect(t.checks, "a second valid challenge shows the newest").toEqual(["123456", "654321"]);
    t.sock.say({ t: "pair_result", ok: true });
    expect(await t.result).toBe("ok");
    expect(t.sock.closed).toBe(true);
  });

  it("ignores bodies sealed with another key, under the wrong direction, malformed, or from before the request", async () => {
    const t = await start();
    t.sock.say({ t: "pair_challenge", body: await t.sealedCheck(checkBody("111111")) }); // before the request was sent
    await wait();
    await t.challenge();
    const bad = [
      await t.sealedCheck(checkBody("222222"), t.stranger), // another key (the code alone is not enough)
      await t.sealedCheck(checkBody("333333"), t.linkKey, aadP2D(DESKTOP, DEVICE)), // device -> desktop direction
      await t.sealedCheck(checkBody("333333"), t.linkKey, aadD2P(DESKTOP, "someone-else")),
      await t.sealedCheck(checkBody("12345")),
      await t.sealedCheck(checkBody("1234567")),
      await t.sealedCheck(checkBody("12345a")),
      await t.sealedCheck(checkBody(123456)),
      await t.sealedCheck(checkBody("123456", "pair_other")),
      await t.sealedCheck("not json"),
      await t.sealedCheck("[]"),
      "AAAA",
      "!!",
    ];
    for (const body of bad) t.sock.say({ t: "pair_challenge", body });
    t.sock.say({ t: "pair_challenge", body: 5 });
    await wait();
    expect(t.checks).toEqual([]);
    // An `ok:true` with no number ever shown is not a pairing.
    t.sock.say({ t: "pair_result", ok: true });
    expect(await t.result).toBe("error");
  });

  it("a pair_result that follows the challenge at once, then a close, still counts", async () => {
    const t = await start();
    await t.challenge();
    t.sock.say({ t: "pair_challenge", body: await t.sealedCheck(checkBody("000042")) });
    t.sock.say({ t: "pair_result", ok: true });
    t.sock.onclose?.();
    expect(await t.result).toBe("ok");
    expect(t.checks).toEqual(["000042"]);
  });

  it("maps refusals, no_pairing, odd frames and closes", async () => {
    let t = await start();
    t.sock.say({ t: "pair_result", ok: false });
    expect(await t.result).toBe("refused");
    t = await start();
    t.sock.say({ t: "error", code: "no_pairing" });
    expect(await t.result).toBe("no_pairing");
    t = await start();
    t.sock.onmessage?.({ data: new ArrayBuffer(4) });
    t.sock.onmessage?.({ data: "not json" });
    t.sock.say({ t: "error", code: "limit" });
    expect(await t.result).toBe("error");
    t = await start();
    t.sock.onclose?.();
    expect(await t.result).toBe("error");
  });
  it("times out", async () => {
    const t = await start(30);
    expect(await t.result).toBe("timeout");
  });
});

describe("pair_check body", () => {
  it("is exactly {k:pair_check, check:<6 digits>}", () => {
    expect(parsePairCheck(checkBody("000000"))).toBe("000000");
    expect(parsePairCheck(checkBody("0123456"))).toBeNull();
    expect(parsePairCheck(checkBody("12 456"))).toBeNull();
    expect(parsePairCheck(checkBody("١٢٣٤٥٦"))).toBeNull(); // not ASCII digits
    expect(parsePairCheck(null)).toBeNull();
    expect(parsePairCheck("{")).toBeNull();
  });
  it("arrives as a pair_challenge server frame with a body", () => {
    expect(parseServerFrame('{"t":"pair_challenge","body":"abc"}')).toEqual({ t: "pair_challenge", body: "abc" });
    expect(parseServerFrame('{"t":"pair_challenge"}')).toBeNull();
    expect(parseServerFrame('{"t":"pair_challenge","body":5}')).toBeNull();
  });
});

describe("device helpers", () => {
  it("names the device from the user agent", () => {
    expect(deviceNameFromUA("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)")).toBe("iPhone");
    expect(deviceNameFromUA("Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/UD1A) AppleWebKit")).toBe("Pixel 8");
    expect(deviceNameFromUA("Mozilla/5.0 (Linux; Android 14; K) Chrome")).toBe("Android");
    expect(deviceNameFromUA("")).toBe("Browser");
  });
  it("detects iPadOS posing as a Mac", () => {
    expect(isIos("Macintosh", "MacIntel", 5)).toBe(true);
    expect(isIos("Macintosh", "MacIntel", 0)).toBe(false);
    expect(isIos("iPhone", "iPhone", 5)).toBe(true);
  });
});
