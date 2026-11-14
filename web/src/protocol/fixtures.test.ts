// Checks this code against the server's protocol fixtures (D:/Git/yMux-Server/fixtures, see its
// README.md): ECDH + HKDF link key, the sealed pair_check, sealed bodies (open AND re-seal with
// the recorded nonce), signatures, the pairing proof, the `ref` of a bad_sig reply, and a replay
// of the recorded session through the session rules. Skipped when the fixtures directory is not
// there or is still the older (HMAC link key) set.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, createHmac, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { b64uDecode, b64uEncode, utf8 } from "./encoding";
import { parseBody, parsePeekData, parseServerFrame, type Body } from "./messages";
import { CommandRouter } from "./router";
import { aadD2P, deriveLinkKey, linkKeyInfo, open, seal } from "./seal";
import { SessionTracker } from "./session";
import { cmdRef, hmacProof } from "./signing";
import { runPairing, parsePairCheck } from "../net/pairing";

const DIR = join(__dirname, "..", "..", "..", "fixtures");
const HAVE =
  existsSync(join(DIR, "link_key.json")) &&
  existsSync(join(DIR, "sealed_pair_check.json")) &&
  existsSync(join(DIR, "sealed_bad_sig_reply.json")) &&
  /shared_secret_hex/.test(readFileSync(join(DIR, "link_key.json"), "utf8"));

const read = <T = Record<string, any>>(name: string): T => JSON.parse(readFileSync(join(DIR, name), "utf8")) as T;
const hex = (h: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16))) as Uint8Array<ArrayBuffer>;

async function verify(pubkey: string, sig: string, signed: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", b64uDecode(pubkey)!, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64uDecode(sig)!, utf8(signed));
}

/** A P-256 private key (ECDH or ECDSA) from the fixture's scalar and public point, non-extractable. */
async function privateKey(algo: "ECDH" | "ECDSA", privateHex: string, publicB64: string, usages: KeyUsage[]): Promise<CryptoKey> {
  const pub = b64uDecode(publicB64)!;
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: b64uEncode(hex(privateHex)),
    x: b64uEncode(pub.slice(1, 33)),
    y: b64uEncode(pub.slice(33, 65)),
    ext: true,
  };
  return crypto.subtle.importKey("jwk", jwk, { name: algo, namedCurve: "P-256" }, false, usages);
}

const SEALED = [
  "sealed_open",
  "sealed_session",
  "sealed_cmd",
  "sealed_reply",
  "sealed_panes",
  "sealed_reopen",
  "sealed_pair_check",
  "sealed_bad_sig_reply",
];

describe.skipIf(!HAVE)("server protocol fixtures", () => {
  const lk = HAVE ? read("link_key.json") : {};
  const keys = HAVE ? read("keys.json") : {};
  const code = (): Uint8Array<ArrayBuffer> => b64uDecode(lk.code)!;
  const derive = async (): Promise<CryptoKey> =>
    deriveLinkKey({
      ekPrivate: await privateKey("ECDH", lk.ek.private_hex, lk.ek.public, ["deriveBits", "deriveKey"]),
      ek: lk.ek.public,
      dk: lk.dk.public,
      code: code(),
      desktopId: lk.desktop_id,
      deviceId: lk.device_id,
      pubkey: lk.pubkey,
    });

  it("derives the recorded shared secret and link key (ECDH from the device side, HKDF-SHA256)", async () => {
    expect(Array.from(code())).toEqual(Array.from(hex(lk.code_hex)));
    expect(lk.info).toBe(linkKeyInfo(lk.desktop_id, lk.device_id, lk.pubkey, lk.ek.public, lk.dk.public));
    // The shared secret, from the device's private key and the desktop's public point.
    const ekPriv = await privateKey("ECDH", lk.ek.private_hex, lk.ek.public, ["deriveBits"]);
    const dkPub = await crypto.subtle.importKey("raw", b64uDecode(lk.dk.public)!, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: dkPub }, ekPriv, 256));
    expect(Buffer.from(shared).toString("hex")).toBe(lk.shared_secret_hex);
    // K by node's HKDF, and by this code's WebCrypto path (through the bodies sealed under it).
    expect(Buffer.from(hkdfSync("sha256", shared, code(), lk.info, 32)).toString("hex")).toBe(lk.key_hex);
    const key = await derive();
    expect(key.extractable).toBe(false);
    for (const name of SEALED) {
      const f = read(`${name}.json`);
      expect(f.link_key_hex, name).toBe(lk.key_hex);
      expect(await seal(key, f.aad, f.plaintext, hex(f.nonce_hex)), `${name}: re-sealing gives the recorded body`).toBe(f.body);
    }
  });

  it("opens every sealed body, and only under its own direction's AAD", async () => {
    const key = await derive();
    for (const name of SEALED) {
      const f = read(`${name}.json`);
      expect(await open(key, f.aad, f.body), name).toBe(f.plaintext);
      const other = f.aad.replace(f.direction, f.direction === "p2d" ? "d2p" : "p2d");
      expect(other).not.toBe(f.aad);
      expect(await open(key, other, f.body), `${name} under the other direction`).toBeNull();
    }
    // A key made with another code (the QR alone is not enough) opens nothing.
    const wrong = await deriveLinkKey({
      ekPrivate: await privateKey("ECDH", lk.ek.private_hex, lk.ek.public, ["deriveBits"]),
      ek: lk.ek.public,
      dk: lk.dk.public,
      code: new Uint8Array(16).fill(1) as Uint8Array<ArrayBuffer>,
      desktopId: lk.desktop_id,
      deviceId: lk.device_id,
      pubkey: lk.pubkey,
    });
    expect(await open(wrong, read("sealed_pair_check.json").aad, read("sealed_pair_check.json").body)).toBeNull();
  });

  it("reads the check number out of the sealed pair_challenge, and only from there", async () => {
    const key = await derive();
    const sealed = read("sealed_pair_check.json");
    expect(read("pair_challenge.json").body).toBe(sealed.body);
    expect(parseServerFrame(JSON.stringify(read("pair_challenge_forwarded.json")))).toEqual({ t: "pair_challenge", body: sealed.body });
    expect(parsePairCheck(await open(key, aadD2P(lk.desktop_id, lk.device_id), sealed.body))).toBe(keys.pair_check);

    // End to end through runPairing: request fields, proof, and the number the socket delivers.
    const pr = read("pair_request.json");
    const sent: string[] = [];
    const checks: string[] = [];
    let onmessage: ((ev: { data: unknown }) => void) | null = null;
    const sock = {
      send: (s: string) => sent.push(s),
      close: () => undefined,
      set onmessage(fn: ((ev: { data: unknown }) => void) | null) {
        onmessage = fn;
      },
      onclose: null,
      onerror: null,
    };
    const result = runPairing({
      url: "wss://x/ws/pair",
      link: { desktopId: lk.desktop_id, code: code(), dk: lk.dk.public },
      deviceId: lk.device_id,
      pubkey: lk.pubkey,
      ek: lk.ek.public,
      name: pr.name,
      privateKey: await privateKey("ECDSA", keys.device.private_hex, keys.device.public, ["sign"]),
      linkKey: key,
      onSent: () => undefined,
      onCheck: (c) => checks.push(c),
      socket: () => sock as unknown as WebSocket,
    });
    onmessage!({ data: JSON.stringify({ t: "challenge", nonce: keys.nonce }) });
    await new Promise((r) => setTimeout(r, 50));
    const req = JSON.parse(sent[0]!);
    expect(req).toMatchObject({ t: "pair_request", v: 1, desktop_id: pr.desktop_id, device_id: pr.device_id, pubkey: pr.pubkey, ek: pr.ek, name: pr.name, proof: pr.proof });
    expect(await verify(pr.pubkey, req.sig, keys.signed_strings.pair_request)).toBe(true);
    onmessage!({ data: JSON.stringify(read("pair_challenge_forwarded.json")) });
    await new Promise((r) => setTimeout(r, 50));
    expect(checks).toEqual([keys.pair_check]);
    onmessage!({ data: JSON.stringify({ t: "pair_result", ok: true }) });
    expect(await result).toBe("ok");
  });

  it("verifies every recorded signature and the pairing proof (which covers ek)", async () => {
    const dev = keys.device.public as string;
    for (const name of ["sealed_open", "sealed_cmd"]) {
      const f = read(`${name}.json`);
      expect(f.signed_string).toBe(`ymux-remote-v1|cmd|${f.body}`);
      expect(await verify(dev, f.sig, f.signed_string), name).toBe(true);
      expect(await verify(dev, f.sig, f.signed_string + "x"), `${name} altered`).toBe(false);
    }
    const cmd = read("cmd_device.json");
    expect(cmd.body).toBe(read("sealed_cmd.json").body);
    expect(await verify(dev, cmd.sig, `ymux-remote-v1|cmd|${cmd.body}`)).toBe(true);
    expect(await verify(dev, read("hello_device.json").sig, keys.signed_strings.device_hello)).toBe(true);
    expect(await verify(keys.desktop.public, read("hello_desktop.json").sig, keys.signed_strings.desktop_hello)).toBe(true);
    const pr = read("pair_request.json");
    expect(keys.signed_strings.pair_proof_message).toBe(`ymux-remote-v1|pair|${pr.desktop_id}|${pr.device_id}|${pr.pubkey}|${pr.ek}`);
    expect(await verify(pr.pubkey, pr.sig, keys.signed_strings.pair_request)).toBe(true);
    expect(await hmacProof(code(), keys.signed_strings.pair_proof_message)).toBe(pr.proof);
    expect(b64uEncode(new Uint8Array(createHmac("sha256", code()).update(keys.signed_strings.pair_proof_message).digest()))).toBe(pr.proof);
  });

  it("names a command in a re:0 reply by the first 16 bytes of SHA-256 of its sig string, and acts only on a match", async () => {
    const key = await derive();
    const f = read("sealed_bad_sig_reply.json");
    expect(createHash("sha256").update(f.ref_sig).digest("hex")).toBe(f.ref_sha256_hex);
    expect(f.ref_sha256_hex.startsWith(f.ref_first16_hex)).toBe(true);
    const plain = JSON.parse((await open(key, f.aad, f.body))!);
    expect(plain.ref).toBe(b64uEncode(hex(f.ref_first16_hex)));
    expect(await cmdRef(f.ref_sig)).toBe(plain.ref);

    const body = parseBody(JSON.stringify(plain))!;
    expect(body).toMatchObject({ k: "reply", re: 0, result: { ok: false, code: "bad_sig" }, session: "", ref: plain.ref, n: null, atMs: null });
    expect(new SessionTracker().accept(body, 0), "the empty-session re:0 needs neither n nor at_ms").not.toBeNull();

    // A router whose command carries exactly that signature treats it as unknown; a different one does not.
    for (const [sig, matches] of [[f.ref_sig, true], [f.ref_sig.slice(0, -1) + (f.ref_sig.endsWith("A") ? "B" : "A"), false]] as const) {
      let asked = 0;
      const router = new CommandRouter({
        send: () => undefined,
        seal: async (s) => s,
        sign: async () => sig,
        onUnconfirmed: () => asked++,
        timeoutMs: 400,
        confirmMs: 50,
      });
      router.setSession({ desktopId: lk.desktop_id, deviceId: lk.device_id, session: keys.session });
      const p = router.request({ op: "interrupt", pane: keys.pane });
      await new Promise((r) => setTimeout(r, 50));
      const b = body as Extract<Body, { k: "reply" }>;
      expect(router.handleRef(b.ref), String(matches)).toBe(matches);
      expect(asked).toBe(matches ? 1 : 0);
      expect(await p).toEqual({ ok: false, code: "could_not_confirm" });
    }
  });

  it("replays the recorded desktop bodies through the session rules", async () => {
    const key = await derive();
    const bodyOf = async (name: string): Promise<Body> => {
      const f = read(`${name}.json`);
      const plain = await open(key, f.aad, f.body);
      const b = parseBody(plain);
      if (!b) throw new Error(`${name} does not parse`);
      return b;
    };
    const tracker = new SessionTracker();
    const openFx = read("sealed_open.json");
    const openPlain = JSON.parse((await open(key, openFx.aad, openFx.body))!);
    expect(openPlain).toMatchObject({ k: "open", desktop_id: lk.desktop_id, device_id: lk.device_id });
    expect(openPlain.nonce).toBe(keys.open_nonce);

    const session = await bodyOf("sealed_session");
    const localNow = keys.now_ms - 4000; // the phone's clock runs 4 s behind the desktop's
    expect(tracker.accept(session, localNow), "no open sent yet").toBeNull();
    tracker.beginOpen("some other nonce", localNow);
    expect(tracker.accept(session, localNow), "wrong nonce").toBeNull();
    tracker.beginOpen(openPlain.nonce, localNow - 10_001);
    expect(tracker.accept(session, localNow), "arrived more than 10 s after the open").toBeNull();
    tracker.beginOpen(openPlain.nonce, localNow - 9_000);
    expect(tracker.accept(session, localNow)).not.toBeNull();
    expect(session).toMatchObject({ k: "session", cap: "respond", name: "My PC", session: keys.session, prev: { session: keys.prev_session, seq: 3 } });
    expect(tracker.offsetMs).toBe(4000);

    const reply = await bodyOf("sealed_reply");
    const panes = await bodyOf("sealed_panes");
    const reopen = await bodyOf("sealed_reopen");
    // The phone's clock reads (desktop clock - 4 s): panes carry at_ms = now + 1 s.
    const at = (ms: number) => ms - 4000;
    expect(tracker.accept(panes, at(1731600001000)), "n=2 before n=1 is fine (greater than 0)").not.toBeNull();
    expect(tracker.accept(reply, at(1731600001000)), "n=1 after n=2 is not").toBeNull();
    expect(tracker.accept(reopen, at(1731600001000))).not.toBeNull();
    expect(tracker.accept(reopen, at(1731600001000)), "replayed").toBeNull();
    expect(reply).toMatchObject({ k: "reply", re: 1, result: { ok: true } });

    // 30.001 s behind the estimated desktop clock is too old, whatever its n.
    const fresh = new SessionTracker();
    fresh.beginOpen(openPlain.nonce, localNow);
    expect(fresh.accept(session, localNow)).not.toBeNull();
    expect(fresh.accept(panes, at(1731600001000 + 30_001)), "stale").toBeNull();
    expect(fresh.accept(panes, at(1731600001000 + 30_000)), "exactly 30 s").not.toBeNull();

    // The recorded command carries the menu_id and a ts_ms made from the offset.
    const c = read("sealed_cmd.json");
    const cmd = JSON.parse(c.plaintext);
    expect(cmd).toMatchObject({ k: "cmd", session: keys.session, seq: 1, ts_ms: 1731600000123 });
    expect(cmd.cmd).toEqual({ op: "answer", pane: keys.pane, n: 1, label: "Yes", menu_id: "m7-3fA" });
    expect(parsePeekData({ lines: [], menu_id: cmd.cmd.menu_id })!.menuId).toBe("m7-3fA");
  });
});
