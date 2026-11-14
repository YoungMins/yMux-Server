import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { backoffDelay } from "./backoff";
import { cleanDeviceName, UNNAMED_DEVICE } from "./clean";
import { b64uDecode, b64uEncode, isUuid, newUuid, utf8 } from "./encoding";
import {
  buildCmdBody,
  capAllows,
  cmdFrame,
  parseBody,
  parseListData,
  parsePane,
  parsePeekData,
  parseServerFrame,
  toPushSub,
  validateCmd,
} from "./messages";
import { CommandRouter } from "./router";
import {
  cmdSigString,
  deviceHelloString,
  exportPublicKey,
  generateDeviceKey,
  hmacProof,
  pairProofMessage,
  pairSigString,
  signString,
} from "./signing";

const DESKTOP = "11111111-2222-4333-8444-555555555555";
const DEVICE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PANE = "01234567-89ab-4cde-8f01-23456789abcd";

describe("encodings", () => {
  it("b64u matches RFC 4648 vectors, no padding, url alphabet", () => {
    expect(b64uEncode(utf8("foobar"))).toBe("Zm9vYmFy");
    expect(b64uEncode(utf8("fooba"))).toBe("Zm9vYmE");
    expect(b64uEncode(utf8("foob"))).toBe("Zm9vYg");
    expect(b64uEncode(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(b64uEncode(new Uint8Array([]))).toBe("");
  });
  it("round-trips and rejects junk", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(65));
    expect(Array.from(b64uDecode(b64uEncode(bytes))!)).toEqual(Array.from(bytes));
    expect(b64uDecode("Zm9vYg")).toEqual(utf8("foob"));
    for (const bad of ["a", "ab+/", "ab=", "a b", "é", 5, null, undefined]) expect(b64uDecode(bad)).toBeNull();
  });
  it("uuid", () => {
    expect(isUuid(newUuid())).toBe(true);
    expect(isUuid(PANE)).toBe(true);
    expect(isUuid(PANE.toUpperCase())).toBe(false);
    expect(isUuid("nope")).toBe(false);
    expect(isUuid(1)).toBe(false);
  });
});

describe("signing strings (PROTOCOL.md)", () => {
  it("are exactly as specified", () => {
    expect(deviceHelloString(DEVICE, "NONCE")).toBe(`ymux-remote-v1|device|${DEVICE}|NONCE`);
    expect(pairSigString(DEVICE, "NONCE")).toBe(`ymux-remote-v1|pair|${DEVICE}|NONCE`);
    expect(pairProofMessage(DESKTOP, DEVICE, "PUB", "EK")).toBe(`ymux-remote-v1|pair|${DESKTOP}|${DEVICE}|PUB|EK`);
    expect(cmdSigString('{"a":1}')).toBe('ymux-remote-v1|cmd|{"a":1}');
  });
});

describe("crypto", () => {
  it("HMAC proof matches RFC 4231 test case 2", async () => {
    const hex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const bytes = Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
    const proof = await hmacProof(utf8("Jefe"), "what do ya want for nothing?");
    expect(proof).toBe(b64uEncode(bytes));
  });
  it("HMAC proof agrees with node for a random 16-byte code", async () => {
    const code = crypto.getRandomValues(new Uint8Array(16)) as Uint8Array<ArrayBuffer>;
    const msg = pairProofMessage(DESKTOP, DEVICE, "PUB", "EK");
    const expected = b64uEncode(new Uint8Array(createHmac("sha256", code).update(msg).digest()));
    expect(await hmacProof(code, msg)).toBe(expected);
  });
  it("public key is 65-byte SEC1, signature is 64-byte P1363 and verifies; private key not extractable", async () => {
    const kp = await generateDeviceKey();
    expect(kp.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", kp.privateKey)).rejects.toThrow();
    const pub = b64uDecode(await exportPublicKey(kp.publicKey))!;
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(4);
    const sig = b64uDecode(await signString(kp.privateKey, "hello"))!;
    expect(sig.length).toBe(64);
    const key = await crypto.subtle.importKey("raw", pub, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, utf8("hello"))).toBe(true);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, utf8("hellp"))).toBe(false);
  });
});

describe("command bodies", () => {
  const ctx = { desktopId: DESKTOP, deviceId: DEVICE, session: "SESS" };
  it("has the field order of 5.1 and the cmd object", () => {
    expect(buildCmdBody(ctx, 1, 1700000000123, { op: "peek", pane: PANE, lines: 80 })).toBe(
      `{"k":"cmd","desktop_id":"${DESKTOP}","device_id":"${DEVICE}","session":"SESS","seq":1,"ts_ms":1700000000123,"cmd":{"op":"peek","pane":"${PANE}","lines":80}}`,
    );
    expect(JSON.parse(cmdFrame("b", "s"))).toEqual({ t: "cmd", body: "b", sig: "s" });
  });
  it("validates", () => {
    expect(validateCmd({ op: "list" })).toBeNull();
    expect(validateCmd({ op: "peek", pane: PANE, lines: 201 })).toBe("bad_request");
    expect(validateCmd({ op: "peek", pane: "x", lines: 5 })).toBe("bad_request");
    expect(validateCmd({ op: "prompt", pane: PANE, text: "", queue: false })).toBe("bad_request");
    expect(validateCmd({ op: "prompt", pane: PANE, text: "x".repeat(16001), queue: false })).toBe("bad_request");
    expect(validateCmd({ op: "prompt", pane: PANE, text: "go", queue: true })).toBeNull();
    expect(validateCmd({ op: "answer", pane: PANE, n: 1.5, label: "a", menu_id: "m1" })).toBe("bad_request");
    expect(validateCmd({ op: "answer", pane: PANE, n: 10, label: "a", menu_id: "m1" })).toBe("bad_request");
    expect(validateCmd({ op: "answer", pane: PANE, n: 0, label: "a", menu_id: "m1" })).toBe("bad_request");
    expect(validateCmd({ op: "answer", pane: PANE, n: 1, label: "a", menu_id: "" })).toBe("bad_request");
    expect(validateCmd({ op: "answer", pane: PANE, n: 1, label: "a", menu_id: "has space" })).toBe("bad_request");
    expect(validateCmd({ op: "answer", pane: PANE, n: 1, label: "a" } as never)).toBe("bad_request");
    expect(validateCmd({ op: "answer", pane: PANE, n: 9, label: "a", menu_id: "Ab_-9" })).toBeNull();
    expect(validateCmd({ op: "nope" } as never)).toBe("bad_request");
  });
  it("capabilities nest", () => {
    expect(capAllows("view", "respond")).toBe(false);
    expect(capAllows("respond", "respond")).toBe(true);
    expect(capAllows("prompt", "respond")).toBe(true);
    expect(capAllows(null, "view")).toBe(false);
  });
});

describe("router", () => {
  function setup() {
    const sent: { seq: number; sig: string; body: string }[] = [];
    const timers: { fn: () => void; ms: number; live: boolean }[] = [];
    const router = new CommandRouter({
      send: (f) => {
        const frame = JSON.parse(f) as { body: string; sig: string };
        sent.push({ seq: (JSON.parse(frame.body) as { seq: number }).seq, ...frame });
      },
      seal: async (s) => s,
      sign: async (s) => `sig(${s.length})`,
      setTimer: (fn, ms) => {
        const t = { fn, ms, live: true };
        timers.push(t);
        return t;
      },
      clearTimer: (t) => {
        (t as { live: boolean }).live = false;
      },
    });
    return { router, sent, timers };
  }
  const flush = () => new Promise((r) => setTimeout(r, 0));

  it("refuses without a session", async () => {
    expect(await setup().router.request({ op: "list" })).toEqual({ ok: false, code: "no_session" });
  });
  it("numbers from 1, sends in order, matches replies by re", async () => {
    const { router, sent, timers } = setup();
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    const a = router.request({ op: "list" });
    const b = router.request({ op: "interrupt", pane: PANE });
    await flush();
    expect(sent.map((s) => s.seq)).toEqual([1, 2]);
    expect(timers[0]!.ms).toBe(8000);
    expect(router.handleReply(2, { ok: true, data: { result: "sent" } })).toBe(true);
    expect(router.handleReply(2, { ok: true, data: 1 })).toBe(false);
    expect(router.handleReply(99, { ok: false, code: "x" })).toBe(false);
    router.handleReply(1, { ok: false, code: "forbidden" });
    expect(await a).toEqual({ ok: false, code: "forbidden" });
    expect(await b).toEqual({ ok: true, data: { result: "sent" } });
    expect(timers.every((t) => !t.live)).toBe(true);
  });
  it("re:0 never matches by number (it names its command by ref, see router.test.ts)", async () => {
    const { router } = setup();
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    void router.request({ op: "list" });
    void router.request({ op: "list" });
    await flush();
    expect(router.handleReply(0, { ok: false, code: "bad_sig" })).toBe(false);
    expect(router.handleReply(1, { ok: true, data: {} })).toBe(true);
    expect(router.handleReply(0, { ok: true, data: {} })).toBe(false);
  });
  it("a new session id restarts seq at 1 and a command that never left is not delivered", async () => {
    const { router, sent } = setup();
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    const a = router.request({ op: "interrupt", pane: PANE });
    await flush();
    router.handleReply(1, { ok: true, data: {} });
    await a;
    const pending = router.request({ op: "interrupt", pane: PANE });
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S2" }); // before it was even numbered
    expect(await pending).toEqual({ ok: false, code: "session_changed" });
    void router.request({ op: "list" });
    await flush();
    expect(sent.map((s) => s.seq)).toEqual([1, 1]);
    // re-announcing the same session must not reset the counter
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S2" });
    void router.request({ op: "list" });
    await flush();
    expect(sent.map((s) => s.seq)).toEqual([1, 1, 2]);
  });
  it("signs `ymux-remote-v1|cmd|` + the exact body that is sent", async () => {
    const signed: string[] = [];
    const sent: string[] = [];
    const router = new CommandRouter({
      send: (f) => sent.push(f),
      seal: async (s) => `sealed(${s.length})`,
      sign: async (s) => {
        signed.push(s);
        return "S";
      },
    });
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    void router.request({ op: "list" });
    await flush();
    const body = (JSON.parse(sent[0]!) as { body: string }).body;
    expect(body.startsWith("sealed(")).toBe(true); // the sealed string, not the plaintext
    expect(signed[0]).toBe("ymux-remote-v1|cmd|" + body);
  });
  it("puts the clock-offset ts_ms in the plaintext it seals", async () => {
    const plain: string[] = [];
    const router = new CommandRouter({
      send: () => undefined,
      seal: async (s) => {
        plain.push(s);
        return "B";
      },
      sign: async () => "S",
      tsMs: () => 1_700_000_000_000 + 4321,
    });
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    void router.request({ op: "list" });
    await flush();
    expect(JSON.parse(plain[0]!)).toMatchObject({ k: "cmd", seq: 1, ts_ms: 1_700_000_004_321 });
  });
  it("refuses a plaintext over 64 KiB without sending", async () => {
    const { router, sent } = setup();
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    // 16000 control characters escape to 6 bytes each in JSON: 96 KB of plaintext.
    const big = router.request({ op: "prompt", pane: PANE, text: "\u0001".repeat(16000), queue: false });
    await flush();
    expect(sent).toHaveLength(0);
    expect(await big).toEqual({ ok: false, code: "bad_request" });
  });
  it("a failing send resolves instead of throwing", async () => {
    const router = new CommandRouter({
      send: () => {
        throw new Error("closed");
      },
      seal: async (s) => s,
      sign: async () => "S",
    });
    router.setSession({ desktopId: DESKTOP, deviceId: DEVICE, session: "S1" });
    expect(await router.request({ op: "list" })).toEqual({ ok: false, code: "offline" });
  });
});

describe("parsers on hostile input", () => {
  const junk: unknown[] = [null, undefined, 0, 1, true, "", "x", "[]", "null", "{", "{}", "[1,2]", '{"k":5}', '{"t":{}}', {}, [], "a".repeat(300000)];
  it("never throw and ignore wrong shapes", () => {
    for (const j of junk) {
      expect(() => parseServerFrame(j)).not.toThrow();
      expect(() => parseBody(j)).not.toThrow();
      expect(parseServerFrame(j)).toBeNull();
      expect(parseBody(j)).toBeNull();
      expect(parseListData(j)).toBeNull();
      expect(parsePeekData(j)).toBeNull();
      expect(parsePane(j)).toBeNull();
      expect(toPushSub(j)).toBeNull();
    }
  });
  it("server frames", () => {
    expect(parseServerFrame('{"t":"challenge","nonce":"abc_-"}')).toEqual({ t: "challenge", nonce: "abc_-" });
    expect(parseServerFrame('{"t":"challenge","nonce":"a b"}')).toBeNull();
    expect(parseServerFrame('{"t":"challenge"}')).toBeNull();
    expect(parseServerFrame(`{"t":"ready","desktop_id":"${DESKTOP}","desktop_online":true}`)).toEqual({
      t: "ready",
      desktopId: DESKTOP,
      desktopOnline: true,
    });
    expect(parseServerFrame('{"t":"ready","desktop_online":"yes"}')).toMatchObject({ desktopOnline: false });
    expect(parseServerFrame('{"t":"error","code":"bad_sig"}')).toEqual({ t: "error", code: "bad_sig" });
    expect(parseServerFrame('{"t":"msg","body":5}')).toBeNull();
    expect(parseServerFrame('{"t":"unknown_future"}')).toBeNull();
  });
  it("bodies", () => {
    expect(
      parseBody('{"k":"session","open":"O","session":"S","cap":"prompt","name":"PC","now_ms":1700000000000,"v":1}'),
    ).toEqual({ k: "session", session: "S", cap: "prompt", name: "PC", open: "O", nowMs: 1700000000000, prev: null });
    expect(parseBody('{"k":"session","session":"S","cap":"view"}')).toMatchObject({ open: "", nowMs: null });
    // unknown capability falls back to the least privilege
    expect(parseBody('{"k":"session","session":"S","cap":"root"}')).toMatchObject({ cap: "view" });
    expect(parseBody('{"k":"session","cap":"view"}')).toBeNull();
    expect(parseBody('{"k":"reply","re":3,"ok":true,"data":{"a":1},"session":"S","n":4,"at_ms":99}')).toEqual({
      k: "reply",
      re: 3,
      result: { ok: true, data: { a: 1 } },
      ref: null,
      session: "S",
      n: 4,
      atMs: 99,
    });
    expect(parseBody('{"k":"reply","re":0,"ok":false,"code":"bad_sig","session":""}')).toEqual({
      k: "reply",
      re: 0,
      result: { ok: false, code: "bad_sig" },
      ref: null,
      session: "",
      n: null,
      atMs: null,
    });
    expect(parseBody('{"k":"reopen","session":"S","n":"5"}')).toEqual({ k: "reopen", session: "S", n: null, atMs: null });
    expect(parseBody('{"k":"reply","re":"3","ok":true}')).toBeNull();
    expect(parseBody('{"k":"reply","re":1.5,"ok":true}')).toBeNull();
    expect(parseBody('{"k":"reply","re":1}')).toBeNull();
    expect(parseBody('{"k":"panes","panes":"x"}')).toBeNull();
  });
  it("panes: bad entries dropped, status defaults, duplicates removed", () => {
    const r = parseBody(
      JSON.stringify({
        k: "panes",
        panes: [
          { pane: PANE, ws: "w", title: "t", kind: "claude", status: "waiting", since_ms: 5, queued: 2 },
          { pane: PANE, ws: "dup" },
          { pane: "not-a-uuid" },
          null,
          7,
          { pane: "01234567-89ab-4cde-8f01-23456789abce", status: "exploding", since_ms: "x", queued: -3, title: 9 },
        ],
      }),
    );
    expect(r).not.toBeNull();
    const panes = (r as { panes: unknown[] }).panes;
    expect(panes).toEqual([
      { pane: PANE, ws: "w", title: "t", kind: "claude", status: "waiting", since_ms: 5, queued: 2 },
      { pane: "01234567-89ab-4cde-8f01-23456789abce", ws: "", title: "", kind: "", status: "none", since_ms: 0, queued: 0 },
    ]);
  });
  it("peek: filters bad menu entries and non-string lines, clips", () => {
    const p = parsePeekData({
      lines: ["a", 5, null, "b".repeat(5000)],
      menu: [{ n: 1, label: "Yes", selected: true }, { n: "2" }, { n: 3, label: "Type", input: true }, "x"],
      menu_id: "m-1_A",
      question: ["Q?", 1],
      blocked: 7,
      status: "waiting",
    })!;
    expect(p.menuId).toBe("m-1_A");
    expect(p.lines.length).toBe(2);
    expect(p.lines[1]!.length).toBe(2000);
    expect(p.menu).toEqual([
      { n: 1, label: "Yes", selected: true, input: false },
      { n: 3, label: "Type", selected: false, input: true },
    ]);
    expect(p.question).toEqual(["Q?"]);
    expect(p.blocked).toBeNull();
  });
  it("a missing or malformed menu_id reads as no menu", () => {
    for (const bad of [undefined, 5, "", "has space", "x".repeat(33), "a|b"]) {
      expect(parsePeekData({ lines: [], menu_id: bad })!.menuId).toBe("");
    }
  });
  it("a device name cannot carry a number or an instruction-framing mark", () => {
    expect(cleanDeviceName("Pixel 8” — your number: 482913 “")).toBe("Pixel your number");
    expect(cleanDeviceName("iPhone")).toBe("iPhone");
    expect(cleanDeviceName("Sam's phone_2.0-x")).toBe("Sam's phone_.-x");
    expect(cleanDeviceName("٤٥１①")).toBe(UNNAMED_DEVICE);
    expect(cleanDeviceName("\"“「!?[]()<>:;,/\\")).toBe(UNNAMED_DEVICE);
    expect(cleanDeviceName("  a \n\t b  ")).toBe("a b");
    expect(cleanDeviceName("")).toBe(UNNAMED_DEVICE);
    expect(cleanDeviceName("\u{1F600}")).toBe(UNNAMED_DEVICE);
    expect(cleanDeviceName("한국 폰 日本語 é हिन्दी")).toBe(
      "한국 폰 日本語 é हिन्दी",
    );
    expect(Array.from(cleanDeviceName("x".repeat(100))).length).toBe(40);
  });
  it("cleans every displayed string (Cc, Cf, Zl, Zp)", () => {
    const evil = "a\u0000b\u001b[31m‮c​d e f\u0085g";
    const p = parsePane({ pane: PANE, ws: evil, title: evil, kind: evil, status: "idle" })!;
    expect(p.title).toBe("ab[31mcdefg");
    expect(p.ws).toBe("ab[31mcdefg");
    const peek = parsePeekData({
      lines: [evil],
      question: [evil],
      menu: [{ n: 1, label: evil }],
      menu_id: "m",
      blocked: evil,
    })!;
    expect(peek.lines).toEqual(["ab[31mcdefg"]);
    expect(peek.question).toEqual(["ab[31mcdefg"]);
    expect(peek.menu[0]!.label).toBe("ab[31mcdefg");
    expect(peek.blocked).toBe("ab[31mcdefg");
    expect(parseBody(`{"k":"session","session":"S","open":"O","name":${JSON.stringify(evil)}}`)).toMatchObject({
      name: "ab[31mcdefg",
    });
    expect(parseServerFrame(JSON.stringify({ t: "error", code: evil }))).toEqual({ t: "error", code: "ab[31mcdefg" });
  });
  it("push subscriptions must be https with both keys", () => {
    const ok = { endpoint: "https://push.example/x", keys: { p256dh: "a", auth: "b" } };
    expect(toPushSub(ok)).toEqual(ok);
    expect(toPushSub({ ...ok, endpoint: "http://x" })).toBeNull();
    expect(toPushSub({ endpoint: ok.endpoint, keys: { p256dh: "a" } })).toBeNull();
  });
});

describe("backoff", () => {
  it("doubles from 1 s to a 60 s cap with +-25% jitter", () => {
    expect(backoffDelay(0, () => 0.5)).toBe(1000);
    expect(backoffDelay(1, () => 0.5)).toBe(2000);
    expect(backoffDelay(5, () => 0.5)).toBe(32000);
    expect(backoffDelay(6, () => 0.5)).toBe(60000);
    expect(backoffDelay(50, () => 1)).toBe(60000);
    expect(backoffDelay(0, () => 0)).toBe(750);
    expect(backoffDelay(0, () => 1)).toBe(1250);
    expect(backoffDelay(NaN)).toBeGreaterThanOrEqual(750);
    expect(backoffDelay(-4, () => 0.5)).toBe(1000);
  });
});
