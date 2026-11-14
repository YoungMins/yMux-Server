// One real Remote (real keys and sealing) on a fake socket, with the test playing server and desktop:
// the unknown-outcome rules end to end, and the freshness rules of PROTOCOL.md 5.1.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { b64uEncode, newUuid } from "../protocol/encoding";
import { aadD2P, aadP2D, open, seal } from "../protocol/seal";
import { cmdRef, exportPublicKey, generateDeviceKey } from "../protocol/signing";
import { Remote } from "./remote";
import type { Pairing } from "./storage";

class FakeWS {
  static all: FakeWS[] = [];
  static OPEN = 1;
  readyState = 1;
  sent: string[] = [];
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(readonly url: string) {
    FakeWS.all.push(this);
  }
  send(s: string): void {
    this.sent.push(s);
  }
  close(): void {}
  say(o: unknown): void {
    this.onmessage?.({ data: JSON.stringify(o) });
  }
}

const PANE = "11111111-1111-4111-8111-111111111111";
const flush = (ms = 30) => new Promise((r) => setTimeout(r, ms));

async function makePairing(): Promise<Pairing> {
  const kp = await generateDeviceKey();
  return {
    deviceId: newUuid(),
    desktopId: newUuid(),
    pubkey: await exportPublicKey(kp.publicKey),
    name: "Phone",
    privateKey: kp.privateKey,
    linkKey: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    desktopName: "",
    addedMs: 1,
  };
}

/** The desktop and server side of one connection. */
class Desk {
  ws!: FakeWS;
  n = 0;
  session = "";
  constructor(readonly p: Pairing) {}
  seal(plain: object): Promise<string> {
    return seal(this.p.linkKey, aadD2P(this.p.desktopId, this.p.deviceId), JSON.stringify(plain));
  }
  async say(plain: object): Promise<void> {
    this.ws.say({ t: "msg", body: await this.seal(plain) });
  }
  /** The plaintexts of every command frame the phone sent, with its frame. */
  async cmds(): Promise<{ frame: { body: string; sig: string }; plain: Record<string, any> }[]> {
    const out = [];
    for (const f of this.ws.sent) {
      if (!f.includes('"t":"cmd"')) continue;
      const frame = JSON.parse(f) as { body: string; sig: string };
      const t = await open(this.p.linkKey, aadP2D(this.p.desktopId, this.p.deviceId), frame.body);
      out.push({ frame, plain: JSON.parse(t!) as Record<string, any> });
    }
    return out;
  }
  /** Handshake, then answer the phone's open with a session. `prev` settles older commands. */
  async connect(ws: FakeWS, prev?: { session: string; seq: number }, atOffsetMs = 0): Promise<void> {
    this.ws = ws;
    const before = (await this.cmds()).filter((c) => c.plain.k === "open").length;
    if (before === 0) {
      ws.say({ t: "challenge", nonce: "abc" });
      await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
      ws.say({ t: "ready", desktop_id: this.p.desktopId, desktop_online: true });
    }
    await vi.waitFor(async () => expect((await this.cmds()).filter((c) => c.plain.k === "open")).toHaveLength(before + 1), { timeout: 4000 });
    const opens = (await this.cmds()).filter((c) => c.plain.k === "open");
    const nonce = opens.at(-1)!.plain.nonce as string;
    const old = this.session;
    this.session = `S${Math.random().toString(36).slice(2, 8)}`;
    this.n = 0;
    await this.say({
      k: "session",
      open: nonce,
      session: this.session,
      cap: "prompt",
      name: "PC",
      now_ms: Date.now() + atOffsetMs,
      prev: prev ?? { session: old, seq: 0 },
      v: 1,
    });
  }
  panes(at: number, title = "t"): Promise<void> {
    const pane = { pane: PANE, ws: "w", title, kind: "claude", status: "idle", since_ms: 0, queued: 0 };
    return this.say({ k: "panes", panes: [pane], session: this.session, n: ++this.n, at_ms: at });
  }
}

beforeEach(() => {
  FakeWS.all = [];
  vi.stubGlobal("WebSocket", FakeWS);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

async function started() {
  const p = await makePairing();
  const remote = new Remote(p, "ws://test/ws/device");
  remote.start();
  const desk = new Desk(p);
  await desk.connect(FakeWS.all[0]!);
  await vi.waitFor(() => expect(remote.state.session).not.toBeNull());
  await vi.waitFor(async () => expect((await desk.cmds()).some((c) => c.plain.cmd?.op === "list")).toBe(true));
  return { p, remote, desk };
}

describe("freshness", () => {
  it("drops a body whose at_ms is more than 30 s old and counts it; a fresh one is accepted", async () => {
    const { remote, desk } = await started();
    await desk.panes(Date.now() - 31_000, "STALE");
    await vi.waitFor(() => expect(remote.state.dropped).toBe(1));
    expect(remote.state.panes?.map((x) => x.title) ?? []).not.toContain("STALE");
    await desk.panes(Date.now() - 1_000, "FRESH");
    await vi.waitFor(() => expect(remote.state.panes?.[0]?.title).toBe("FRESH"));
    remote.stop();
  });

  it("does not accept a session that comes more than 10 s after its open, and asks again", async () => {
    const p = await makePairing();
    const remote = new Remote(p, "ws://test/ws/device");
    remote.start();
    const desk = new Desk(p);
    const real = Date.now;
    desk.ws = FakeWS.all[0]!;
    desk.ws.say({ t: "challenge", nonce: "abc" });
    await vi.waitFor(() => expect(desk.ws.sent.length).toBeGreaterThanOrEqual(1));
    desk.ws.say({ t: "ready", desktop_id: p.desktopId, desktop_online: true });
    await vi.waitFor(async () => expect((await desk.cmds()).filter((c) => c.plain.k === "open")).toHaveLength(1));
    const nonce = (await desk.cmds())[0]!.plain.nonce as string;
    vi.spyOn(Date, "now").mockImplementation(() => real() + 10_500); // 10.5 s have passed
    await desk.say({ k: "session", open: nonce, session: "LATE", cap: "prompt", name: "PC", now_ms: real(), v: 1 });
    await flush(100);
    expect(remote.state.session, "a late session is not trusted").toBeNull();
    vi.restoreAllMocks();
    remote.stop();
  });
});

describe("unknown outcomes through a real Remote", () => {
  it("a plaintext desktop_offline is not a failure: a new open settles the command from prev (delivered)", async () => {
    const { remote, desk } = await started();
    const old = desk.session;
    const list = (await desk.cmds()).filter((c) => c.plain.cmd?.op === "list").length;
    const p = remote.request({ op: "interrupt", pane: PANE });
    await vi.waitFor(async () => expect((await desk.cmds()).some((c) => c.plain.cmd?.op === "interrupt")).toBe(true));
    const seq = (await desk.cmds()).find((c) => c.plain.cmd?.op === "interrupt")!.plain.seq as number;
    desk.ws.say({ t: "error", code: "desktop_offline" }); // the relay's say-so, not the desktop's
    let stateText = "";
    void p.then((r) => (stateText = JSON.stringify(r)));
    await flush(50);
    expect(stateText, "not reported while unconfirmed").toBe("");
    await desk.connect(desk.ws, { session: old, seq }); // the desktop did accept it
    expect(await p).toEqual({ ok: false, code: "delivered_unknown" });
    // sent once; only the reads (the first list) were asked again
    expect((await desk.cmds()).filter((c) => c.plain.cmd?.op === "interrupt")).toHaveLength(1);
    expect(list).toBeGreaterThanOrEqual(1);
    remote.stop();
  });

  it("... and as not delivered when prev says the desktop never got it", async () => {
    const { remote, desk } = await started();
    const old = desk.session;
    const p = remote.request({ op: "prompt", pane: PANE, text: "hi", queue: false });
    await vi.waitFor(async () => expect((await desk.cmds()).some((c) => c.plain.cmd?.op === "prompt")).toBe(true));
    const seq = (await desk.cmds()).find((c) => c.plain.cmd?.op === "prompt")!.plain.seq as number;
    desk.ws.say({ t: "error", code: "busy" });
    await desk.connect(desk.ws, { session: old, seq: seq - 1 });
    expect(await p).toEqual({ ok: false, code: "not_delivered" });
    expect((await desk.cmds()).filter((c) => c.plain.cmd?.op === "prompt")).toHaveLength(1);
    remote.stop();
  });

  it("a re:0 acts only through its ref: a stranger's ref changes nothing, the right one makes that command unknown", async () => {
    const { remote, desk } = await started();
    const old = desk.session;
    const opensBefore = (await desk.cmds()).filter((c) => c.plain.k === "open").length;
    const p = remote.request({ op: "interrupt", pane: PANE });
    await vi.waitFor(async () => expect((await desk.cmds()).some((c) => c.plain.cmd?.op === "interrupt")).toBe(true));
    await flush(50); // the ref of the frame is known now
    const sent = (await desk.cmds()).find((c) => c.plain.cmd?.op === "interrupt")!;
    const reply = (ref: string) => ({ k: "reply", re: 0, ok: false, code: "bad_sig", ref, session: "" });

    await desk.say(reply(b64uEncode(new Uint8Array(16).fill(9))));
    await flush(1300); // longer than the gap between opens: a provoked open would have gone out
    expect((await desk.cmds()).filter((c) => c.plain.k === "open"), "no new open for a stranger's ref").toHaveLength(opensBefore);

    await desk.say(reply(await cmdRef(sent.frame.sig)));
    // the matching ref provokes a new open, which connect() waits for and answers
    await desk.connect(desk.ws, { session: old, seq: (sent.plain.seq as number) - 1 }); // never accepted
    expect(await p).toEqual({ ok: false, code: "not_delivered" });
    remote.stop();
  }, 15000);

  it("a read that was in flight is asked again in the new session; a write is not", async () => {
    const { remote, desk } = await started();
    const old = desk.session;
    const w = remote.request({ op: "prompt", pane: PANE, text: "once", queue: false });
    const r = remote.request({ op: "peek", pane: PANE, lines: 5 });
    await vi.waitFor(async () => expect((await desk.cmds()).some((c) => c.plain.cmd?.op === "peek")).toBe(true));
    desk.ws.say({ t: "error", code: "desktop_offline" });
    await desk.connect(desk.ws, { session: old, seq: 99 });
    await vi.waitFor(async () => expect((await desk.cmds()).filter((c) => c.plain.cmd?.op === "peek")).toHaveLength(2));
    const again = (await desk.cmds()).filter((c) => c.plain.cmd?.op === "peek").at(-1)!;
    expect(again.plain.session).toBe(desk.session);
    await desk.say({ k: "reply", re: again.plain.seq, ok: true, data: { lines: [] }, session: desk.session, n: ++desk.n, at_ms: Date.now() });
    expect(await r).toMatchObject({ ok: true });
    expect(await w).toEqual({ ok: false, code: "delivered_unknown" });
    expect((await desk.cmds()).filter((c) => c.plain.cmd?.op === "prompt")).toHaveLength(1);
    remote.stop();
  });
});
