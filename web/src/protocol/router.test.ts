// PROTOCOL.md 5.1 "Unknown outcomes": every trigger, every resolution, and no re-sent writes.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { b64uEncode } from "./encoding";
import type { Cmd, Prev } from "./messages";
import { CommandRouter, COULD_NOT_CONFIRM, DELIVERED_UNKNOWN, NOT_DELIVERED, CLIENT_TIMEOUT_MS, CONFIRM_MS } from "./router";

const DESKTOP = "11111111-2222-4333-8444-555555555555";
const DEVICE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PANE = "01234567-89ab-4cde-8f01-23456789abcd";
const ctx = (session: string) => ({ desktopId: DESKTOP, deviceId: DEVICE, session });
/** Long enough for the frames to leave and for each command's ref (an async SHA-256) to be known. */
const flush = () => new Promise((r) => setTimeout(r, 25));

/** The ref the desktop would put in a `re:0` for this frame (first 16 bytes of SHA-256 of its `sig` string). */
const refOfFrame = (frame: string): string => {
  const { sig } = JSON.parse(frame) as { sig: string };
  return b64uEncode(new Uint8Array(createHash("sha256").update(sig).digest().subarray(0, 16)));
};

function setup() {
  const frames: string[] = [];
  const timers: { fn: () => void; ms: number; live: boolean }[] = [];
  let asked = 0;
  let signed = 0;
  const router = new CommandRouter({
    send: (f) => frames.push(f),
    seal: async (s) => s,
    sign: async () => `SIG${++signed}`, // one distinct signature per command, as with ECDSA
    onUnconfirmed: () => asked++,
    setTimer: (fn, ms) => {
      const t = { fn, ms, live: true };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => {
      (t as { live: boolean }).live = false;
    },
  });
  const sent = (op?: string) =>
    frames
      .map((f) => JSON.parse(JSON.parse(f).body) as { seq: number; session: string; cmd: { op: string } })
      .filter((p) => !op || p.cmd.op === op);
  /** Fires the live timer with this duration (a client timeout or a confirm deadline). */
  const fire = (ms: number) => {
    const t = timers.find((x) => x.live && x.ms === ms);
    if (!t) throw new Error(`no live timer of ${ms} ms`);
    t.live = false;
    t.fn();
  };
  const fireAll = (ms: number) => {
    for (const t of timers.filter((x) => x.live && x.ms === ms)) {
      t.live = false;
      t.fn();
    }
  };
  return { router, frames, timers, sent, fire, fireAll, asked: () => asked };
}

const INTERRUPT: Cmd = { op: "interrupt", pane: PANE };
const PROMPT: Cmd = { op: "prompt", pane: PANE, text: "go", queue: false };
const prev = (session: string, seq: number): Prev => ({ session, seq });

describe("unknown outcomes: each trigger", () => {
  it("a client timeout is not a failure: the command is unconfirmed and a new open is asked for", async () => {
    const { router, fire, asked } = setup();
    router.setSession(ctx("S1"));
    let hooked = 0;
    const p = router.request(INTERRUPT, { onUnconfirmed: () => hooked++ });
    await flush();
    fire(CLIENT_TIMEOUT_MS);
    expect(asked()).toBe(1);
    expect(hooked).toBe(1);
    expect(router.unconfirmedCount).toBe(1);
    router.setSession(ctx("S2"), prev("S1", 1));
    expect(await p).toEqual({ ok: false, code: DELIVERED_UNKNOWN });
  });

  it("a re:0 whose ref matches a command in flight makes THAT command unknown; others are untouched", async () => {
    const { router, frames, asked } = setup();
    router.setSession(ctx("S1"));
    const a = router.request(PROMPT);
    const b = router.request(INTERRUPT);
    await flush();
    expect(frames).toHaveLength(2);
    expect(router.handleRef(refOfFrame(frames[1]!))).toBe(true);
    expect(asked()).toBe(1);
    expect(router.unconfirmedCount).toBe(1);
    // The first one still gets its real answer.
    expect(router.handleReply(1, { ok: true, data: { result: "sent" } })).toBe(true);
    expect(await a).toEqual({ ok: true, data: { result: "sent" } });
    router.setSession(ctx("S2"), prev("S1", 1)); // the desktop only accepted seq 1
    expect(await b).toEqual({ ok: false, code: NOT_DELIVERED });
  });

  it("a re:0 whose ref matches nothing (or nothing sent) is ignored", async () => {
    const { router, frames, asked } = setup();
    router.setSession(ctx("S1"));
    const p = router.request(INTERRUPT);
    await flush();
    expect(router.handleRef(null)).toBe(false);
    expect(router.handleRef("A".repeat(22))).toBe(false);
    expect(router.handleRef(refOfFrame(frames[0]!).replace(/.$/, (c) => (c === "A" ? "B" : "A")))).toBe(false);
    expect(asked()).toBe(0);
    expect(router.unconfirmedCount).toBe(0);
    router.handleReply(1, { ok: true, data: {} });
    expect(await p).toMatchObject({ ok: true });
  });

  it("the socket dropping leaves sent commands unconfirmed (not failed) and unsent ones failed", async () => {
    const { router, asked } = setup();
    router.setSession(ctx("S1"));
    const sentOne = router.request(INTERRUPT);
    await flush();
    const unsent = router.request(PROMPT); // numbered later: dropped before it is sent
    router.setSession(null);
    expect(await unsent).toEqual({ ok: false, code: "session_changed" });
    expect(router.unconfirmedCount).toBe(1);
    expect(asked()).toBe(1);
    // reconnected, a session names the old one
    router.setSession(ctx("S2"), prev("S1", 5));
    expect(await sentOne).toEqual({ ok: false, code: DELIVERED_UNKNOWN });
  });

  it("a plaintext server frame (desktop_offline, error) marks everything on the wire unknown", async () => {
    const { router, asked } = setup();
    router.setSession(ctx("S1"));
    const a = router.request(PROMPT);
    const b = router.request(INTERRUPT);
    await flush();
    router.markUnknown();
    expect(router.unconfirmedCount).toBe(2);
    expect(asked()).toBe(2); // both asked; the owner's one-open-at-a-time rule collapses them
    router.setSession(ctx("S2"), prev("S1", 1));
    expect(await a).toEqual({ ok: false, code: DELIVERED_UNKNOWN });
    expect(await b).toEqual({ ok: false, code: NOT_DELIVERED });
  });
});

describe("unknown outcomes: each resolution", () => {
  it("seq <= prev.seq in prev.session is delivered-unknown; higher is not delivered", async () => {
    const { router, fire } = setup();
    router.setSession(ctx("S1"));
    const ps = [router.request(PROMPT), router.request(INTERRUPT), router.request(PROMPT)];
    await flush();
    fire(CLIENT_TIMEOUT_MS); // all three timers were created with the same duration: fire them one by one
    fire(CLIENT_TIMEOUT_MS);
    fire(CLIENT_TIMEOUT_MS);
    router.setSession(ctx("S2"), prev("S1", 2));
    expect(await Promise.all(ps)).toEqual([
      { ok: false, code: DELIVERED_UNKNOWN },
      { ok: false, code: DELIVERED_UNKNOWN },
      { ok: false, code: NOT_DELIVERED },
    ]);
  });

  it("prev naming another session, an empty one, or none says nothing: could-not-confirm after 15 s", async () => {
    for (const p of [prev("OTHER", 9), prev("", 0), null]) {
      const { router, fire } = setup();
      router.setSession(ctx("S1"));
      const w = router.request(INTERRUPT);
      await flush();
      fire(CLIENT_TIMEOUT_MS);
      router.setSession(ctx("S2"), p);
      expect(router.unconfirmedCount, JSON.stringify(p)).toBe(1);
      fire(CONFIRM_MS);
      expect(await w, JSON.stringify(p)).toEqual({ ok: false, code: COULD_NOT_CONFIRM });
    }
  });

  it("no session within 15 s: a write is could-not-confirm, a read is a plain timeout", async () => {
    const { router, fire } = setup();
    router.setSession(ctx("S1"));
    const w = router.request(PROMPT);
    const r = router.request({ op: "list" });
    await flush();
    router.markUnknown();
    fire(CONFIRM_MS);
    fire(CONFIRM_MS);
    expect(await w).toEqual({ ok: false, code: COULD_NOT_CONFIRM });
    expect(await r).toEqual({ ok: false, code: "timeout" });
  });

  it("a genuine reply of the same session still settles an unconfirmed command with its real result", async () => {
    const { router, fire } = setup();
    router.setSession(ctx("S1"));
    const p = router.request(INTERRUPT);
    await flush();
    fire(CLIENT_TIMEOUT_MS);
    expect(router.handleReply(1, { ok: true, data: { result: "sent" } })).toBe(true);
    expect(await p).toEqual({ ok: true, data: { result: "sent" } });
    expect(router.unconfirmedCount).toBe(0);
  });

  it("seq restarts per session: an old unconfirmed seq never matches the new session's reply", async () => {
    const { router, fire } = setup();
    router.setSession(ctx("S1"));
    const old = router.request(INTERRUPT);
    await flush();
    fire(CLIENT_TIMEOUT_MS);
    router.setSession(ctx("S2"), prev("OTHER", 0)); // cannot be settled, stays unconfirmed
    const fresh = router.request(PROMPT);
    await flush();
    expect(router.handleReply(1, { ok: true, data: { result: "sent" } })).toBe(true);
    expect(await fresh).toEqual({ ok: true, data: { result: "sent" } });
    expect(router.unconfirmedCount).toBe(1);
    fire(CONFIRM_MS);
    expect(await old).toEqual({ ok: false, code: COULD_NOT_CONFIRM });
  });

  it("a command that never left is not delivered when its time runs out", async () => {
    const timers: { fn: () => void; ms: number }[] = [];
    const router = new CommandRouter({
      send: () => {
        throw new Error("must not send");
      },
      seal: () => new Promise<string>(() => undefined), // never finishes
      sign: async () => "S",
      setTimer: (fn, ms) => (timers.push({ fn, ms }), timers.length),
      clearTimer: () => undefined,
    });
    router.setSession(ctx("S1"));
    const p = router.request(INTERRUPT);
    await flush();
    timers[0]!.fn();
    expect(await p).toEqual({ ok: false, code: NOT_DELIVERED });
  });
});

describe("no automatic retry", () => {
  it("never re-sends a write, whatever the resolution", async () => {
    for (const p of [prev("S1", 1), prev("S1", 0), prev("OTHER", 3), null]) {
      const { router, fireAll, sent } = setup();
      router.setSession(ctx("S1"));
      const w1 = router.request(PROMPT);
      const w2 = router.request(INTERRUPT);
      const w3 = router.request({ op: "answer", pane: PANE, n: 1, label: "Yes", menu_id: "m1" });
      await flush();
      router.markUnknown();
      router.setSession(ctx("S2"), p);
      await flush();
      fireAll(CONFIRM_MS);
      await Promise.all([w1, w2, w3]);
      await flush();
      expect(sent("prompt"), JSON.stringify(p)).toHaveLength(1);
      expect(sent("interrupt")).toHaveLength(1);
      expect(sent("answer")).toHaveLength(1);
      expect(sent().every((x) => x.session === "S1")).toBe(true);
    }
  });

  it("asks a read again in the new session and answers with that reply", async () => {
    const { router, fire, sent } = setup();
    router.setSession(ctx("S1"));
    const r = router.request({ op: "peek", pane: PANE, lines: 80 });
    await flush();
    fire(CLIENT_TIMEOUT_MS);
    router.setSession(ctx("S2"), prev("S1", 1));
    await flush();
    expect(sent("peek").map((x) => [x.session, x.seq])).toEqual([
      ["S1", 1],
      ["S2", 1],
    ]);
    expect(router.handleReply(1, { ok: true, data: { lines: [] } })).toBe(true);
    expect(await r).toEqual({ ok: true, data: { lines: [] } });
  });

  it("asks a read again only once", async () => {
    const { router, fire, sent } = setup();
    router.setSession(ctx("S1"));
    const r = router.request({ op: "list" });
    await flush();
    fire(CLIENT_TIMEOUT_MS);
    router.setSession(ctx("S2"), prev("S1", 1));
    await flush();
    fire(CLIENT_TIMEOUT_MS); // the retry also gets no answer
    router.setSession(ctx("S3"), prev("S2", 1));
    await flush();
    expect(sent("list")).toHaveLength(2);
    expect(await r).toEqual({ ok: false, code: "timeout" });
  });
});

describe("consecutive seqs and the desktop's timeout reply", () => {
  it("numbers frames 1, 2, 3 in the order they were asked, with no number skipped", async () => {
    const { router, sent } = setup();
    router.setSession(ctx("S1"));
    void router.request({ op: "list" });
    void router.request(INTERRUPT);
    void router.request({ op: "peek", pane: PANE, lines: 80 });
    await flush();
    expect(sent().map((p) => p.seq)).toEqual([1, 2, 3]);
  });

  it("a command that was numbered but never sent gives its number back", async () => {
    const frames: string[] = [];
    let failNext = false;
    const router = new CommandRouter({
      send: (f) => {
        if (failNext) {
          failNext = false;
          throw new Error("not connected");
        }
        frames.push(f);
      },
      seal: async (s) => s,
      sign: async () => "S",
      setTimer: () => 0,
      clearTimer: () => undefined,
    });
    router.setSession(ctx("S1"));
    void router.request({ op: "list" });
    await flush();
    failNext = true;
    expect(await router.request(INTERRUPT)).toEqual({ ok: false, code: "offline" });
    void router.request({ op: "list" });
    await flush();
    const seqs = frames.map((f) => (JSON.parse(JSON.parse(f).body) as { seq: number }).seq);
    expect(seqs).toEqual([1, 2]);
  });

  it.each(["answer", "interrupt", "prompt"] as const)(
    "a timeout reply to %s means delivered, result unknown (never auto-retried)",
    async (op) => {
      const { router, sent } = setup();
      router.setSession(ctx("S1"));
      const cmd: Cmd =
        op === "answer"
          ? { op: "answer", pane: PANE, n: 1, label: "Yes", menu_id: "m" }
          : op === "interrupt"
            ? INTERRUPT
            : PROMPT;
      const p = router.request(cmd);
      await flush();
      expect(router.handleReply(1, { ok: false, code: "timeout" })).toBe(true);
      expect(await p).toEqual({ ok: false, code: DELIVERED_UNKNOWN });
      expect(sent(op)).toHaveLength(1);
    },
  );

  it("a timeout reply to a read stays a plain timeout", async () => {
    const { router } = setup();
    router.setSession(ctx("S1"));
    const p = router.request({ op: "peek", pane: PANE, lines: 80 });
    await flush();
    router.handleReply(1, { ok: false, code: "timeout" });
    expect(await p).toEqual({ ok: false, code: "timeout" });
  });

  it("a dropped command (server said busy) leaves the write not delivered once a new session reports prev", async () => {
    const { router, asked } = setup();
    router.setSession(ctx("S1"));
    const p = router.request(PROMPT);
    await flush();
    router.markUnknown(); // the server's plaintext busy / rate_limited frame
    expect(asked()).toBe(1);
    router.setSession(ctx("S2"), prev("S1", 0));
    expect(await p).toEqual({ ok: false, code: NOT_DELIVERED });
  });
});

// A relay forwarded a write twice: the desktop ran the first and answered the second `replay`.
describe("a replay reply proves the command was accepted", () => {
  const REPLAY = { ok: false, code: "replay" } as const;
  const SENT = { ok: true, data: { result: "sent" } } as const;

  it.each(["interrupt", "prompt"] as const)("%s: replay first resolves to delivered-unknown; the real reply then upgrades it", async (op) => {
    const { router, sent } = setup();
    router.setSession(ctx("S1"));
    const late: unknown[] = [];
    const p = router.request(op === "prompt" ? PROMPT : INTERRUPT, { onLate: (r) => late.push(r) });
    await flush();
    expect(router.handleReply(1, REPLAY)).toBe(true);
    expect(await p).toEqual({ ok: false, code: DELIVERED_UNKNOWN });
    expect(late).toEqual([]);
    router.handleReply(1, SENT);
    expect(late).toEqual([SENT]);
    router.handleReply(1, SENT); // delivered once only
    expect(late).toHaveLength(1);
    expect(sent(op)).toHaveLength(1); // never re-sent
  });

  it("a later failure other than replay or timeout replaces delivered-unknown; those two do not", async () => {
    const { router } = setup();
    router.setSession(ctx("S1"));
    const late: unknown[] = [];
    const p = router.request(PROMPT, { onLate: (r) => late.push(r) });
    await flush();
    router.handleReply(1, REPLAY);
    await p;
    router.handleReply(1, REPLAY);
    router.handleReply(1, { ok: false, code: "timeout" });
    expect(late).toEqual([]);
    router.handleReply(1, { ok: false, code: "forbidden" });
    expect(late).toEqual([{ ok: false, code: "forbidden" }]);
  });

  it("the real reply first: a replay after it is ignored", async () => {
    const { router } = setup();
    router.setSession(ctx("S1"));
    const late: unknown[] = [];
    const p = router.request(PROMPT, { onLate: (r) => late.push(r) });
    await flush();
    expect(router.handleReply(1, SENT)).toBe(true);
    expect(await p).toEqual(SENT);
    expect(router.handleReply(1, REPLAY)).toBe(false);
    expect(late).toEqual([]);
  });

  it("a read ignores a replay reply and keeps waiting for the real one", async () => {
    const { router } = setup();
    router.setSession(ctx("S1"));
    let done = false;
    const p = router.request({ op: "list" }).then((r) => {
      done = true;
      return r;
    });
    await flush();
    router.handleReply(1, REPLAY);
    await flush();
    expect(done).toBe(false);
    const real = { ok: true, data: { panes: [] } } as const;
    router.handleReply(1, real);
    expect(await p).toEqual(real);
  });

  it("a new session forgets the late-reply wait", async () => {
    const { router } = setup();
    router.setSession(ctx("S1"));
    const late: unknown[] = [];
    const p = router.request(PROMPT, { onLate: (r) => late.push(r) });
    await flush();
    router.handleReply(1, REPLAY);
    await p;
    router.setSession(ctx("S2"), prev("S1", 1));
    router.handleReply(1, SENT);
    expect(late).toEqual([]);
  });
});
