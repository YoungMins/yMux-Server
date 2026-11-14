import { describe, expect, it } from "vitest";
import { menuChoices } from "../model/menu";
import { cleanText } from "./clean";
import { needsReopen, parseBody, parsePeekData, startsWithBang, type Body } from "./messages";
import { MAX_BODY_AGE_MS, OPEN_LIFETIME_MS, OpenGate, SessionTracker } from "./session";

const PANE = "01234567-89ab-4cde-8f01-23456789abcd";
/** The phone's clock when its `open` goes out and its `session` arrives, and the desktop's at that moment. */
const LOCAL = 500_000;
const DESK = 1_000_000;

const body = (o: Record<string, unknown>): Body => {
  const b = parseBody(JSON.stringify(o));
  if (!b) throw new Error("test body does not parse");
  return b;
};
const session = (open: string, id = "S1", nowMs = DESK, extra: Record<string, unknown> = {}) =>
  body({ k: "session", open, session: id, cap: "prompt", name: "PC", now_ms: nowMs, v: 1, ...extra });
const panes = (sess: string, n: number, at: number | null = DESK) =>
  body({ k: "panes", panes: [], session: sess, n, ...(at === null ? {} : { at_ms: at }) });
const reply = (re: number, ok: boolean, sess: string, n?: number, code = "bad_session", at: number | null = DESK) =>
  body({
    k: "reply",
    re,
    ok,
    ...(ok ? { data: {} } : { code }),
    session: sess,
    ...(n === undefined ? {} : { n }),
    ...(at === null ? {} : { at_ms: at }),
  });

function opened(nonce = "N1", id = "S1", localNow = LOCAL): SessionTracker {
  const t = new SessionTracker();
  t.beginOpen(nonce, localNow);
  expect(t.accept(session(nonce, id), localNow)).not.toBeNull();
  return t;
}

describe("session acceptance", () => {
  it("accepts a session only when `open` equals the most recent nonce sent", () => {
    const t = new SessionTracker();
    expect(t.accept(session("N1"), LOCAL), "no open sent yet").toBeNull();
    t.beginOpen("N1", LOCAL);
    t.beginOpen("N2", LOCAL);
    expect(t.accept(session("N1"), LOCAL), "older nonce").toBeNull();
    expect(t.accept(session("WRONG"), LOCAL)).toBeNull();
    expect(t.session).toBeNull();
    expect(t.accept(session("N2", "S9"), LOCAL)).not.toBeNull();
    expect(t.session).toBe("S9");
    expect(t.dropped).toBe(3);
  });
  it("accepts a session only within 10 s of sending the open, and a late one burns the nonce", () => {
    expect(OPEN_LIFETIME_MS).toBe(10_000);
    const t = new SessionTracker();
    t.beginOpen("N1", LOCAL);
    expect(t.openLive(LOCAL + 10_000)).toBe(true);
    expect(t.openLive(LOCAL + 10_001)).toBe(false);
    expect(t.accept(session("N1"), LOCAL + 10_001), "10.001 s later").toBeNull();
    expect(t.session).toBeNull();
    expect(t.accept(session("N1"), LOCAL + 1), "the nonce is gone").toBeNull();
    t.beginOpen("N2", LOCAL);
    expect(t.accept(session("N2", "S2"), LOCAL + 10_000), "exactly 10 s").not.toBeNull();
    expect(t.session).toBe("S2");
    const u = new SessionTracker();
    u.beginOpen("N", LOCAL);
    expect(u.accept(session("N"), LOCAL - 1), "a clock that went backwards").toBeNull();
  });
  it("consumes the nonce: a replayed session body cannot reset the counter", () => {
    const t = opened("N1", "S1");
    expect(t.accept(panes("S1", 5), LOCAL)).not.toBeNull();
    expect(t.accept(session("N1", "S1"), LOCAL)).toBeNull();
    expect(t.accept(panes("S1", 5), LOCAL), "n=5 is still the last accepted").toBeNull();
    expect(t.accept(panes("S1", 6), LOCAL)).not.toBeNull();
  });
  it("drops a body of another or stale session, or without a session", () => {
    const t = opened("N1", "S1");
    expect(t.accept(panes("S0", 1), LOCAL)).toBeNull();
    expect(t.accept(panes("", 1), LOCAL)).toBeNull();
    expect(t.accept(body({ k: "panes", panes: [], n: 1, at_ms: DESK }), LOCAL)).toBeNull();
    expect(t.accept(panes("S1", 1), LOCAL)).not.toBeNull();
    t.beginOpen("N2", LOCAL);
    expect(t.accept(session("N2", "S2"), LOCAL)).not.toBeNull();
    expect(t.accept(panes("S1", 2), LOCAL), "the old session is stale now").toBeNull();
    expect(t.accept(panes("S2", 1), LOCAL), "n restarts with the new session").not.toBeNull();
  });
  it("needs n above the last accepted one; a missing or odd n is dropped", () => {
    const t = opened();
    expect(t.accept(panes("S1", 1), LOCAL)).not.toBeNull();
    expect(t.accept(panes("S1", 1), LOCAL), "equal").toBeNull();
    expect(t.accept(panes("S1", 0), LOCAL), "lower").toBeNull();
    expect(t.accept(body({ k: "panes", panes: [], session: "S1", at_ms: DESK }), LOCAL), "missing").toBeNull();
    expect(t.accept(body({ k: "panes", panes: [], session: "S1", n: "3", at_ms: DESK }), LOCAL), "not a number").toBeNull();
    expect(t.accept(panes("S1", 7), LOCAL), "gaps are fine").not.toBeNull();
    expect(t.accept(panes("S1", 3), LOCAL)).toBeNull();
    expect(t.dropped).toBe(5);
  });
  it("parses prev, and treats a missing or malformed prev as none", () => {
    const ok = session("N", "S2", DESK, { prev: { session: "S1", seq: 4 } });
    expect(ok).toMatchObject({ prev: { session: "S1", seq: 4 } });
    expect(session("N", "S2", DESK, { prev: { session: "", seq: 0 } })).toMatchObject({ prev: { session: "", seq: 0 } });
    for (const bad of [undefined, null, 5, "x", {}, { session: "S1" }, { seq: 1 }, { session: "S1", seq: -1 }, { session: "S1", seq: 1.5 }, { session: 7, seq: 1 }]) {
      expect(session("N", "S2", DESK, { prev: bad }), JSON.stringify(bad)).toMatchObject({ prev: null });
    }
  });
});

describe("freshness (at_ms)", () => {
  it("drops a body more than 30 s behind the estimated desktop clock, and keeps one exactly 30 s behind", () => {
    expect(MAX_BODY_AGE_MS).toBe(30_000);
    const t = opened();
    // 100 s later on the phone's clock the desktop's is 100 s later too.
    const later = LOCAL + 100_000;
    const now = DESK + 100_000;
    expect(t.accept(panes("S1", 1, now - 30_001), later), "30.001 s old").toBeNull();
    expect(t.accept(panes("S1", 1, now - 30_000), later), "30 s old").not.toBeNull();
    expect(t.accept(panes("S1", 2, now + 5_000), later), "from the future is only the desktop's clock").not.toBeNull();
    expect(t.dropped).toBe(1);
  });
  it("a stale body does not burn n", () => {
    const t = opened();
    expect(t.accept(panes("S1", 9, DESK - 60_000), LOCAL)).toBeNull();
    expect(t.accept(panes("S1", 9, DESK), LOCAL), "the same n, fresh, is still acceptable").not.toBeNull();
  });
  it("needs at_ms at all", () => {
    const t = opened();
    expect(t.accept(panes("S1", 1, null), LOCAL)).toBeNull();
    expect(t.accept(reply(1, true, "S1", 2, "x", null), LOCAL)).toBeNull();
    expect(t.accept(body({ k: "reopen", session: "S1", n: 3 }), LOCAL)).toBeNull();
    expect(t.accept(body({ k: "panes", panes: [], session: "S1", n: 4, at_ms: "x" }), LOCAL)).toBeNull();
    expect(t.dropped).toBe(4);
  });
  it("uses the offset recorded from the session (a phone clock that is far off still works)", () => {
    const t = new SessionTracker();
    t.beginOpen("N", 7_000);
    expect(t.accept(session("N", "S", DESK), 7_000)).not.toBeNull(); // phone reads 7 000, desktop 1 000 000
    expect(t.accept(panes("S", 1, DESK + 2_000), 9_000)).not.toBeNull();
    expect(t.accept(panes("S", 2, DESK - 40_000 + 2_000), 9_000), "40 s stale").toBeNull();
  });
});

describe("re:0 replies", () => {
  it("lets a failure reply with `re:0` and an empty session through, without at_ms and without touching n", () => {
    const t = opened();
    expect(t.accept(panes("S1", 4), LOCAL)).not.toBeNull();
    expect(t.accept(reply(0, false, "", undefined, "bad_sig", null), LOCAL)).not.toBeNull();
    expect(t.accept(reply(0, false, "", 1, "bad_sig"), LOCAL), "still accepted, n ignored").not.toBeNull();
    expect(t.accept(panes("S1", 5), LOCAL), "n was not advanced by the exception").not.toBeNull();
  });
  it("is exactly that: not for successes, other re, or other sessions", () => {
    const t = opened();
    expect(t.accept(reply(0, true, ""), LOCAL), "a success").toBeNull();
    expect(t.accept(reply(3, false, ""), LOCAL), "re != 0").toBeNull();
    expect(t.accept(reply(0, false, "OTHER"), LOCAL), "a foreign session").toBeNull();
    expect(t.accept(reply(0, false, "S1", 1), LOCAL), "the normal path still works").not.toBeNull();
    // The exception works even before any session exists (the failed open itself).
    expect(new SessionTracker().accept(reply(0, false, "", undefined, "bad_sig"), LOCAL)).not.toBeNull();
  });
  it("parses ref (22 b64u characters) and ignores anything else", () => {
    const ref = "A".repeat(22);
    expect(body({ k: "reply", re: 0, ok: false, code: "bad_sig", session: "", ref })).toMatchObject({ ref });
    for (const bad of [undefined, 5, "short", "A".repeat(23), "A".repeat(21) + "!"]) {
      expect(body({ k: "reply", re: 0, ok: false, session: "", ref: bad })).toMatchObject({ ref: null });
    }
  });
});

describe("session edge cases", () => {
  it("drops a session body without now_ms and everything after a reset", () => {
    const t = new SessionTracker();
    t.beginOpen("N1", LOCAL);
    expect(t.accept(body({ k: "session", open: "N1", session: "S1" }), LOCAL)).toBeNull();
    const u = opened();
    u.reset();
    expect(u.session).toBeNull();
    expect(u.openLive(LOCAL)).toBe(false);
    expect(u.accept(panes("S1", 9), LOCAL)).toBeNull();
  });
});

describe("clock offset", () => {
  it("records desktop minus local clock from the session and applies it to ts_ms", () => {
    const t = opened("N1", "S1", 500_000); // desktop says 1_000_000 while the phone's clock reads 500_000
    expect(t.offsetMs).toBe(500_000);
    expect(t.tsMs(600_000)).toBe(1_100_000);
    const fast = new SessionTracker();
    fast.beginOpen("N", 1_090_000);
    fast.accept(session("N", "S", 1_000_000), 1_090_000); // phone 90 s ahead
    expect(fast.offsetMs).toBe(-90_000);
    expect(fast.tsMs(1_100_000)).toBe(1_010_000);
  });
  it("starts at zero and keeps the offset across a reset", () => {
    const t = new SessionTracker();
    expect(t.tsMs(42)).toBe(42);
    const u = opened();
    u.reset();
    expect(u.offsetMs).toBe(500_000);
  });
});

describe("open backoff", () => {
  it("allows the first open at once, then at most one per second", () => {
    const g = new OpenGate();
    expect(g.waitMs(1_000_000)).toBe(0);
    g.noteSent(1_000_000);
    g.noteSession();
    expect(g.waitMs(1_000_000)).toBe(1000);
    expect(g.waitMs(1_000_400)).toBe(600);
    expect(g.waitMs(1_001_000)).toBe(0);
  });
  it("doubles the gap while opens go unanswered, up to 30 s", () => {
    const g = new OpenGate();
    let now = 0;
    const gaps: number[] = [];
    for (let i = 0; i < 9; i++) {
      const w = g.waitMs(now);
      gaps.push(w);
      now += w;
      g.noteSent(now);
    }
    expect(gaps).toEqual([0, 2000, 4000, 8000, 16000, 30000, 30000, 30000, 30000]);
  });
  it("resets after a session, and a lost connection does not count as a failure", () => {
    const g = new OpenGate();
    g.noteSent(0);
    g.noteSent(2000);
    g.noteSent(6000);
    expect(g.waitMs(6000)).toBe(8000);
    g.noteSession();
    expect(g.waitMs(6000)).toBe(1000);
    g.noteSent(7000);
    g.noteDisconnect();
    expect(g.waitMs(7000)).toBe(1000);
  });
});

describe("what triggers a new open", () => {
  it("reopen, bad_session and expired do; other failures and successes do not", () => {
    expect(needsReopen(body({ k: "reopen", session: "S1", n: 2 }))).toBe(true);
    expect(needsReopen(reply(3, false, "S1", 2, "bad_session"))).toBe(true);
    expect(needsReopen(reply(3, false, "S1", 2, "expired"))).toBe(true);
    expect(needsReopen(reply(3, false, "S1", 2, "forbidden"))).toBe(false);
    expect(needsReopen(reply(3, false, "S1", 2, "replay"))).toBe(false);
    expect(needsReopen(reply(3, true, "S1", 2))).toBe(false);
    expect(needsReopen(panes("S1", 2))).toBe(false);
  });
});

describe("answer buttons carry the menu_id of the peek that rendered them", () => {
  const peek = (id: string, labels: string[], extra: Record<string, unknown>[] = []) =>
    parsePeekData({
      lines: ["x"],
      menu: [...labels.map((label, i) => ({ n: i + 1, label })), ...extra],
      menu_id: id,
      status: "waiting",
    })!;

  it("builds answer commands from one peek; a later peek does not change them", () => {
    const first = peek("menu-A", ["Yes", "No"]);
    const buttons = menuChoices(PANE, first, true, false);
    const second = peek("menu-B", ["Yes", "No"]);
    const later = menuChoices(PANE, second, true, false);
    expect(buttons.map((b) => b.cmd)).toEqual([
      { op: "answer", pane: PANE, n: 1, label: "Yes", menu_id: "menu-A" },
      { op: "answer", pane: PANE, n: 2, label: "No", menu_id: "menu-A" },
    ]);
    expect(later[0]!.cmd).toMatchObject({ menu_id: "menu-B" });
    expect(buttons[0]!.cmd).toMatchObject({ menu_id: "menu-A" });
  });
  it("disables options above 9 and input options with a note, and everything without a menu id", () => {
    const p = peek("m", ["a"], [{ n: 10, label: "ten" }, { n: 2, label: "Type here", input: true }]);
    const c = menuChoices(PANE, p, true, false);
    expect(c.map((x) => [x.option.n, x.disabled, x.note, x.cmd === null])).toEqual([
      [1, false, null, false],
      [10, true, "range", true],
      [2, true, "input", true],
    ]);
    expect(menuChoices(PANE, peek("", ["a"]), true, false)[0]).toMatchObject({ disabled: true, cmd: null });
  });
  it("disables all buttons while busy or without the respond capability", () => {
    const p = peek("m", ["a", "b"]);
    expect(menuChoices(PANE, p, false, false).every((c) => c.disabled)).toBe(true);
    expect(menuChoices(PANE, p, true, true).every((c) => c.disabled)).toBe(true);
    expect(menuChoices(PANE, null, true, false)).toEqual([]);
  });
});

describe("prompt starting with !", () => {
  it("looks at the first non-blank character", () => {
    expect(startsWithBang("!ls")).toBe(true);
    expect(startsWithBang("  \n\t! ls")).toBe(true);
    expect(startsWithBang("ls !")).toBe(false);
    expect(startsWithBang("")).toBe(false);
  });
});

describe("cleanText", () => {
  it("drops Cc, Cf, Zl and Zp", () => {
    expect(cleanText("a\u0000b\u0007c\u001bd\u007fe")).toBe("abcde");
    expect(cleanText("x​y‎z‮w⁦v﻿u")).toBe("xyzwvu");
    expect(cleanText("p q r")).toBe("pqr");
    expect(cleanText("t\tu\nv")).toBe("tuv");
  });
  it("keeps newlines only on request, and leaves ordinary text alone", () => {
    expect(cleanText("a\nb​\r\nc", true)).toBe("a\nb\nc");
    expect(cleanText("héllo 日本語 \u{1F600} ا", true)).toBe("héllo 日本語 \u{1F600} ا");
    expect(cleanText("")).toBe("");
  });
});
