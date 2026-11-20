import { describe, expect, it } from "vitest";
import { MAX_OLDER_STEPS, afterOlderReply, decide, idle, sent, tap, throttleMs, type Env, type Sched } from "./chatSchedule";

const free: Env = { inflight: false, throttleMs: 0, pollWanted: false };

describe("rate limit", () => {
  it("allows 4 per second and says when the next may go", () => {
    expect(throttleMs([], 1000, 4)).toBe(0);
    expect(throttleMs([100, 200, 300], 500, 4)).toBe(0);
    expect(throttleMs([100, 200, 300, 400], 500, 4)).toBe(605);
    expect(throttleMs([100, 200, 300, 400], 1100, 4)).toBe(0);
  });
  it("a clock that went backwards counts as an expired window", () => {
    expect(throttleMs([5000, 5100, 5200, 5300], 900, 4)).toBe(0);
    const times = [5000, 5100, 5200, 5300];
    throttleMs(times, 900, 4);
    expect(times).toEqual([]);
  });
});

describe("chat scheduling", () => {
  it("does nothing when nothing is wanted, and a poll when one is", () => {
    expect(decide(idle, free)).toEqual({ do: "none" });
    expect(decide(idle, { ...free, pollWanted: true })).toEqual({ do: "poll" });
  });
  it("a pending older step goes before the forward poll, also when the throttle ends", () => {
    const s = tap(idle);
    expect(decide(s, { ...free, pollWanted: true })).toEqual({ do: "older" });
    expect(decide(s, { ...free, pollWanted: true, throttleMs: 300 })).toEqual({ do: "wait", ms: 300 });
    expect(decide(s, { ...free, pollWanted: true, throttleMs: 0 })).toEqual({ do: "older" });
  });
  it("a tap during a poll in flight is remembered once and runs when the poll settles", () => {
    let s = tap(idle);
    s = tap(tap(s)); // more taps: still one step
    expect(decide(s, { ...free, inflight: true, pollWanted: true })).toEqual({ do: "none" });
    expect(s.pendingOlder).toBe(true);
    expect(decide(s, { ...free, pollWanted: true })).toEqual({ do: "older" });
    s = sent(s);
    expect(decide(s, { ...free, pollWanted: true })).toEqual({ do: "poll" });
  });
  it("initial load + three fast empty backward replies: the chain survives the throttle", () => {
    let s: Sched = tap(idle);
    let sentCount = 0;
    let throttled = 0;
    const log: string[] = [];
    // each loop: the desktop answers an empty-but-moving reply, the limit holds the next step once
    for (let reply = 0; reply < 3; reply++) {
      const d = decide(s, { ...free, throttleMs: reply === 1 ? 250 : 0 });
      if (d.do === "wait") {
        throttled++;
        log.push("wait");
        expect(s.pendingOlder, "the step is still pending while held back").toBe(true);
        expect(decide(s, free)).toEqual({ do: "older" }); // the timer fires: it is the older step, not a poll
      }
      log.push("older");
      s = sent(s);
      sentCount++;
      s = afterOlderReply(s, { olderEmpty: true, older: true });
      expect(s.active).toBe(true);
    }
    expect(sentCount).toBe(3);
    expect(throttled).toBe(1);
    // the fourth reply has items: the chain ends cleanly
    s = afterOlderReply(sent(s), { olderEmpty: false, older: true });
    expect(s).toEqual(idle);
  });
  it("a chain is cut at MAX_OLDER_STEPS and ends when older runs out", () => {
    let s = tap(idle);
    for (let i = 0; i < MAX_OLDER_STEPS; i++) s = afterOlderReply(sent(s), { olderEmpty: true, older: true });
    expect(s.pendingOlder).toBe(true);
    expect(afterOlderReply(sent(s), { olderEmpty: true, older: true })).toEqual(idle);
    expect(afterOlderReply(sent(tap(idle)), { olderEmpty: true, older: false })).toEqual(idle);
  });
  it("taps are ignored while a chain is active", () => {
    const s = sent(tap(idle));
    expect(tap(s)).toBe(s);
  });
});
