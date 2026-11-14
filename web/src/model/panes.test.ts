import { describe, expect, it } from "vitest";
import type { Pane } from "../protocol/messages";
import { formatSince, relTime, sortPanes } from "./panes";

function pane(n: number, over: Partial<Pane> = {}): Pane {
  return {
    pane: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    ws: "w",
    title: `t${n}`,
    kind: "claude",
    status: "idle",
    since_ms: 0,
    queued: 0,
    ...over,
  };
}

describe("sorting", () => {
  it("waiting first (longest waiting first), then working, done, idle, none", () => {
    const list = [
      pane(1, { status: "idle" }),
      pane(2, { status: "done", since_ms: 100 }),
      pane(3, { status: "waiting", since_ms: 500 }),
      pane(4, { status: "working", since_ms: 300 }),
      pane(5, { status: "waiting", since_ms: 200 }),
      pane(6, { status: "none" }),
      pane(7, { status: "working", since_ms: 900 }),
    ];
    expect(sortPanes(list).map((p) => p.title)).toEqual(["t5", "t3", "t7", "t4", "t2", "t1", "t6"]);
  });
  it("does not mutate its input", () => {
    const list = [pane(2, { status: "idle" }), pane(1, { status: "waiting" })];
    sortPanes(list);
    expect(list[0]!.title).toBe("t2");
  });
});

describe("relative time", () => {
  const now = 1_000_000_000_000;
  it("picks the unit", () => {
    expect(relTime(now - 5000, now)).toEqual({ value: -5, unit: "second" });
    expect(relTime(now - 59_999, now)).toEqual({ value: -59, unit: "second" });
    expect(relTime(now - 60_000, now)).toEqual({ value: -1, unit: "minute" });
    expect(relTime(now - 3_600_000 * 5, now)).toEqual({ value: -5, unit: "hour" });
    expect(relTime(now - 86_400_000 * 3, now)).toEqual({ value: -3, unit: "day" });
  });
  it("is empty without a timestamp and clamps clock skew", () => {
    expect(relTime(0, now)).toBeNull();
    expect(relTime(NaN, now)).toBeNull();
    expect(relTime(now + 5000, now)).toEqual({ value: -0, unit: "second" });
  });
  it("formats through Intl", () => {
    expect(formatSince(now - 120_000, now, "en")).toMatch(/2/);
    expect(formatSince(0, now, "en")).toBe("");
    expect(formatSince(now - 120_000, now, "zz-invalid-tag-!!")).not.toBe("");
  });
});
