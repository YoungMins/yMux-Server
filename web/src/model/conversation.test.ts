import { describe, expect, it } from "vitest";
import type { ChatItem, ChatPage } from "../protocol/messages";
import {
  MAX_KEPT,
  REPROBE_MS,
  applyPage,
  groupRows,
  items,
  jumpLatest,
  markUnsupported,
  newConversation,
  noteFailure,
  nextRequest,
  olderRequest,
  viewMode,
  type Conversation,
} from "./conversation";

const it_ = (id: number | string, role: ChatItem["role"] = "assistant"): ChatItem => ({ id: String(id), role, text: `m${id}`, ts: 0 });
const ids = (c: Conversation): string[] => items(c).map((i) => i.id);
const range = (a: number, b: number): ChatItem[] => Array.from({ length: b - a + 1 }, (_, i) => it_(a + i));
const pg = (over: Partial<ChatPage> & { items: ChatItem[] }): ChatPage => ({
  conv: "c1",
  agent: "claude",
  start: 0,
  end: 0,
  older: false,
  newer: false,
  ...over,
});
const T = 1_000_000;
const newest = (p: Partial<ChatPage> & { items: ChatItem[] }): Conversation => applyPage(newConversation(), {}, pg(p), T);

describe("conversation: requests", () => {
  it("asks for the newest items first, then after the end", () => {
    let c = newConversation();
    expect(nextRequest(c, T)).toEqual({});
    c = applyPage(c, {}, pg({ items: range(1, 3), start: 10, end: 40 }), T);
    expect(nextRequest(c, T)).toEqual({ conv: "c1", after: 40 });
  });
  it("asks for older items before the start cursor", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    expect(olderRequest(c)).toEqual({ conv: "c1", before: 50 });
    c = applyPage(c, { conv: "c1", before: 50 }, pg({ items: range(1, 4), start: 10, end: 50 }), T);
    expect(olderRequest(c)).toBeNull();
  });
  it("never asks again after unknown_op", () => {
    const c = markUnsupported(newConversation());
    expect(nextRequest(c, T)).toBeNull();
    expect(nextRequest(c, T + 10 * REPROBE_MS)).toBeNull();
    expect(viewMode(c)).toBe("screen");
  });
});

describe("conversation: continuity", () => {
  it("an after reply is an append only when start equals the position asked", () => {
    let c = newest({ items: range(1, 3), start: 0, end: 5 });
    c = applyPage(c, { conv: "c1", after: 5 }, pg({ items: [it_(3), it_(4), it_(5)], start: 5, end: 8, newer: true }), T);
    expect(ids(c)).toEqual(["1", "2", "3", "4", "5"]);
    expect(c.newer).toBe(true);
    expect(c.end).toBe(8);
    c = applyPage(c, { conv: "c1", after: 8 }, pg({ items: [], start: 8, end: 9 }), T);
    expect(ids(c)).toEqual(["1", "2", "3", "4", "5"]);
    expect(c.end).toBe(9);
    expect(c.newer).toBe(false);
  });
  it("a newest page in answer to `after` replaces everything, with no duplicates or misplaced items", () => {
    let c = newest({ items: range(1, 5), start: 0, end: 50 });
    // the desktop did not honour after: 50 (start != 50): this is its newest page
    c = applyPage(c, { conv: "c1", after: 50 }, pg({ items: range(3, 9), start: 20, end: 90, older: true }), T);
    expect(ids(c)).toEqual(["3", "4", "5", "6", "7", "8", "9"]);
    expect(c.start).toBe(20);
    expect(c.end).toBe(90);
    expect(c.older).toBe(true);
  });
  it("a newest page in answer to `before` replaces everything", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    c = applyPage(c, { conv: "c1", before: 50 }, pg({ items: range(7, 12), start: 70, end: 120, older: true }), T);
    expect(ids(c)).toEqual(["7", "8", "9", "10", "11", "12"]);
    expect(c.end).toBe(120);
  });
  it("before replies prepend when end equals the position asked", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    c = applyPage(c, { conv: "c1", before: 50 }, pg({ items: range(3, 5), start: 20, end: 50, older: true }), T);
    expect(ids(c)).toEqual(["3", "4", "5", "6", "7", "8"]);
    expect(olderRequest(c)).toEqual({ conv: "c1", before: 20 });
  });
  it("a different conv replaces everything", () => {
    let c = newest({ items: range(1, 3), end: 5 });
    c = applyPage(c, { conv: "c1", after: 5 }, pg({ conv: "c2", items: range(100, 101), start: 5, end: 9 }), T);
    expect(ids(c)).toEqual(["100", "101"]);
    expect(nextRequest(c, T)).toEqual({ conv: "c2", after: 9 });
  });
  it("a request without params replaces", () => {
    let c = newest({ items: range(1, 3), end: 5 });
    c = applyPage(c, {}, pg({ items: range(2, 4), end: 6 }), T);
    expect(ids(c)).toEqual(["2", "3", "4"]);
  });
  it("an empty after reply with the same end changes nothing visible", () => {
    const c = newest({ items: range(1, 3), end: 5 });
    const d = applyPage(c, { conv: "c1", after: 5 }, pg({ items: [], start: 5, end: 5 }), T);
    expect(d.rev).toBe(c.rev);
  });
});

describe("conversation: older with empty stretches", () => {
  it("an empty before reply that moved the cursor back advances it and keeps older", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    c = applyPage(c, { conv: "c1", before: 50 }, pg({ items: [], start: 30, end: 50, older: true }), T);
    expect(ids(c)).toEqual(["5", "6", "7", "8"]);
    expect(c.olderEmpty).toBe(true);
    expect(olderRequest(c)).toEqual({ conv: "c1", before: 30 });
  });
  it("an empty before reply that did not move stops offering older", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    c = applyPage(c, { conv: "c1", before: 50 }, pg({ items: [], start: 50, end: 50, older: true }), T);
    expect(c.older).toBe(false);
    expect(olderRequest(c)).toBeNull();
  });
  it("an empty newest page with older true can still load older", () => {
    let c = newest({ items: [], start: 70, end: 70, older: true });
    expect(olderRequest(c)).toEqual({ conv: "c1", before: 70 });
    c = applyPage(c, { conv: "c1", before: 70 }, pg({ items: range(1, 2), start: 10, end: 70 }), T);
    expect(ids(c)).toEqual(["1", "2"]);
    expect(c.older).toBe(false);
  });
});

describe("conversation: memory cap and browsing", () => {
  const fill = (n: number): Conversation => {
    let c = newest({ items: range(1, 40), start: 0, end: 100, newer: true });
    let next = 41;
    let end = 100;
    while (next <= n) {
      const last = Math.min(next + 39, n);
      const prev = end;
      end += 100;
      c = applyPage(c, { conv: "c1", after: prev }, pg({ items: range(next, last), start: prev, end, newer: last < n }), T);
      next = last + 1;
    }
    return c;
  };
  it("keeps at most 400 items, dropping the oldest, and then older is true", () => {
    const c = fill(520);
    expect(items(c).length).toBeLessThanOrEqual(MAX_KEPT);
    expect(items(c).length).toBeGreaterThan(MAX_KEPT - 40);
    expect(items(c).at(-1)!.id).toBe("520");
    expect(c.older).toBe(true);
    expect(c.browsing).toBe(false);
    expect(olderRequest(c)!.before).toBeGreaterThan(0);
  });
  it("loading older beyond the cap drops the newest, suspends forward polling and offers the jump", () => {
    let c = fill(400);
    c = applyPage(c, { conv: "c1", before: 0 }, pg({ items: Array.from({ length: 40 }, (_, i) => it_(`p${i}`)), start: 0, end: 0, older: true }), T);
    // end === 0 === before, start 0: not moved but fresh items exist
    expect(items(c).length).toBeLessThanOrEqual(MAX_KEPT);
    expect(c.browsing).toBe(true);
    expect(c.newer).toBe(true);
    expect(nextRequest(c, T)).toBeNull();
    const j = jumpLatest(c);
    expect(nextRequest(j, T)).toEqual({});
    const fresh = applyPage(j, {}, pg({ items: range(361, 400), start: 3600, end: 4000 }), T);
    expect(fresh.browsing).toBe(false);
    expect(nextRequest(fresh, T)).toEqual({ conv: "c1", after: 4000 });
  });
});

describe("conversation: a page that keeps failing", () => {
  it("after 3 failures in a row at the same position the next request is a newest-page one", () => {
    let c = newest({ items: range(1, 3), start: 0, end: 5, older: true });
    const req = { conv: "c1", after: 5 };
    c = noteFailure(c, req);
    c = noteFailure(c, req);
    expect(nextRequest(c, T)).toEqual(req);
    c = noteFailure(c, req);
    expect(nextRequest(c, T)).toEqual({});
    // the newest page replaces the view and the count starts over
    c = applyPage(c, {}, pg({ items: range(4, 6), start: 10, end: 60 }), T);
    expect(nextRequest(c, T)).toEqual({ conv: "c1", after: 60 });
  });
  it("a success resets the count; failures at different positions do not add up", () => {
    let c = newest({ items: range(1, 3), end: 5, older: true });
    const req = { conv: "c1", after: 5 };
    c = noteFailure(noteFailure(c, req), req);
    c = applyPage(c, req, pg({ items: [], start: 5, end: 5 }), T);
    c = noteFailure(c, req);
    expect(nextRequest(c, T)).toEqual(req);
    c = noteFailure(noteFailure(c, { conv: "c1", after: 6 }), req);
    expect(nextRequest(c, T)).toEqual(req);
  });
  it("works for a `before` request too, and plain requests are not counted", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    const req = { conv: "c1", before: 50 };
    for (let i = 0; i < 3; i++) c = noteFailure(c, req);
    expect(olderRequest(c)).toEqual({});
    const d = noteFailure(noteFailure(noteFailure(c, {}), {}), {});
    expect(d).toBe(c);
  });
});

describe("conversation: jump to latest", () => {
  it("a late reply to an older request is ignored once the jump was asked", () => {
    let c = newest({ items: range(5, 8), start: 50, end: 90, older: true });
    c = jumpLatest(c);
    const late = applyPage(c, { conv: "c1", before: 50 }, pg({ items: range(1, 4), start: 10, end: 50 }), T);
    expect(late).toBe(c);
    const lateAfter = applyPage(c, { conv: "c1", after: 90 }, pg({ items: range(9, 10), start: 90, end: 100 }), T);
    expect(lateAfter).toBe(c);
    const fresh = applyPage(c, {}, pg({ items: range(7, 12), start: 70, end: 120 }), T);
    expect(ids(fresh)).toEqual(["7", "8", "9", "10", "11", "12"]);
    expect(fresh.resync).toBe(false);
  });
  it("the reprobe of an empty conversation does not stall when the clock went backwards", () => {
    const c = applyPage(newConversation(), {}, pg({ conv: "", items: [] }), T);
    expect(nextRequest(c, T - 5000)).toEqual({});
  });
});

describe("conversation: rows", () => {
  it("collapses consecutive tool items into one row and keeps messages apart", () => {
    const rows = groupRows([it_(1, "user"), it_(2, "tool"), it_(3, "tool"), it_(4, "assistant"), it_(5, "tool"), it_(6, "user")]);
    expect(rows.map((r) => (r.kind === "msg" ? r.item.id : r.items.map((i) => i.id).join("+")))).toEqual(["1", "2+3", "4", "5", "6"]);
    expect(groupRows([])).toEqual([]);
  });
});

describe("conversation: empty and unsupported", () => {
  it("the empty form means screen mode, re-probed after 30 s", () => {
    let c = newConversation();
    expect(viewMode(c)).toBe("screen");
    c = applyPage(c, {}, pg({ conv: "", items: [] }), T);
    expect(c.loaded).toBe(true);
    expect(viewMode(c)).toBe("screen");
    expect(nextRequest(c, T + 1000)).toBeNull();
    expect(nextRequest(c, T + REPROBE_MS)).toEqual({});
  });
  it("a conversation that appears later switches to chat", () => {
    let c = applyPage(newConversation(), {}, pg({ conv: "", items: [] }), T);
    c = applyPage(c, {}, pg({ items: range(1, 2), end: 3 }), T + REPROBE_MS);
    expect(viewMode(c)).toBe("chat");
    expect(ids(c)).toEqual(["1", "2"]);
  });
  it("one empty form after a good reply keeps the conversation; the second in a row clears it", () => {
    let c = newest({ items: range(1, 2), end: 3 });
    const empty = pg({ conv: "", items: [] });
    c = applyPage(c, { conv: "c1", after: 3 }, empty, T + 5);
    expect(viewMode(c)).toBe("chat");
    expect(ids(c)).toEqual(["1", "2"]);
    expect(nextRequest(c, T + 6)).toEqual({ conv: "c1", after: 3 });
    c = applyPage(c, { conv: "c1", after: 3 }, empty, T + 10);
    expect(items(c)).toEqual([]);
    expect(viewMode(c)).toBe("screen");
  });
  it("a good reply between two empty ones resets the streak", () => {
    let c = newest({ items: range(1, 2), end: 3 });
    const empty = pg({ conv: "", items: [] });
    c = applyPage(c, { conv: "c1", after: 3 }, empty, T);
    c = applyPage(c, { conv: "c1", after: 3 }, pg({ items: [], start: 3, end: 3 }), T);
    c = applyPage(c, { conv: "c1", after: 3 }, empty, T);
    expect(viewMode(c)).toBe("chat");
  });
  it("a conversation with no items yet is still chat mode", () => {
    const c = newest({ items: [], end: 0 });
    expect(viewMode(c)).toBe("chat");
    expect(nextRequest(c, T)).toEqual({ conv: "c1", after: 0 });
  });
  it("starts unsupported when told so", () => {
    expect(newConversation(true).unsupported).toBe(true);
  });
});
