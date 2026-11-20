import { describe, expect, it } from "vitest";
import { cleanBlock } from "./clean";
import { parseChatData, validateCmd } from "./messages";

const P = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const item = (id: string, role: string, text: unknown, ts = 0): unknown => ({ id, role, text, ts_ms: ts });
const page = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  conv: "abc_DEF-1",
  agent: "claude",
  items: [item("1", "user", "hi"), item("2.5", "assistant", "hello")],
  start: 0,
  end: 3,
  older: false,
  newer: false,
  ...over,
});

describe("chat command", () => {
  it("validates pane, conv and ONE of after/before", () => {
    expect(validateCmd({ op: "chat", pane: P })).toBeNull();
    expect(validateCmd({ op: "chat", pane: P, conv: "abc", after: 5 })).toBeNull();
    expect(validateCmd({ op: "chat", pane: P, conv: "abc", before: 0 })).toBeNull();
    expect(validateCmd({ op: "chat", pane: "nope" })).toBe("bad_request");
    expect(validateCmd({ op: "chat", pane: P, conv: "a b", after: 1 })).toBe("bad_request");
    expect(validateCmd({ op: "chat", pane: P, conv: "abc", after: 1, before: 2 })).toBe("bad_request");
    expect(validateCmd({ op: "chat", pane: P, after: 1 })).toBe("bad_request");
    expect(validateCmd({ op: "chat", pane: P, conv: "abc", after: -1 })).toBe("bad_request");
    expect(validateCmd({ op: "chat", pane: P, conv: "abc", after: 1.5 })).toBe("bad_request");
    expect(validateCmd({ op: "chat", pane: P, conv: "abc", after: 2 ** 53 })).toBe("bad_request");
  });
});

describe("cleanBlock", () => {
  it("turns CR and CRLF into LF, keeps LF and tab, removes other Cc/Cf/Zl/Zp", () => {
    expect(cleanBlock("a\r\nb\rc\nd\te")).toBe("a\nb\nc\nd\te");
    expect(cleanBlock("a\u0000b\u001bc​d‮e f g\u0085h")).toBe("abcdefgh");
  });
});

describe("parseChatData", () => {
  it("parses a full page", () => {
    const p = parseChatData(page({ older: true, newer: true }));
    expect(p).toEqual({
      conv: "abc_DEF-1",
      agent: "claude",
      items: [
        { id: "1", role: "user", text: "hi", ts: 0 },
        { id: "2.5", role: "assistant", text: "hello", ts: 0 },
      ],
      start: 0,
      end: 3,
      older: true,
      newer: true,
    });
  });
  it("accepts the empty form", () => {
    expect(parseChatData({ conv: "" })).toEqual({ conv: "", agent: "", items: [], start: 0, end: 0, older: false, newer: false });
  });
  it("rejects what is not a chat reply", () => {
    for (const bad of [null, undefined, 5, "x", [], {}, { conv: 5 }, { conv: "a b" }, { conv: "x".repeat(33) }]) {
      expect(parseChatData(bad), JSON.stringify(bad)).toBeNull();
    }
  });
  it("rejects bad positions", () => {
    for (const over of [
      { start: -1 },
      { start: 1.5 },
      { start: 2 ** 53 },
      { end: "3" },
      { start: 5, end: 3 },
      { start: undefined },
    ]) {
      expect(parseChatData(page(over)), JSON.stringify(over)).toBeNull();
    }
  });
  it("rejects more than 40 items, drops items with a bad id, role or text", () => {
    const many = Array.from({ length: 41 }, (_, i) => item(String(i), "user", "x"));
    expect(parseChatData(page({ items: many }))).toBeNull();
    const mixed = [
      item("1", "user", "ok"),
      item("a1", "user", "bad id"),
      item("2", "system", "bad role"),
      item("3", "user", 5),
      item("4".repeat(41), "user", "long id"),
      item("", "user", "empty id"),
      "junk",
      item("5", "tool", "Bash: ls"),
    ];
    const p = parseChatData(page({ items: mixed }))!;
    expect(p.items.map((i) => i.id)).toEqual(["1", "5"]);
  });
  it("drops a repeated id inside one reply", () => {
    const p = parseChatData(page({ items: [item("1", "user", "a"), item("1", "user", "b")] }))!;
    expect(p.items).toHaveLength(1);
    expect(p.items[0]!.text).toBe("a");
  });
  it("cleans user/assistant text keeping newlines and tabs, and clips to 8000", () => {
    const p = parseChatData(page({ items: [item("1", "assistant", "a\r\n\tb‮\u0000c"), item("2", "user", "y".repeat(9000))] }))!;
    expect(p.items[0]!.text).toBe("a\n\tbc");
    expect(p.items[1]!.text).toHaveLength(8000);
  });
  it("makes a tool text one clean line of at most 200 chars", () => {
    const p = parseChatData(page({ items: [item("1", "tool", "Bash:\n ls‮" + "z".repeat(300))] }))!;
    expect(p.items[0]!.text.includes("\n")).toBe(false);
    expect(p.items[0]!.text).toHaveLength(200);
  });
  it("normalises ts and tolerates an unknown agent", () => {
    const p = parseChatData(page({ agent: "gemini", items: [item("1", "user", "a", -5), item("2", "user", "b", 1700000000000)] }))!;
    expect(p.agent).toBe("");
    expect(p.items.map((i) => i.ts)).toEqual([0, 1700000000000]);
  });
  it("treats an empty conv with items as the empty form", () => {
    expect(parseChatData({ conv: "", items: [item("1", "user", "a")], start: 0, end: 1 })!.items).toEqual([]);
  });
});
