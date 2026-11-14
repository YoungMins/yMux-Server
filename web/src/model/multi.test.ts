import { describe, expect, it } from "vitest";
import type { Pane } from "../protocol/messages";
import { composerAccess, composerMode, listSections, rowSubtitle, shouldQueue, showsComputers } from "./chat";
import { sortDesktops } from "./desktops";
import { paneHash, paneKey, parsePaneHash, resolvePaneHash } from "./route";

const A = "aaaaaaaa-0000-4000-8000-000000000001";
const B = "bbbbbbbb-0000-4000-8000-000000000002";
const P1 = "11111111-1111-4111-8111-111111111111";
const P2 = "22222222-2222-4222-8222-222222222222";

const pane = (id: string, over: Partial<Pane> = {}): Pane => ({
  pane: id,
  ws: "w",
  title: id.slice(0, 2),
  kind: "claude",
  status: "idle",
  since_ms: 0,
  queued: 0,
  ...over,
});

describe("deep links", () => {
  it("parses the new form #pane=<desktop>.<pane>", () => {
    expect(parsePaneHash(`#pane=${A}.${P1}`)).toEqual({ desktopId: A, pane: P1 });
  });
  it("still parses the old form #pane=<pane>", () => {
    expect(parsePaneHash(`#pane=${P1}`)).toEqual({ desktopId: null, pane: P1 });
  });
  it("rejects anything else", () => {
    for (const h of ["", "#pane=", "#pane=x", `#pane=${A}.`, `#pane=.${P1}`, `#pane=${A}.${P1}.${P2}`, `#pane=${A}/${P1}`, `#x=${P1}`])
      expect(parsePaneHash(h), h).toBeNull();
  });
  it("builds hashes and keys from (desktop, pane)", () => {
    expect(paneHash({ desktopId: A, pane: P1 })).toBe(`#pane=${A}.${P1}`);
    expect(paneKey({ desktopId: A, pane: P1 })).not.toBe(paneKey({ desktopId: B, pane: P1 }));
  });
});

describe("routing keyed by (desktop, pane)", () => {
  const both = [
    { desktopId: A, panes: [pane(P1)] },
    { desktopId: B, panes: [pane(P1), pane(P2)] },
  ];
  it("a new-form link names its desktop even when the same pane uuid exists on both", () => {
    expect(resolvePaneHash({ desktopId: B, pane: P1 }, both)).toEqual({ desktopId: B, pane: P1 });
    expect(resolvePaneHash({ desktopId: A, pane: P1 }, both)).toEqual({ desktopId: A, pane: P1 });
  });
  it("an unknown desktop does not resolve", () => {
    expect(resolvePaneHash({ desktopId: "cccccccc-0000-4000-8000-000000000003", pane: P1 }, both)).toBeNull();
  });
  it("an old link is resolved only when unambiguous", () => {
    expect(resolvePaneHash({ desktopId: null, pane: P2 }, both)).toEqual({ desktopId: B, pane: P2 });
    expect(resolvePaneHash({ desktopId: null, pane: P1 }, both), "same uuid on two desktops").toBeNull();
    expect(resolvePaneHash({ desktopId: null, pane: "33333333-3333-4333-8333-333333333333" }, both)).toBeNull();
  });
  it("an old link with a single pairing means that desktop, even before its list loaded", () => {
    expect(resolvePaneHash({ desktopId: null, pane: P1 }, [{ desktopId: A, panes: null }])).toEqual({ desktopId: A, pane: P1 });
  });
  it("with two pairings an old link waits for the lists", () => {
    expect(resolvePaneHash({ desktopId: null, pane: P1 }, [{ desktopId: A, panes: null }, { desktopId: B, panes: null }])).toBeNull();
  });
});

describe("desktop ordering", () => {
  const d = (id: string, name: string, panes: Pane[] | null) => ({ desktopId: id, name, panes });
  it("desktops with a waiting agent first, then by name", () => {
    const sorted = sortDesktops([
      d("3", "Zed", [pane(P1, { status: "working" })]),
      d("2", "Home", [pane(P1)]),
      d("1", "Office", [pane(P2, { status: "waiting", since_ms: 5 })]),
      d("4", "Attic", null),
    ]);
    expect(sorted.map((x) => x.name)).toEqual(["Office", "Attic", "Home", "Zed"]);
  });
  it("sections: waiting agents first inside each, headers only with two computers", () => {
    const s = listSections([
      d(B, "Home", [pane(P1, { status: "idle" }), pane(P2, { status: "waiting", since_ms: 1 })]),
      d(A, "Office", [pane(P1, { status: "working", since_ms: 1 })]),
    ]);
    expect(s.map((x) => x.name)).toEqual(["Home", "Office"]);
    expect(s[0]!.panes.map((p) => p.pane)).toEqual([P2, P1]);
    expect(showsComputers(s)).toBe(true);
    expect(showsComputers(s.slice(0, 1))).toBe(false);
  });
});

describe("composer", () => {
  it("send with text, stop when empty and working, else disabled", () => {
    expect(composerMode("hi", "idle", "prompt", true)).toBe("send");
    expect(composerMode("hi", "working", "prompt", true)).toBe("send");
    expect(composerMode("  ", "working", "prompt", true)).toBe("stop");
    expect(composerMode("", "working", "respond", true)).toBe("stop");
    expect(composerMode("", "idle", "prompt", true)).toBe("disabled");
    expect(composerMode("", "waiting", "prompt", true)).toBe("disabled");
  });
  it("needs the capability and a ready connection", () => {
    expect(composerMode("hi", "idle", "respond", true)).toBe("disabled");
    expect(composerMode("", "working", "view", true)).toBe("disabled");
    expect(composerMode("hi", "idle", "prompt", false)).toBe("disabled");
    expect(composerMode("", "working", "prompt", false)).toBe("disabled");
    expect(composerMode("hi", "idle", null, true)).toBe("disabled");
  });
  it("queues automatically only while the agent is working", () => {
    expect(shouldQueue("working")).toBe(true);
    for (const s of ["idle", "waiting", "done", "none"] as const) expect(shouldQueue(s)).toBe(false);
  });
  it("the composer is replaced by a line without the prompt capability", () => {
    expect(composerAccess("prompt")).toBe("full");
    expect(composerAccess("respond")).toBe("answer");
    expect(composerAccess("view")).toBe("view");
    expect(composerAccess(null)).toBeNull();
  });
});

describe("row subtitle", () => {
  it("<workspace> · <computer> · <status> <time>", () => {
    expect(rowSubtitle({ ws: "api", computer: "Office", status: "Working", since: "5 min ago" })).toBe(
      "api · Office · Working 5 min ago",
    );
  });
  it("leaves out the computer with one pairing and parts that are empty", () => {
    expect(rowSubtitle({ ws: "api", computer: null, status: "Working", since: "5 min ago" })).toBe("api · Working 5 min ago");
    expect(rowSubtitle({ ws: "", computer: null, status: "Idle", since: "" })).toBe("Idle");
  });
});
