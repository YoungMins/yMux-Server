// The testable parts of the UI polish: where a result is shown, when the composer scrolls, what a
// settled write says, and the status dot rules in the stylesheet.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { growLayout, promptConsumed, reportTarget } from "../model/chat";
import { COULD_NOT_CONFIRM, DELIVERED_UNKNOWN, NOT_DELIVERED } from "../protocol/router";
import { errorText, resultText } from "./common";
import { linkProblemKey } from "./pairView";

describe("composer height", () => {
  // 22 px lines, 20 px padding + 2 px border around them.
  const grow = (content: number) => growLayout(content, 22, 22);
  it("a one-line box has no scroll: overflow hidden, and it never exceeds the content", () => {
    expect(grow(44)).toEqual({ height: 44, overflowY: "hidden" });
    expect(grow(66)).toEqual({ height: 66, overflowY: "hidden" });
  });
  it("is hidden up to exactly six lines, and scrolls only above that", () => {
    const cap = 22 * 6 + 22;
    expect(grow(cap)).toEqual({ height: cap, overflowY: "hidden" });
    expect(grow(cap + 1)).toEqual({ height: cap, overflowY: "auto" });
    expect(grow(1000)).toEqual({ height: cap, overflowY: "auto" });
  });
});

describe("a result is shown once", () => {
  it("on the bubble while the send's own bubble is visible, otherwise in the note", () => {
    expect(reportTarget(true, true)).toBe("bubble");
    expect(reportTarget(true, false), "the bubble faded or is hidden").toBe("note");
    expect(reportTarget(false, true), "an answer tapped while an old bubble is still up").toBe("note");
    expect(reportTarget(false, false)).toBe("note");
  });
});

describe("what a settled prompt does to the typed text", () => {
  it("is cleared when it was sent, queued, or delivered with an unknown result; kept otherwise", () => {
    expect(promptConsumed({ ok: true, data: {} }, "sent")).toBe(true);
    expect(promptConsumed({ ok: true, data: {} }, "queued")).toBe(true);
    expect(promptConsumed({ ok: true, data: {} }, "waiting")).toBe(false);
    expect(promptConsumed({ ok: true, data: {} }, null)).toBe(false);
    expect(promptConsumed({ ok: false, code: DELIVERED_UNKNOWN }, null)).toBe(true);
    expect(promptConsumed({ ok: false, code: NOT_DELIVERED }, null)).toBe(false);
    expect(promptConsumed({ ok: false, code: COULD_NOT_CONFIRM }, null)).toBe(false);
    expect(promptConsumed({ ok: false, code: "forbidden" }, null)).toBe(false);
  });
  it("says each outcome in its own plain words, never as a generic error", () => {
    const words = [DELIVERED_UNKNOWN, NOT_DELIVERED, COULD_NOT_CONFIRM].map((c) => errorText(c));
    expect(new Set(words).size).toBe(3);
    for (const w of words) expect(w).not.toMatch(/Something went wrong/);
    expect(words[0]).toMatch(/result unknown/);
    expect(words[1]).toMatch(/Not delivered/);
    expect(words[2]).toMatch(/before sending again/);
    expect(resultText({ ok: false, code: NOT_DELIVERED }, null)).toBe(words[1]);
  });
});

describe("pairing link problems", () => {
  it("an older yMux's QR gets the update message, anything else the bad-link one", () => {
    expect(linkProblemKey("old")).toBe("pair.oldQr");
    expect(linkProblemKey("bad")).toBe("pair.badLink");
  });
});

describe("status dots", () => {
  const css = readFileSync(join(__dirname, "..", "style.css"), "utf8");
  const rule = (sel: string): string => {
    const m = new RegExp(`${sel.replace(/[.]/g, "\\.")}\\s*\\{([^}]*)\\}`).exec(css);
    if (!m) throw new Error(`no rule for ${sel}`);
    return m[1]!;
  };
  it("are one 10 px circle for all five statuses: only colours and the pulse differ", () => {
    const base = rule(".sdot");
    expect(base).toMatch(/width:\s*10px/);
    expect(base).toMatch(/height:\s*10px/);
    expect(base).toMatch(/border-radius:\s*50%/);
    expect(base).toMatch(/box-sizing:\s*border-box/);
    expect(base).toMatch(/background:\s*transparent/); // idle / none: a hollow ring
    for (const s of ["working", "waiting", "done"]) {
      const r = rule(`.sdot--${s}`);
      expect(r, s).not.toMatch(/width|height|border-radius/);
      expect(r, s).toMatch(/background:\s*var\(--(accent|attn|muted)\)/);
    }
    expect(rule(".sdot--working")).toMatch(/animation:\s*pulse/);
    expect(rule(".sdot--waiting")).not.toMatch(/animation/);
    expect(rule(".sdot--done")).not.toMatch(/animation/);
    expect(css).not.toMatch(/\.sdot--done \.icon/); // no check mark inside the done dot
  });
  it("the composer's textarea hides its overflow by default and cannot be resized", () => {
    const r = rule(".composer__input");
    expect(r).toMatch(/overflow-y:\s*hidden/);
    expect(r).toMatch(/resize:\s*none/);
  });
});
