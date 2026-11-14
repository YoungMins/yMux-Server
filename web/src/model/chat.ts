// Pure decisions of the conversation screen and the list rows. No DOM.
import { capAllows, type Cap, type Pane, type PaneStatus, type ReplyResult } from "../protocol/messages";
import { DELIVERED_UNKNOWN } from "../protocol/router";
import { sortDesktops, type DesktopSummary } from "./desktops";
import { sortPanes } from "./panes";

export type ComposerMode = "send" | "stop" | "disabled";

/**
 * The one round button: Send when there is text, Stop (interrupt) when the box is empty and the
 * agent is working, else a disabled Send. Stop needs `respond`; nothing works while not ready.
 */
export function composerMode(text: string, status: PaneStatus, cap: Cap | null, ready: boolean): ComposerMode {
  if (!ready) return "disabled";
  if (text.trim() !== "") return capAllows(cap, "prompt") ? "send" : "disabled";
  if (status === "working" && capAllows(cap, "respond")) return "stop";
  return "disabled";
}

/**
 * Height of the composer's textarea: it grows with its content up to `maxRows` lines, and only
 * above that does it scroll. `contentHeight` is scrollHeight plus the borders (it is border-box),
 * `chrome` the padding plus the borders. Below the cap the overflow is hidden, so a one-line box
 * never shows scroll arrows.
 */
export function growLayout(
  contentHeight: number,
  lineHeight: number,
  chrome: number,
  maxRows = 6,
): { height: number; overflowY: "hidden" | "auto" } {
  const cap = lineHeight * maxRows + chrome;
  return { height: Math.min(contentHeight, cap), overflowY: contentHeight > cap ? "auto" : "hidden" };
}

/** Where a send result is shown: on the sent bubble while that bubble is visible, else in the note. */
export const reportTarget = (ownsBubble: boolean, bubbleVisible: boolean): "bubble" | "note" =>
  ownsBubble && bubbleVisible ? "bubble" : "note";

/**
 * Whether the typed text is done with after a `prompt` request: it was sent or queued, or it was
 * delivered with the result unknown (sending it again could run it twice). Anything else keeps it.
 */
export function promptConsumed(r: ReplyResult, result: string | null): boolean {
  if (r.ok) return result === "sent" || result === "queued";
  return r.code === DELIVERED_UNKNOWN;
}

/** A busy agent gets the text queued instead of a refusal. */
export const shouldQueue = (status: PaneStatus): boolean => status === "working";

export type ComposerAccess = "full" | "answer" | "view";

/** What the bottom of the screen offers for this device's capability; null = no session yet. */
export function composerAccess(cap: Cap | null): ComposerAccess | null {
  if (cap === null) return null;
  return cap === "prompt" ? "full" : cap === "respond" ? "answer" : "view";
}

/** "<workspace> · <computer> · <status> <time>"; empty parts are left out. */
export function rowSubtitle(parts: { ws: string; computer: string | null; status: string; since: string }): string {
  const statusAndTime = [parts.status, parts.since].filter((s) => s !== "").join(" ");
  return [parts.ws, parts.computer ?? "", statusAndTime].filter((s) => s !== "").join(" · ");
}

export interface ListSection {
  desktopId: string;
  name: string;
  panes: Pane[];
}

/** Computers with a waiting agent first, then by name; inside, waiting agents first. */
export function listSections(desktops: readonly DesktopSummary[]): ListSection[] {
  return sortDesktops(desktops).map((d) => ({ desktopId: d.desktopId, name: d.name, panes: sortPanes(d.panes ?? []) }));
}

/** Section headers (and the computer in each row) appear only with more than one computer. */
export const showsComputers = (sections: readonly ListSection[]): boolean => sections.length > 1;
