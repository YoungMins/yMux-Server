// What one pane's conversation looks like on the phone and what to ask next. Pure, no DOM.
// Positions are opaque (PROTOCOL.md 5.2): they are only ever echoed back. The cursors `start` and
// `end` move with every accepted reply, empty or not, and do not depend on the stored pages.
// Items are kept in pages (`chunks`), each remembering the positions its reply gave, so that trimming
// memory by whole pages can set the cursor to a position the desktop really gave.
//
// A reply is folded in only when it is the continuation that was asked for: `after: e` honoured
// means `start === e`, `before: s` honoured means `end === s`, same `conv`. Any other reply is a
// newest page and replaces everything.
import type { ChatItem, ChatPage } from "../protocol/messages";

export const MAX_KEPT = 400;
export const REPROBE_MS = 30_000;
const PAGE_ITEMS = 40;

export interface Chunk {
  start: number;
  end: number;
  items: ChatItem[];
}

export interface Conversation {
  /** A reply has been seen (chat or the empty form). */
  loaded: boolean;
  /** The desktop answered `unknown_op`: never ask again in this page session. */
  unsupported: boolean;
  /** When the empty form was last seen (for the 30 s re-probe). */
  emptyAt: number;
  /** Consecutive empty-form replies while a conversation was shown (one is not believed). */
  emptyStreak: number;
  conv: string;
  agent: ChatPage["agent"];
  chunks: Chunk[];
  start: number;
  end: number;
  older: boolean;
  newer: boolean;
  /** Newest pages were dropped to make room for older ones: no forward polling until "latest". */
  browsing: boolean;
  /** The next request must be a plain newest-page one ("jump to latest"). */
  resync: boolean;
  /** The last `before` reply added nothing but moved the cursor back (more may lie further). */
  olderEmpty: boolean;
  /** Which position the last failed `after`/`before` request asked for, and how many times in a row. */
  failKey: string;
  failCount: number;
  /** Goes up whenever what is shown changes. */
  rev: number;
}

/** After this many failures in a row at one position the next request is a newest-page one. */
export const MAX_FAILS = 3;

/** The params of a `chat` request (the pane is added by the caller). */
export interface ChatRequest {
  conv?: string;
  after?: number;
  before?: number;
}

export const newConversation = (unsupported = false): Conversation => ({
  loaded: false,
  unsupported,
  emptyAt: 0,
  emptyStreak: 0,
  conv: "",
  agent: "",
  chunks: [],
  start: 0,
  end: 0,
  older: false,
  newer: false,
  browsing: false,
  resync: false,
  olderEmpty: false,
  failKey: "",
  failCount: 0,
  rev: 0,
});

const failKeyOf = (req: ChatRequest): string => (req.after !== undefined ? `a${req.after}` : req.before !== undefined ? `b${req.before}` : "");

/** A request failed (an error code, or a reply that did not parse). Plain requests are not counted. */
export function noteFailure(c: Conversation, req: ChatRequest): Conversation {
  const key = failKeyOf(req);
  if (key === "") return c;
  return { ...c, failKey: key, failCount: key === c.failKey ? c.failCount + 1 : 1 };
}

/** The request to send in place of `req`: a newest-page one when `req` has failed too often. */
const orNewest = (c: Conversation, req: ChatRequest): ChatRequest =>
  c.failCount >= MAX_FAILS && c.failKey === failKeyOf(req) ? {} : req;

export const items = (c: Conversation): ChatItem[] => c.chunks.flatMap((k) => k.items);
export const itemCount = (c: Conversation): number => c.chunks.reduce((n, k) => n + k.items.length, 0);

export type Row = { kind: "msg"; item: ChatItem } | { kind: "tools"; items: ChatItem[] };

/** What the screen shows: messages as they are, runs of consecutive tool items as one row. */
export function groupRows(list: readonly ChatItem[]): Row[] {
  const rows: Row[] = [];
  for (const item of list) {
    const last = rows[rows.length - 1];
    if (item.role !== "tool") rows.push({ kind: "msg", item });
    else if (last?.kind === "tools") last.items.push(item);
    else rows.push({ kind: "tools", items: [item] });
  }
  return rows;
}

/** "chat" only while there is a conversation to show; before the first reply it is "screen". */
export const viewMode = (c: Conversation): "chat" | "screen" => (!c.unsupported && c.loaded && c.conv !== "" ? "chat" : "screen");

export function markUnsupported(c: Conversation): Conversation {
  return c.unsupported ? c : { ...newConversation(true), rev: c.rev + 1 };
}

/** "Jump to latest": forget the browsing position; the next request is a newest-page one. */
export const jumpLatest = (c: Conversation): Conversation => ({ ...c, browsing: false, resync: true });

/** The next poll's params, or null when nothing should be asked now. */
export function nextRequest(c: Conversation, now: number): ChatRequest | null {
  if (c.unsupported) return null;
  if (!c.loaded || c.resync) return {};
  // a clock that went backwards must not stall the re-probe
  if (c.conv === "") return now - c.emptyAt >= REPROBE_MS || now < c.emptyAt ? {} : null;
  if (c.browsing) return null;
  return orNewest(c, { conv: c.conv, after: c.end });
}

/** "Load older": the items just before the start cursor. */
export const olderRequest = (c: Conversation): ChatRequest | null =>
  c.conv !== "" && c.older && !c.resync ? orNewest(c, { conv: c.conv, before: c.start }) : null;

const idSet = (c: Conversation): Set<string> => new Set(c.chunks.flatMap((k) => k.items.map((i) => i.id)));

/** A newest page: everything shown is replaced. */
function replace(c: Conversation, page: ChatPage): Conversation {
  const chunks = page.items.length ? [{ start: page.start, end: page.end, items: page.items }] : [];
  return {
    ...c,
    loaded: true,
    conv: page.conv,
    agent: page.agent,
    chunks,
    start: page.start,
    end: page.end,
    older: page.older,
    newer: page.newer,
    browsing: false,
    resync: false,
    olderEmpty: false,
    emptyStreak: 0,
    failKey: "",
    failCount: 0,
    rev: c.rev + 1,
  };
}

/** Drops the oldest pages beyond the cap (then `older`), or the newest ones when `fromEnd` (then `newer`, browsing). */
function trim(c: Conversation, fromEnd: boolean): Conversation {
  let { chunks, older, newer, start, end, browsing } = c;
  let total = itemCount(c);
  while (total > MAX_KEPT && chunks.length > 1) {
    if (fromEnd) {
      total -= chunks[chunks.length - 1]!.items.length;
      chunks = chunks.slice(0, -1);
      end = chunks[chunks.length - 1]!.end;
      newer = true;
      browsing = true;
    } else {
      total -= chunks[0]!.items.length;
      chunks = chunks.slice(1);
      start = chunks[0]!.start;
      older = true;
    }
  }
  return chunks === c.chunks ? c : { ...c, chunks, start, end, older, newer, browsing };
}

/** Folds one reply to `req` into the conversation. */
export function applyPage(c: Conversation, req: ChatRequest, page: ChatPage, now: number): Conversation {
  // a late reply to a request asked before "jump to latest" is ignored; only the newest page counts
  if (c.resync && (req.after !== undefined || req.before !== undefined)) return c;
  const next = applyReply(c, req, page, now);
  return next.failCount === 0 ? next : { ...next, failKey: "", failCount: 0 };
}

function applyReply(c: Conversation, req: ChatRequest, page: ChatPage, now: number): Conversation {
  if (page.conv === "") {
    // One empty answer after a good one is not believed (a flicker); the second in a row is.
    if (c.conv !== "" && c.emptyStreak < 1) return { ...c, emptyStreak: c.emptyStreak + 1 };
    return { ...newConversation(c.unsupported), loaded: true, emptyAt: now, rev: c.rev + 1 };
  }
  const same = c.conv === page.conv;
  const afterOk = same && req.after !== undefined && page.start === req.after;
  const beforeOk = same && req.before !== undefined && page.end === req.before;
  if (!afterOk && !beforeOk) return replace(c, page);

  const seen = idSet(c);
  const fresh = page.items.filter((i) => !seen.has(i.id));
  const base = { ...c, emptyStreak: 0 };

  if (beforeOk) {
    // Both cursors may move with nothing to show: the cursor is the position, not the pages.
    const moved = page.start < c.start;
    const stalled = fresh.length === 0 && !moved;
    const older = stalled ? false : page.older;
    const chunks = fresh.length ? [{ start: page.start, end: page.end, items: fresh }, ...c.chunks] : c.chunks;
    const olderEmpty = fresh.length === 0 && moved && older;
    const next = { ...base, chunks, start: moved ? page.start : c.start, older, olderEmpty };
    const changed = fresh.length > 0 || moved || older !== c.older || olderEmpty !== c.olderEmpty;
    return changed ? trim({ ...next, rev: c.rev + 1 }, true) : c;
  }

  // after: e honoured
  if (fresh.length === 0 && page.end === c.end && page.newer === c.newer && c.emptyStreak === 0) return c;
  let chunks = c.chunks;
  if (fresh.length) {
    const last = chunks[chunks.length - 1];
    chunks =
      last && last.items.length + fresh.length <= PAGE_ITEMS
        ? [...chunks.slice(0, -1), { start: last.start, end: page.end, items: [...last.items, ...fresh] }]
        : [...chunks, { start: page.start, end: page.end, items: fresh }];
  }
  const changed = fresh.length > 0 || page.end !== c.end || page.newer !== c.newer;
  return trim({ ...base, chunks, end: page.end, newer: page.newer, rev: changed ? c.rev + 1 : c.rev }, false);
}
