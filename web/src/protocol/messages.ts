// Message builders and defensive parsers (PROTOCOL.md sections 3-6).
// Parsers never throw: anything of the wrong shape yields null / is dropped.
import { cleanText } from "./clean";
import { isUuid } from "./encoding";

export const PROTOCOL_VERSION = 1;
export const MAX_FRAME = 256 * 1024;
export const MAX_PROMPT_CHARS = 16000;
/** The desktop refuses a command plaintext over 64 KiB (PROTOCOL.md 5.1). */
export const MAX_CMD_BYTES = 64 * 1024;
const MENU_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
/** Highest option number the desktop will type (PROTOCOL.md 5.2). */
export const MAX_ANSWER_N = 9;

export type Cap = "view" | "respond" | "prompt";
export type PaneStatus = "working" | "waiting" | "done" | "idle" | "none";

const CAP_RANK: Record<Cap, number> = { view: 0, respond: 1, prompt: 2 };
const STATUSES: readonly string[] = ["working", "waiting", "done", "idle", "none"];

export function capAllows(cap: Cap | null | undefined, needed: Cap): boolean {
  return !!cap && CAP_RANK[cap] >= CAP_RANK[needed];
}

export interface Pane {
  pane: string;
  ws: string;
  title: string;
  kind: string;
  status: PaneStatus;
  since_ms: number;
  queued: number;
}
export interface MenuOption {
  n: number;
  label: string;
  selected: boolean;
  input: boolean;
}
export interface Peek {
  lines: string[];
  menu: MenuOption[];
  /** Names one appearance of one menu; "" when there is none. An answer must echo it. */
  menuId: string;
  question: string[];
  blocked: string | null;
  status: PaneStatus;
}

export type Cmd =
  | { op: "list" }
  | { op: "peek"; pane: string; lines: number }
  | { op: "answer"; pane: string; n: number; label: string; menu_id: string }
  | { op: "interrupt"; pane: string }
  | { op: "prompt"; pane: string; text: string; queue: boolean };

export type ReplyResult = { ok: true; data: unknown } | { ok: false; code: string };

/** Session and counter every desktop -> device body after `session` carries (5.1). */
export interface Envelope {
  session: string | null;
  n: number | null;
  /** The desktop's clock when it made the body (epoch ms); null when absent. */
  atMs: number | null;
}

/** What happened to the session this one revoked (PROTOCOL.md 5.1); null when absent or malformed. */
export interface Prev {
  session: string;
  seq: number;
}

export type Body =
  | { k: "session"; session: string; cap: Cap; name: string; open: string; nowMs: number | null; prev: Prev | null }
  | ({ k: "panes"; panes: Pane[] } & Envelope)
  | ({ k: "reply"; re: number; result: ReplyResult; ref: string | null } & Envelope)
  | ({ k: "reopen" } & Envelope);

export type ServerFrame =
  | { t: "challenge"; nonce: string }
  | { t: "ready"; desktopId: string; desktopOnline: boolean }
  | { t: "error"; code: string }
  | { t: "pair_result"; ok: boolean }
  | { t: "pair_challenge"; body: string }
  | { t: "msg"; body: string }
  | { t: "desktop_online" }
  | { t: "desktop_offline" };

type Rec = Record<string, unknown>;

export function asRec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}
/** Display text: cleaned (5.2) and clipped. */
function str(v: unknown, max: number, fallback = ""): string {
  return typeof v === "string" ? cleanText(v.length > max ? v.slice(0, max) : v) : fallback;
}
/** Identifiers (session, nonce): clipped only, never altered, so equality stays exact. */
function ident(v: unknown, max: number): string | null {
  return typeof v === "string" && v.length <= max ? v : null;
}
function num(v: unknown, fallback = 0): number {
  return typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : fallback;
}
function arr(v: unknown, max: number): unknown[] {
  return Array.isArray(v) ? v.slice(0, max) : [];
}

export function parseJson(text: unknown): unknown {
  if (typeof text !== "string" || text.length > MAX_FRAME) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// ---- server frames ------------------------------------------------------

const NONCE_RE = /^[A-Za-z0-9_-]{1,256}$/;

export function parseServerFrame(text: unknown): ServerFrame | null {
  const r = asRec(parseJson(text));
  if (!r || typeof r.t !== "string") return null;
  switch (r.t) {
    case "challenge":
      return typeof r.nonce === "string" && NONCE_RE.test(r.nonce)
        ? { t: "challenge", nonce: r.nonce }
        : null;
    case "ready":
      return { t: "ready", desktopId: str(r.desktop_id, 64), desktopOnline: r.desktop_online === true };
    case "error":
      return { t: "error", code: str(r.code, 64, "error") };
    case "pair_result":
      return { t: "pair_result", ok: r.ok === true };
    case "pair_challenge":
      return typeof r.body === "string" ? { t: "pair_challenge", body: r.body } : null;
    case "msg":
      return typeof r.body === "string" ? { t: "msg", body: r.body } : null;
    case "desktop_online":
      return { t: "desktop_online" };
    case "desktop_offline":
      return { t: "desktop_offline" };
    default:
      return null;
  }
}

// ---- desktop bodies -----------------------------------------------------

export function parseStatus(v: unknown): PaneStatus {
  return typeof v === "string" && STATUSES.includes(v) ? (v as PaneStatus) : "none";
}

export function parsePane(v: unknown): Pane | null {
  const r = asRec(v);
  if (!r || !isUuid(r.pane)) return null;
  return {
    pane: r.pane,
    ws: str(r.ws, 200),
    title: str(r.title, 200),
    kind: str(r.kind, 40),
    status: parseStatus(r.status),
    since_ms: Math.max(0, num(r.since_ms)),
    queued: Math.max(0, num(r.queued)),
  };
}

export function parsePanes(v: unknown): Pane[] {
  const out: Pane[] = [];
  const seen = new Set<string>();
  for (const x of arr(v, 500)) {
    const p = parsePane(x);
    if (p && !seen.has(p.pane)) {
      seen.add(p.pane);
      out.push(p);
    }
  }
  return out;
}

export function parseMenuOption(v: unknown): MenuOption | null {
  const r = asRec(v);
  if (!r || typeof r.n !== "number" || !Number.isInteger(r.n)) return null;
  return { n: r.n, label: str(r.label, 400), selected: r.selected === true, input: r.input === true };
}

function strList(v: unknown, maxItems: number, maxLen: number): string[] {
  return arr(v, maxItems)
    .filter((x): x is string => typeof x === "string")
    .map((s) => cleanText(s.slice(0, maxLen)));
}

/** True when the first non-blank character is `!` (the desktop refuses such a prompt). */
export function startsWithBang(text: string): boolean {
  return text.trimStart().startsWith("!");
}

export function parseListData(data: unknown): Pane[] | null {
  const r = asRec(data);
  return r && Array.isArray(r.panes) ? parsePanes(r.panes) : null;
}

export function parsePeekData(data: unknown): Peek | null {
  const r = asRec(data);
  if (!r || !Array.isArray(r.lines)) return null;
  const menu: MenuOption[] = [];
  for (const x of arr(r.menu, 50)) {
    const o = parseMenuOption(x);
    if (o) menu.push(o);
  }
  return {
    lines: strList(r.lines, 400, 2000),
    menu,
    menuId: typeof r.menu_id === "string" && MENU_ID_RE.test(r.menu_id) ? r.menu_id : "",
    question: strList(r.question, 50, 2000),
    blocked: typeof r.blocked === "string" ? str(r.blocked, 80) : null,
    status: parseStatus(r.status),
  };
}

/** `data.result` when it is one of the allowed words, else null. */
export function parseResultData(data: unknown, allowed: readonly string[]): string | null {
  const r = asRec(data);
  return r && typeof r.result === "string" && allowed.includes(r.result) ? r.result : null;
}

function envelope(r: Rec): Envelope {
  return {
    session: ident(r.session, 200),
    n: typeof r.n === "number" && Number.isSafeInteger(r.n) ? r.n : null,
    atMs: typeof r.at_ms === "number" && Number.isFinite(r.at_ms) ? r.at_ms : null,
  };
}

function parsePrev(v: unknown): Prev | null {
  const r = asRec(v);
  if (!r) return null;
  const session = ident(r.session, 200);
  if (session === null || typeof r.seq !== "number" || !Number.isSafeInteger(r.seq) || r.seq < 0) return null;
  return { session, seq: r.seq };
}

/** `ref` of a `re:0` reply: b64u of 16 bytes. */
const REF_RE = /^[A-Za-z0-9_-]{22}$/;

export function parseBody(text: unknown): Body | null {
  const r = asRec(parseJson(text));
  if (!r || typeof r.k !== "string") return null;
  switch (r.k) {
    case "session": {
      const session = ident(r.session, 200);
      if (!session) return null;
      const cap: Cap = r.cap === "respond" || r.cap === "prompt" ? r.cap : "view";
      const nowMs = typeof r.now_ms === "number" && Number.isFinite(r.now_ms) ? r.now_ms : null;
      return {
        k: "session",
        session,
        cap,
        name: str(r.name, 120),
        open: ident(r.open, 200) ?? "",
        nowMs,
        prev: parsePrev(r.prev),
      };
    }
    case "panes":
      return Array.isArray(r.panes) ? { k: "panes", panes: parsePanes(r.panes), ...envelope(r) } : null;
    case "reopen":
      return { k: "reopen", ...envelope(r) };
    case "reply": {
      if (typeof r.re !== "number" || !Number.isInteger(r.re) || r.re < 0) return null;
      if (typeof r.ok !== "boolean") return null;
      return {
        k: "reply",
        re: r.re,
        result: r.ok ? { ok: true, data: r.data } : { ok: false, code: str(r.code, 64, "failed") },
        ref: typeof r.ref === "string" && REF_RE.test(r.ref) ? r.ref : null,
        ...envelope(r),
      };
    }
    default:
      return null;
  }
}

// ---- builders -----------------------------------------------------------

/** Returns an error code when the command must not be sent, else null. */
export function validateCmd(cmd: Cmd): string | null {
  switch (cmd.op) {
    case "list":
      return null;
    case "peek":
      return isUuid(cmd.pane) && Number.isInteger(cmd.lines) && cmd.lines >= 1 && cmd.lines <= 200
        ? null
        : "bad_request";
    case "answer":
      return isUuid(cmd.pane) &&
        Number.isInteger(cmd.n) &&
        cmd.n >= 1 &&
        cmd.n <= MAX_ANSWER_N &&
        typeof cmd.label === "string" &&
        typeof cmd.menu_id === "string" &&
        MENU_ID_RE.test(cmd.menu_id)
        ? null
        : "bad_request";
    case "interrupt":
      return isUuid(cmd.pane) ? null : "bad_request";
    case "prompt":
      return isUuid(cmd.pane) &&
        typeof cmd.text === "string" &&
        cmd.text.length >= 1 &&
        cmd.text.length <= MAX_PROMPT_CHARS &&
        typeof cmd.queue === "boolean"
        ? null
        : "bad_request";
    default:
      return "bad_request";
  }
}

export interface CmdContext {
  desktopId: string;
  deviceId: string;
  session: string;
}

/** The command plaintext (sealed before it is sent): field order as in PROTOCOL.md 5.1. */
export function buildCmdBody(ctx: CmdContext, seq: number, tsMs: number, cmd: Cmd): string {
  return JSON.stringify({
    k: "cmd",
    desktop_id: ctx.desktopId,
    device_id: ctx.deviceId,
    session: ctx.session,
    seq,
    ts_ms: Math.trunc(tsMs),
    cmd,
  });
}

/** The session-opening plaintext (5.1); `nonce` is b64u of 16 random bytes. */
export const buildOpenBody = (desktopId: string, deviceId: string, nonce: string): string =>
  JSON.stringify({ k: "open", desktop_id: desktopId, device_id: deviceId, nonce });

/** True when the body tells the device to open a new session (`reopen`, `bad_session`, `expired`). */
export function needsReopen(b: Body): boolean {
  if (b.k === "reopen") return true;
  return b.k === "reply" && !b.result.ok && (b.result.code === "bad_session" || b.result.code === "expired");
}

export const cmdFrame = (body: string, sig: string): string => JSON.stringify({ t: "cmd", body, sig });

export const deviceHello = (deviceId: string, sig: string): string =>
  JSON.stringify({ t: "hello", role: "device", v: PROTOCOL_VERSION, device_id: deviceId, sig });

export const pairRequestFrame = (p: {
  desktopId: string;
  deviceId: string;
  pubkey: string;
  ek: string;
  name: string;
  proof: string;
  sig: string;
}): string =>
  JSON.stringify({
    t: "pair_request",
    v: PROTOCOL_VERSION,
    desktop_id: p.desktopId,
    device_id: p.deviceId,
    pubkey: p.pubkey,
    ek: p.ek,
    name: p.name,
    proof: p.proof,
    sig: p.sig,
  });

export interface PushSub {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export const pushSubscribeFrame = (sub: PushSub): string => JSON.stringify({ t: "push_subscribe", sub });
export const pushUnsubscribeFrame = (): string => JSON.stringify({ t: "push_unsubscribe" });

/** Normalises PushSubscription.toJSON() output; null when unusable (endpoints must be https). */
export function toPushSub(v: unknown): PushSub | null {
  const r = asRec(v);
  const keys = asRec(r?.keys);
  if (!r || !keys) return null;
  const { endpoint } = r;
  if (typeof endpoint !== "string" || !endpoint.startsWith("https://")) return null;
  if (typeof keys.p256dh !== "string" || typeof keys.auth !== "string") return null;
  return { endpoint, keys: { p256dh: keys.p256dh, auth: keys.auth } };
}
