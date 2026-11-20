// Sends signed commands, numbers them per session, matches replies by (session, seq), and keeps
// track of commands whose outcome is unknown (PROTOCOL.md 5.1, "Unknown outcomes").
//
// A command with no trustworthy reply is never reported as failed. It becomes UNCONFIRMED, the
// owner is asked to send a new `open`, and the answering `session.prev` settles it:
//   same session, seq <= prev.seq  -> DELIVERED_UNKNOWN (the desktop accepted it)
//   same session, seq  > prev.seq  -> NOT_DELIVERED     (it never will be)
//   anything else, or no session within CONFIRM_MS -> COULD_NOT_CONFIRM
// Reads (`list`, `peek`) are simply asked again in the new session. A write is never re-sent.
import { utf8 } from "./encoding";
import { cmdRef, cmdSigString } from "./signing";
import {
  buildCmdBody,
  cmdFrame,
  MAX_CMD_BYTES,
  validateCmd,
  type Cmd,
  type CmdContext,
  type Prev,
  type ReplyResult,
} from "./messages";

export const CLIENT_TIMEOUT_MS = 8000;
/** How long an unconfirmed command waits for the session that can settle it. */
export const CONFIRM_MS = 15000;

/** Failure codes for commands that were settled afterwards (shown as plain words, not as errors). */
export const DELIVERED_UNKNOWN = "delivered_unknown";
export const NOT_DELIVERED = "not_delivered";
export const COULD_NOT_CONFIRM = "could_not_confirm";

const isRead = (cmd: Cmd): boolean => cmd.op === "list" || cmd.op === "peek" || cmd.op === "chat";

export interface RouterDeps {
  send: (frame: string) => void;
  /** Seals the command plaintext (AES-GCM under the link key) into the body string. */
  seal: (plaintext: string) => Promise<string>;
  sign: (s: string) => Promise<string>;
  /** `ts_ms`: this device's clock plus the offset recorded from the session. */
  tsMs?: () => number;
  timeoutMs?: number;
  confirmMs?: number;
  /** A command just became unconfirmed: the owner should send a new `open`. */
  onUnconfirmed?: () => void;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (t: unknown) => void;
}

export interface RequestHooks {
  /** This request has no trustworthy answer (yet); the final one follows from the promise. */
  onUnconfirmed?: () => void;
  /** A write was shown as delivered-unknown after a `replay` reply; its genuine reply arrived later. */
  onLate?: (r: ReplyResult) => void;
}

type State = "queued" | "inflight" | "unconfirmed";

interface Entry {
  cmd: Cmd;
  hooks: RequestHooks | undefined;
  /** A read that was already asked again once. */
  retried: boolean;
  session: string;
  seq: number;
  /** b64u(first 16 bytes of SHA-256(sig string as sent)): what a `re:0` failure names (PROTOCOL.md 5). */
  ref: string;
  state: State;
  /** The frame was handed to the socket. */
  sent: boolean;
  done: boolean;
  timer: unknown;
  resolve: (r: ReplyResult) => void;
  finish: (r: ReplyResult) => void;
}

/** request() always resolves: failures are `{ok:false, code}`. */
export class CommandRouter {
  private seq = 0;
  private ctx: CmdContext | null = null;
  /** Replies of the CURRENT session by seq. Seq restarts per session, so the session is in the key. */
  private pending = new Map<string, Entry>();
  /** Writes settled as delivered-unknown by a `replay` reply, awaiting their genuine reply (current session only). */
  private lateWrites = new Map<string, { onLate: ((r: ReplyResult) => void) | undefined }>();
  /** Every unfinished request, numbered or still waiting to be. */
  private all = new Set<Entry>();
  private chain: Promise<void> = Promise.resolve();
  private readonly timeoutMs: number;
  private readonly confirmMs: number;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (t: unknown) => void;

  constructor(private readonly deps: RouterDeps) {
    this.timeoutMs = deps.timeoutMs ?? CLIENT_TIMEOUT_MS;
    this.confirmMs = deps.confirmMs ?? CONFIRM_MS;
    this.setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = deps.clearTimer ?? ((t) => clearTimeout(t as ReturnType<typeof setTimeout>));
  }

  /**
   * A different session id starts a fresh seq counter (first command is seq 1) and settles what
   * was in flight in the old one from `prev`. `null` = no session (link lost): sent commands
   * become unconfirmed, unsent ones fail.
   */
  setSession(ctx: CmdContext | null, prev: Prev | null = null): void {
    if (ctx && this.ctx && ctx.session === this.ctx.session) {
      this.ctx = ctx;
      return;
    }
    this.ctx = ctx;
    this.seq = 0;
    this.pending.clear();
    this.lateWrites.clear();
    for (const e of [...this.all]) {
      if (e.done) continue;
      if (!e.sent) e.finish({ ok: false, code: "session_changed" });
      else if (ctx === null) this.unconfirm(e, true);
      else this.settle(e, prev);
    }
  }

  get hasSession(): boolean {
    return this.ctx !== null;
  }

  /** Number of requests that have no trustworthy answer yet. */
  get unconfirmedCount(): number {
    let n = 0;
    for (const e of this.all) if (e.state === "unconfirmed" && !e.done) n++;
    return n;
  }

  /**
   * A reply of the current session. Returns true when it matched a request. `re:0` never
   * matches here: it names its command by `ref` (handleRef).
   */
  handleReply(re: number, result: ReplyResult): boolean {
    const s = this.ctx?.session;
    if (re === 0 || !s) return false;
    const key = `${s}#${re}`;
    const isReplay = !result.ok && result.code === "replay";
    const late = this.lateWrites.get(key);
    if (late) {
      // Already shown as "delivered, result unknown" because a duplicate was answered `replay`.
      // The genuine reply (or a failure other than replay/timeout) replaces that; nothing else does.
      if (isReplay || (!result.ok && result.code === "timeout")) return true;
      this.lateWrites.delete(key);
      try {
        late.onLate?.(result);
      } catch {
        /* a view bug must not stop the router */
      }
      return true;
    }
    const e = this.pending.get(key);
    if (!e || !e.sent) return false;
    if (isReplay) {
      // `replay` answers a DUPLICATE of this seq (a relay forwarded the frame twice), so the
      // command was accepted earlier. A write is delivered with its result unknown, and its text
      // must never be sent again; the genuine reply may still follow (lateWrites). A read just
      // keeps waiting for the real answer.
      if (isRead(e.cmd)) return true;
      this.lateWrites.set(key, { onLate: e.hooks?.onLate });
      e.finish({ ok: false, code: DELIVERED_UNKNOWN });
      return true;
    }
    // The desktop accepted the command and the app was still working on it after 5 s: for a
    // write that is "delivered, result unknown" (the page may yet have typed it), never "no
    // answer", which would invite sending it a second time.
    if (!result.ok && result.code === "timeout" && !isRead(e.cmd)) {
      e.finish({ ok: false, code: DELIVERED_UNKNOWN });
      return true;
    }
    e.finish(result);
    return true;
  }

  /**
   * A `re:0` failure: acts only when `ref` names a command in flight, and then only by treating
   * that command's outcome as unknown (the desktop could not read it, so nothing was run).
   */
  handleRef(ref: string | null): boolean {
    if (!ref) return false;
    for (const e of this.all) {
      if (!e.done && e.sent && e.ref === ref) {
        this.unconfirm(e, true);
        return true;
      }
    }
    return false;
  }

  /** A plaintext server frame (`desktop_offline`, `error`, ...): every command on the wire is unknown. */
  markUnknown(): void {
    for (const e of [...this.all]) if (!e.done && e.sent) this.unconfirm(e, true);
  }

  request(cmd: Cmd, hooks?: RequestHooks): Promise<ReplyResult> {
    return this.issue(cmd, hooks, false);
  }

  private issue(cmd: Cmd, hooks: RequestHooks | undefined, retried: boolean): Promise<ReplyResult> {
    const ctx = this.ctx;
    if (!ctx) return Promise.resolve({ ok: false, code: "no_session" });
    const bad = validateCmd(cmd);
    if (bad) return Promise.resolve({ ok: false, code: bad });

    return new Promise<ReplyResult>((resolve) => {
      const entry: Entry = {
        cmd,
        hooks,
        retried,
        session: ctx.session,
        seq: 0,
        ref: "",
        state: "queued",
        sent: false,
        done: false,
        timer: null,
        resolve,
        finish: (r) => {
          if (entry.done) return;
          entry.done = true;
          this.clearTimer(entry.timer);
          if (entry.seq) this.pending.delete(`${entry.session}#${entry.seq}`);
          this.all.delete(entry);
          resolve(r);
        },
      };
      this.all.add(entry);
      entry.timer = this.setTimer(() => this.unconfirm(entry, true), this.timeoutMs);

      // Serialised so frames leave in seq order even though signing is async.
      this.chain = this.chain.then(async () => {
        if (entry.done) return;
        if (this.ctx !== ctx) {
          entry.finish({ ok: false, code: "session_changed" });
          return;
        }
        // Seqs are consecutive (PROTOCOL.md 5.1): the desktop ends the session on a skipped
        // number. This chain handles one command at a time, so a number taken for a frame that
        // never leaves is simply given back.
        const seq = ++this.seq;
        entry.seq = seq;
        this.pending.set(`${entry.session}#${seq}`, entry);
        const giveBack = (): void => {
          if (this.ctx === ctx && this.seq === seq) this.seq = seq - 1;
          this.pending.delete(`${entry.session}#${seq}`);
          entry.seq = 0;
        };
        try {
          const plain = buildCmdBody(ctx, seq, (this.deps.tsMs ?? Date.now)(), cmd);
          if (utf8(plain).length > MAX_CMD_BYTES) {
            giveBack();
            entry.finish({ ok: false, code: "bad_request" });
            return;
          }
          const body = await this.deps.seal(plain);
          const signed = cmdSigString(body);
          const sig = await this.deps.sign(signed);
          if (entry.done) {
            giveBack();
            return;
          }
          if (this.ctx !== ctx) {
            giveBack();
            entry.finish({ ok: false, code: "session_changed" });
            return;
          }
          this.deps.send(cmdFrame(body, sig));
          entry.sent = true;
          if (entry.state === "queued") entry.state = "inflight";
          // Needed only to recognise a `re:0` for this command, which cannot come back before a
          // hash of 90 bytes is done; it must not hold up the frame itself or the next one.
          void cmdRef(sig).then((ref) => {
            entry.ref = ref;
          });
        } catch {
          if (!entry.sent) giveBack();
          entry.finish({ ok: false, code: "offline" });
        }
      });
    });
  }

  /**
   * No trustworthy answer: stop waiting for one, start the deadline for settling it, and (when
   * `reopen`) ask the owner for a new session. A request that never left is simply not delivered.
   */
  private unconfirm(e: Entry, reopen: boolean): void {
    if (e.done || e.state === "unconfirmed") return;
    if (!e.sent) {
      e.finish({ ok: false, code: NOT_DELIVERED });
      return;
    }
    e.state = "unconfirmed";
    this.clearTimer(e.timer);
    e.timer = this.setTimer(
      () => e.finish(isRead(e.cmd) ? { ok: false, code: "timeout" } : { ok: false, code: COULD_NOT_CONFIRM }),
      this.confirmMs,
    );
    try {
      e.hooks?.onUnconfirmed?.();
    } catch {
      /* a view bug must not stop the settling */
    }
    if (reopen) this.deps.onUnconfirmed?.();
  }

  /** A new session arrived: settle a command that was sent in an older one. */
  private settle(e: Entry, prev: Prev | null): void {
    if (isRead(e.cmd)) {
      if (e.retried) {
        e.finish({ ok: false, code: "timeout" }); // asked twice without an answer: just no answer
        return;
      }
      // A read is idempotent: ask again in the new session.
      e.done = true;
      this.clearTimer(e.timer);
      this.all.delete(e);
      void this.issue(e.cmd, e.hooks, true).then(e.resolve);
      return;
    }
    if (prev && prev.session !== "" && prev.session === e.session) {
      e.finish({ ok: false, code: e.seq <= prev.seq ? DELIVERED_UNKNOWN : NOT_DELIVERED });
      return;
    }
    // `prev` names another session (or none): it says nothing about this command. Wait out the deadline.
    this.unconfirm(e, false);
  }
}
