// Session rules (PROTOCOL.md 5.1) as pure state: which desktop bodies are accepted, the
// clock offset, and how often the device may ask for a new session. No sockets, no DOM.
import type { Body } from "./messages";

/** A `session` is accepted only this soon after the `open` it answers (PROTOCOL.md 5.1). */
export const OPEN_LIFETIME_MS = 10_000;
/** A body whose `at_ms` is further behind the estimated desktop clock than this is dropped. */
export const MAX_BODY_AGE_MS = 30_000;

/**
 * Accepts or drops decoded desktop -> device bodies.
 *  - `session` only when its `open` equals the most recent nonce sent AND it arrives within
 *    10 s of sending that `open` (the nonce is consumed on use, so a replayed `session` body
 *    cannot reset the counter).
 *  - everything else only with the current session, an `at_ms` not more than 30 s behind the
 *    estimated desktop clock, and an `n` above the last accepted one. A stale body is dropped
 *    before `n` is looked at, so it cannot burn a counter value.
 *  - exception: a failure reply with `re:0` and an empty session. It is accepted without `at_ms`
 *    and never advances `n`; the caller acts on it only when its `ref` names a command in flight
 *    and then only by treating that command's outcome as unknown.
 */
export class SessionTracker {
  private openNonce: string | null = null;
  private openAt = 0;
  private current: string | null = null;
  private lastN = 0;
  private offset = 0;
  /** Bodies dropped by the rules above (a debug indicator only). */
  dropped = 0;

  get session(): string | null {
    return this.current;
  }
  /** Desktop clock minus this device's clock at the moment the session arrived. */
  get offsetMs(): number {
    return this.offset;
  }
  /** True while an `open` is waiting for its `session` and is still inside its 10 s. */
  openLive(localNowMs: number): boolean {
    return this.openNonce !== null && localNowMs - this.openAt <= OPEN_LIFETIME_MS;
  }

  /** Remember the nonce of the `open` that is about to be sent, and when. */
  beginOpen(nonce: string, localNowMs: number): void {
    this.openNonce = nonce;
    this.openAt = localNowMs;
  }

  /** Link lost or desktop gone: nothing is current any more. The clock offset is kept. */
  reset(): void {
    this.openNonce = null;
    this.current = null;
    this.lastN = 0;
  }

  /** The body when it is accepted, null when it is dropped. */
  accept(b: Body, localNowMs: number): Body | null {
    const out = this.decide(b, localNowMs);
    if (!out) this.dropped++;
    return out;
  }

  private decide(b: Body, localNowMs: number): Body | null {
    if (b.k === "session") {
      if (this.openNonce === null || b.open !== this.openNonce || b.nowMs === null) return null;
      const late = localNowMs - this.openAt > OPEN_LIFETIME_MS || localNowMs < this.openAt;
      this.openNonce = null;
      if (late) return null;
      this.current = b.session;
      this.lastN = 0;
      this.offset = b.nowMs - localNowMs;
      return b;
    }
    if (b.k === "reply" && !b.result.ok && b.re === 0 && b.session === "") return b;
    if (this.current === null || b.session !== this.current) return null;
    if (b.atMs === null || localNowMs + this.offset - b.atMs > MAX_BODY_AGE_MS) return null;
    if (b.n === null || b.n <= this.lastN) return null;
    this.lastN = b.n;
    return b;
  }

  /** `ts_ms` for a command: the device's clock plus the recorded offset. */
  tsMs(localNowMs: number): number {
    return localNowMs + this.offset;
  }
}

export const OPEN_MIN_INTERVAL_MS = 1000;
export const OPEN_MAX_INTERVAL_MS = 30000;

/**
 * At most one `open` per second; while opens keep going unanswered the gap doubles up to 30 s,
 * so a relay that never answers (or keeps sending `reopen`) cannot make the device spin.
 */
export class OpenGate {
  private lastAt = -Infinity;
  private failures = 0;
  private pending = false;

  /** Milliseconds to wait before the next `open` may go out (0 = now). */
  waitMs(nowMs: number): number {
    const exp = this.failures + (this.pending ? 1 : 0);
    const gap = Math.min(OPEN_MAX_INTERVAL_MS, OPEN_MIN_INTERVAL_MS * 2 ** Math.min(exp, 10));
    return Math.max(0, this.lastAt + gap - nowMs);
  }

  /** An `open` was sent. A previous one that never got a session counts as a failure. */
  noteSent(nowMs: number): void {
    if (this.pending) this.failures++;
    this.pending = true;
    this.lastAt = nowMs;
  }

  /** A valid `session` arrived. */
  noteSession(): void {
    this.pending = false;
    this.failures = 0;
  }

  /** The socket dropped: an unanswered open is not the desktop's fault. */
  noteDisconnect(): void {
    this.pending = false;
  }
}
