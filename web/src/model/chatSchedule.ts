// Which `chat` request goes out next. Pure: the view only carries it out.
// One older step may be pending (a tap, or the next step of a chain through empty stretches); it has
// priority over the forward poll, survives the rate limit and any poll in flight, and is never queued
// twice.

export const MAX_OLDER_STEPS = 5;

export interface Sched {
  /** An older step is wanted and not yet sent. */
  pendingOlder: boolean;
  /** Steps of the current chain already sent beyond the first. */
  steps: number;
  /** A chain is running (from the tap until it ends), pending or in flight. */
  active: boolean;
}

export const idle: Sched = { pendingOlder: false, steps: 0, active: false };

export interface Env {
  inflight: boolean;
  /** Milliseconds until the rate limit lets a command go; 0 when it may go now. */
  throttleMs: number;
  /** A forward poll is wanted (the interval fired, or `newer` asks for the next page). */
  pollWanted: boolean;
}

/**
 * Milliseconds until another command may go under a limit of `max` per second; 0 when it may go now.
 * `sentAt` holds send times (from a monotonic clock) and is pruned in place. An entry from the
 * "future" (the clock went backwards) counts as expired, so the limit can never stall.
 */
export function throttleMs(sentAt: number[], now: number, max: number): number {
  while (sentAt.length && (now - sentAt[0]! >= 1000 || sentAt[0]! > now)) sentAt.shift();
  return sentAt.length >= max ? sentAt[0]! + 1000 - now + 5 : 0;
}

export type Decision = { do: "older" } | { do: "poll" } | { do: "wait"; ms: number } | { do: "none" };

/** A tap on "load older": one pending step, however many taps arrive. */
export const tap = (s: Sched): Sched => (s.active ? s : { pendingOlder: true, steps: 0, active: true });

export function decide(s: Sched, env: Env): Decision {
  if (env.inflight) return { do: "none" }; // asked again when the reply settles
  if (!s.pendingOlder && !env.pollWanted) return { do: "none" };
  if (env.throttleMs > 0) return { do: "wait", ms: env.throttleMs };
  return s.pendingOlder ? { do: "older" } : { do: "poll" };
}

/** The pending step was sent. */
export const sent = (s: Sched): Sched => ({ ...s, pendingOlder: false });

/** An older reply arrived: continue through an empty-but-moving stretch, else the chain ends. */
export function afterOlderReply(s: Sched, c: { olderEmpty: boolean; older: boolean }): Sched {
  if (c.olderEmpty && c.older && s.steps < MAX_OLDER_STEPS) return { pendingOlder: true, steps: s.steps + 1, active: true };
  return idle;
}
