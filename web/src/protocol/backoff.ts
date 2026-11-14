// PROTOCOL.md section 7: 1 s doubling to 60 s, with jitter.
export const BACKOFF_MIN_MS = 1000;
export const BACKOFF_MAX_MS = 60000;

export function backoffDelay(attempt: number, rand: () => number = Math.random): number {
  const n = Number.isFinite(attempt) ? Math.max(0, Math.min(10, Math.floor(attempt))) : 0;
  const base = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** n);
  const jittered = base * (0.75 + 0.5 * rand());
  return Math.round(Math.min(BACKOFF_MAX_MS, jittered));
}
