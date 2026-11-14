// A new pairing is PROVISIONAL (PROTOCOL.md 4.7): `pair_result ok:true` is plaintext from the
// server and proves nothing. The new pairing replaces an earlier one for the same computer only
// after the first valid sealed `session` arrives under the new link key within 20 s. Until then
// it lives in memory, outside the Fleet, so the working pairing keeps its connection untouched.
import { addPairing, type AddResult, type Pairing } from "./storage";
import type { Link } from "./connection";

export const PROVISIONAL_MS = 20000;

/** The part of a Remote the confirmation needs (a test double can stand in). */
export interface Probe {
  state: { link: Link; session: unknown };
  subscribe: (fn: () => void) => () => void;
  start: () => void;
  stop: () => void;
}

export type PromoteResult = AddResult | { ok: false; reason: "not_confirmed" };

/** Resolves true on the first session, false at the deadline or when the server forgets the device. */
export function awaitFirstSession(
  probe: Probe,
  ms = PROVISIONAL_MS,
  setTimer: (fn: () => void, ms: number) => unknown = (fn, t) => setTimeout(fn, t),
  clearTimer: (t: unknown) => void = (t) => clearTimeout(t as ReturnType<typeof setTimeout>),
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let finished = false;
    let unsub: () => void = () => undefined;
    const finish = (ok: boolean): void => {
      if (finished) return;
      finished = true;
      clearTimer(timer);
      unsub();
      resolve(ok);
    };
    const timer = setTimer(() => finish(false), ms);
    unsub = probe.subscribe(() => {
      if (probe.state.session !== null && probe.state.link === "online") finish(true);
      else if (probe.state.link === "removed") finish(false); // the server does not know this device
    });
    probe.start();
  });
}

/**
 * Connects the new pairing on its own, and only when a session arrives in time adds it to the
 * list (replacing that computer's earlier pairing in place). Otherwise the list is untouched.
 * `getList` is read again after the wait, so a change made meanwhile is not overwritten.
 */
export async function promoteIfConfirmed(
  getList: () => readonly Pairing[],
  p: Pairing,
  make: (p: Pairing) => Probe,
  ms = PROVISIONAL_MS,
): Promise<PromoteResult> {
  const early = addPairing(getList(), p);
  if (!early.ok) return early; // full, or a key already used for another computer: no need to connect
  const probe = make(p);
  let confirmed = false;
  try {
    confirmed = await awaitFirstSession(probe, ms);
  } finally {
    probe.stop();
  }
  if (!confirmed) return { ok: false, reason: "not_confirmed" };
  return addPairing(getList(), p);
}
