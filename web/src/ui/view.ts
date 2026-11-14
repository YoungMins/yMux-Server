import type { Fleet } from "../net/fleet";
import type { AddResult, Pairing } from "../net/storage";

export interface View {
  el: HTMLElement;
  destroy?: () => void;
}

export type AddOutcome = AddResult | { ok: false; reason: "save" | "not_confirmed" };

export interface Ctx {
  fleet: Fleet;
  /** A pairing from before link keys existed was found and nothing else is paired. */
  legacy: boolean;
  /** Hash navigation. */
  go: (hash: string) => void;
  /**
   * Confirms a provisional pairing (a first valid session within 20 s), then stores and starts it
   * (adds a computer, or replaces that same computer's pairing). Unconfirmed: nothing changes.
   */
  addPairing: (p: Pairing) => Promise<AddOutcome>;
  /** Deletes one pairing's keys here, tells its server to drop the push subscription, closes it. */
  removePairing: (desktopId: string) => Promise<void>;
  /** Deletes every pairing. */
  removeAll: () => Promise<void>;
}
