// One Remote (connection, session, router, state) per pairing. Remotes never share anything:
// every body is opened with its own link key and lands in its own state, so one computer being
// offline or misbehaving cannot stall or feed another.
import { pushUnsubscribeFrame } from "../protocol/messages";
import { isOnline, Remote } from "./remote";
import type { Pairing } from "./storage";

export interface FleetEntry {
  pairing: Pairing;
  remote: Remote;
}

export interface FleetOptions {
  make?: (p: Pairing) => Remote;
  /** The connection of this pairing became ready (every connect and reconnect). */
  onReady?: (remote: Remote, p: Pairing) => void;
  /** A computer told us its name and it differs from the stored one (persist the list). */
  onName?: (desktopId: string, name: string) => void;
}

interface Slot extends FleetEntry {
  unsub: () => void;
}

export class Fleet {
  private slots = new Map<string, Slot>();
  private listeners = new Set<() => void>();

  constructor(private readonly o: FleetOptions = {}) {}

  get size(): number {
    return this.slots.size;
  }
  entries(): FleetEntry[] {
    return [...this.slots.values()].map(({ pairing, remote }) => ({ pairing, remote }));
  }
  pairings(): Pairing[] {
    return [...this.slots.values()].map((s) => s.pairing);
  }
  remotes(): Remote[] {
    return [...this.slots.values()].map((s) => s.remote);
  }
  get(desktopId: string): FleetEntry | undefined {
    const s = this.slots.get(desktopId);
    return s ? { pairing: s.pairing, remote: s.remote } : undefined;
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** Make the running connections match this list (same order). Starts new ones, stops gone ones. */
  sync(pairings: readonly Pairing[]): void {
    const next = new Map<string, Slot>();
    for (const p of pairings) {
      const old = this.slots.get(p.desktopId);
      if (old && old.pairing.deviceId === p.deviceId) {
        old.pairing = p;
        next.set(p.desktopId, old);
        continue;
      }
      next.set(p.desktopId, this.open(p));
    }
    // Gone, or the same computer paired again (the old device identity is dropped).
    const kept = new Set(next.values());
    for (const s of this.slots.values()) if (!kept.has(s)) this.close(s, true);
    this.slots = next;
    this.notify();
  }

  /** Drop one pairing's connection (and tell the server to forget its push subscription). */
  remove(desktopId: string): void {
    const s = this.slots.get(desktopId);
    if (!s) return;
    this.close(s, true);
    this.slots.delete(desktopId);
    this.notify();
  }

  stopAll(): void {
    for (const s of this.slots.values()) this.close(s, false);
    this.slots.clear();
    this.notify();
  }

  reconnectAll(): void {
    for (const s of this.slots.values()) s.remote.reconnectNow();
  }

  /** The page is visible again: refresh what is up, reconnect what is not. */
  wake(): void {
    for (const { remote } of this.slots.values()) {
      if (isOnline(remote.state)) void remote.refreshList();
      else if (remote.state.link !== "removed") remote.reconnectNow();
    }
  }

  private open(p: Pairing): Slot {
    const remote = this.o.make ? this.o.make(p) : new Remote(p);
    const slot: Slot = { pairing: p, remote, unsub: () => undefined };
    remote.onReady = () => this.o.onReady?.(remote, slot.pairing);
    slot.unsub = remote.subscribe(() => {
      const n = remote.state.session?.name;
      if (n && n !== slot.pairing.desktopName) {
        slot.pairing = { ...slot.pairing, desktopName: n };
        this.o.onName?.(slot.pairing.desktopId, n);
      }
      this.notify();
    });
    remote.start();
    return slot;
  }

  private close(s: Slot, unsubscribePush: boolean): void {
    s.unsub();
    if (unsubscribePush) s.remote.sendFrame(pushUnsubscribeFrame());
    s.remote.stop();
  }

  private notify(): void {
    for (const fn of [...this.listeners]) {
      try {
        fn();
      } catch {
        /* a view bug must not break a socket */
      }
    }
  }
}
