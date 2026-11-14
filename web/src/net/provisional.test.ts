// A pairing is provisional until a valid session arrives under its key (PROTOCOL.md 4.7).
import { describe, expect, it } from "vitest";
import { newUuid } from "../protocol/encoding";
import { exportPublicKey, generateDeviceKey } from "../protocol/signing";
import type { Link } from "./connection";
import { awaitFirstSession, PROVISIONAL_MS, promoteIfConfirmed, type Probe } from "./provisional";
import { MAX_PAIRINGS, type Pairing } from "./storage";

async function pairing(desktopId: string, name = ""): Promise<Pairing> {
  const kp = await generateDeviceKey();
  return {
    deviceId: newUuid(),
    desktopId,
    pubkey: await exportPublicKey(kp.publicKey),
    name: "Phone",
    privateKey: kp.privateKey,
    linkKey: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    desktopName: name,
    addedMs: 1,
  };
}

class FakeProbe implements Probe {
  state: { link: Link; session: unknown } = { link: "connecting", session: null };
  started = 0;
  stopped = 0;
  private subs = new Set<() => void>();
  subscribe(fn: () => void): () => void {
    this.subs.add(fn);
    return () => this.subs.delete(fn);
  }
  start(): void {
    this.started++;
  }
  stop(): void {
    this.stopped++;
  }
  set(link: Link, session: unknown = null): void {
    this.state = { link, session };
    for (const f of [...this.subs]) f();
  }
  get listeners(): number {
    return this.subs.size;
  }
}

/** Timers the test fires by hand. */
function manual() {
  const timers: { fn: () => void; ms: number; live: boolean }[] = [];
  return {
    timers,
    setTimer: (fn: () => void, ms: number) => {
      const t = { fn, ms, live: true };
      timers.push(t);
      return t;
    },
    clearTimer: (t: unknown) => {
      (t as { live: boolean }).live = false;
    },
    fire: () => {
      const t = timers.find((x) => x.live)!;
      t.live = false;
      t.fn();
    },
  };
}

describe("awaitFirstSession", () => {
  it("resolves true on the first session, and stops listening", async () => {
    const p = new FakeProbe();
    const m = manual();
    const r = awaitFirstSession(p, PROVISIONAL_MS, m.setTimer, m.clearTimer);
    expect(PROVISIONAL_MS).toBe(20000);
    expect(m.timers[0]!.ms).toBe(20000);
    expect(p.started).toBe(1);
    p.set("online"); // connected, but no session yet: not enough
    p.set("online", { cap: "view" });
    expect(await r).toBe(true);
    expect(p.listeners).toBe(0);
    expect(m.timers[0]!.live).toBe(false);
  });
  it("resolves false at the deadline", async () => {
    const p = new FakeProbe();
    const m = manual();
    const r = awaitFirstSession(p, PROVISIONAL_MS, m.setTimer, m.clearTimer);
    p.set("online");
    m.fire();
    expect(await r).toBe(false);
    expect(p.listeners).toBe(0);
  });
  it("resolves false at once when the server does not know the device (removed)", async () => {
    const p = new FakeProbe();
    const m = manual();
    const r = awaitFirstSession(p, PROVISIONAL_MS, m.setTimer, m.clearTimer);
    p.set("removed");
    expect(await r).toBe(false);
  });
});

describe("promoteIfConfirmed", () => {
  it("promotes on a session: the new pairing replaces that computer's old one, in place", async () => {
    const desk = newUuid();
    const other = await pairing(newUuid(), "Home");
    const old = await pairing(desk, "Office");
    const fresh = await pairing(desk);
    const probe = new FakeProbe();
    const r = promoteIfConfirmed(() => [old, other], fresh, () => probe);
    await new Promise((x) => setTimeout(x, 0));
    probe.set("online", { cap: "prompt" });
    const res = await r;
    expect(res).toMatchObject({ ok: true, replaced: true });
    if (res.ok) expect(res.list).toEqual([fresh, other]);
    expect(probe.stopped).toBe(1);
  });

  it("discards on no session: pair_result alone changes nothing, the old pairing stays", async () => {
    const desk = newUuid();
    const old = await pairing(desk, "Office");
    const list = [old];
    const fresh = await pairing(desk);
    const probe = new FakeProbe();
    const r = promoteIfConfirmed(() => list, fresh, () => probe, 10);
    expect(await r).toEqual({ ok: false, reason: "not_confirmed" });
    expect(list).toEqual([old]);
    expect(list[0]).toBe(old);
    expect(probe.stopped).toBe(1);
  });

  it("discards when the server says it does not know the device", async () => {
    const desk = newUuid();
    const old = await pairing(desk);
    const probe = new FakeProbe();
    const r = promoteIfConfirmed(() => [old], await pairing(desk), () => probe);
    await new Promise((x) => setTimeout(x, 0));
    probe.set("removed");
    expect(await r).toEqual({ ok: false, reason: "not_confirmed" });
  });

  it("refuses a full list or a reused key without connecting at all", async () => {
    const list: Pairing[] = [];
    for (let i = 0; i < MAX_PAIRINGS; i++) list.push(await pairing(newUuid()));
    let made = 0;
    const make = () => (made++, new FakeProbe());
    expect(await promoteIfConfirmed(() => list, await pairing(newUuid()), make)).toEqual({ ok: false, reason: "full" });
    const reused = { ...(await pairing(newUuid())), deviceId: list[0]!.deviceId };
    expect(await promoteIfConfirmed(() => list, reused, make)).toEqual({ ok: false, reason: "reused_key" });
    expect(made).toBe(0);
  });

  it("reads the list again after the wait, so a change made meanwhile is not lost", async () => {
    const desk = newUuid();
    const fresh = await pairing(desk);
    let list: Pairing[] = [];
    const probe = new FakeProbe();
    const r = promoteIfConfirmed(() => list, fresh, () => probe);
    await new Promise((x) => setTimeout(x, 0));
    const added = await pairing(newUuid());
    list = [added]; // another pairing was stored while waiting
    probe.set("online", { cap: "view" });
    const res = await r;
    expect(res.ok && res.list).toEqual([added, fresh]);
  });
});
