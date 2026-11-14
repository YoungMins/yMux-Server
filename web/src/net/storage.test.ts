import { describe, expect, it } from "vitest";
import { newUuid } from "../protocol/encoding";
import { exportPublicKey, generateDeviceKey } from "../protocol/signing";
import { addPairing, interpretStored, MAX_PAIRINGS, removePairing, type Identity, type Pairing } from "./storage";

async function identity(desktopId: string): Promise<Identity> {
  const kp = await generateDeviceKey();
  const linkKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return {
    deviceId: newUuid(),
    desktopId,
    pubkey: await exportPublicKey(kp.publicKey),
    name: "Phone",
    privateKey: kp.privateKey,
    linkKey,
  };
}
const pairing = async (desktopId: string, desktopName = ""): Promise<Pairing> => ({
  ...(await identity(desktopId)),
  desktopName,
  addedMs: 1000,
});

describe("storage migration", () => {
  it("turns the single stored identity into a one-element list", async () => {
    const id = await identity(newUuid());
    const s = interpretStored(undefined, id);
    expect(s.migrated).toBe(true);
    expect(s.legacy).toBe(false);
    expect(s.pairings).toHaveLength(1);
    expect(s.pairings[0]).toMatchObject({ desktopId: id.desktopId, deviceId: id.deviceId, desktopName: "" });
    expect(s.pairings[0]!.addedMs).toBeGreaterThan(0);
    expect(s.pairings[0]!.privateKey).toBe(id.privateKey);
  });
  it("an identity without a link key stays unpaired (legacy)", async () => {
    const { linkKey: _drop, ...old } = await identity(newUuid());
    void _drop;
    expect(interpretStored(undefined, old)).toEqual({ pairings: [], legacy: true, migrated: false });
  });
  it("the list wins over an old single record and is cleaned", async () => {
    const a = await pairing(newUuid());
    const dup = { ...a, deviceId: newUuid() };
    const s = interpretStored([a, dup, { junk: 1 }, null], await identity(newUuid()));
    expect(s.migrated).toBe(false);
    expect(s.pairings).toEqual([a]);
  });
  it("nothing stored means nothing paired", () => {
    expect(interpretStored(undefined, undefined)).toEqual({ pairings: [], legacy: false, migrated: false });
  });
});

describe("adding pairings", () => {
  it("a new desktop is added without asking", async () => {
    const a = await pairing(newUuid());
    const b = await pairing(newUuid());
    const r = addPairing([a], b);
    expect(r).toMatchObject({ ok: true, replaced: false });
    expect(r.ok && r.list).toEqual([a, b]);
  });
  it("the same desktop replaces only its own pairing, in place", async () => {
    const a = await pairing(newUuid());
    const b = await pairing(newUuid());
    const c = await pairing(newUuid());
    const a2 = { ...(await identity(a.desktopId)), desktopName: "A", addedMs: 5 };
    const r = addPairing([a, b, c], a2);
    expect(r.ok && r.replaced).toBe(true);
    expect(r.ok && r.list).toEqual([a2, b, c]);
  });
  it("stops at the cap but still allows replacing", async () => {
    const list: Pairing[] = [];
    for (let i = 0; i < MAX_PAIRINGS; i++) list.push(await pairing(newUuid()));
    expect(addPairing(list, await pairing(newUuid()))).toEqual({ ok: false, reason: "full" });
    const again = await pairing(list[3]!.desktopId);
    expect(addPairing(list, again)).toMatchObject({ ok: true, replaced: true });
  });
  it("never reuses a device id or key across desktops", async () => {
    const a = await pairing(newUuid());
    const other = await pairing(newUuid());
    expect(addPairing([a], { ...other, deviceId: a.deviceId })).toEqual({ ok: false, reason: "reused_key" });
    expect(addPairing([a], { ...other, pubkey: a.pubkey })).toEqual({ ok: false, reason: "reused_key" });
  });
});

describe("removing pairings", () => {
  it("removing one leaves the other intact", async () => {
    const a = await pairing(newUuid());
    const b = await pairing(newUuid());
    const left = removePairing([a, b], a.desktopId);
    expect(left).toEqual([b]);
    expect(left[0]!.privateKey).toBe(b.privateKey);
    expect(removePairing([a], newUuid())).toEqual([a]);
  });
});
