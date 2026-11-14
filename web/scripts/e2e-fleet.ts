// End-to-end DEVICE side, TWO desktops (run by scripts/e2e.ps1 through
// `vitest run --config vitest.e2e.config.ts scripts/e2e-fleet.ts`): one process, the PWA's real
// `Fleet` with two pairings, against one real server and two real desktops (two instances of the
// desktop's live test with different desktop ids and keys, the same setup token).
//
// Env: E2E_URL, E2E_DIR_A, E2E_DIR_B (the desktops' rendezvous directories).
// The in-memory "storage" is the pairing list the PWA keeps (`addPairing` / `removePairing`).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BASE, WS_BASE, rendezvous, sleep, socksFor, until } from "./e2e-common";
import { newUuid } from "../src/protocol/encoding";
import {
  cmdFrame,
  parseListData,
  parsePeekData,
  parseResultData,
  parseServerFrame,
  type ReplyResult,
} from "../src/protocol/messages";
import { aadD2P, aadP2D, deriveLinkKey, generateAgreementKey, open, seal } from "../src/protocol/seal";
import { cmdSigString, exportPublicKey, generateDeviceKey, signString } from "../src/protocol/signing";
import { Fleet } from "../src/net/fleet";
import { Remote } from "../src/net/remote";
import { parsePairFragment, pairWsUrl, runPairing } from "../src/net/pairing";
import { promoteIfConfirmed } from "../src/net/provisional";
import { addPairing, removePairing, type Pairing } from "../src/net/storage";

const DIR_A = process.env.E2E_DIR_A ?? "";
const DIR_B = process.env.E2E_DIR_B ?? "";
if (!DIR_A || !DIR_B) throw new Error("E2E_DIR_A and E2E_DIR_B are required");
const A = rendezvous(DIR_A);
const B = rendezvous(DIR_B);
const SHARED = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const ONLY_A = "a0a0a0a0-a0a0-4a0a-8a0a-a0a0a0a0a0a0";
const ONLY_B = "b0b0b0b0-b0b0-4b0b-8b0b-b0b0b0b0b0b0";

let list: Pairing[] = [];
let pa: Pairing;
let pb: Pairing;
let fleet: Fleet;
let ra: Remote;
let rb: Remote;

afterAll(() => fleet?.stopAll());

const ok = (r: ReplyResult): unknown => {
  expect(r, JSON.stringify(r)).toMatchObject({ ok: true });
  return (r as { ok: true; data: unknown }).data;
};

async function pairWith(dir: string, who: ReturnType<typeof rendezvous>, name: string): Promise<Pairing> {
  await until("pair-url.txt", () => existsSync(join(dir, "pair-url.txt")), 60000);
  const url = readFileSync(join(dir, "pair-url.txt"), "utf8").trim();
  const link = parsePairFragment(new URL(url).hash);
  expect(link, "the pairing URL fragment parses").not.toBeNull();
  expect(url.startsWith(BASE + "/#pair=")).toBe(true);
  const kp = await generateDeviceKey();
  const pubkey = await exportPublicKey(kp.publicKey);
  const deviceId = newUuid();
  // The key agreement: a fresh ek, K from (ek, dk, code). The ek private key is not kept.
  const agree = await generateAgreementKey();
  const ek = await exportPublicKey(agree.publicKey);
  const linkKey = await deriveLinkKey({
    ekPrivate: agree.privateKey,
    ek,
    dk: link!.dk,
    code: link!.code,
    desktopId: link!.desktopId,
    deviceId,
    pubkey,
  });
  const checks: string[] = [];
  const outcome = await runPairing({
    url: pairWsUrl(new URL(BASE)),
    link: link!,
    deviceId,
    pubkey,
    ek,
    name,
    privateKey: kp.privateKey,
    linkKey,
    onSent: () => {},
    // The number comes from the sealed pair_challenge; the fake desktop "types" what is in this file.
    onCheck: (digits) => {
      checks.push(digits);
      who.touch("pair-check-device.txt", digits);
    },
    timeoutMs: 60000,
  });
  expect(outcome).toBe("ok");
  expect(checks.at(-1), `a check number arrived for ${who.dir}`).toMatch(/^\d{6}$/);
  // Provisional: the pairing counts once the desktop opens a session under the new key.
  const promoted = await promoteIfConfirmed(
    () => [],
    { deviceId, desktopId: link!.desktopId, pubkey, name, privateKey: kp.privateKey, linkKey, desktopName: "", addedMs: Date.now() },
    (p) => new Remote(p, `${WS_BASE}/ws/device`),
    30000,
  );
  expect(promoted, `${who.dir}: the first session under the new key`).toMatchObject({ ok: true });
  return {
    deviceId,
    desktopId: link!.desktopId,
    pubkey,
    name,
    privateKey: kp.privateKey,
    linkKey,
    desktopName: "",
    addedMs: Date.now(),
  };
}

/** Command frames this pairing's socket sent that open under its own key, with their plaintext. */
async function sentBy(p: Pairing): Promise<{ frame: string; body: string; plain: Record<string, unknown> }[]> {
  const out: { frame: string; body: string; plain: Record<string, unknown> }[] = [];
  for (const s of socksFor(p.deviceId)) {
    for (const frame of s.outgoing) {
      if (!frame.includes('"t":"cmd"')) continue;
      const body = (JSON.parse(frame) as { body: string }).body;
      const t = await open(p.linkKey, aadP2D(p.desktopId, p.deviceId), body);
      if (t !== null) out.push({ frame, body, plain: JSON.parse(t) as Record<string, unknown> });
    }
  }
  return out;
}

/** Sealed bodies the desktop sent this pairing's sockets. */
function msgBodies(p: Pairing): string[] {
  const out: string[] = [];
  for (const s of socksFor(p.deviceId)) {
    for (const text of s.incoming) {
      const f = parseServerFrame(text);
      if (f?.t === "msg") out.push(f.body);
    }
  }
  return out;
}

async function repliesFor(p: Pairing): Promise<{ re: number; ok: boolean; code?: string }[]> {
  const out: { re: number; ok: boolean; code?: string }[] = [];
  for (const body of msgBodies(p)) {
    const t = await open(p.linkKey, aadD2P(p.desktopId, p.deviceId), body);
    const b = t === null ? null : (JSON.parse(t) as { k?: string; re?: number; ok?: boolean; code?: string });
    if (b?.k === "reply" && typeof b.re === "number" && typeof b.ok === "boolean") out.push({ re: b.re, ok: b.ok, code: b.code });
  }
  return out;
}

const online = (r: Remote) => r.state.link === "online" && r.state.desktopOnline && r.state.session !== null;

describe("one device, two desktops, one server", () => {
  it("pairs with both desktops (check number from the sealed challenge, then a first session) into one pairing list", async () => {
    pa = await pairWith(DIR_A, A, "E2E phone (A)");
    pb = await pairWith(DIR_B, B, "E2E phone (B)");
    expect(pa.desktopId).not.toBe(pb.desktopId);
    for (const p of [pa, pb]) {
      const r = addPairing(list, p);
      expect(r.ok).toBe(true);
      if (r.ok) list = r.list;
    }
    // Keys belong to one desktop: the same device id for the other desktop is refused.
    expect(addPairing(list, { ...pb, desktopId: newUuid() })).toEqual({ ok: false, reason: "reused_key" });
    expect(list.map((p) => p.desktopId)).toEqual([pa.desktopId, pb.desktopId]);
  });

  it("runs one Remote per pairing and gets a session from each desktop", async () => {
    fleet = new Fleet({ make: (p) => new Remote(p, `${WS_BASE}/ws/device`) });
    fleet.sync(list);
    ra = fleet.get(pa.desktopId)!.remote;
    rb = fleet.get(pb.desktopId)!.remote;
    expect(fleet.size).toBe(2);
    await until("both online with a session", () => online(ra) && online(rb), 30000);
    expect(ra.state.session).toMatchObject({ cap: "prompt", name: "Desk A" });
    expect(rb.state.session).toMatchObject({ cap: "prompt", name: "Desk B" });
    expect(ra.sessionId).not.toBe(rb.sessionId);
    A.touch("d.session");
    B.touch("d.session");
  });

  it("lists only each desktop's own panes, with one uuid on both and a different title", async () => {
    const la = parseListData(ok(await ra.request({ op: "list" })))!;
    const lb = parseListData(ok(await rb.request({ op: "list" })))!;
    expect(la.map((p) => p.pane).sort()).toEqual([SHARED, ONLY_A].sort());
    expect(lb.map((p) => p.pane).sort()).toEqual([SHARED, ONLY_B].sort());
    const title = (l: typeof la, id: string) => l.find((p) => p.pane === id)!.title;
    expect(title(la, SHARED)).toBe("Shared as seen from A");
    expect(title(lb, SHARED)).toBe("Shared as seen from B");
    expect(title(la, ONLY_A)).toBe("Alpha only");
    expect(title(lb, ONLY_B)).toBe("Beta only");
    // The live state of each Remote holds the same and nothing of the other.
    await until("both automatic lists", () => ra.state.panes && rb.state.panes, 10000);
    expect(ra.state.panes!.map((p) => p.title).sort()).toEqual(["Alpha only", "Shared as seen from A"]);
    expect(rb.state.panes!.map((p) => p.title).sort()).toEqual(["Beta only", "Shared as seen from B"]);
  });

  it("sends a command to one desktop only: the same pane uuid reaches the addressed page", async () => {
    const pk = async (r: Remote) => parsePeekData(ok(await r.request({ op: "peek", pane: SHARED, lines: 80 })))!;
    // Exactly one peek each: the desktops count them at the end.
    const peekA = await pk(ra);
    const peekB = await pk(rb);
    expect(peekA.lines[0]).toBe("$ claude (A)");
    expect(peekA.menuId).toBe("e2e-menu-A");
    expect(peekB.lines[0]).toBe("$ claude (B)");
    expect(peekB.menuId).toBe("e2e-menu-B");
    const sent = (r: ReplyResult) => parseResultData(ok(r), ["sent"]);
    expect(sent(await ra.request({ op: "prompt", pane: SHARED, text: "to-A", queue: false }))).toBe("sent");
    expect(sent(await rb.request({ op: "prompt", pane: ONLY_B, text: "to-B", queue: false }))).toBe("sent");
  });

  it("cannot open a body sealed for one pairing with the other's key", async () => {
    const fromA = (await sentBy(pa)).filter((c) => c.plain.k === "cmd").pop()!;
    expect(await open(pa.linkKey, aadP2D(pa.desktopId, pa.deviceId), fromA.body)).not.toBeNull();
    expect(await open(pb.linkKey, aadP2D(pb.desktopId, pb.deviceId), fromA.body), "B's key").toBeNull();
    expect(await open(pb.linkKey, aadP2D(pa.desktopId, pa.deviceId), fromA.body), "B's key, A's context").toBeNull();
    expect(await open(pa.linkKey, aadP2D(pb.desktopId, pb.deviceId), fromA.body), "A's key, B's context").toBeNull();
    // And the other way round, on what each desktop sent.
    for (const body of msgBodies(pa)) {
      expect(await open(pa.linkKey, aadD2P(pa.desktopId, pa.deviceId), body)).not.toBeNull();
      expect(await open(pb.linkKey, aadD2P(pb.desktopId, pb.deviceId), body)).toBeNull();
    }
    for (const body of msgBodies(pb)) {
      expect(await open(pb.linkKey, aadD2P(pb.desktopId, pb.deviceId), body)).not.toBeNull();
      expect(await open(pa.linkKey, aadD2P(pa.desktopId, pa.deviceId), body)).toBeNull();
    }
  });

  it("drops frames carried to the wrong desktop or sealed for the wrong one", async () => {
    // 1. A's genuine, signed, still-unreplayed-looking prompt frame, thrown into B's connection.
    const toA = (await sentBy(pa)).find((c) => (c.plain.cmd as { text?: string } | undefined)?.text === "to-A")!;
    expect(rb.sendFrame(toA.frame)).toBe(true);
    // 2. B's device signs a body sealed for A's pairing (right for A, meaningless to B's desktop).
    const sealedForA = await seal(
      pa.linkKey,
      aadP2D(pa.desktopId, pa.deviceId),
      JSON.stringify({
        k: "cmd", desktop_id: pa.desktopId, device_id: pa.deviceId, session: ra.sessionId, seq: 500,
        ts_ms: Date.now(), cmd: { op: "prompt", pane: SHARED, text: "cross-B-to-A", queue: false },
      }),
    );
    expect(rb.sendFrame(cmdFrame(sealedForA, await signString(pb.privateKey, cmdSigString(sealedForA))))).toBe(true);
    // 3. And A's device signs a body sealed for B's pairing.
    const sealedForB = await seal(
      pb.linkKey,
      aadP2D(pb.desktopId, pb.deviceId),
      JSON.stringify({
        k: "cmd", desktop_id: pb.desktopId, device_id: pb.deviceId, session: rb.sessionId, seq: 500,
        ts_ms: Date.now(), cmd: { op: "prompt", pane: ONLY_B, text: "cross-A-to-B", queue: false },
      }),
    );
    expect(ra.sendFrame(cmdFrame(sealedForB, await signString(pa.privateKey, cmdSigString(sealedForB))))).toBe(true);
    await sleep(2500);
    // Dropped silently or answered `bad_sig` (re:0); never executed (the desktops count what ran).
    for (const p of [pa, pb]) {
      for (const x of await repliesFor(p)) {
        if (!x.ok) expect(x, JSON.stringify(x)).toEqual({ re: 0, ok: false, code: "bad_sig" });
      }
    }
    expect((await repliesFor(pb)).some((x) => x.code === "bad_sig"), "B answered the foreign frame sealed bad_sig").toBe(true);
    // Both links still work.
    ok(await ra.request({ op: "list" }));
    ok(await rb.request({ op: "list" }));
  });

  it("keeps B answering promptly while A is stopped", async () => {
    A.touch("d.stop");
    await A.fromDesktop("h.stopped");
    await until("A to show offline", () => ra.state.link === "online" && !ra.state.desktopOnline, 20000);
    const t0 = Date.now();
    const gone = await ra.request({ op: "list" });
    expect(gone.ok).toBe(false);
    expect(Date.now() - t0, "a command to the stopped desktop fails fast").toBeLessThan(3000);
    for (let i = 0; i < 10; i++) {
      const t = Date.now();
      ok(await rb.request({ op: "list" }));
      expect(Date.now() - t, `B's list ${i} while A is stopped`).toBeLessThan(1500);
    }
    expect(online(rb)).toBe(true);
    expect(parseResultData(ok(await rb.request({ op: "prompt", pane: ONLY_B, text: "while-A-stopped", queue: false })), ["sent"])).toBe("sent");
  });

  it("brings A back with its own panes when it starts again", async () => {
    A.touch("d.start");
    await A.fromDesktop("h.started");
    await until("A online again", () => online(ra), 30000);
    const la = parseListData(ok(await ra.request({ op: "list" })))!;
    expect(la.map((p) => p.pane).sort()).toEqual([SHARED, ONLY_A].sort());
    expect(online(rb)).toBe(true);
    // Nothing legitimate was ignored on either connection, so nothing crossed over.
    expect(ra.state.dropped).toBe(0);
    expect(rb.state.dropped).toBe(0);
  });

  it("removing the pairing with A leaves B fully working", async () => {
    A.touch("d.remove");
    await A.fromDesktop("h.removed");
    await until("A removed", () => ra.state.link === "removed", 30000);
    const errors = socksFor(pa.deviceId)
      .flatMap((s) => s.incoming)
      .map((t) => parseServerFrame(t))
      .filter((f): f is { t: "error"; code: string } => f?.t === "error");
    expect(errors.some((e) => e.code === "unknown_device"), "A's reconnect was answered unknown_device").toBe(true);
    // What the PWA does next: forget the pairing.
    list = removePairing(list, pa.desktopId);
    fleet.sync(list);
    expect(fleet.size).toBe(1);
    expect(fleet.get(pa.desktopId)).toBeUndefined();
    expect(online(rb)).toBe(true);
    const lb = parseListData(ok(await rb.request({ op: "list" })))!;
    expect(lb.map((p) => p.pane).sort()).toEqual([SHARED, ONLY_B].sort());
    A.touch("d.done");
    B.touch("d.done");
  });
});
