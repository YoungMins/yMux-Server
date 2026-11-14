// Real Remotes (real keys, real sealing) on a fake WebSocket: what one desktop's connection
// delivers can only ever land in that desktop's state.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolvePaneHash } from "../model/route";
import { newUuid } from "../protocol/encoding";
import { pushSubscribeFrame, pushUnsubscribeFrame, type PushSub } from "../protocol/messages";
import { aadD2P, aadP2D, open, seal } from "../protocol/seal";
import { exportPublicKey, generateDeviceKey } from "../protocol/signing";
import { Fleet } from "./fleet";
import { fanOut, resyncPush } from "./push";
import { Remote } from "./remote";
import type { Pairing } from "./storage";

class FakeWS {
  static all: FakeWS[] = [];
  static OPEN = 1;
  readyState = 1;
  sent: string[] = [];
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(readonly url: string) {
    FakeWS.all.push(this);
  }
  send(s: string): void {
    this.sent.push(s);
  }
  close(): void {
    this.closed = true;
  }
  say(o: unknown): void {
    this.onmessage?.({ data: JSON.stringify(o) });
  }
}

const socketsOf = (p: Pairing): FakeWS[] => FakeWS.all.filter((w) => w.url.includes(p.desktopId));
const lastSocket = (p: Pairing): FakeWS => socketsOf(p).at(-1)!;

async function makePairing(name: string): Promise<Pairing> {
  const kp = await generateDeviceKey();
  return {
    deviceId: newUuid(),
    desktopId: newUuid(),
    pubkey: await exportPublicKey(kp.publicKey),
    name: "Phone",
    privateKey: kp.privateKey,
    linkKey: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    desktopName: name,
    addedMs: 1,
  };
}

const makeFleet = (extra: ConstructorParameters<typeof Fleet>[0] = {}): Fleet =>
  new Fleet({ make: (p) => new Remote(p, `ws://test/${p.desktopId}/ws/device`), ...extra });

/** Plays the server and desktop side of one connection. */
class Peer {
  n = 0;
  session = "";
  constructor(readonly p: Pairing) {}

  async sealed(plain: object): Promise<string> {
    return seal(this.p.linkKey, aadD2P(this.p.desktopId, this.p.deviceId), JSON.stringify(plain));
  }
  async body(ws: FakeWS, plain: object): Promise<void> {
    ws.say({ t: "msg", body: await this.sealed(plain) });
  }
  /** Handshake, then answer the device's `open` with a session. */
  async connect(ws: FakeWS, cap = "prompt", name = "PC"): Promise<void> {
    ws.say({ t: "challenge", nonce: "abc" });
    await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
    ws.say({ t: "ready", desktop_id: this.p.desktopId, desktop_online: true });
    const cmds = (): string[] => ws.sent.filter((f) => f.includes('"t":"cmd"'));
    await vi.waitFor(() => expect(cmds()).toHaveLength(1));
    const frame = JSON.parse(cmds()[0]!) as { body: string };
    const plain = await open(this.p.linkKey, aadP2D(this.p.desktopId, this.p.deviceId), frame.body);
    const { nonce } = JSON.parse(plain!) as { nonce: string };
    this.session = `S-${this.p.desktopId.slice(0, 4)}`;
    this.n = 0;
    await this.body(ws, { k: "session", open: nonce, session: this.session, cap, name, now_ms: Date.now(), v: 1 });
    // The session is accepted once the device asks for the list (a list that was still unanswered
    // when the link dropped is asked again as well).
    await vi.waitFor(() => expect(cmds().length).toBeGreaterThanOrEqual(2));
  }
  panes(ws: FakeWS, panes: object[]): Promise<void> {
    return this.body(ws, { k: "panes", panes, session: this.session, n: ++this.n, at_ms: Date.now() });
  }
}

const PANE = "11111111-1111-4111-8111-111111111111";
const mk = (title: string, status = "idle") => ({ pane: PANE, ws: "w", title, kind: "claude", status, since_ms: 0, queued: 0 });

beforeEach(() => {
  FakeWS.all = [];
  vi.stubGlobal("WebSocket", FakeWS);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("one connection per pairing", () => {
  it("starts one socket per pairing and keeps them independent", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet();
    fleet.sync([a, b]);
    expect(FakeWS.all).toHaveLength(2);
    expect(socketsOf(a)).toHaveLength(1);
    expect(socketsOf(b)).toHaveLength(1);
    fleet.stopAll();
  });

  it("routes by (desktop, pane): two desktops with the SAME pane uuid", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet();
    fleet.sync([a, b]);
    const [pa, pb] = [new Peer(a), new Peer(b)];
    await pa.connect(lastSocket(a));
    await pb.connect(lastSocket(b));
    await pa.panes(lastSocket(a), [mk("from-office")]);
    await pb.panes(lastSocket(b), [mk("from-home")]);
    await vi.waitFor(() => expect(fleet.get(b.desktopId)!.remote.state.panes?.[0]?.title).toBe("from-home"));
    expect(fleet.get(a.desktopId)!.remote.state.panes?.[0]?.title).toBe("from-office");

    const lists = fleet.entries().map((e) => ({ desktopId: e.pairing.desktopId, panes: e.remote.state.panes }));
    expect(resolvePaneHash({ desktopId: null, pane: PANE }, lists), "old link is ambiguous").toBeNull();
    expect(resolvePaneHash({ desktopId: b.desktopId, pane: PANE }, lists)).toEqual({ desktopId: b.desktopId, pane: PANE });

    // A command for B's pane leaves on B's socket only, sealed for B.
    const aSent = lastSocket(a).sent.length;
    const bSent = lastSocket(b).sent.length;
    void fleet.get(b.desktopId)!.remote.request({ op: "peek", pane: PANE, lines: 10 });
    await vi.waitFor(() => expect(lastSocket(b).sent.length).toBeGreaterThan(bSent));
    expect(lastSocket(a).sent.length).toBe(aSent);
    const cmd = JSON.parse(lastSocket(b).sent.at(-1)!) as { body: string };
    const plain = JSON.parse((await open(b.linkKey, aadP2D(b.desktopId, b.deviceId), cmd.body))!) as { desktop_id: string; cmd: { pane: string } };
    expect(plain.desktop_id).toBe(b.desktopId);
    expect(plain.cmd.pane).toBe(PANE);
    fleet.stopAll();
  });
});

describe("isolation", () => {
  it("a body that arrives on A's connection never updates B", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet();
    fleet.sync([a, b]);
    const [pa, pb] = [new Peer(a), new Peer(b)];
    await pa.connect(lastSocket(a));
    await pb.connect(lastSocket(b));
    await pb.panes(lastSocket(b), [mk("home-only")]);
    await vi.waitFor(() => expect(fleet.get(b.desktopId)!.remote.state.panes?.[0]?.title).toBe("home-only"));

    // A's connection delivers a perfectly valid body of A: only A changes.
    await pa.panes(lastSocket(a), [mk("office-only", "waiting")]);
    await vi.waitFor(() => expect(fleet.get(a.desktopId)!.remote.state.panes?.[0]?.title).toBe("office-only"));
    expect(fleet.get(b.desktopId)!.remote.state.panes?.[0]?.title).toBe("home-only");

    // B's sealed body pushed down A's socket (a hostile or confused relay) does not open there.
    const before = fleet.get(a.desktopId)!.remote.state.dropped;
    await pb.panes(lastSocket(a), [mk("injected")]);
    await vi.waitFor(() => expect(fleet.get(a.desktopId)!.remote.state.dropped).toBeGreaterThan(before));
    expect(fleet.get(a.desktopId)!.remote.state.panes?.[0]?.title).toBe("office-only");
    expect(fleet.get(b.desktopId)!.remote.state.panes?.[0]?.title).toBe("home-only");
    fleet.stopAll();
  });

  it("a server that answers for another desktop is refused", async () => {
    const a = await makePairing("Office");
    const fleet = makeFleet();
    fleet.sync([a]);
    const ws = lastSocket(a);
    ws.say({ t: "challenge", nonce: "abc" });
    await vi.waitFor(() => expect(ws.sent.length).toBe(1));
    ws.say({ t: "ready", desktop_id: newUuid(), desktop_online: true });
    await vi.waitFor(() => expect(fleet.get(a.desktopId)!.remote.state.link).toBe("removed"));
    expect(ws.sent).toHaveLength(1); // no session was opened
    fleet.stopAll();
  });

  it("one desktop dropping its connection leaves the other online", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet();
    fleet.sync([a, b]);
    await new Peer(a).connect(lastSocket(a));
    await new Peer(b).connect(lastSocket(b));
    await vi.waitFor(() => expect(fleet.get(b.desktopId)!.remote.state.session).not.toBeNull());
    lastSocket(a).onclose?.();
    expect(fleet.get(a.desktopId)!.remote.state.link).toBe("offline");
    expect(fleet.get(a.desktopId)!.remote.state.offlineSince).not.toBeNull();
    expect(fleet.get(b.desktopId)!.remote.state.link).toBe("online");
    expect(fleet.get(b.desktopId)!.remote.state.offlineSince).toBeNull();
    fleet.stopAll();
  });
});

describe("removing a pairing", () => {
  it("unsubscribes push on its connection, closes it, and leaves the other intact", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet();
    fleet.sync([a, b]);
    await new Peer(a).connect(lastSocket(a));
    await new Peer(b).connect(lastSocket(b));
    const wa = lastSocket(a);
    const wb = lastSocket(b);
    const bSent = wb.sent.length;
    fleet.remove(a.desktopId);
    expect(wa.sent.at(-1)).toBe(pushUnsubscribeFrame());
    expect(wa.closed).toBe(true);
    expect(fleet.get(a.desktopId)).toBeUndefined();
    expect(fleet.size).toBe(1);
    expect(wb.closed).toBe(false);
    expect(wb.sent.length).toBe(bSent);
    expect(fleet.get(b.desktopId)!.remote.state.session).not.toBeNull();
    fleet.stopAll();
  });

  it("pairing the same desktop again replaces its connection only", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet();
    fleet.sync([a, b]);
    const oldA = lastSocket(a);
    const bRemote = fleet.get(b.desktopId)!.remote;
    const a2: Pairing = { ...(await makePairing("Office")), desktopId: a.desktopId };
    fleet.sync([a2, b]);
    expect(oldA.closed).toBe(true);
    expect(socketsOf(a)).toHaveLength(2);
    expect(fleet.get(b.desktopId)!.remote).toBe(bRemote);
    fleet.stopAll();
  });
});

describe("push fan-out", () => {
  const wire: PushSub = { endpoint: "https://push.example/x", keys: { p256dh: "k", auth: "a" } };

  it("sends the same frame to every connection that is up and counts them", () => {
    const got: string[][] = [[], [], []];
    const sinks = got.map((g, i) => ({ sendFrame: (f: string) => (i === 1 ? false : (g.push(f), true)) }));
    expect(fanOut(sinks, pushSubscribeFrame(wire))).toBe(2);
    expect(got[0]).toEqual(got[2]);
    expect(got[1]).toEqual([]);
  });

  it("re-sends the subscription after every (re)connect of every pairing", async () => {
    const a = await makePairing("Office");
    const b = await makePairing("Home");
    const fleet = makeFleet({ onReady: (remote) => void resyncPush(remote, async () => wire) });
    fleet.sync([a, b]);
    const frame = pushSubscribeFrame(wire);
    const count = (p: Pairing): number => socketsOf(p).reduce((n, w) => n + w.sent.filter((f) => f === frame).length, 0);
    await new Peer(a).connect(lastSocket(a));
    await new Peer(b).connect(lastSocket(b));
    await vi.waitFor(() => {
      expect(count(a)).toBe(1);
      expect(count(b)).toBe(1);
    });
    // A reconnects: only A's server gets it again.
    fleet.get(a.desktopId)!.remote.reconnectNow();
    expect(socketsOf(a)).toHaveLength(2);
    await new Peer(a).connect(lastSocket(a));
    await vi.waitFor(() => expect(count(a)).toBe(2));
    expect(count(b)).toBe(1);
    // A pairing added later gets it as soon as it is ready.
    const c = await makePairing("Attic");
    fleet.sync([a, b, c]);
    await new Peer(c).connect(lastSocket(c));
    await vi.waitFor(() => expect(count(c)).toBe(1));
    fleet.stopAll();
  });
});
