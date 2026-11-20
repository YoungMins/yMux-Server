// End-to-end DEVICE side, one desktop (run by scripts/e2e.ps1 through
// `vitest run --config vitest.e2e.config.ts scripts/e2e-device.ts`).
// It drives the PWA's shipped protocol/net code (pairing with the link key, connection, session
// opening, sealing, router, message builders, WebCrypto signing) against a real server and a real
// desktop. Only three things are test-local: a WebSocket subclass that adds the Origin header a
// browser would send (and records every frame; e2e-common.ts), an in-memory Identity instead of
// IndexedDB, and the file handshake with the desktop test.
//
// Env: E2E_URL (http://127.0.0.1:<port>), E2E_DIR (shared rendezvous directory).
// The pairing URL (`#pair=<desktop_id>.<code>.<dk>`) is read from E2E_PAIR_URL, else from
// <E2E_DIR>/pair-url.txt. The check number the device receives in the sealed `pair_challenge` is
// written to <E2E_DIR>/pair-check-device.txt: the fake desktop "types" it (the desktop never shows
// or writes the number itself).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BASE, WS_BASE, hooks, incoming, lastSock, outgoing, rendezvous, sleep, until, untilAsync } from "./e2e-common";
import { b64uEncode, newUuid } from "../src/protocol/encoding";
import {
  cmdFrame,
  parseBody,
  parseChatData,
  parseListData,
  parsePeekData,
  parseResultData,
  parseServerFrame,
  type ChatPage,
  type ReplyResult,
} from "../src/protocol/messages";
import { aadD2P, aadP2D, deriveLinkKey, generateAgreementKey, open, seal } from "../src/protocol/seal";
import { cmdSigString, exportPublicKey, generateDeviceKey, signString } from "../src/protocol/signing";
import { Remote } from "../src/net/remote";
import { parsePairFragment, pairWsUrl, runPairing, type PairLink } from "../src/net/pairing";
import { promoteIfConfirmed } from "../src/net/provisional";
import type { Identity, Pairing } from "../src/net/storage";

const DIR = process.env.E2E_DIR ?? "";
if (!DIR) throw new Error("E2E_DIR is required");
const { touch, fromDesktop } = rendezvous(DIR);
const P1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const P2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

interface Plain {
  k?: string;
  re?: number;
  ok?: boolean;
  code?: string;
  ref?: string;
  seq?: number;
  session?: string;
  n?: number;
  cmd?: { op?: string; text?: string };
}

/** Every desktop body that crossed the wire and opens under our key (accepted by the session rules or not). */
async function incomingPlains(): Promise<Plain[]> {
  const out: Plain[] = [];
  for (const text of [...incoming]) {
    const f = parseServerFrame(text);
    if (f?.t !== "msg") continue;
    const p = await open(identity.linkKey, aadD2P(identity.desktopId, identity.deviceId), f.body);
    if (p === null) continue;
    try {
      out.push(JSON.parse(p) as Plain);
    } catch {
      /* not JSON */
    }
  }
  return out;
}

/** Reply bodies seen on the wire, in arrival order. */
async function replies(): Promise<{ re: number; ok: boolean; code?: string }[]> {
  return (await incomingPlains())
    .filter((b) => b.k === "reply" && typeof b.re === "number" && typeof b.ok === "boolean")
    .map((b) => ({ re: b.re!, ok: b.ok!, code: b.code }));
}

/** The command frames we sent (opens excluded), opened with our own key. */
async function sentCmds(from = 0): Promise<{ frame: string; plain: Plain }[]> {
  const out: { frame: string; plain: Plain }[] = [];
  for (const frame of outgoing.slice(from)) {
    if (!frame.includes('"t":"cmd"')) continue;
    const body = (JSON.parse(frame) as { body: string }).body;
    const p = await open(identity.linkKey, aadP2D(identity.desktopId, identity.deviceId), body);
    if (p === null) continue;
    const plain = JSON.parse(p) as Plain;
    if (plain.k === "cmd") out.push({ frame, plain });
  }
  return out;
}

// ---- shared state of the run ------------------------------------------------------------

let remote: Remote;
let identity: Identity;
const offlineEvents: boolean[] = [];

afterAll(() => {
  remote?.stop();
});

/** The device's half of a pairing: a fresh `ek`, and the link key derived from the code and `dk`. */
async function agree(link: PairLink, deviceId: string, pubkey: string): Promise<{ ek: string; linkKey: CryptoKey }> {
  const pair = await generateAgreementKey();
  const ek = await exportPublicKey(pair.publicKey);
  const linkKey = await deriveLinkKey({
    ekPrivate: pair.privateKey,
    ek,
    dk: link.dk,
    code: link.code,
    desktopId: link.desktopId,
    deviceId,
    pubkey,
  });
  return { ek, linkKey };
}

/** Ask the desktop for pairing round `k` (it opens a window and publishes the link), read the link. */
async function pairingRound(k: number, plan: string): Promise<PairLink> {
  touch(`d.pair${k}`, plan);
  const file = `pair-url-${k}.txt`;
  await until(file, () => existsSync(join(DIR, file)), 60000);
  const url = readFileSync(join(DIR, file), "utf8").trim();
  const link = parsePairFragment(new URL(url).hash);
  expect(link, "the pairing URL fragment parses").not.toBeNull();
  expect(url.startsWith(BASE + "/#pair=")).toBe(true);
  return link!;
}

interface NewDevice {
  link: PairLink;
  deviceId: string;
  pubkey: string;
  privateKey: CryptoKey;
  ek: string;
  linkKey: CryptoKey;
}

async function newDevice(link: PairLink): Promise<NewDevice> {
  const kp = await generateDeviceKey();
  const pubkey = await exportPublicKey(kp.publicKey);
  const deviceId = newUuid();
  return { link, deviceId, pubkey, privateKey: kp.privateKey, ...(await agree(link, deviceId, pubkey)) };
}

function pairWith(d: NewDevice, name: string, onCheck: (digits: string) => void = () => {}) {
  return runPairing({
    url: pairWsUrl(new URL(BASE)),
    link: d.link,
    deviceId: d.deviceId,
    pubkey: d.pubkey,
    ek: d.ek,
    name,
    privateKey: d.privateKey,
    linkKey: d.linkKey,
    onSent: () => {},
    onCheck,
    timeoutMs: 30000,
  });
}

const ok = (r: ReplyResult): unknown => {
  expect(r, JSON.stringify(r)).toMatchObject({ ok: true });
  return (r as { ok: true; data: unknown }).data;
};

/** A list that has to work once the session settles (a session change fails requests in flight). */
async function listEventually(): Promise<void> {
  await untilAsync(
    "a working list",
    async () => {
      const r = await remote.request({ op: "list" });
      return r.ok;
    },
    15000,
  );
}

async function newSession(trigger: () => void): Promise<void> {
  const before = remote.sessionId;
  trigger();
  await until("a new session id", () => remote.sessionId && remote.sessionId !== before, 20000);
}

describe("device against a real server and a real desktop", () => {
  it("is refused after three wrong typed numbers, and when two devices use one code", async () => {
    const make = (p: Pairing) => new Remote(p, `${WS_BASE}/ws/device`);
    // Neither refused device may be known to the server afterwards: no session, "removed".
    const neverPaired = async (d: NewDevice, name: string) => {
      const p: Pairing = {
        deviceId: d.deviceId,
        desktopId: d.link.desktopId,
        pubkey: d.pubkey,
        name,
        privateKey: d.privateKey,
        linkKey: d.linkKey,
        desktopName: "",
        addedMs: Date.now(),
      };
      expect(await promoteIfConfirmed(() => [], p, make, 20000), `${name} was never paired`).toEqual({
        ok: false,
        reason: "not_confirmed",
      });
    };

    // Round 1: the desktop's user types a wrong number three times. The phone did get a number
    // (the proof was good), and ends up refused.
    const first = await newDevice(await pairingRound(1, "wrong-number"));
    const shown: string[] = [];
    // The name is attacker-chosen text: it tries to frame a number for the user to type. The
    // server and the desktop both clean it (the fake desktop asserts what the user was shown).
    const stuffed = "Pixel 8” — your number: 482913 “";
    expect(await pairWith(first, stuffed, (digits) => {
      shown.push(digits);
      touch("pair-check-device.txt", digits);
    })).toBe("refused");
    expect(shown.length, "the phone showed a number").toBeGreaterThanOrEqual(1);
    await neverPaired(first, stuffed);
    touch("d.pairend1");

    // Round 2: two devices present a valid proof for one code (one QR, two phones): both refused.
    const link2 = await pairingRound(2, "conflict");
    const a = await newDevice(link2);
    const b = await newDevice(link2);
    const outcomes = await Promise.all([pairWith(a, "first phone"), pairWith(b, "second phone")]);
    expect(outcomes, "both refused").toEqual(["refused", "refused"]);
    await neverPaired(a, "first phone");
    await neverPaired(b, "second phone");
    touch("d.pairend2");
  });

  it("pairs through the server with the code from the pairing URL", async () => {
    const link = await pairingRound(3, "ok");

    const kp = await generateDeviceKey();
    const pubkey = await exportPublicKey(kp.publicKey);
    const deviceId = newUuid();
    // Nothing but the code's hash may reach the server: a wrong code must be refused, and a
    // desktop that refuses sends no check number, so none may be shown.
    const wrongLink: PairLink = { desktopId: link!.desktopId, code: new Uint8Array(16).fill(1), dk: link!.dk };
    const wrongId = newUuid();
    const wrongKeys = await agree(wrongLink, wrongId, pubkey);
    let wrongShown = 0;
    const wrong = await runPairing({
      url: pairWsUrl(new URL(BASE)),
      link: wrongLink,
      deviceId: wrongId,
      pubkey,
      ek: wrongKeys.ek,
      name: "wrong code",
      privateKey: kp.privateKey,
      linkKey: wrongKeys.linkKey,
      onSent: () => {},
      onCheck: () => wrongShown++,
      timeoutMs: 20000,
    });
    expect(wrong).not.toBe("ok");
    expect(wrongShown, "a wrong code was shown no check number").toBe(0);

    // The link key comes from the key agreement before the request goes out; the desktop
    // derives the same one from its private dk, so only it can seal the check number for us.
    const { ek, linkKey } = await agree(link!, deviceId, pubkey);
    expect(linkKey.extractable).toBe(false);
    const checks: string[] = [];
    const outcome = await runPairing({
      url: pairWsUrl(new URL(BASE)),
      link: link!,
      deviceId,
      pubkey,
      ek,
      name: "Test phone",
      privateKey: kp.privateKey,
      linkKey,
      onSent: () => {},
      // What the phone shows is what the user types on the computer: the fake desktop reads this file.
      onCheck: (digits) => {
        checks.push(digits);
        touch("pair-check-device.txt", digits);
      },
      timeoutMs: 60000,
    });
    expect(outcome).toBe("ok");
    expect(checks.length, "a number arrived in the sealed pair_challenge").toBeGreaterThanOrEqual(1);
    expect(checks.at(-1)).toMatch(/^\d{6}$/);
    identity = { deviceId, desktopId: link!.desktopId, pubkey, name: "Test phone", privateKey: kp.privateKey, linkKey };
    const pairing: Pairing = { ...identity, desktopName: "", addedMs: Date.now() };
    const make = (p: Pairing) => new Remote(p, `${WS_BASE}/ws/device`);

    // `pair_result ok:true` is plaintext and proves nothing: a pairing that never gets a session
    // under its key (here: a device the server does not know) replaces nothing.
    const fkp = await generateDeviceKey();
    const forged: Pairing = {
      deviceId: newUuid(),
      desktopId: identity.desktopId,
      pubkey: await exportPublicKey(fkp.publicKey),
      name: "forged",
      privateKey: fkp.privateKey,
      linkKey: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
      desktopName: "",
      addedMs: Date.now(),
    };
    const existing = [pairing];
    expect(await promoteIfConfirmed(() => existing, forged, make, 30000)).toEqual({ ok: false, reason: "not_confirmed" });
    expect(existing).toEqual([pairing]);

    // The real one is promoted as soon as the desktop opens a session for it.
    const promoted = await promoteIfConfirmed(() => [], pairing, make, 30000);
    expect(promoted).toMatchObject({ ok: true, replaced: false });
  });

  it("connects /ws/device, opens a session and receives it", async () => {
    remote = new Remote(identity, `${WS_BASE}/ws/device`);
    remote.subscribe(() => offlineEvents.push(remote.state.desktopOnline));
    remote.start();
    await until("online with a session", () => remote.state.link === "online" && remote.state.session, 20000);
    expect(remote.state.desktopOnline).toBe(true);
    expect(remote.state.session).toMatchObject({ cap: "prompt", name: "E2E PC" });
    expect(remote.sessionId, "the session id is set").toBeTruthy();
    // Our first command frame was the sealed `open`; nothing on the wire is readable JSON.
    const opens = outgoing.filter((f) => f.includes('"t":"cmd"'));
    expect(opens.length).toBeGreaterThanOrEqual(1);
    for (const f of opens) expect((JSON.parse(f) as { body: string }).body).not.toContain("desktop_id");
    // The automatic list that follows the session.
    await until("the first pane list", () => remote.state.panes, 10000);
    expect(remote.state.panes!.map((p) => p.pane).sort()).toEqual([P1, P2]);
    touch("d.session");
    // The desktop changes a pane: the unsolicited `panes` push must arrive.
    const pushed = await until("a panes push", () => remote.state.panes?.find((p) => p.pane === P2 && p.status === "waiting"), 20000);
    expect(pushed.queued).toBe(1);
    expect(remote.state.dropped, "nothing legitimate was ignored").toBe(0);
  });

  it("runs list, peek, answer (with menu_id), interrupt and prompt", async () => {
    const list = parseListData(ok(await remote.request({ op: "list" })));
    expect(list?.map((p) => p.title).sort()).toEqual(["Claude one", "Codex two"]);

    const peekNow = async () => {
      const p = parsePeekData(ok(await remote.request({ op: "peek", pane: P2, lines: 80 })));
      expect(p).not.toBeNull();
      return p!;
    };
    const peek = await peekNow();
    expect(peek.lines).toEqual(["$ claude (S)", "Allow this command?", "ls -la"]);
    expect(peek.question).toEqual(["Allow this command?"]);
    expect(peek.status).toBe("waiting");
    expect(peek.menu.map((m) => m.n)).toEqual([1, 2]);
    expect(peek.menuId, "a waiting pane has a menu id").toMatch(/^[A-Za-z0-9_-]{1,32}$/);
    const long = peek.menu[1]!.label;
    expect([...long].length, "labels leave the desktop clipped to 120").toBe(120);
    expect(long.endsWith("…")).toBe(true);

    // Each answer carries the menu_id of the peek that showed its button.
    const answer = async (n: number, label: string, menuId?: string) => {
      const id = menuId ?? (await peekNow()).menuId;
      return parseResultData(
        ok(await remote.request({ op: "answer", pane: P2, n, label, menu_id: id })),
        ["sent", "stale", "gone", "failed"],
      );
    };
    expect(await answer(1, "Yes")).toBe("sent");
    expect(await answer(2, long), "the clipped label echoed back still matches").toBe("sent");
    expect(await answer(2, "Yes, and redacted " + long.slice(18)), "an altered label is stale").toBe("stale");
    expect(await answer(1, "Yes", "not-the-current-menu"), "an answer for another menu appearance is stale").toBe("stale");

    // Something else types into the pane between this peek and the answer (the user, another
    // device): the pane's input generation advances, so the id on the phone's button is stale
    // even though the same options are still on screen. A fresh peek mints a new id that works.
    const before = await peekNow();
    touch("d.bump");
    await fromDesktop("h.bumped");
    expect(await answer(1, "Yes", before.menuId), "an id from before the pane's input changed is stale").toBe("stale");
    const after = await peekNow();
    expect(after.menuId, "the page reports a new menu id").not.toBe(before.menuId);
    expect(await answer(1, "Yes", after.menuId)).toBe("sent");

    expect(parseResultData(ok(await remote.request({ op: "interrupt", pane: P2 })), ["sent"])).toBe("sent");
    const prompt = (text: string, queue: boolean) => remote.request({ op: "prompt", pane: P2, text, queue });
    expect(parseResultData(ok(await prompt("go on", false)), ["sent", "queued"])).toBe("sent");
    expect(parseResultData(ok(await prompt("!rm -rf /", false)), ["refused", "sent"]), "a leading ! is refused").toBe("refused");
    expect(parseResultData(ok(await prompt("later, please", true)), ["sent", "queued"])).toBe("queued");
  });

  it("reads the conversation with chat: the newest page, then nothing after its end", async () => {
    const ask = async (pane: string, extra: { conv?: string; after?: number; before?: number } = {}) => {
      const r = await remote.request({ op: "chat", pane, ...extra });
      return { code: r.ok ? "" : r.code, page: r.ok ? parseChatData(r.data) : null };
    };
    // The fake desktop serves a synthetic conversation on one of its panes; do not assume which.
    let pane = "";
    let first: ChatPage | null = null;
    let code = "";
    for (const p of [P1, P2]) {
      const r = await ask(p);
      code = r.code || code;
      if (r.page && r.page.conv !== "") {
        pane = p;
        first = r.page;
        break;
      }
    }
    expect(first, `a pane answers chat with a conversation (error codes seen: "${code}"; unknown_op means the desktop lacks chat)`).not.toBeNull();
    const page = first!;
    expect(page.conv).toMatch(/^[A-Za-z0-9_-]{1,32}$/);
    expect(["claude", "codex"]).toContain(page.agent);
    expect(page.items.length, "the newest page has items").toBeGreaterThan(0);
    expect(page.items.length).toBeLessThanOrEqual(40);
    expect(page.start).toBeLessThanOrEqual(page.end);
    expect(new Set(page.items.map((i) => i.id)).size, "ids are unique").toBe(page.items.length);
    for (const i of page.items) {
      expect(["user", "assistant", "tool"]).toContain(i.role);
      expect(i.id).toMatch(/^[0-9.]{1,40}$/);
      if (i.role === "tool") expect(i.text.includes("\n"), "a tool text is one line").toBe(false);
    }
    const texts = page.items.filter((i) => i.role !== "tool").map((i) => i.text);
    expect(texts.some((x) => x.includes("|") && /\n\s*\|?\s*:?-{2,}/.test(x)), "a Markdown pipe table arrives with its newlines").toBe(true);
    expect(texts.some((x) => /[가-힣]/u.test(x)), "Hangul text survives").toBe(true);

    const next = await ask(pane, { conv: page.conv, after: page.end });
    expect(next.page, `after: end is answered (${next.code})`).not.toBeNull();
    expect(next.page!.conv).toBe(page.conv);
    expect(next.page!.items, "nothing is new after the end").toEqual([]);
    expect(next.page!.newer).toBe(false);
  });

  it("reports a write the page was still typing after 5 s as delivered, result unknown, and never re-sends it", async () => {
    // The fake page never answers this prompt: the desktop answers `timeout` after 5 s. For a
    // write that is not "no answer" (which invites sending it again): it may well have been typed.
    const promptsBefore = (await sentCmds()).filter((c) => c.plain.cmd?.op === "prompt").length;
    const t0 = Date.now();
    const res = await remote.request({ op: "prompt", pane: P2, text: "still typing", queue: false });
    expect(res).toEqual({ ok: false, code: "delivered_unknown" });
    expect(Date.now() - t0, "the desktop's 5 s timeout, not the phone's 8 s one").toBeLessThan(7500);
    expect((await replies()).some((x) => !x.ok && x.code === "timeout"), "the desktop did answer timeout").toBe(true);
    await sleep(1000);
    expect((await sentCmds()).filter((c) => c.plain.cmd?.op === "prompt").length, "sent once, never again").toBe(
      promptsBefore + 1,
    );
    ok(await remote.request({ op: "list" }));
  });

  it("a relay that forwards a prompt twice runs it once and the phone never shows a failure", async () => {
    // The desktop runs the first copy and answers the second `replay`. Which of the two replies
    // reaches the phone first is not fixed; either way it ends at the real result or at
    // delivered-unknown (a `replay` proves the command was accepted), never at a failure.
    const before = (await replies()).length;
    const late: { ok: boolean; code?: string }[] = [];
    hooks.duplicateNextCmd = true;
    const res = await remote.request({ op: "prompt", pane: P2, text: "dup once", queue: false }, { onLate: (r) => late.push(r) });
    expect(res.ok ? parseResultData(ok(res), ["sent"]) : res.code, "the real result or delivered-unknown").toSatisfy(
      (v: unknown) => v === "sent" || v === "delivered_unknown",
    );
    await untilAsync("both replies", async () => (await replies()).length >= before + 2, 5000);
    const mine = (await replies()).slice(before);
    expect(mine.some((x) => !x.ok && x.code === "replay"), "the duplicate was answered replay").toBe(true);
    expect(mine.some((x) => x.ok), "the real reply exists").toBe(true);
    await sleep(300);
    if (!res.ok) expect(late.length, "a delivered-unknown shown first is upgraded by the real reply").toBe(1);
    expect(late.every((r) => r.ok), "never a failure").toBe(true);
    const dups = (await sentCmds()).filter((c) => c.plain.cmd?.op === "prompt" && c.plain.cmd.text === "dup once");
    expect(dups.length, "the frame crossed the wire twice").toBe(2);
    ok(await remote.request({ op: "list" }));
  });

  it("rejects a replayed frame and a tampered body", async () => {
    // Replay: the very last signed command frame (the queued prompt), sent again.
    const last = (await sentCmds()).pop()!;
    const seq = last.plain.seq!;
    const before = (await replies()).length;
    expect(remote.sendFrame(last.frame)).toBe(true);
    const r = await untilAsync("a replay reply", async () => (await replies()).slice(before).find((x) => x.re === seq && !x.ok), 5000);
    expect(r.code).toBe("replay");

    // Tampered: one character of the sealed body changed on the way out. The desktop cannot trust
    // the body, so it answers re:0 with the `ref` of our signature. That is not "failed" for the
    // phone (a plaintext relay could have said as much): the command becomes unconfirmed, a new
    // `open` follows, and `prev` tells it the desktop never accepted that seq. Not by the 8 s timeout.
    const interruptsBefore = (await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length;
    hooks.tamperNext = true;
    const t0 = Date.now();
    const res = await remote.request({ op: "interrupt", pane: P2 });
    expect(res).toEqual({ ok: false, code: "not_delivered" });
    expect(Date.now() - t0, "settled by the re:0 + prev, not by the 8 s timeout").toBeLessThan(6000);
    expect((await replies()).some((x) => x.re === 0 && x.code === "bad_sig")).toBe(true);
    // (The altered frame does not open under our key, so it is not counted: any other interrupt
    // frame would be a resend, and a write is never sent again on its own.)
    expect((await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length).toBe(interruptsBefore);
    await listEventually();

    // And the link still works afterwards.
    ok(await remote.request({ op: "list" }));
  });

  it("answers `bad_session` to a command re-sent after a NEW session was opened", async () => {
    // An interrupt that runs once; its signed frame is then re-sent into the next session.
    expect(parseResultData(ok(await remote.request({ op: "interrupt", pane: P2 })), ["sent"])).toBe("sent");
    const old = (await sentCmds()).pop()!;
    expect(old.plain.session).toBe(remote.sessionId);
    await newSession(() => remote.reopenSession());
    const before = (await incomingPlains()).length;
    expect(remote.sendFrame(old.frame)).toBe(true);
    const r = await untilAsync(
      "a bad_session reply",
      async () => (await incomingPlains()).slice(before).find((b) => b.k === "reply" && b.ok === false && b.code === "bad_session"),
      8000,
    );
    expect([0, old.plain.seq]).toContain(r.re);
    // The device reacts to bad_session by opening again; let that settle, then everything works.
    await sleep(1500);
    await listEventually();
  });

  it("answers `expired` to a command whose ts_ms is 5 minutes old, then refreshes the session", async () => {
    const before = remote.sessionId;
    remote.tsSkewMs = -5 * 60 * 1000;
    const res = await remote.request({ op: "interrupt", pane: P2 });
    remote.tsSkewMs = 0;
    expect(res).toEqual({ ok: false, code: "expired" });
    // `expired` makes the device open a fresh session (refreshing the clock offset); then retry works.
    await until("a refreshed session", () => remote.sessionId && remote.sessionId !== before, 20000);
    await sleep(500);
    await listEventually();
  });

  it("answers `expired` to a prompt whose ts_ms is 31 s old", async () => {
    const before = remote.sessionId;
    remote.tsSkewMs = -31_000;
    const res = await remote.request({ op: "prompt", pane: P1, text: "stale", queue: false });
    remote.tsSkewMs = 0;
    expect(res).toEqual({ ok: false, code: "expired" });
    await until("a refreshed session", () => remote.sessionId && remote.sessionId !== before, 20000);
    await sleep(500);
    await listEventually();
  });

  it("drops a panes body whose at_ms is older than 30 s", async () => {
    const sock = lastSock(identity.deviceId);
    const droppedBefore = remote.state.dropped;
    const panesBefore = remote.state.panes;
    // Made by us with the link key (we hold it); what is tested is the PWA's own freshness rule.
    const stale = await seal(
      identity.linkKey,
      aadD2P(identity.desktopId, identity.deviceId),
      JSON.stringify({
        k: "panes",
        panes: [{ pane: P1, ws: "w", title: "STALE", kind: "claude", status: "idle", since_ms: 0, queued: 0 }],
        session: remote.sessionId,
        n: 1_000_000,
        at_ms: Date.now() - 32_000,
      }),
    );
    sock.forge(JSON.stringify({ t: "msg", body: stale }));
    await until("the stale body to be counted", () => remote.state.dropped === droppedBefore + 1, 5000);
    expect(remote.state.panes, "the list did not change").toBe(panesBefore);
    await listEventually();
  });

  it("ignores a re:0 whose ref names no command in flight", async () => {
    const sock = lastSock(identity.deviceId);
    const session = remote.sessionId;
    const frames = outgoing.length;
    const list = remote.request({ op: "list" });
    await until("the list frame to leave", () => outgoing.length > frames, 5000);
    const bogus = await seal(
      identity.linkKey,
      aadD2P(identity.desktopId, identity.deviceId),
      JSON.stringify({ k: "reply", re: 0, ok: false, code: "bad_sig", ref: b64uEncode(new Uint8Array(16).fill(7)), session: "" }),
    );
    sock.forge(JSON.stringify({ t: "msg", body: bogus }));
    expect(await list).toMatchObject({ ok: true });
    await sleep(1500);
    expect(remote.sessionId, "no new open was provoked").toBe(session);
    expect(outgoing.length, "only the list frame left").toBe(frames + 1);
  });

  it("reports a command as delivered, result unknown, when a forged desktop_offline hides a genuine delivery", async () => {
    // The relay withholds the desktop's reply and then tells us (in plaintext) that it is offline.
    // The command did run, so the phone must not say it failed.
    const interruptsBefore = (await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length;
    hooks.dropMsg = true;
    const frames = outgoing.length;
    const req = remote.request({ op: "interrupt", pane: P2 });
    await until("the interrupt frame to leave", () => outgoing.length > frames, 5000);
    await sleep(700); // the desktop runs it and replies; the reply is thrown away
    lastSock(identity.deviceId).forge(JSON.stringify({ t: "error", code: "desktop_offline" }));
    hooks.dropMsg = false;
    expect(await req).toEqual({ ok: false, code: "delivered_unknown" });
    expect((await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length, "sent once, never again").toBe(
      interruptsBefore + 1,
    );
    await listEventually();
  });

  it("reports a command the relay lost as not delivered, after the new session says so", async () => {
    const interruptsBefore = (await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length;
    hooks.dropNextCmd = true;
    const res = await remote.request({ op: "interrupt", pane: P2 }); // the frame never arrives: 8 s, then a new open
    expect(res).toEqual({ ok: false, code: "not_delivered" });
    // The lost frame is the only one: nothing was re-sent.
    expect((await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length).toBe(interruptsBefore + 1);
    await listEventually();
  });

  it("a dropped command ends the session at the next one (bad_session), and prev says exactly what ran", async () => {
    // Seqs are consecutive: the desktop accepts a command only as last accepted + 1. The relay
    // drops command k and delivers k+1, so the desktop revokes the session and answers
    // `bad_session`; the new session's `prev` says k was never accepted (nor was k+1).
    const interruptsBefore = (await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length;
    const before = remote.sessionId;
    const repliesBefore = (await incomingPlains()).length;
    const frames = outgoing.length;
    hooks.dropNextCmd = true;
    const lost = remote.request({ op: "interrupt", pane: P2 });
    await until("the dropped frame to leave", () => outgoing.length > frames && !hooks.dropNextCmd, 5000);
    const next = remote.request({ op: "list" }); // k+1, same session
    const gap = await untilAsync(
      "a bad_session reply for the gap",
      async () => (await incomingPlains()).slice(repliesBefore).find((b) => b.k === "reply" && b.re === 0 && b.code === "bad_session"),
      8000,
    );
    expect(gap.ok).toBe(false);
    expect(await lost, "the dropped write is not delivered").toEqual({ ok: false, code: "not_delivered" });
    expect(await next, "the read is simply asked again in the new session").toMatchObject({ ok: true });
    expect(remote.sessionId, "a new session replaced the revoked one").not.toBe(before);
    expect((await sentCmds()).filter((c) => c.plain.cmd?.op === "interrupt").length, "sent once, never again").toBe(
      interruptsBefore + 1,
    );
  });

  it("revokes the session when a command skips a seq, and does not run it", async () => {
    ok(await remote.request({ op: "list" }));
    const before = remote.sessionId;
    const last = (await sentCmds()).filter((c) => c.plain.session === before).pop()!;
    // Signed and sealed correctly, in the current session, but seq last + 2.
    const plain = JSON.stringify({
      k: "cmd",
      desktop_id: identity.desktopId,
      device_id: identity.deviceId,
      session: before,
      seq: last.plain.seq! + 2,
      ts_ms: Date.now(),
      cmd: { op: "interrupt", pane: P2 },
    });
    const body = await seal(identity.linkKey, aadP2D(identity.desktopId, identity.deviceId), plain);
    const frame = cmdFrame(body, await signString(identity.privateKey, cmdSigString(body)));
    const seen = (await incomingPlains()).length;
    expect(remote.sendFrame(frame)).toBe(true);
    await untilAsync(
      "bad_session for the skipped seq",
      async () => (await incomingPlains()).slice(seen).find((b) => b.k === "reply" && b.re === 0 && b.code === "bad_session"),
      5000,
    );
    // The desktop ended the session: the phone's next command finds out and moves to a new one.
    await listEventually();
    expect(remote.sessionId).not.toBe(before);
  });

  it("drops a frame with a valid signature whose body is sealed under a wrong key", async () => {
    // A key from another agreement entirely (the right code with any other ek/dk gives another key).
    const wrongKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const plain = JSON.stringify({
      k: "cmd",
      desktop_id: identity.desktopId,
      device_id: identity.deviceId,
      session: remote.sessionId,
      seq: 1000,
      ts_ms: Date.now(),
      cmd: { op: "interrupt", pane: P2 },
    });
    const body = await seal(wrongKey, aadP2D(identity.desktopId, identity.deviceId), plain);
    const frame = cmdFrame(body, await signString(identity.privateKey, cmdSigString(body)));
    const before = (await incomingPlains()).length;
    expect(remote.sendFrame(frame)).toBe(true);
    // The desktop knows this device, so it answers (sealed, rate limited) bad_sig with the `ref`
    // of the signature it was shown: the only thing it can say about a body it cannot open.
    const sigOf = (JSON.parse(frame) as { sig: string }).sig;
    const ref = b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sigOf))).slice(0, 16));
    await untilAsync(
      "a bad_sig reply carrying our ref",
      async () => (await incomingPlains()).slice(before).find((b) => b.k === "reply" && b.re === 0 && b.code === "bad_sig" && b.ref === ref),
      5000,
    );
    await sleep(1000);
    // Nothing else came back for it (never executed: the desktop counts what reached its page).
    // (Replies to the page's own lists, which a session change may re-ask, are not about this
    // frame: its seq is 1000, and a `re:0` is how the desktop names a body it cannot open.)
    const seen = (await incomingPlains()).slice(before).filter((b) => b.k === "reply" && (b.re === 0 || b.re === 1000));
    for (const x of seen) expect(x, JSON.stringify(x)).toMatchObject({ re: 0, ok: false, code: "bad_sig", ref });
    await listEventually();
  });

  it("rate limits a device's commands without losing its session", async () => {
    // A signed frame of the CURRENT session, sent again and again: each one that gets through the
    // server is answered `replay`; the excess never reaches the desktop at all.
    ok(await remote.request({ op: "list" }));
    const last = (await sentCmds()).pop()!;
    const session = remote.sessionId;
    const limited = () => incoming.filter((t) => t.includes('"rate_limited"')).length;
    const before = limited();
    for (let i = 0; i < 120; i++) expect(remote.sendFrame(last.frame)).toBe(true);
    await until("a rate_limited error from the server", () => limited() > before, 5000);
    await sleep(1500);
    expect(remote.state.link).toBe("online");
    expect(remote.state.session, "still has a session").not.toBeNull();
    expect(remote.sessionId, "and it is the same one").toBe(session);
    ok(await remote.request({ op: "list" }));
    touch("d.phaseA");
  });

  it("gets a fresh session after the desktop drops and reconnects", async () => {
    await fromDesktop("h.reconnected");
    await until("a desktop_online + session", () => remote.state.desktopOnline && remote.state.session, 20000);
    expect(offlineEvents.includes(false), "the device saw the desktop go offline").toBe(true);
    await sleep(500);
    const first = outgoing.length;
    const list = parseListData(ok(await remote.request({ op: "list" })));
    expect(list).toHaveLength(2);
    const sent = await sentCmds(first);
    expect(sent[0]!.plain.seq!, "a new session restarts seq at 1").toBeLessThanOrEqual(2);
    const prompt = await remote.request({ op: "prompt", pane: P1, text: "after reconnect", queue: false });
    expect(parseResultData(ok(prompt), ["sent"])).toBe("sent");
    touch("d.phaseR");
  });

  it("is told to reopen and refused `prompt` once the desktop lowers the capability to view", async () => {
    const before = remote.sessionId;
    await fromDesktop("h.capview");
    await until("a view session", () => remote.state.session?.cap === "view", 20000);
    expect(remote.sessionId, "a capability change gives a new session").not.toBe(before);
    expect((await incomingPlains()).some((b) => b.k === "reopen"), "the desktop told the device to reopen").toBe(true);
    await listEventually();
    expect(await remote.request({ op: "prompt", pane: P1, text: "should not run", queue: false })).toEqual({
      ok: false,
      code: "forbidden",
    });
    expect(await remote.request({ op: "interrupt", pane: P1 })).toEqual({ ok: false, code: "forbidden" });
    touch("d.phaseB");
  });

  it("loses its socket when the desktop removes the device, and cannot reconnect", async () => {
    await fromDesktop("h.removed");
    await until("the link to drop", () => remote.state.link !== "online", 20000);
    await until("link removed", () => remote.state.link === "removed", 30000);
    const errors = incoming
      .map((t) => parseServerFrame(t))
      .filter((f): f is { t: "error"; code: string } => f?.t === "error");
    expect(errors.some((e) => e.code === "unknown_device"), "the reconnect was answered unknown_device").toBe(true);
    // Never an unparsed leftover: every body that opens is well-formed.
    for (const text of incoming) {
      const f = parseServerFrame(text);
      if (f?.t !== "msg") continue;
      const p = await open(identity.linkKey, aadD2P(identity.desktopId, identity.deviceId), f.body);
      expect(p, "every relayed body opens under the link key").not.toBeNull();
      expect(parseBody(p)).not.toBeNull();
    }
    touch("d.done", "ok");
  });
});
