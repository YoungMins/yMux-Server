// Ties connection, sealing, session rules, command router and the live state the screens read.
import { b64uEncode } from "../protocol/encoding";
import {
  buildOpenBody,
  cmdFrame,
  needsReopen,
  parseBody,
  parseListData,
  type Cap,
  type Cmd,
  type Pane,
  type ReplyResult,
} from "../protocol/messages";
import { CommandRouter, type RequestHooks } from "../protocol/router";
import { aadD2P, aadP2D, open, seal } from "../protocol/seal";
import { OPEN_LIFETIME_MS, OpenGate, SessionTracker } from "../protocol/session";
import { cmdSigString, signString } from "../protocol/signing";
import { DeviceConnection, type Link } from "./connection";
import type { Identity } from "./storage";

export interface RemoteState {
  link: Link;
  desktopOnline: boolean;
  session: { cap: Cap; name: string } | null;
  /** null until the first `list` answered. */
  panes: Pane[] | null;
  /** Bodies ignored by the session rules or that did not open (debug indicator only). */
  dropped: number;
  /** When this page saw the computer go from reachable to not (epoch ms), else null. */
  offlineSince: number | null;
}

/** Link up, computer connected and a session open: commands can run. */
export function isOnline(s: RemoteState): boolean {
  return s.link === "online" && s.desktopOnline && s.session !== null;
}

/** A session is replaced at least this often while connected, so the clock offset cannot drift. */
export const REOPEN_EVERY_MS = 10 * 60 * 1000;

export function deviceWsUrl(loc: { protocol: string; host: string }): string {
  return `${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}/ws/device`;
}

export class Remote {
  state: RemoteState = {
    link: "connecting",
    desktopOnline: false,
    session: null,
    panes: null,
    dropped: 0,
    offlineSince: null,
  };
  onReady: (() => void) | null = null;
  /** Test seam (end-to-end only): added to every `ts_ms`. */
  tsSkewMs = 0;
  private listeners = new Set<() => void>();
  private conn: DeviceConnection;
  private router: CommandRouter;
  private tracker = new SessionTracker();
  private gate = new OpenGate();
  private openTimer: ReturnType<typeof setTimeout> | null = null;
  /** Fires when an `open` got no `session` inside its 10 s. */
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  /** Incoming bodies are opened one at a time so `n` is checked in arrival order. */
  private inChain: Promise<void> = Promise.resolve();

  /** `wsUrl` defaults to this page's own server; the end-to-end test points it elsewhere. */
  constructor(
    private readonly id: Identity,
    wsUrl: string = deviceWsUrl(location),
  ) {
    this.router = new CommandRouter({
      send: (frame) => {
        if (!this.conn.send(frame)) throw new Error("not connected");
      },
      seal: (plain) => seal(id.linkKey, aadP2D(id.desktopId, id.deviceId), plain),
      sign: (s) => signString(id.privateKey, s),
      tsMs: () => this.tracker.tsMs(Date.now()) + this.tsSkewMs,
      // A command with no trustworthy answer: a new session settles it from `prev`.
      onUnconfirmed: () => this.requestOpen(),
    });
    this.conn = new DeviceConnection({
      url: wsUrl,
      deviceId: id.deviceId,
      sign: (s) => signString(id.privateKey, s),
      onLink: (link) => {
        if (link === "online") this.set({ link });
        else {
          this.dropSession();
          this.gate.noteDisconnect();
          this.set({ link, desktopOnline: false, session: null });
        }
      },
      onReady: (desktopId, online) => {
        if (desktopId !== id.desktopId) {
          // The server answered for another desktop: nothing it relays here may be trusted.
          this.conn.stop();
          this.dropSession();
          this.set({ link: "removed", desktopOnline: false, session: null });
          return;
        }
        this.set({ desktopOnline: online });
        this.onReady?.();
        if (online) this.requestOpen();
      },
      onDesktop: (online) => {
        if (online) {
          this.set({ desktopOnline: true });
          this.requestOpen();
        } else {
          this.dropSession();
          this.set({ desktopOnline: false, session: null });
        }
      },
      onBody: (text) => {
        this.inChain = this.inChain.then(() => this.handleBody(text)).catch(() => undefined);
      },
      // A plaintext server frame says nothing the desktop signed: whatever was on the wire has an
      // unknown outcome (the frame may or may not have been delivered), never a failed one.
      onError: () => this.router.markUnknown(),
    });
  }

  /** The desktop this connection belongs to; everything it delivers is about this desktop only. */
  get desktopId(): string {
    return this.id.desktopId;
  }

  start(): void {
    this.stopped = false;
    this.conn.start();
  }
  stop(): void {
    this.stopped = true;
    this.conn.stop();
    this.dropSession();
  }
  reconnectNow(): void {
    this.conn.reconnectNow();
  }
  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  request(cmd: Cmd, hooks?: RequestHooks): Promise<ReplyResult> {
    return this.router.request(cmd, hooks);
  }
  sendFrame(frame: string): boolean {
    return this.conn.send(frame);
  }
  /** The current session id (end-to-end test only; never shown). */
  get sessionId(): string | null {
    return this.tracker.session;
  }
  /** Ask for a fresh session (rate limited: one per second, backing off while unanswered). */
  reopenSession(): void {
    this.requestOpen();
  }

  async refreshList(): Promise<void> {
    const r = await this.router.request({ op: "list" });
    if (r.ok) {
      const panes = parseListData(r.data);
      if (panes) this.set({ panes });
    } else if (r.code === "timeout") {
      this.conn.reconnectNow();
    }
  }

  private dropSession(): void {
    for (const t of [this.openTimer, this.expiryTimer, this.refreshTimer]) if (t !== null) clearTimeout(t);
    this.openTimer = this.expiryTimer = this.refreshTimer = null;
    this.tracker.reset();
    this.router.setSession(null);
  }

  private set(patch: Partial<RemoteState>): void {
    const was = isOnline(this.state);
    this.state = { ...this.state, ...patch };
    const now = isOnline(this.state);
    if (was && !now) this.state = { ...this.state, offlineSince: Date.now() };
    else if (now && this.state.offlineSince !== null) this.state = { ...this.state, offlineSince: null };
    for (const fn of [...this.listeners]) {
      try {
        fn();
      } catch {
        /* a view bug must not break the socket */
      }
    }
  }

  private requestOpen(): void {
    // One `open` at a time: while one is inside its 10 s, its `session` settles everything.
    if (this.stopped || this.openTimer !== null || this.tracker.openLive(Date.now())) return;
    this.openTimer = setTimeout(() => {
      this.openTimer = null;
      void this.sendOpen();
    }, this.gate.waitMs(Date.now()));
  }

  private async sendOpen(): Promise<void> {
    if (this.stopped || !this.conn.isOpen || !this.state.desktopOnline) return;
    const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(16)));
    const now = Date.now();
    this.gate.noteSent(now);
    this.tracker.beginOpen(nonce, now);
    // No `session` within 10 s: that `open` is dead, send another (behind the gate).
    if (this.expiryTimer !== null) clearTimeout(this.expiryTimer);
    this.expiryTimer = setTimeout(() => {
      this.expiryTimer = null;
      this.requestOpen();
    }, OPEN_LIFETIME_MS + 100);
    try {
      const plain = buildOpenBody(this.id.desktopId, this.id.deviceId, nonce);
      const body = await seal(this.id.linkKey, aadP2D(this.id.desktopId, this.id.deviceId), plain);
      this.conn.send(cmdFrame(body, await signString(this.id.privateKey, cmdSigString(body))));
    } catch {
      /* the next trigger tries again, behind the gate */
    }
  }

  private async handleBody(text: string): Promise<void> {
    const plain = await open(this.id.linkKey, aadD2P(this.id.desktopId, this.id.deviceId), text);
    const parsed = plain === null ? null : parseBody(plain);
    const b = parsed ? this.tracker.accept(parsed, Date.now()) : null;
    if (!b) {
      if (!parsed) this.tracker.dropped++;
      this.set({ dropped: this.tracker.dropped });
      // A session that came too late (or for a nonce that is gone): ask again.
      if (parsed?.k === "session") this.requestOpen();
      return;
    }
    if (b.k === "session") {
      this.gate.noteSession();
      if (this.expiryTimer !== null) clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
      this.router.setSession({ desktopId: this.id.desktopId, deviceId: this.id.deviceId, session: b.session }, b.prev);
      this.set({ session: { cap: b.cap, name: b.name }, desktopOnline: true });
      // Keep the clock offset fresh: replace the session at least every 10 minutes.
      if (this.refreshTimer !== null) clearTimeout(this.refreshTimer);
      this.refreshTimer = setTimeout(() => {
        this.refreshTimer = null;
        this.requestOpen();
      }, REOPEN_EVERY_MS);
      void this.refreshList();
    } else if (b.k === "panes") {
      this.set({ panes: b.panes });
    } else if (b.k === "reply") {
      if (b.re === 0 && !b.result.ok) this.router.handleRef(b.ref);
      else this.router.handleReply(b.re, b.result);
    }
    if (needsReopen(b)) this.requestOpen();
  }
}
