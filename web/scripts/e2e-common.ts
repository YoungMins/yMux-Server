// Shared by the end-to-end device scripts (e2e-device.ts, e2e-fleet.ts). Importing this module
// replaces the global WebSocket with a browser-like one: it adds the Origin header a browser would
// send and records every frame, per socket, so a script can look at what really crossed the wire.
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const BASE = process.env.E2E_URL ?? "";
if (!BASE) throw new Error("E2E_URL is required");
export const ORIGIN = new URL(BASE).origin;
export const WS_BASE = BASE.replace(/^http/, "ws");

export interface Sock {
  /** Set once the socket sent its device hello. */
  deviceId: string | null;
  incoming: string[];
  outgoing: string[];
  /**
   * Hands the page's handler a frame as if the server had sent it (a hostile or confused relay).
   * It is not recorded in `incoming`, which only holds what really crossed the wire.
   */
  forge: (text: string) => void;
}

const NativeWS = globalThis.WebSocket;
/** Every socket opened, oldest first. */
export const socks: Sock[] = [];
/** Every frame of every socket (the single-desktop script has one device). */
export const incoming: string[] = [];
export const outgoing: string[] = [];
export const hooks = {
  /** Change one character of the next outgoing `cmd` body (the signature then fails). */
  tamperNext: false,
  /** Swallow the next outgoing `cmd` frame: the relay loses it (it is still recorded in `outgoing`). */
  dropNextCmd: false,
  /** Discard every `msg` frame the server sends, as a relay that withholds replies would. */
  dropMsg: false,
  /** Send the next outgoing `cmd` frame twice, as a relay that forwards a frame again would. */
  duplicateNextCmd: false,
};

export function socksFor(deviceId: string): Sock[] {
  return socks.filter((s) => s.deviceId === deviceId);
}

/** The newest socket of this device. */
export function lastSock(deviceId: string): Sock {
  const s = socksFor(deviceId).at(-1);
  if (!s) throw new Error(`no socket for ${deviceId}`);
  return s;
}

class TestWS extends NativeWS {
  private forging = false;
  private readonly sock: Sock = {
    deviceId: null,
    incoming: [],
    outgoing: [],
    forge: (text) => {
      this.forging = true;
      try {
        this.dispatchEvent(new MessageEvent("message", { data: text }));
      } finally {
        this.forging = false;
      }
    },
  };

  constructor(url: string | URL) {
    super(url, { headers: { Origin: ORIGIN } } as unknown as string[]);
    socks.push(this.sock);
    this.addEventListener("message", (ev) => {
      if (this.forging) return;
      const text = String(ev.data);
      incoming.push(text);
      this.sock.incoming.push(text);
    });
    // The page's `onmessage` runs behind a filter, so a relay that drops replies can be played.
    let handler: ((ev: MessageEvent) => unknown) | null = null;
    Object.defineProperty(this, "onmessage", {
      configurable: true,
      get: () => handler,
      set: (fn: ((ev: MessageEvent) => unknown) | null) => {
        handler = fn;
      },
    });
    this.addEventListener("message", (ev) => {
      const text = String(ev.data);
      if (hooks.dropMsg && !this.forging && text.includes('"t":"msg"')) return;
      handler?.call(this, ev);
    });
  }

  override send(data: string): void {
    if (hooks.dropNextCmd && data.includes('"t":"cmd"')) {
      hooks.dropNextCmd = false;
      outgoing.push(data);
      this.sock.outgoing.push(data);
      return;
    }
    let out = data;
    if (hooks.tamperNext && data.includes('"t":"cmd"')) {
      hooks.tamperNext = false;
      const f = JSON.parse(data) as { body: string; sig: string };
      // Still a well-formed sealed body of the same length; one character differs, so the
      // signature (made over the original string) no longer verifies.
      const i = 20;
      const swapped = f.body[i] === "A" ? "B" : "A";
      out = JSON.stringify({ ...f, body: f.body.slice(0, i) + swapped + f.body.slice(i + 1) });
    }
    if (this.sock.deviceId === null && out.includes('"role":"device"')) {
      try {
        this.sock.deviceId = (JSON.parse(out) as { device_id: string }).device_id;
      } catch {
        /* not a hello */
      }
    }
    outgoing.push(out);
    this.sock.outgoing.push(out);
    super.send(out);
    if (hooks.duplicateNextCmd && out.includes('"t":"cmd"')) {
      hooks.duplicateNextCmd = false;
      outgoing.push(out);
      this.sock.outgoing.push(out);
      super.send(out);
    }
  }
}
(globalThis as { WebSocket: unknown }).WebSocket = TestWS;

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function until<T>(what: string, fn: () => T | null | undefined | false, ms = 30000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(25);
  }
}

export async function untilAsync<T>(
  what: string,
  fn: () => Promise<T | null | undefined | false>,
  ms = 30000,
): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(50);
  }
}

/** A rendezvous directory shared with one desktop-side test. */
export function rendezvous(dir: string) {
  return {
    dir,
    touch: (name: string, text = "1") => writeFileSync(join(dir, name), text),
    /** Wait for a file the desktop wrote (it writes files atomically). */
    fromDesktop: (name: string, ms = 90000) =>
      until(`${name} from the desktop test`, () => existsSync(join(dir, name)), ms),
  };
}
