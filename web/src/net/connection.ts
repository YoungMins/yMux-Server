// /ws/device: handshake (PROTOCOL.md 3.2), reconnect with backoff (7), frame delivery.
import { backoffDelay } from "../protocol/backoff";
import { deviceHello, parseServerFrame } from "../protocol/messages";
import { deviceHelloString } from "../protocol/signing";

export type Link = "connecting" | "online" | "offline" | "removed";

export interface ConnectionOptions {
  url: string;
  deviceId: string;
  sign: (s: string) => Promise<string>;
  onLink: (link: Link) => void;
  onReady: (desktopId: string, desktopOnline: boolean) => void;
  onDesktop: (online: boolean) => void;
  onBody: (body: string) => void;
  /** Server error frame after the handshake (e.g. `desktop_offline`). */
  onError: (code: string) => void;
}

const HANDSHAKE_TIMEOUT_MS = 10000;

export class DeviceConnection {
  private ws: WebSocket | null = null;
  private ready = false;
  private stopped = true;
  private attempt = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private hsTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly o: ConnectionOptions) {}

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.attempt = 0;
    this.open();
  }

  stop(): void {
    this.stopped = true;
    this.clearTimers();
    this.detach();
  }

  /** Drop the socket (if any) and connect again immediately. */
  reconnectNow(): void {
    if (this.stopped) return;
    this.clearTimers();
    this.detach();
    this.attempt = 0;
    this.open();
  }

  /** True when the frame was handed to an open, authenticated socket. */
  send(frame: string): boolean {
    if (!this.ready || !this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    try {
      this.ws.send(frame);
      return true;
    } catch {
      return false;
    }
  }

  get isOpen(): boolean {
    return this.ready;
  }

  private clearTimers(): void {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.hsTimer) clearTimeout(this.hsTimer);
    this.retryTimer = null;
    this.hsTimer = null;
  }

  private detach(): void {
    const ws = this.ws;
    this.ws = null;
    this.ready = false;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* already closed */
      }
    }
  }

  private open(): void {
    this.clearTimers();
    this.o.onLink("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.o.url);
    } catch {
      this.scheduleRetry();
      return;
    }
    this.ws = ws;
    this.ready = false;
    this.hsTimer = setTimeout(() => {
      if (this.ws === ws && !this.ready) this.failed(ws);
    }, HANDSHAKE_TIMEOUT_MS);

    ws.onmessage = (ev) => {
      if (this.ws !== ws || typeof ev.data !== "string") return;
      void this.onFrame(ws, ev.data);
    };
    ws.onclose = () => {
      if (this.ws === ws) this.failed(ws);
    };
    ws.onerror = () => {
      /* onclose follows */
    };
  }

  private failed(ws: WebSocket): void {
    if (this.ws !== ws) return;
    this.detach();
    if (this.stopped) return;
    this.o.onLink("offline");
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (this.stopped) return;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.o.onLink("offline");
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (!this.stopped) this.open();
    }, backoffDelay(this.attempt++));
  }

  private async onFrame(ws: WebSocket, text: string): Promise<void> {
    const f = parseServerFrame(text);
    if (!f) return;
    if (!this.ready) {
      if (f.t === "challenge") {
        try {
          const sig = await this.o.sign(deviceHelloString(this.o.deviceId, f.nonce));
          if (this.ws === ws) ws.send(deviceHello(this.o.deviceId, sig));
        } catch {
          this.failed(ws);
        }
      } else if (f.t === "ready") {
        if (this.hsTimer) clearTimeout(this.hsTimer);
        this.hsTimer = null;
        this.ready = true;
        this.attempt = 0;
        this.o.onLink("online");
        this.o.onReady(f.desktopId, f.desktopOnline);
      } else if (f.t === "error") {
        if (f.code === "unknown_device" || f.code === "bad_sig") {
          this.stopped = true;
          this.clearTimers();
          this.detach();
          this.o.onLink("removed");
        } else {
          this.failed(ws);
        }
      }
      return;
    }
    switch (f.t) {
      case "desktop_online":
        this.o.onDesktop(true);
        break;
      case "desktop_offline":
        this.o.onDesktop(false);
        break;
      case "msg":
        this.o.onBody(f.body);
        break;
      case "error":
        this.o.onError(f.code);
        break;
      default:
        break;
    }
  }
}
