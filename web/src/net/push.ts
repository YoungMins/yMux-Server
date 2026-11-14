// Web Push enrolment (PROTOCOL.md section 6). Must be called from a user gesture.
import { b64uDecode } from "../protocol/encoding";
import { asRec, pushSubscribeFrame, pushUnsubscribeFrame, toPushSub, type PushSub } from "../protocol/messages";
import type { Remote } from "./remote";

export type PushStatus = "unsupported" | "denied" | "on" | "off";

export function pushSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "serviceWorker" in navigator &&
    typeof PushManager !== "undefined" &&
    typeof Notification !== "undefined"
  );
}

async function currentSubscription(): Promise<PushSubscription | null> {
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    return (await reg?.pushManager.getSubscription()) ?? null;
  } catch {
    return null;
  }
}

export async function pushStatus(): Promise<PushStatus> {
  if (!pushSupported()) return "unsupported";
  if (Notification.permission === "denied") return "denied";
  return (await currentSubscription()) && Notification.permission === "granted" ? "on" : "off";
}

async function vapidKey(): Promise<Uint8Array<ArrayBuffer>> {
  const res = await fetch("/api/info", { cache: "no-store" });
  const info = asRec(await res.json());
  const key = b64uDecode(info?.vapid);
  if (!key) throw new Error("no vapid key");
  return key;
}

/** Anything frames can be sent to: a Remote, or a stand-in in tests. */
export interface FrameSink {
  sendFrame(frame: string): boolean;
}

/** The same frame to every connection; how many took it. A connection that is down is skipped. */
export function fanOut(sinks: Iterable<FrameSink>, frame: string): number {
  let n = 0;
  for (const s of sinks) if (s.sendFrame(frame)) n++;
  return n;
}

export async function enablePush(remotes: readonly Remote[]): Promise<PushStatus> {
  // Asking for permission has to be the first thing: it needs the click's user activation.
  const perm = await Notification.requestPermission();
  if (perm !== "granted") return perm === "denied" ? "denied" : "off";
  const reg = await navigator.serviceWorker.ready;
  const existing = await reg.pushManager.getSubscription();
  const sub =
    existing ??
    (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: await vapidKey() }));
  const wire = toPushSub(sub.toJSON());
  // The same browser subscription goes to every pairing; ones that are down get it on reconnect.
  if (!wire || fanOut(remotes, pushSubscribeFrame(wire)) === 0) {
    if (!existing) await sub.unsubscribe().catch(() => false);
    throw new Error("subscribe failed");
  }
  return "on";
}

/** Drops the browser's subscription (after the servers were told, or when no pairing is left). */
export async function dropBrowserSubscription(): Promise<void> {
  const sub = await currentSubscription();
  await sub?.unsubscribe().catch(() => false);
}

export async function disablePush(remotes: readonly FrameSink[]): Promise<void> {
  fanOut(remotes, pushUnsubscribeFrame());
  await dropBrowserSubscription();
}

async function currentWire(): Promise<PushSub | null> {
  if (!pushSupported() || Notification.permission !== "granted") return null;
  const sub = await currentSubscription();
  return sub ? toPushSub(sub.toJSON()) : null;
}

/** After every reconnect and after a new pairing: keep that server's copy of the subscription. */
export async function resyncPush(sink: FrameSink, getWire: () => Promise<PushSub | null> = currentWire): Promise<void> {
  const wire = await getWire();
  if (wire) sink.sendFrame(pushSubscribeFrame(wire));
}
