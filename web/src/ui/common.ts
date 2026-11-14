import { currentLang, t, type Key } from "../i18n";
import { needsInstallHint } from "../device/env";
import { isOnline, type Remote } from "../net/remote";
import type { PaneStatus, ReplyResult } from "../protocol/messages";
import { COULD_NOT_CONFIRM, DELIVERED_UNKNOWN, NOT_DELIVERED } from "../protocol/router";
import { h } from "./dom";

/**
 * Status as a dot of one size and shape family (a 10 px circle); the word is always next to it
 * (colour is never the only signal). Working pulses, waiting is the attention colour, done is
 * muted and filled, idle and no agent are a hollow ring.
 */
export function statusDot(status: PaneStatus): HTMLElement {
  return h("span", { class: `sdot sdot--${status}`, "aria-hidden": "true" });
}

export const statusText = (status: PaneStatus): string => t(`status.${status}` as Key);

/** The name to show for a computer: what it told us, else what was stored, else a plain word. */
export const computerName = (name: string): string => name || t("desktop.unnamed");

/** Online indicator text for one computer. */
export function onlineText(remote: Remote): string {
  const s = remote.state;
  if (isOnline(s)) return t("desktop.online");
  if (s.link === "connecting" && s.offlineSince === null) return t("conn.connecting");
  return t("desktop.offline");
}

/** "Offline since 14:32" (or with the date when it is not today); null when it is not offline. */
export function offlineSinceText(remote: Remote, now = Date.now()): string | null {
  const s = remote.state;
  if (isOnline(s) || s.offlineSince === null) return null;
  const d = new Date(s.offlineSince);
  const sameDay = new Date(now).toDateString() === d.toDateString();
  let when: string;
  try {
    when = new Intl.DateTimeFormat(currentLang(), sameDay ? { timeStyle: "short" } : { dateStyle: "short", timeStyle: "short" }).format(d);
  } catch {
    when = d.toLocaleString();
  }
  return t("desktop.offlineSince", { when });
}

/** Banner for what is wrong with the connection, or null when all is well. */
export function connectionNotice(remote: Remote | null): string | null {
  if (!remote) return null;
  const s = remote.state;
  if (s.link === "removed") return t("conn.removed");
  if (s.link === "connecting") return t("conn.connecting");
  if (s.link === "offline") return t("conn.offline");
  if (!s.desktopOnline) return t("conn.desktopOffline");
  if (!s.session) return t("conn.noSession");
  return null;
}

export function installHint(): HTMLElement | null {
  return needsInstallHint() ? h("p", { class: "note" }, t("install.ios")) : null;
}

/** A plain-words line for a failed request. */
export function errorText(code: string): string {
  switch (code) {
    case "timeout":
      return t("err.timeout");
    case "forbidden":
      return t("err.forbidden");
    case "expired":
      return t("err.expired");
    case "bad_session":
      return t("err.session");
    case "desktop_offline":
      return t("conn.desktopOffline");
    case DELIVERED_UNKNOWN:
      return t("res.deliveredUnknown");
    case NOT_DELIVERED:
      return t("res.notDelivered");
    case COULD_NOT_CONFIRM:
      return t("res.couldNotConfirm");
    case "no_session":
    case "offline":
    case "session_changed":
      return t("err.offline");
    default:
      return t("err.generic", { code });
  }
}

const RESULT_KEY: Record<string, Key> = {
  sent: "res.sent",
  queued: "res.queued",
  waiting: "res.waiting",
  blocked: "res.blocked",
  refused: "res.refused",
  gone: "res.gone",
  failed: "res.failed",
  stale: "res.stale",
};

export function resultText(r: ReplyResult, result: string | null): string {
  if (!r.ok) return errorText(r.code);
  return result && RESULT_KEY[result] ? t(RESULT_KEY[result]) : t("res.failed");
}
