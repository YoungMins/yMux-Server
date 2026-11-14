// Pane routes. A pane id is only unique per desktop, so every route, cache key and DOM id is
// keyed by (desktop id, pane id). Pure: no DOM, no sockets.
import { isUuid } from "../protocol/encoding";
import type { Pane } from "../protocol/messages";

export interface PaneRef {
  desktopId: string;
  pane: string;
}

/** What a `#pane=` hash says: the old form has no desktop. */
export interface PaneHash {
  desktopId: string | null;
  pane: string;
}

/** The one string used for cache keys and DOM ids. */
export const paneKey = (r: PaneRef): string => `${r.desktopId}.${r.pane}`;

export const paneHash = (r: PaneRef): string => `#pane=${paneKey(r)}`;

/** `#pane=<desktop_id>.<pane uuid>` or the old `#pane=<pane uuid>`. */
export function parsePaneHash(hash: string): PaneHash | null {
  if (!hash.startsWith("#pane=")) return null;
  const parts = hash.slice(6).split(".");
  if (parts.length === 1 && isUuid(parts[0])) return { desktopId: null, pane: parts[0] };
  if (parts.length === 2 && isUuid(parts[0]) && isUuid(parts[1])) return { desktopId: parts[0], pane: parts[1] };
  return null;
}

export interface DesktopPanes {
  desktopId: string;
  /** null until that desktop's first list arrived. */
  panes: readonly Pane[] | null;
}

/**
 * The pane a hash points at, or null when it cannot be told (yet): then the list is shown.
 * The old form is resolved from the loaded lists; with one pairing it can only mean that desktop.
 */
export function resolvePaneHash(h: PaneHash, desktops: readonly DesktopPanes[]): PaneRef | null {
  if (h.desktopId !== null) {
    return desktops.some((d) => d.desktopId === h.desktopId) ? { desktopId: h.desktopId, pane: h.pane } : null;
  }
  if (desktops.length === 1) return { desktopId: desktops[0]!.desktopId, pane: h.pane };
  const owners = desktops.filter((d) => d.panes?.some((p) => p.pane === h.pane));
  return owners.length === 1 ? { desktopId: owners[0]!.desktopId, pane: h.pane } : null;
}
