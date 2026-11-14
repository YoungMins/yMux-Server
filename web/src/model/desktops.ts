// Pure ordering of the desktop sections in the agent list.
import type { Pane } from "../protocol/messages";

export interface DesktopSummary {
  desktopId: string;
  name: string;
  panes: readonly Pane[] | null;
}

export const hasWaiting = (panes: readonly Pane[] | null): boolean => !!panes?.some((p) => p.status === "waiting");

/** Desktops with a waiting agent first, then by name (then id, so the order is total). */
export function sortDesktops<T extends DesktopSummary>(list: readonly T[]): T[] {
  return [...list].sort((a, b) => {
    const w = Number(hasWaiting(b.panes)) - Number(hasWaiting(a.panes));
    return w || a.name.localeCompare(b.name) || a.desktopId.localeCompare(b.desktopId);
  });
}

/** The name the computer last told us, else the one stored at pairing, else "". */
export const desktopName = (sessionName: string | undefined, storedName: string): string =>
  sessionName || storedName;
