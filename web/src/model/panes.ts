// Pure list model: ordering, grouping, relative time.
import type { Pane, PaneStatus } from "../protocol/messages";

const RANK: Record<PaneStatus, number> = { waiting: 0, working: 1, done: 2, idle: 3, none: 4 };

/** Waiting first (longest waiting first), then working, done, idle, none (newest first). */
export function comparePanes(a: Pane, b: Pane): number {
  const r = RANK[a.status] - RANK[b.status];
  if (r !== 0) return r;
  if (a.since_ms !== b.since_ms) {
    if (a.since_ms === 0) return 1;
    if (b.since_ms === 0) return -1;
    return a.status === "waiting" ? a.since_ms - b.since_ms : b.since_ms - a.since_ms;
  }
  return a.title.localeCompare(b.title) || a.pane.localeCompare(b.pane);
}

export function sortPanes(panes: readonly Pane[]): Pane[] {
  return [...panes].sort(comparePanes);
}

export type TimeUnit = "second" | "minute" | "hour" | "day";
export interface RelTime {
  value: number; // negative = in the past, as Intl.RelativeTimeFormat expects
  unit: TimeUnit;
}

export function relTime(sinceMs: number, nowMs: number): RelTime | null {
  if (!Number.isFinite(sinceMs) || sinceMs <= 0 || !Number.isFinite(nowMs)) return null;
  const s = Math.max(0, Math.floor((nowMs - sinceMs) / 1000));
  if (s < 60) return { value: -s, unit: "second" };
  if (s < 3600) return { value: -Math.floor(s / 60), unit: "minute" };
  if (s < 86400) return { value: -Math.floor(s / 3600), unit: "hour" };
  return { value: -Math.floor(s / 86400), unit: "day" };
}

export function formatSince(sinceMs: number, nowMs: number, lang: string): string {
  const r = relTime(sinceMs, nowMs);
  if (!r) return "";
  try {
    return new Intl.RelativeTimeFormat(lang, { numeric: "auto", style: "short" }).format(r.value, r.unit);
  } catch {
    return `${-r.value} ${r.unit}`;
  }
}
