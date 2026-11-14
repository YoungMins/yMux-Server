// The device's pairings live in IndexedDB as ONE list; the CryptoKeys (non-extractable) are stored
// as they are. One pairing = one (desktop, device) pair with its own device id, signing key and
// link key: a key is never shared between desktops.
export interface Identity {
  deviceId: string;
  desktopId: string;
  pubkey: string;
  /** This device's name as shown on the computer. */
  name: string;
  privateKey: CryptoKey;
  /** AES-256-GCM link key (non-extractable), derived from the pairing code at pairing time. */
  linkKey: CryptoKey;
}

export interface Pairing extends Identity {
  /** The computer's name as last seen in a session message ("" until the first one). */
  desktopName: string;
  /** When this pairing was made, epoch ms. */
  addedMs: number;
}

export const MAX_PAIRINGS = 8;

const DB = "ymux-remote";
const STORE = "kv";
const KEY_LIST = "pairings";
/** The single identity of versions before the list existed. */
const KEY_LEGACY = "identity";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

function hasBase(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r.deviceId === "string" &&
    typeof r.desktopId === "string" &&
    typeof r.pubkey === "string" &&
    typeof r.name === "string" &&
    typeof CryptoKey !== "undefined" &&
    r.privateKey instanceof CryptoKey
  );
}

export function validIdentity(v: unknown): v is Identity {
  return hasBase(v) && v.linkKey instanceof CryptoKey;
}

/** A stored record (or a single old identity) as a pairing; null when it is not a complete one. */
export function toPairing(v: unknown): Pairing | null {
  if (!validIdentity(v)) return null;
  const r = v as Identity & Partial<Pairing>;
  return {
    deviceId: r.deviceId,
    desktopId: r.desktopId,
    pubkey: r.pubkey,
    name: r.name,
    privateKey: r.privateKey,
    linkKey: r.linkKey,
    desktopName: typeof r.desktopName === "string" ? r.desktopName : "",
    addedMs: typeof r.addedMs === "number" && Number.isFinite(r.addedMs) ? r.addedMs : 0,
  };
}

export interface Stored {
  pairings: Pairing[];
  /** A pairing from before link keys existed: unusable, the user must pair again. */
  legacy: boolean;
  /** The list came from the single-identity shape and should be written back in the new one. */
  migrated: boolean;
}

/** Pure: what the two stored values mean. */
export function interpretStored(list: unknown, single: unknown): Stored {
  if (Array.isArray(list)) {
    const seen = new Set<string>();
    const pairings: Pairing[] = [];
    for (const item of list) {
      const p = toPairing(item);
      if (!p || seen.has(p.desktopId) || pairings.length >= MAX_PAIRINGS) continue;
      seen.add(p.desktopId);
      pairings.push(p);
    }
    return { pairings, legacy: pairings.length === 0 && hasBase(single), migrated: false };
  }
  const p = toPairing(single);
  if (p) return { pairings: [{ ...p, addedMs: p.addedMs || Date.now() }], legacy: false, migrated: true };
  return { pairings: [], legacy: hasBase(single), migrated: false };
}

export type AddResult =
  | { ok: true; list: Pairing[]; replaced: boolean }
  | { ok: false; reason: "full" | "reused_key" };

/**
 * A new desktop is appended; the same desktop again replaces only its own pairing (in place).
 * A device id or public key already used for ANOTHER desktop is refused: keys are per desktop.
 */
export function addPairing(list: readonly Pairing[], p: Pairing): AddResult {
  if (list.some((x) => x.desktopId !== p.desktopId && (x.deviceId === p.deviceId || x.pubkey === p.pubkey))) {
    return { ok: false, reason: "reused_key" };
  }
  const i = list.findIndex((x) => x.desktopId === p.desktopId);
  if (i >= 0) {
    const next = [...list];
    next[i] = p;
    return { ok: true, list: next, replaced: true };
  }
  if (list.length >= MAX_PAIRINGS) return { ok: false, reason: "full" };
  return { ok: true, list: [...list, p], replaced: false };
}

export function removePairing(list: readonly Pairing[], desktopId: string): Pairing[] {
  return list.filter((x) => x.desktopId !== desktopId);
}

export async function loadPairings(): Promise<Stored> {
  try {
    const [list, single] = await Promise.all([
      run("readonly", (s) => s.get(KEY_LIST)),
      run("readonly", (s) => s.get(KEY_LEGACY)),
    ]);
    const stored = interpretStored(list, single);
    if (stored.migrated) await savePairings(stored.pairings);
    return stored;
  } catch {
    return { pairings: [], legacy: false, migrated: false };
  }
}

/** Writes the whole list; the old single-identity record goes with it. */
export async function savePairings(list: readonly Pairing[]): Promise<boolean> {
  try {
    await run("readwrite", (s) => s.put([...list], KEY_LIST));
    try {
      await run("readwrite", (s) => s.delete(KEY_LEGACY));
    } catch {
      /* the list wins over the old record anyway */
    }
    return true;
  } catch {
    return false;
  }
}

export async function clearAll(): Promise<void> {
  try {
    await run("readwrite", (s) => s.clear());
  } catch {
    /* nothing stored, or storage unavailable */
  }
  try {
    indexedDB.deleteDatabase(DB);
  } catch {
    /* ignore */
  }
}
