// /ws/pair flow (PROTOCOL.md section 4). The code is the HKDF salt and the HMAC key of the proof;
// the link key itself comes from the key agreement, so the code alone cannot produce it.
import { b64uDecode, b64uEncode, isUuid } from "../protocol/encoding";
import { pairRequestFrame, parseJson, parseServerFrame, asRec } from "../protocol/messages";
import { aadD2P, open } from "../protocol/seal";
import { hmacProof, pairProofMessage, pairSigString, signString } from "../protocol/signing";

export interface PairLink {
  desktopId: string;
  /** The 16 pairing-code bytes. Wiped by the caller once the code has served. */
  code: Uint8Array<ArrayBuffer>;
  /** The desktop's key-agreement public key (b64u raw P-256 point), made fresh for this window. */
  dk: string;
}

export type PairParse = { ok: true; link: PairLink } | { ok: false; reason: "old" | "bad" };

/** A raw uncompressed P-256 point in canonical b64u (so the string in `info` is unambiguous). */
export function isValidDk(s: string): boolean {
  const b = b64uDecode(s);
  return !!b && b.length === 65 && b[0] === 4 && b64uEncode(b) === s;
}

/**
 * `#pair=<desktop_id>.<b64u code>.<dk>`. A link without a valid `dk` comes from a yMux that
 * predates the key agreement: `old` (the page tells the user to update yMux). Anything else
 * that does not parse is `bad`.
 */
export function parsePairLink(hash: string): PairParse {
  const m = /^#pair=([^.&]+)\.([A-Za-z0-9_-]+)(?:\.([^.&]*))?$/.exec(hash);
  if (!m || !isUuid(m[1])) return { ok: false, reason: "bad" };
  const code = b64uDecode(m[2]);
  if (!code || code.length !== 16) return { ok: false, reason: "bad" };
  const dk = m[3];
  if (dk === undefined || !isValidDk(dk)) return { ok: false, reason: "old" };
  return { ok: true, link: { desktopId: m[1], code, dk } };
}

export function parsePairFragment(hash: string): PairLink | null {
  const p = parsePairLink(hash);
  return p.ok ? p.link : null;
}

export type PairOutcome = "ok" | "refused" | "no_pairing" | "timeout" | "error";

export interface PairParams {
  url: string;
  link: PairLink;
  deviceId: string;
  pubkey: string;
  /** This pairing's `ek` public key (b64u), sent in the request. */
  ek: string;
  name: string;
  privateKey: CryptoKey;
  /** The link key, already derived. It opens `pair_challenge`. */
  linkKey: CryptoKey;
  onSent: () => void;
  /** A `pair_challenge` that opened under the link key and carried a 6-digit check number. */
  onCheck: (digits: string) => void;
  timeoutMs?: number;
  socket?: (url: string) => WebSocket;
}

export function pairWsUrl(loc: { protocol: string; host: string }): string {
  return `${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}/ws/pair`;
}

/** The check number inside an opened `pair_challenge` body; null for anything else. */
export function parsePairCheck(plain: string | null): string | null {
  const r = plain === null ? null : asRec(parseJson(plain));
  return r && r.k === "pair_check" && typeof r.check === "string" && /^\d{6}$/.test(r.check) ? r.check : null;
}

export function runPairing(p: PairParams): Promise<PairOutcome> {
  return new Promise<PairOutcome>((resolve) => {
    let ws: WebSocket;
    try {
      ws = (p.socket ?? ((u) => new WebSocket(u)))(p.url);
    } catch {
      resolve("error");
      return;
    }
    let settled = false;
    let sent = false;
    let shown = false;
    const done = (r: PairOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.onmessage = ws.onclose = ws.onerror = null;
      try {
        ws.close();
      } catch {
        /* already closed */
      }
      resolve(r);
    };
    // The desktop asks its user first, so allow a little longer than the 120 s window.
    const timer = setTimeout(() => done("timeout"), p.timeoutMs ?? 150000);

    // Frames are handled one at a time, in arrival order: "the newest check number" means the
    // newest to arrive, and a `pair_result` is judged after every challenge before it.
    let chain: Promise<void> = Promise.resolve();
    const handle = async (f: NonNullable<ReturnType<typeof parseServerFrame>>): Promise<void> => {
      if (settled) return;
      if (f.t === "challenge" && !sent) {
        sent = true;
        try {
          const proof = await hmacProof(p.link.code, pairProofMessage(p.link.desktopId, p.deviceId, p.pubkey, p.ek));
          const sig = await signString(p.privateKey, pairSigString(p.deviceId, f.nonce));
          ws.send(
            pairRequestFrame({
              desktopId: p.link.desktopId,
              deviceId: p.deviceId,
              pubkey: p.pubkey,
              ek: p.ek,
              name: p.name,
              proof,
              sig,
            }),
          );
          p.onSent();
        } catch {
          done("error");
        }
      } else if (f.t === "pair_challenge") {
        // Only a body that opens under OUR link key counts; the number comes from nowhere else.
        if (!sent) return;
        const check = parsePairCheck(await open(p.linkKey, aadD2P(p.link.desktopId, p.deviceId), f.body));
        if (check === null || settled) return;
        shown = true;
        p.onCheck(check);
      } else if (f.t === "pair_result") {
        // A plaintext `ok:true` proves nothing by itself (the caller still waits for a session),
        // but one that comes without any check number having been shown is not a pairing.
        done(f.ok ? (shown ? "ok" : "error") : "refused");
      } else if (f.t === "error") {
        done(f.code === "no_pairing" ? "no_pairing" : "error");
      }
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") return;
      const f = parseServerFrame(ev.data);
      if (f) chain = chain.then(() => handle(f)).catch(() => done("error"));
    };
    // After every frame that already arrived (the server closes right after `pair_result`).
    const fail = (): void => {
      chain = chain.then(() => done("error"));
    };
    ws.onclose = fail;
    ws.onerror = fail;
  });
}
