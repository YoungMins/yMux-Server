// PROTOCOL.md 5.2: text from the desktop or server is cleaned again before it is shown.
// Drops Unicode categories Cc, Cf, Zl, Zp (controls, format characters, line/paragraph
// separators), which hide or reorder text (bidi overrides, zero-width characters, escapes).

const STRIP = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** What a device name that cleans to nothing becomes (same word as the desktop and the server). */
export const UNNAMED_DEVICE = "Unnamed device";
export const MAX_DEVICE_NAME = 40;

/**
 * A device name as every party shows it: a stranger can choose one, and it appears next to the
 * prompt for the check number, so it must not carry a number or punctuation that frames a fake
 * instruction. Keeps letters, marks, spaces and `. - _ '`; drops every digit (Nd) and all other
 * punctuation and symbols; collapses whitespace; at most 40 characters; never empty.
 */
export function cleanDeviceName(s: string): string {
  const kept = cleanText(s.slice(0, MAX_DEVICE_NAME * 4))
    .replace(/[^\p{L}\p{M}\s.\-_']/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  const out = Array.from(kept).slice(0, MAX_DEVICE_NAME).join("").trim();
  return out === "" ? UNNAMED_DEVICE : out;
}

/**
 * Multi-line message text (PROTOCOL.md 5.2, `chat` user/assistant texts): CR and CRLF become LF,
 * LF and tab stay, every other Cc/Cf/Zl/Zp character goes.
 */
export function cleanBlock(s: string): string {
  return s.replace(/\r\n?/g, "\n").replace(STRIP, (m) => (m === "\n" || m === "\t" ? m : ""));
}

/** `keepNewline` is for values that are multi-line by design; every other control goes. */
export function cleanText(s: string, keepNewline = false): string {
  return s.replace(STRIP, (m) => (keepNewline && m === "\n" ? m : ""));
}
