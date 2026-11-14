// Fills the build-time placeholders of public/sw.js: the precache list, a build id and the table of
// fixed notification strings (PROTOCOL.md section 6: the device shows fixed text chosen by `kind`,
// never text taken from the push). The worker cannot import the app bundle, so the strings it needs
// are copied out of the app's own dictionaries here.
import { LANGS, TABLE } from "../src/i18n/index";

/** The only strings the service worker uses. */
export const SW_KEYS = ["app.name", "push.waiting", "push.done"] as const;

export type SwStrings = Record<string, Record<(typeof SW_KEYS)[number], string>>;

export function swStrings(): SwStrings {
  const out: SwStrings = {};
  for (const lang of LANGS) {
    const dict = TABLE[lang] as Record<string, string>;
    const row = {} as Record<(typeof SW_KEYS)[number], string>;
    for (const k of SW_KEYS) row[k] = dict[k] ?? "";
    out[lang] = row;
  }
  return out;
}

export function injectSw(source: string, files: string[], build: string): string {
  return source
    .replace('["__PRECACHE__"]', () => JSON.stringify(files))
    .replace('"__BUILD__"', () => JSON.stringify(build))
    .replace("/*__STRINGS__*/{}", () => JSON.stringify(swStrings()));
}
