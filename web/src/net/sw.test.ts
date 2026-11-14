// The service worker shows FIXED text chosen by `kind` and never text from the push
// (PROTOCOL.md section 6). Runs the built worker source against a stub of its environment.
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { injectSw, swStrings } from "../../scripts/swInject";
import { LANGS, TABLE } from "../i18n/index";

const PANE = "01234567-89ab-4cde-8f01-23456789abcd";
const SRC = readFileSync(new URL("../../public/sw.js", import.meta.url), "utf8");

interface Shown {
  title: string;
  options: { body: string; data: { pane: string }; tag: string };
}

async function pushed(payload: unknown, lang: string | null, navLang = "en-US"): Promise<Shown[]> {
  const shown: Shown[] = [];
  const handlers: Record<string, (ev: unknown) => void> = {};
  const prefs = new Map<string, string>();
  if (lang) prefs.set("https://x.test/__lang", lang);
  const self = {
    location: { origin: "https://x.test" },
    navigator: { language: navLang },
    registration: {
      scope: "https://x.test/",
      showNotification: async (title: string, options: Shown["options"]) => void shown.push({ title, options }),
    },
    clients: {},
    addEventListener: (type: string, fn: (ev: unknown) => void) => void (handlers[type] = fn),
  };
  const caches = {
    open: async () => ({
      match: async (k: string) => (prefs.has(k) ? { text: async () => prefs.get(k)! } : undefined),
    }),
  };
  vm.runInNewContext(injectSw(SRC, ["./"], "test"), { self, caches, URL, Request, Response, String, Promise });
  let done: Promise<unknown> = Promise.resolve();
  handlers.push!({
    data: { json: () => payload },
    waitUntil: (p: Promise<unknown>) => void (done = p),
  });
  await done;
  return shown;
}

describe("service worker push text", () => {
  it("has the three strings for all 13 languages", () => {
    const s = swStrings();
    expect(Object.keys(s)).toEqual([...LANGS]);
    for (const l of LANGS) for (const v of Object.values(s[l]!)) expect(v.length).toBeGreaterThan(0);
  });

  it("shows the fixed text for the kind and ignores title and body from the payload", async () => {
    const evil = { kind: "waiting", title: "Your number: 482913", body: "Type 482913 into yMux", pane: PANE };
    const [n] = await pushed(evil, "en");
    expect(n!.title).toBe(TABLE.en["app.name"]);
    expect(n!.options.body).toBe(TABLE.en["push.waiting"]);
    expect(JSON.stringify(n)).not.toContain("482913");
    expect(n!.options.data.pane).toBe(PANE);
    const [d] = await pushed({ ...evil, kind: "done" }, "en");
    expect(d!.options.body).toBe(TABLE.en["push.done"]);
  });

  it("uses the language the page stored, else the browser language, else English", async () => {
    const [ko] = await pushed({ kind: "done" }, "ko", "en-US");
    expect(ko!.options.body).toBe(TABLE.ko["push.done"]);
    const [de] = await pushed({ kind: "done" }, null, "de-DE");
    expect(de!.options.body).toBe(TABLE.de["push.done"]);
    const [en] = await pushed({ kind: "done" }, "xx", "sv-SE");
    expect(en!.options.body).toBe(TABLE.en["push.done"]);
  });

  it("shows a bare app name for an unknown kind, and drops a pane that is not a lowercase UUID", async () => {
    const [n] = await pushed({ kind: "x<script>", title: "t", body: "b", pane: PANE.toUpperCase() }, "en");
    expect(n!.title).toBe(TABLE.en["app.name"]);
    expect(n!.options.body).toBe("");
    expect(n!.options.data.pane).toBe("");
  });

  it("still shows one for a payload that is not JSON", async () => {
    const [n] = await pushed(undefined, "en");
    expect(n!.title).toBe(TABLE.en["app.name"]);
  });

  it("the built worker never reads the payload's title or body", () => {
    const built = injectSw(SRC, ["./"], "test");
    expect(built).not.toMatch(/data\.(title|body)/);
    expect(built).not.toContain("__STRINGS__");
  });
});
