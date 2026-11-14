import { describe, expect, it } from "vitest";
import { en } from "./en";
import { LANGS, TABLE, format, isRtl, matchLang } from "./index";

const placeholders = (s: string): string[] => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).sort();

describe("i18n", () => {
  it("has the 13 languages in the required order", () => {
    expect([...LANGS]).toEqual(["en", "ko", "ja", "zh", "hi", "es", "fr", "ar", "pt", "ru", "tr", "de", "vi"]);
  });
  it("has no gaps: every language has exactly the English keys, non-empty, same placeholders", () => {
    const keys = Object.keys(en).sort();
    expect(keys.length).toBeGreaterThan(50);
    for (const lang of LANGS) {
      const dict = TABLE[lang] as Record<string, string>;
      expect(Object.keys(dict).sort(), lang).toEqual(keys);
      for (const k of keys) {
        expect(typeof dict[k], `${lang}.${k}`).toBe("string");
        expect(dict[k]!.trim().length, `${lang}.${k}`).toBeGreaterThan(0);
        expect(placeholders(dict[k]!), `${lang}.${k}`).toEqual(placeholders((en as Record<string, string>)[k]!));
      }
    }
  });
  it("non-English languages really are translated", () => {
    for (const lang of LANGS.filter((l) => l !== "en")) {
      const same = Object.keys(en).filter((k) => (TABLE[lang] as Record<string, string>)[k] === (en as Record<string, string>)[k]);
      expect(same.length, `${lang} copies English: ${same.join(",")}`).toBeLessThan(10); // cognates (Agents, Prompt, Question...) legitimately match
    }
  });
  it("detects the browser language and sets rtl only for Arabic", () => {
    expect(matchLang("pt-BR")).toBe("pt");
    expect(matchLang("zh-Hant-TW")).toBe("zh");
    expect(matchLang("ar")).toBe("ar");
    expect(matchLang("sv")).toBe("en");
    expect(matchLang(undefined)).toBe("en");
    expect(LANGS.filter(isRtl)).toEqual(["ar"]);
  });
  it("fills placeholders and leaves unknown ones alone", () => {
    expect(format("{n} queued", { n: 3 })).toBe("3 queued");
    expect(format("{x}", { n: 1 })).toBe("{x}");
  });
});
