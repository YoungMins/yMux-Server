import { en, type Dict, type Key } from "./en";
import { ar, es, fr, pt } from "./l2";
import { hi, ja, ko, zh } from "./l1";
import { de, ru, tr, vi } from "./l3";

export type { Key };

/** Order is part of the contract (CLAUDE-side docs and the settings picker use it). */
export const LANGS = ["en", "ko", "ja", "zh", "hi", "es", "fr", "ar", "pt", "ru", "tr", "de", "vi"] as const;
export type Lang = (typeof LANGS)[number];

export const TABLE: Record<Lang, Dict> = { en, ko, ja, zh, hi, es, fr, ar, pt, ru, tr, de, vi };

export const LANG_NAMES: Record<Lang, string> = {
  en: "English",
  ko: "한국어",
  ja: "日本語",
  zh: "中文",
  hi: "हिन्दी",
  es: "Español",
  fr: "Français",
  ar: "العربية",
  pt: "Português",
  ru: "Русский",
  tr: "Türkçe",
  de: "Deutsch",
  vi: "Tiếng Việt",
};

const STORE_KEY = "ymux-remote-lang";

export function isLang(v: unknown): v is Lang {
  return typeof v === "string" && (LANGS as readonly string[]).includes(v);
}

/** "pt-BR" -> "pt"; unknown -> "en". */
export function matchLang(tag: unknown): Lang {
  if (typeof tag !== "string") return "en";
  const base = tag.toLowerCase().split(/[-_]/)[0];
  return isLang(base) ? base : "en";
}

export function isRtl(lang: Lang): boolean {
  return lang === "ar";
}

/** The user's saved choice, or null for "automatic". */
export function savedLang(): Lang | null {
  try {
    const v = localStorage.getItem(STORE_KEY);
    return isLang(v) ? v : null;
  } catch {
    return null;
  }
}

let current: Lang = "en";

export function currentLang(): Lang {
  return current;
}

export function initLang(): Lang {
  current = savedLang() ?? matchLang(typeof navigator !== "undefined" ? navigator.language : "en");
  applyLang();
  return current;
}

/** null = automatic. */
export function setLang(lang: Lang | null): Lang {
  try {
    if (lang) localStorage.setItem(STORE_KEY, lang);
    else localStorage.removeItem(STORE_KEY);
  } catch {
    /* storage unavailable: the choice lasts for this page only */
  }
  current = lang ?? matchLang(typeof navigator !== "undefined" ? navigator.language : "en");
  applyLang();
  return current;
}

function applyLang(): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = current;
  document.documentElement.dir = isRtl(current) ? "rtl" : "ltr";
  rememberForWorker(current);
}

/** Where the service worker reads the page's language (it cannot read localStorage). */
export const WORKER_PREFS_CACHE = "ymux-prefs";
export const WORKER_LANG_PATH = "__lang";

function rememberForWorker(lang: Lang): void {
  try {
    if (typeof caches === "undefined") return;
    const key = new URL(WORKER_LANG_PATH, document.baseURI).href;
    void caches
      .open(WORKER_PREFS_CACHE)
      .then((c) => c.put(key, new Response(lang)))
      .catch(() => undefined);
  } catch {
    /* best effort: the worker then follows the browser language */
  }
}

export function format(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in params ? String(params[k]) : m));
}

export function t(key: Key, params?: Record<string, string | number>): string {
  return format(TABLE[current][key] ?? en[key], params);
}
