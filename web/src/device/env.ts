// Small, pure-ish helpers about the device the page runs on.

/** A short editable default for the pairing name, from the user agent. */
export function deviceNameFromUA(ua: string): string {
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua)) return "iPad";
  if (/Android/i.test(ua)) {
    const m = /Android [\d.]+;\s*([^;)]+?)(?:\s+Build\/[^;)]*)?[;)]/.exec(ua);
    const model = m?.[1]?.trim();
    if (model && !/^(wv|mobile|k)$/i.test(model)) return model.slice(0, 40);
    return "Android";
  }
  if (/Windows/i.test(ua)) return "Windows browser";
  if (/Macintosh|Mac OS X/i.test(ua)) return "Mac browser";
  if (/Linux/i.test(ua)) return "Linux browser";
  return "Browser";
}

export function isIos(ua: string, platform: string, touchPoints: number): boolean {
  return /iPhone|iPad|iPod/i.test(ua) || (platform === "MacIntel" && touchPoints > 1);
}

export function isStandalone(): boolean {
  try {
    const nav = navigator as Navigator & { standalone?: boolean };
    return nav.standalone === true || window.matchMedia("(display-mode: standalone)").matches;
  } catch {
    return false;
  }
}

/** iOS only allows Web Push for installed PWAs. */
export function needsInstallHint(): boolean {
  try {
    return isIos(navigator.userAgent, navigator.platform, navigator.maxTouchPoints) && !isStandalone();
  } catch {
    return false;
  }
}
