"use strict";
// yMux Remote service worker: offline app shell + Web Push (PROTOCOL.md section 6).
// The build fills in FILES and BUILD (vite.config.ts); in dev they stay placeholders.
const BUILD = "__BUILD__";
const FILES = ["__PRECACHE__"];
// Fixed notification strings per language (scripts/swInject.ts); empty in dev.
const STRINGS = /*__STRINGS__*/{};
const CACHE = "ymux-remote-" + BUILD;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      await Promise.all(
        FILES.filter((f) => f !== "__PRECACHE__").map(async (f) => {
          try {
            await cache.add(new Request(f, { cache: "reload" }));
          } catch (_) {
            /* one missing file must not block the install */
          }
        }),
      );
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) {
        if (key.startsWith("ymux-remote-") && key !== CACHE) await caches.delete(key);
      }
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (/^\/(api|ws|healthz)(\/|$)/.test(url.pathname)) return;
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).catch(async () => (await caches.match("./")) || (await caches.match("index.html")) || Response.error()),
    );
    return;
  }
  event.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
});

// The page stores its language here (src/i18n/index.ts); a worker cannot read localStorage.
async function pageLang() {
  try {
    const cache = await caches.open("ymux-prefs");
    const hit = await cache.match(new URL("__lang", self.registration.scope).href);
    const v = hit ? (await hit.text()).trim() : "";
    if (STRINGS[v]) return v;
  } catch (_) {
    /* fall back to the browser language */
  }
  const base = String((self.navigator && self.navigator.language) || "en")
    .toLowerCase()
    .split(/[-_]/)[0];
  return STRINGS[base] ? base : "en";
}

self.addEventListener("push", (event) => {
  event.waitUntil(
    (async () => {
      let data = {};
      try {
        data = event.data ? event.data.json() : {};
      } catch (_) {
        data = {};
      }
      if (!data || typeof data !== "object") data = {};
      // The text of a push is chosen by whoever can send one (a compromised server included), so
      // none of it is shown: the notification is built from fixed strings picked by `kind`.
      // Only `pane` is used, as the click target, and only when it is a lowercase UUID.
      // Always show one: iOS revokes a subscription whose pushes show nothing.
      const pane = typeof data.pane === "string" && UUID.test(data.pane) ? data.pane : "";
      const kind = data.kind === "waiting" || data.kind === "done" ? data.kind : "";
      const table = STRINGS[await pageLang()] || STRINGS.en || {};
      await self.registration.showNotification(table["app.name"] || "yMux", {
        body: kind ? table["push." + kind] || "" : "",
        tag: pane ? "pane-" + pane : "ymux",
        renotify: true,
        icon: "icons/icon-192.png",
        badge: "icons/icon-192.png",
        data: { pane },
      });
    })(),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const pane = event.notification.data && UUID.test(event.notification.data.pane) ? event.notification.data.pane : "";
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      const target = windows[0];
      if (target) {
        await target.focus();
        if (pane) target.postMessage({ type: "open-pane", pane });
        return;
      }
      await self.clients.openWindow(self.registration.scope + (pane ? "#pane=" + pane : ""));
    })(),
  );
});
