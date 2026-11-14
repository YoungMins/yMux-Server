import { t } from "./i18n";
import { paneKey, parsePaneHash, resolvePaneHash, paneHash, type PaneRef } from "./model/route";
import { Fleet } from "./net/fleet";
import { parsePairLink, type PairParse } from "./net/pairing";
import { promoteIfConfirmed } from "./net/provisional";
import { dropBrowserSubscription, disablePush, resyncPush } from "./net/push";
import { Remote } from "./net/remote";
import { clearAll, loadPairings, savePairings, type Pairing } from "./net/storage";
import { isUuid } from "./protocol/encoding";
import { detailView } from "./ui/detailView";
import { h } from "./ui/dom";
import { listView, type ListView } from "./ui/listView";
import { pairView, unpairedView } from "./ui/pairView";
import { settingsView } from "./ui/settingsView";
import type { AddOutcome, Ctx, View } from "./ui/view";

interface Shell {
  el: HTMLElement;
  main: HTMLElement;
  list: ListView;
}

export function startApp(root: HTMLElement): void {
  let legacy = false;
  let view: View | null = null;
  let shell: Shell | null = null;
  // The old `#pane=<uuid>` form that cannot be placed yet (lists still loading, or two owners).
  let pendingLegacy = false;
  // Kept in memory only: the fragment is stripped after pairing, the code is never stored.
  let pairParse: PairParse | null = null;

  // Writes are queued so an older list can never overwrite a newer one.
  let saving: Promise<unknown> = Promise.resolve();
  const persist = (list: readonly Pairing[]): Promise<boolean> => {
    const p = saving.then(() => savePairings(list));
    saving = p.catch(() => undefined);
    return p;
  };

  const fleet = new Fleet({
    // Every connect and reconnect of every pairing: that server gets the browser's subscription.
    onReady: (remote) => void resyncPush(remote).catch(() => undefined),
    onName: () => void persist(fleet.pairings()),
  });

  const ctx: Ctx = {
    fleet,
    get legacy() {
      return legacy;
    },
    go: (hash) => {
      const target = hash === "#" ? "" : hash;
      if (location.hash === target || (target === "" && location.hash === "#")) render();
      else location.hash = target;
    },
    addPairing: async (p: Pairing): Promise<AddOutcome> => {
      // Provisional until the computer opens a session under the new key; only then does it
      // replace anything. The probe connection is separate from the fleet's.
      const res = await promoteIfConfirmed(() => fleet.pairings(), p, (x) => new Remote(x));
      if (!res.ok) return res;
      if (!(await persist(res.list))) return { ok: false, reason: "save" };
      legacy = false;
      fleet.sync(res.list); // starts the new connection; its onReady sends the push subscription
      return res;
    },
    removePairing: async (desktopId) => {
      fleet.remove(desktopId); // push_unsubscribe on its connection, then close
      if (fleet.size === 0) {
        await dropBrowserSubscription().catch(() => undefined);
        await clearAll();
      } else {
        await persist(fleet.pairings());
      }
      render();
    },
    removeAll: async () => {
      try {
        await disablePush(fleet.remotes());
      } catch {
        /* the keys are deleted either way */
      }
      fleet.stopAll();
      await clearAll();
      ctx.go("#");
    },
  };

  function destroyShell(): void {
    shell?.list.destroy?.();
    shell = null;
  }

  function ensureShell(): Shell {
    if (shell) return shell;
    const list = listView(ctx);
    const main = h("div", { class: "main" });
    const side = h("aside", { class: "side" }, list.el);
    const el = h("div", { class: "shell" }, side, main);
    shell = { el, main, list };
    return shell;
  }

  function route(hash: string): { kind: "settings" } | { kind: "pane"; ref: PaneRef } | { kind: "home" } {
    if (hash === "#settings") return { kind: "settings" };
    const ph = parsePaneHash(hash);
    pendingLegacy = false;
    if (ph) {
      const ref = resolvePaneHash(
        ph,
        fleet.entries().map((e) => ({ desktopId: e.pairing.desktopId, panes: e.remote.state.panes })),
      );
      if (ref) {
        if (ph.desktopId === null) {
          try {
            history.replaceState(null, "", paneHash(ref)); // the old link, in its current form
          } catch {
            /* ignore */
          }
        }
        return { kind: "pane", ref };
      }
      pendingLegacy = ph.desktopId === null;
    }
    return { kind: "home" };
  }

  function render(): void {
    view?.destroy?.();
    view = null;
    const hash = location.hash;
    if (hash.startsWith("#pair=")) {
      pairParse = parsePairLink(hash);
      destroyShell();
      view = pairView(ctx, pairParse);
      root.replaceChildren(view.el);
    } else if (fleet.size === 0) {
      destroyShell();
      view = unpairedView(legacy);
      root.replaceChildren(view.el);
    } else {
      const s = ensureShell();
      const r = route(hash);
      if (r.kind === "settings") view = settingsView(ctx);
      else if (r.kind === "pane") view = detailView(ctx, r.ref);
      else view = { el: h("div", { class: "pane-col empty" }, h("p", { class: "muted" }, t("main.empty"))) };
      s.el.className = `shell ${r.kind === "home" ? "shell--home" : "shell--page"}`;
      s.list.select(r.kind === "pane" ? paneKey(r.ref) : null);
      s.main.replaceChildren(view.el);
      if (root.firstElementChild !== s.el) root.replaceChildren(s.el);
    }
    window.scrollTo(0, 0);
  }

  // The old link form resolves once the lists that can answer it have arrived.
  fleet.subscribe(() => {
    if (!pendingLegacy) return;
    const ph = parsePaneHash(location.hash);
    if (!ph) return;
    const found = resolvePaneHash(
      ph,
      fleet.entries().map((e) => ({ desktopId: e.pairing.desktopId, panes: e.remote.state.panes })),
    );
    if (found) render();
  });

  window.addEventListener("hashchange", render);
  window.addEventListener("online", () => fleet.reconnectAll());
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) fleet.wake();
  });

  // Keep the composer above the on-screen keyboard.
  const vv = window.visualViewport;
  if (vv) {
    const fit = (): void => {
      document.documentElement.style.setProperty("--app-h", `${Math.round(vv.height)}px`);
      if (vv.offsetTop > 0) window.scrollTo(0, 0);
    };
    vv.addEventListener("resize", fit);
    vv.addEventListener("scroll", fit);
    fit();
  }

  try {
    navigator.serviceWorker?.addEventListener("message", (ev: MessageEvent) => {
      const d = ev.data as { type?: unknown; pane?: unknown } | null;
      if (d && d.type === "open-pane" && isUuid(d.pane)) ctx.go(`#pane=${d.pane}`);
    });
  } catch {
    /* no service worker support */
  }

  void loadPairings().then((stored) => {
    legacy = stored.legacy;
    fleet.sync(stored.pairings);
    render();
  });
}
