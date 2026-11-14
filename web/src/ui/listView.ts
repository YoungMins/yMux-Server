import { currentLang, t } from "../i18n";
import { desktopName } from "../model/desktops";
import { listSections, rowSubtitle, showsComputers } from "../model/chat";
import { formatSince } from "../model/panes";
import { paneHash, paneKey } from "../model/route";
import type { Pane } from "../protocol/messages";
import { connectionNotice, computerName, installHint, offlineSinceText, onlineText, statusDot, statusText } from "./common";
import { h, setChildren } from "./dom";
import { icon } from "./icons";
import type { Ctx, View } from "./view";

export interface ListView extends View {
  /** Marks the open conversation (wide screens show list and conversation side by side). */
  select: (key: string | null) => void;
}

function subtitleOf(el: HTMLElement, now: number): string {
  const since = Number(el.dataset.since);
  return rowSubtitle({
    ws: el.dataset.ws ?? "",
    computer: el.dataset.computer ? el.dataset.computer : null,
    status: el.dataset.status ?? "",
    since: since > 0 ? formatSince(since, now, currentLang()) : "",
  });
}

export function tickSince(root: ParentNode): void {
  const now = Date.now();
  for (const el of root.querySelectorAll<HTMLElement>("[data-sub]")) {
    const text = subtitleOf(el, now);
    if (el.textContent !== text) el.textContent = text;
  }
}

export function listView(ctx: Ctx): ListView {
  const body = h("div", { class: "list" });
  const el = h(
    "div",
    { class: "pane-col" },
    h(
      "header",
      { class: "topbar" },
      h("h1", { class: "topbar__title" }, t("app.name")),
      h("a", { class: "iconbtn", href: "#settings", "aria-label": t("nav.settings") }, icon("settings")),
    ),
    h("div", { class: "scroll" }, body),
  );
  let selected: string | null = null;

  const row = (desktopId: string, p: Pane, computer: string | null): HTMLElement => {
    const key = paneKey({ desktopId, pane: p.pane });
    const sub = h("span", {
      class: "row__sub",
      "data-sub": "",
      "data-ws": p.ws,
      "data-computer": computer ?? "",
      "data-status": statusText(p.status),
      "data-since": p.since_ms > 0 ? String(p.since_ms) : null,
    });
    return h(
      "a",
      {
        class: `row row--${p.status}`,
        href: paneHash({ desktopId, pane: p.pane }),
        "data-pane-key": key,
        "aria-current": key === selected ? "page" : null,
      },
      statusDot(p.status),
      h(
        "span",
        { class: "row__main" },
        h(
          "span",
          { class: "row__top" },
          h("span", { class: "row__title" }, p.title || t("list.untitled")),
          p.status === "waiting" ? h("span", { class: "pill" }, t("list.needsAnswer")) : null,
        ),
        sub,
      ),
    );
  };

  const render = (): void => {
    const entries = ctx.fleet.entries();
    const sections = listSections(
      entries.map((e) => ({
        desktopId: e.pairing.desktopId,
        name: computerName(desktopName(e.remote.state.session?.name, e.pairing.desktopName)),
        panes: e.remote.state.panes,
      })),
    );
    const multi = showsComputers(sections);
    const parts: (Node | null)[] = [];
    if (!multi) {
      const only = entries[0]?.remote;
      const notice = only ? connectionNotice(only) : null;
      if (notice) parts.push(h("p", { class: "notice", role: "status" }, notice));
    }
    parts.push(installHint());
    for (const s of sections) {
      const entry = ctx.fleet.get(s.desktopId);
      if (!entry) continue;
      if (multi) {
        const since = offlineSinceText(entry.remote);
        const notice = connectionNotice(entry.remote);
        parts.push(
          h(
            "div",
            { class: "section" },
            h("h2", { class: "section__name" }, s.name),
            h("span", { class: "section__state" }, onlineText(entry.remote)),
            since ? h("span", { class: "section__state" }, since) : null,
          ),
        );
        if (notice) parts.push(h("p", { class: "notice", role: "status" }, notice));
      }
      if (s.panes.length === 0 && entry.remote.state.panes !== null) {
        parts.push(h("p", { class: "muted pad" }, t("list.empty")));
      }
      for (const p of s.panes) parts.push(row(s.desktopId, p, multi ? s.name : null));
    }
    setChildren(body, ...parts);
    tickSince(body);
  };

  render();
  const unsub = ctx.fleet.subscribe(render);
  const timer = setInterval(() => tickSince(body), 1000);
  return {
    el,
    select: (key) => {
      selected = key;
      for (const a of body.querySelectorAll<HTMLElement>("[data-pane-key]")) {
        if (a.dataset.paneKey === key) a.setAttribute("aria-current", "page");
        else a.removeAttribute("aria-current");
      }
    },
    destroy: () => {
      unsub();
      clearInterval(timer);
    },
  };
}
