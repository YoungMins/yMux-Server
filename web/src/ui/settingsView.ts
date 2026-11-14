import { LANGS, LANG_NAMES, currentLang, isLang, savedLang, setLang, t, type Key } from "../i18n";
import { desktopName } from "../model/desktops";
import { disablePush, enablePush, pushStatus, pushSupported, type PushStatus } from "../net/push";
import { isOnline } from "../net/remote";
import { computerName, installHint, offlineSinceText, onlineText } from "./common";
import { h, setChildren } from "./dom";
import { icon } from "./icons";
import type { Ctx, View } from "./view";

const NOTIF_TEXT: Record<PushStatus, Key> = {
  unsupported: "settings.notifUnsupported",
  denied: "settings.notifDenied",
  on: "settings.notifEnabled",
  off: "settings.notifDisabled",
};

const CONFIRM_MS = 3000;

function pairedDate(ms: number): string {
  if (!(ms > 0)) return "";
  try {
    return new Intl.DateTimeFormat(currentLang(), { dateStyle: "medium" }).format(new Date(ms));
  } catch {
    return new Date(ms).toLocaleDateString();
  }
}

export function settingsView(ctx: Ctx): View {
  const notifBox = h("div", { class: "rows" });
  const computersBox = h("div", { class: "rows" });
  let status: PushStatus = pushSupported() ? "off" : "unsupported";
  let error = "";
  let working = false;
  /** The Remove button waiting for its second tap: a desktop id, or "all". */
  let armed: string | null = null;
  let armTimer: ReturnType<typeof setTimeout> | null = null;

  const paintNotif = (): void => {
    const canToggle = status === "on" || status === "off";
    setChildren(
      notifBox,
      h(
        "div",
        { class: "srow" },
        h("div", { class: "srow__text" }, h("div", { class: "srow__label" }, t(NOTIF_TEXT[status]))),
        canToggle
          ? h(
              "button",
              {
                class: `btn ${status === "on" ? "btn--quiet" : "btn--primary"}`,
                type: "button",
                disabled: working,
                onclick: () => void onToggle(),
              },
              t(status === "on" ? "settings.notifOff" : "settings.notifOn"),
            )
          : null,
      ),
      error ? h("p", { class: "notice", role: "alert" }, error) : null,
    );
  };

  async function onToggle(): Promise<void> {
    if (working) return;
    working = true;
    error = "";
    paintNotif();
    try {
      if (status === "on") {
        await disablePush(ctx.fleet.remotes());
        status = "off";
      } else {
        status = await enablePush(ctx.fleet.remotes());
      }
    } catch {
      error = t("settings.notifFailed");
      status = await pushStatus();
    } finally {
      working = false;
      paintNotif();
    }
  }

  function arm(id: string): boolean {
    if (armed === id) {
      armed = null;
      if (armTimer) clearTimeout(armTimer);
      return true;
    }
    armed = id;
    if (armTimer) clearTimeout(armTimer);
    armTimer = setTimeout(() => {
      armed = null;
      paintComputers();
    }, CONFIRM_MS);
    paintComputers();
    return false;
  }

  const removeButton = (id: string, label: Key, confirm: Key, run: () => Promise<void>): HTMLElement => {
    const on = armed === id;
    return h(
      "button",
      {
        class: `btn btn--danger${on ? " is-armed" : ""}`,
        type: "button",
        onclick: (ev) => {
          if (!arm(id)) return;
          (ev.currentTarget as HTMLButtonElement).disabled = true;
          void run();
        },
      },
      t(on ? confirm : label),
    );
  };

  function paintComputers(): void {
    const entries = ctx.fleet.entries();
    const rows = entries.map(({ pairing, remote }) => {
      const s = remote.state;
      const name = computerName(desktopName(s.session?.name, pairing.desktopName));
      const since = offlineSinceText(remote);
      const date = pairedDate(pairing.addedMs);
      return h(
        "div",
        { class: "srow srow--wrap" },
        h(
          "div",
          { class: "srow__text" },
          h("div", { class: "srow__label" }, name),
          h("div", { class: "srow__value" }, `${onlineText(remote)}${since ? ` · ${since}` : ""}`),
          date ? h("div", { class: "srow__value" }, t("computers.paired", { date })) : null,
          s.session && isOnline(s) ? h("div", { class: "srow__value" }, t("settings.access", { cap: t(`cap.${s.session.cap}` as Key) })) : null,
        ),
        removeButton(pairing.desktopId, "computers.remove", "computers.removeConfirm", async () => {
          await ctx.removePairing(pairing.desktopId);
          if (ctx.fleet.size === 0) ctx.go("#");
        }),
      );
    });
    setChildren(computersBox, ...rows, h("p", { class: "hint" }, h("strong", null, t("computers.add")), " ", t("computers.addHint")));
  }

  void pushStatus().then((s) => {
    status = s;
    paintNotif();
  });
  paintNotif();
  paintComputers();
  const unsub = ctx.fleet.subscribe(paintComputers);

  const select = h(
    "select",
    {
      class: "select",
      id: "lang",
      onchange: (ev) => {
        const v = (ev.target as HTMLSelectElement).value;
        setLang(isLang(v) ? v : null);
        location.reload();
      },
    },
    h("option", { value: "auto", selected: savedLang() === null }, t("settings.langAuto")),
    ...LANGS.map((l) => h("option", { value: l, selected: savedLang() === l }, LANG_NAMES[l])),
  );

  const dropped = ctx.fleet.remotes().reduce((n, r) => n + r.state.dropped, 0);
  const removeAllBox = h("div", { class: "rows" });
  const paintRemoveAll = (): void => {
    setChildren(
      removeAllBox,
      h(
        "div",
        { class: "srow" },
        h(
          "div",
          { class: "srow__text" },
          h("div", { class: "srow__label" }, t("settings.forgetHelp")),
          dropped > 0 ? h("div", { class: "srow__value" }, t("settings.dropped", { n: dropped })) : null,
        ),
        removeButton("all", "settings.forget", "settings.forgetConfirm", async () => {
          await ctx.removeAll();
        }),
      ),
    );
  };
  paintRemoveAll();
  const unsubAll = ctx.fleet.subscribe(paintRemoveAll);

  const el = h(
    "div",
    { class: "pane-col" },
    h(
      "header",
      { class: "topbar" },
      h("a", { class: "iconbtn back", href: "#", "aria-label": t("nav.back") }, icon("back")),
      h("h1", { class: "topbar__title" }, t("settings.title")),
    ),
    h(
      "div",
      { class: "scroll" },
      h(
        "div",
        { class: "settings" },
        installHint(),
        h("section", { class: "sgroup" }, h("h2", { class: "sgroup__label" }, t("settings.notifications")), notifBox),
        h("section", { class: "sgroup" }, h("h2", { class: "sgroup__label" }, t("computers.title")), computersBox),
        h(
          "section",
          { class: "sgroup" },
          h("h2", { class: "sgroup__label" }, h("label", { for: "lang" }, t("settings.language"))),
          h("div", { class: "rows" }, h("div", { class: "srow" }, select)),
        ),
        h("section", { class: "sgroup" }, h("h2", { class: "sgroup__label" }, t("settings.device")), removeAllBox),
      ),
    ),
  );
  return {
    el,
    destroy: () => {
      unsub();
      unsubAll();
      if (armTimer) clearTimeout(armTimer);
    },
  };
}
