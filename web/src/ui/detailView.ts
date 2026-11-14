import { currentLang, t } from "../i18n";
import { composerAccess, composerMode, growLayout, promptConsumed, reportTarget, shouldQueue } from "../model/chat";
import { desktopName } from "../model/desktops";
import { menuChoices, type Choice } from "../model/menu";
import { formatSince } from "../model/panes";
import { paneKey, type PaneRef } from "../model/route";
import { isOnline } from "../net/remote";
import {
  capAllows,
  parsePeekData,
  parseResultData,
  startsWithBang,
  type Pane,
  type PaneStatus,
  type Peek,
  type ReplyResult,
} from "../protocol/messages";
import { COULD_NOT_CONFIRM, DELIVERED_UNKNOWN, NOT_DELIVERED } from "../protocol/router";
import { computerName, connectionNotice, errorText, resultText, statusText } from "./common";
import { h, setChildren } from "./dom";
import { icon } from "./icons";
import type { Ctx, View } from "./view";

const POLL_MS = 2000;
const PEEK_LINES = 80;
const CONFIRM_MS = 3000;
const BUBBLE_MS = 4000;
const FADE_MS = 500;
const MAX_ROWS = 6;
const PROMPT_RESULTS = ["sent", "queued", "waiting", "blocked", "refused", "gone", "failed"];
const SETTLED_CODES: readonly string[] = [DELIVERED_UNKNOWN, NOT_DELIVERED, COULD_NOT_CONFIRM];

export function detailView(ctx: Ctx, ref: PaneRef): View {
  // Every command of this screen goes to the connection of THIS desktop and no other.
  const remote = ctx.fleet.get(ref.desktopId)?.remote;
  const paneId = ref.pane;
  const key = paneKey(ref);

  let peek: Peek | null = null;
  let inflight = false;
  let busy = false;
  let optionsSig = "";
  let stick = true;
  let confirmTimer: ReturnType<typeof setTimeout> | null = null;
  let bubbleTimer: ReturnType<typeof setTimeout> | null = null;
  let fadeTimer: ReturnType<typeof setTimeout> | null = null;
  let confirming = false;
  let destroyed = false;
  let message = "";
  let placeholder = "";
  /** The running action is a send: its result belongs on the bubble, not in the note. */
  let bubbleOwned = false;

  const title = h("h1", { class: "topbar__title" });
  const sub = h("span", { class: "topbar__sub" });
  const notice = h("p", { class: "notice", role: "status" });
  const gone = h("p", { class: "notice" }, t("detail.gone"));
  const screen = h("pre", { class: "screen", tabindex: "0", "aria-label": t("detail.screen") });
  const scroll = h("div", { class: "scroll conv__scroll" }, notice, gone, screen);

  const questionBox = h("div", { class: "qcard" });
  const bubble = h("div", { class: "bubble", role: "status", "aria-live": "polite" });
  bubble.hidden = true;
  const note = h("p", { class: "noteline", role: "status", "aria-live": "polite" });
  const accessLine = h("p", { class: "noteline noteline--solo" });
  const textarea = h("textarea", {
    class: "composer__input",
    id: `msg-${key}`,
    rows: "1",
    maxlength: "16000",
    "aria-label": t("detail.prompt"),
  });
  const action = h("button", { class: "roundbtn", type: "button" });
  const form = h("form", { class: "composer" }, textarea, action);
  const foot = h("div", { class: "conv__foot" }, questionBox, bubble, form, accessLine, note);

  const el = h(
    "div",
    { class: "pane-col conv" },
    h(
      "header",
      { class: "topbar" },
      h("a", { class: "iconbtn back", href: "#", "aria-label": t("nav.back") }, icon("back")),
      h("div", { class: "topbar__titles" }, title, sub),
    ),
    scroll,
    foot,
  );

  const pane = (): Pane | undefined => remote?.state.panes?.find((p) => p.pane === paneId);
  const cap = (): "view" | "respond" | "prompt" | null => remote?.state.session?.cap ?? null;
  const ready = (): boolean => !!remote && remote.state.link === "online" && !!remote.state.session;
  const status = (): PaneStatus => pane()?.status ?? peek?.status ?? "none";
  const say = (text: string): void => {
    message = text;
    paintNote();
  };

  scroll.addEventListener("scroll", () => {
    stick = scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 24;
  });

  const noteText = (): string => {
    if (startsWithBang(textarea.value)) return t("detail.bangWarn");
    if (message) return message;
    if (textarea.value.trim() !== "" && shouldQueue(status())) return t("detail.queueNote");
    return "";
  };
  function paintNote(): void {
    const text = noteText();
    note.textContent = text;
    note.hidden = text === "";
  }

  const grow = (): void => {
    textarea.style.height = "auto";
    const cs = getComputedStyle(textarea);
    const px = (v: string): number => parseFloat(v) || 0;
    const border = px(cs.borderTopWidth) + px(cs.borderBottomWidth);
    const chrome = px(cs.paddingTop) + px(cs.paddingBottom) + border;
    // The box is border-box: scrollHeight leaves the borders out, so they are added back.
    const g = growLayout(textarea.scrollHeight + border, px(cs.lineHeight) || 22, chrome, MAX_ROWS);
    textarea.style.height = `${g.height}px`;
    textarea.style.overflowY = g.overflowY;
  };

  const paintAction = (): void => {
    const mode = composerMode(textarea.value, status(), cap(), ready() && !busy);
    const armed = mode === "stop" && confirming;
    action.disabled = mode === "disabled";
    action.className = `roundbtn${mode === "stop" ? " roundbtn--stop" : ""}${armed ? " is-armed" : ""}`;
    action.dataset.mode = mode;
    action.setAttribute(
      "aria-label",
      mode === "stop" ? (armed ? t("detail.interruptConfirm") : t("detail.interrupt")) : t("detail.send"),
    );
    setChildren(action, icon(mode === "stop" ? "stop" : "send"));
  };

  const paintOptions = (): void => {
    const canRespond = capAllows(cap(), "respond");
    const choices = menuChoices(paneId, peek, canRespond, busy);
    // The signature includes the menu id: buttons are rebuilt (and rebound) whenever it changes.
    const sig = JSON.stringify([choices.map((c) => c.option), peek?.menuId ?? "", canRespond, busy, peek?.question ?? []]);
    if (sig === optionsSig) return;
    optionsSig = sig;
    const q = peek?.question ?? [];
    setChildren(
      questionBox,
      ...(q.length ? [h("h2", { class: "qcard__label" }, t("detail.question")), ...q.map((line) => h("p", { class: "q" }, line))] : []),
      ...choices.map((c) => {
        const o = c.option;
        return h(
          "div",
          { class: "option" },
          h(
            "button",
            {
              class: `optbtn${o.selected ? " optbtn--primary" : ""}`,
              type: "button",
              disabled: c.disabled,
              onclick: () => void answer(c),
            },
            `${o.n}. ${o.label}`,
          ),
          c.note ? h("span", { class: "muted" }, t(c.note === "input" ? "detail.inputNote" : "detail.tooHighNote")) : null,
        );
      }),
    );
    questionBox.hidden = q.length === 0 && choices.length === 0;
  };

  const paint = (): void => {
    const p = pane();
    title.textContent = p?.title || t("list.untitled");
    const name = remote ? computerName(desktopName(remote.state.session?.name, ctx.fleet.get(ref.desktopId)?.pairing.desktopName ?? "")) : "";
    const since = p && p.since_ms > 0 ? ` ${formatSince(p.since_ms, Date.now(), currentLang())}` : "";
    sub.textContent = [`${statusText(status())}${since}`, name].filter((s) => s !== "").join(" · ");
    const ph = t("detail.placeholder", { name: p?.kind || p?.title || t("list.untitled") });
    if (ph !== placeholder) {
      placeholder = ph;
      textarea.placeholder = ph;
    }
    const n = remote ? connectionNotice(remote) : t("detail.gone");
    notice.textContent = n ?? "";
    notice.hidden = !n;
    gone.hidden = !(remote?.state.panes && !p);

    const text = peek ? peek.lines.join("\n") : "";
    if (peek && text === "") screen.textContent = t("detail.empty");
    else if (screen.textContent !== text) screen.textContent = text;
    if (stick) scroll.scrollTop = scroll.scrollHeight;

    const access = composerAccess(cap());
    form.hidden = !(access === "full" || access === null);
    accessLine.hidden = access === "full" || access === null;
    accessLine.textContent = access === "answer" ? t("detail.answerOnly") : access === "view" ? t("detail.viewOnly") : "";
    paintAction();
    paintOptions();
    paintNote();
  };

  async function pollNow(): Promise<void> {
    if (destroyed || inflight || document.hidden || !remote || !ready() || !pane()) return;
    inflight = true;
    try {
      const r = await remote.request({ op: "peek", pane: paneId, lines: PEEK_LINES });
      if (destroyed) return;
      if (r.ok) {
        const p = parsePeekData(r.data);
        if (p) peek = p;
      } else if (!peek && r.code !== "session_changed") {
        // A poll that could not be settled is just "no answer"; the write-outcome words are not for it.
        say(errorText(SETTLED_CODES.includes(r.code) ? "timeout" : r.code));
      }
    } finally {
      inflight = false;
    }
    paint();
  }

  /**
   * The state of a running or finished action, shown ONCE: on the sent bubble while that bubble
   * is the action's own and visible, else in the note. `final` starts the bubble's fade.
   */
  function report(text: string, final: boolean): void {
    if (reportTarget(bubbleOwned, !bubble.hidden) === "bubble") {
      const s = bubble.querySelector(".bubble__state");
      if (s) s.textContent = text;
      if (final) settleBubble();
      message = "";
      paintNote();
    } else {
      say(text);
    }
  }

  async function act(run: (progress: (text: string) => void) => Promise<string>, ownsBubble = false): Promise<void> {
    if (busy) return;
    busy = true;
    bubbleOwned = ownsBubble;
    report(t("res.sending"), false);
    paint();
    try {
      report(await run((text) => report(text, false)), true);
    } finally {
      busy = false;
      bubbleOwned = false;
      paint();
    }
    void pollNow();
  }

  const answer = (c: Choice): Promise<void> =>
    act(async (progress) => {
      if (!c.cmd || !remote) return t("res.failed");
      const parse = (r: ReplyResult): string => resultText(r, r.ok ? parseResultData(r.data, ["sent", "stale", "gone", "failed"]) : null);
      const r = await remote.request(c.cmd, { onUnconfirmed: () => progress(t("res.unconfirmed")), onLate: (l) => report(parse(l), true) });
      return parse(r);
    });

  const showBubble = (text: string, state: string): void => {
    if (bubbleTimer) clearTimeout(bubbleTimer);
    if (fadeTimer) clearTimeout(fadeTimer);
    bubble.hidden = false;
    bubble.classList.remove("bubble--fade");
    setChildren(bubble, h("span", { class: "bubble__text" }, text.length > 400 ? `${text.slice(0, 400)}…` : text), h("span", { class: "bubble__state" }, state));
  };
  /** The result is final: let the bubble fade out after a few seconds. */
  const settleBubble = (): void => {
    if (bubbleTimer) clearTimeout(bubbleTimer);
    bubbleTimer = setTimeout(() => {
      bubble.classList.add("bubble--fade");
      fadeTimer = setTimeout(() => {
        bubble.hidden = true;
      }, FADE_MS);
    }, BUBBLE_MS);
  };

  const resetConfirm = (): void => {
    confirming = false;
    if (confirmTimer) clearTimeout(confirmTimer);
    confirmTimer = null;
    if (!destroyed) {
      paintAction();
      if (message === t("detail.interruptConfirm")) say("");
    }
  };

  const send = (): void => {
    const text = textarea.value;
    if (!text.trim() || !remote || composerMode(text, status(), cap(), ready() && !busy) !== "send") return;
    const queue = shouldQueue(status());
    showBubble(text, t("res.sending"));
    void act(async (progress) => {
      const r = await remote.request(
        { op: "prompt", pane: paneId, text, queue },
        {
          onUnconfirmed: () => progress(t("res.unconfirmed")),
          onLate: (l) => report(resultText(l, l.ok ? parseResultData(l.data, PROMPT_RESULTS) : null), true),
        },
      );
      const result = r.ok ? parseResultData(r.data, PROMPT_RESULTS) : null;
      if (promptConsumed(r, result)) {
        textarea.value = "";
        grow();
      }
      return resultText(r, result);
    }, true);
  };

  const stop = (): void => {
    if (!remote) return;
    if (!confirming) {
      confirming = true;
      paintAction();
      say(t("detail.interruptConfirm"));
      confirmTimer = setTimeout(resetConfirm, CONFIRM_MS);
      return;
    }
    resetConfirm();
    void act(async (progress) => {
      const parse = (r: ReplyResult): string => resultText(r, r.ok ? parseResultData(r.data, ["sent", "gone", "failed"]) : null);
      const r = await remote.request(
        { op: "interrupt", pane: paneId },
        { onUnconfirmed: () => progress(t("res.unconfirmed")), onLate: (l) => report(parse(l), true) },
      );
      return parse(r);
    });
  };

  action.addEventListener("click", () => {
    if (action.dataset.mode === "stop") stop();
    else send();
  });
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    send();
  });
  textarea.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
      ev.preventDefault();
      send();
    }
  });
  textarea.addEventListener("input", () => {
    message = "";
    grow();
    paintAction();
    paintNote();
  });

  paint();
  const unsub = ctx.fleet.subscribe(() => {
    paint();
    void pollNow();
  });
  void pollNow();
  const poll = setInterval(() => void pollNow(), POLL_MS);
  const sinceTimer = setInterval(() => {
    if (!remote || !isOnline(remote.state)) return;
    paint();
  }, 1000);
  const onVisible = (): void => {
    if (!document.hidden) void pollNow();
  };
  document.addEventListener("visibilitychange", onVisible);

  return {
    el,
    destroy: () => {
      destroyed = true;
      unsub();
      clearInterval(poll);
      clearInterval(sinceTimer);
      for (const tm of [confirmTimer, bubbleTimer, fadeTimer]) if (tm) clearTimeout(tm);
      document.removeEventListener("visibilitychange", onVisible);
    },
  };
}
