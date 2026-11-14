import { deviceNameFromUA } from "../device/env";
import { t, type Key } from "../i18n";
import { pairWsUrl, runPairing, type PairLink, type PairOutcome, type PairParse } from "../net/pairing";
import { MAX_PAIRINGS } from "../net/storage";
import { cleanDeviceName, UNNAMED_DEVICE } from "../protocol/clean";
import { newUuid } from "../protocol/encoding";
import { deriveLinkKey, generateAgreementKey, isAgreementPoint } from "../protocol/seal";
import { exportPublicKey, generateDeviceKey } from "../protocol/signing";
import { computerName } from "./common";
import { h, setChildren } from "./dom";
import type { Ctx, View } from "./view";

const OUTCOME_TEXT: Record<Exclude<PairOutcome, "ok">, Key> = {
  refused: "pair.refused",
  no_pairing: "pair.noWindow",
  timeout: "pair.timeout",
  error: "pair.error",
};

function stripFragment(): void {
  try {
    history.replaceState(null, "", location.pathname + location.search);
  } catch {
    /* ignore */
  }
}

/** Shown when nothing is paired and there is no pairing link. */
export function unpairedView(legacy = false): View {
  return {
    el: h(
      "main",
      { class: "center" },
      h("h1", { class: "center__title" }, t("app.name")),
      legacy ? h("p", { class: "notice" }, t("pair.legacy")) : null,
      h("p", { class: "center__text" }, t("pair.unpaired")),
    ),
  };
}

/** Why a link cannot be used: an older yMux made it, or it is simply not a pairing link. */
export const linkProblemKey = (reason: "old" | "bad"): Key => (reason === "old" ? "pair.oldQr" : "pair.badLink");

/** The key-agreement half of a pairing: only the public `ek` and the finished link key leave. */
async function makeLinkKey(
  link: PairLink,
  deviceId: string,
  pubkey: string,
): Promise<{ ek: string; linkKey: CryptoKey }> {
  const agree = await generateAgreementKey();
  const ek = await exportPublicKey(agree.publicKey);
  const linkKey = await deriveLinkKey({
    ekPrivate: agree.privateKey,
    ek,
    dk: link.dk,
    code: link.code,
    desktopId: link.desktopId,
    deviceId,
    pubkey,
  });
  return { ek, linkKey }; // `agree` goes out of scope here: the private half is not kept anywhere
}

export function pairView(ctx: Ctx, parsed: PairParse): View {
  if (!parsed.ok) {
    return {
      el: h(
        "main",
        { class: "center" },
        h("h1", { class: "center__title" }, t("pair.title")),
        h("p", { class: "notice" }, t(linkProblemKey(parsed.reason))),
        h("a", { class: "btn btn--primary", href: "#" }, t("pair.continue")),
      ),
    };
  }
  const link = parsed.link;
  const pairings = ctx.fleet.pairings();
  const existing = pairings.find((p) => p.desktopId === link.desktopId);
  const full = !existing && pairings.length >= MAX_PAIRINGS;
  if (full) {
    return {
      el: h(
        "main",
        { class: "center" },
        h("h1", { class: "center__title" }, t("pair.title")),
        h("p", { class: "notice" }, t("pair.full", { max: MAX_PAIRINGS })),
        h("a", { class: "btn btn--primary", href: "#settings" }, t("nav.settings")),
      ),
    };
  }
  const nameInput = h("input", {
    class: "input",
    id: "dev-name",
    type: "text",
    maxlength: "40",
    value: cleanDeviceName(deviceNameFromUA(navigator.userAgent)),
    autocomplete: "off",
  });
  const body = h("div", { class: "stack", role: "status", "aria-live": "polite" });
  const button = h("button", { class: "btn btn--primary", type: "button" }, t(existing ? "pair.replace" : "pair.button"));
  let busy = false;
  // The code has served once the server accepted the request: a new attempt needs a new QR.
  let consumed = false;

  const showForm = (): void =>
    setChildren(
      body,
      existing ? h("p", { class: "notice" }, t("pair.replaceWarn", { name: computerName(existing.desktopName) })) : null,
      h("label", { for: "dev-name", class: "muted" }, t("pair.name")),
      nameInput,
      button,
      h("p", { class: "muted" }, t("pair.scanHint")),
    );

  /** Neutral until a check number has really arrived from the computer. */
  const showWaiting = (): void => setChildren(body, h("p", { class: "center__text" }, t("pair.waiting")));
  const showCheck = (check: string): void =>
    setChildren(
      body,
      h("p", { class: "center__text" }, t("pair.check")),
      h("p", { class: "checknum", "aria-label": check.split("").join(" ") }, check),
      h("p", { class: "muted" }, t("pair.checkHelp")),
    );
  const showFailure = (key: Key, hint: Key | null): void =>
    setChildren(
      body,
      h("p", { class: "notice", role: "alert" }, t(key)),
      hint ? h("p", { class: "muted" }, t(hint)) : null,
      consumed
        ? h("a", { class: "btn btn--primary", href: "#" }, t("pair.continue"))
        : h("button", { class: "btn btn--primary", type: "button", onclick: () => void start() }, t("pair.retry")),
    );

  async function start(): Promise<void> {
    if (busy) return;
    busy = true;
    showWaiting();
    let failure: { key: Key; hint: Key | null } | null = null;
    try {
      if (!(await isAgreementPoint(link.dk))) {
        failure = { key: "pair.oldQr", hint: null };
        consumed = true; // this QR can never work
      } else {
        // A new key pair and device id for THIS computer; nothing is reused from another pairing.
        const kp = await generateDeviceKey();
        const pubkey = await exportPublicKey(kp.publicKey);
        const deviceId = newUuid();
        // The same cleaning the computer and the server apply (digits and quote-like
        // punctuation never reach the pairing dialog), so what is stored here matches.
        const typed = cleanDeviceName(nameInput.value);
        const name = typed !== UNNAMED_DEVICE ? typed : cleanDeviceName(deviceNameFromUA(navigator.userAgent));
        const { ek, linkKey } = await makeLinkKey(link, deviceId, pubkey);
        const outcome = await runPairing({
          url: pairWsUrl(location),
          link,
          deviceId,
          pubkey,
          ek,
          name,
          privateKey: kp.privateKey,
          linkKey,
          onSent: () => undefined,
          onCheck: showCheck,
        });
        if (outcome !== "ok") {
          failure = { key: OUTCOME_TEXT[outcome], hint: outcome === "refused" ? "pair.refusedHint" : null };
        } else {
          consumed = true;
          link.code.fill(0); // the server accepted it: the code has no further use on this device
          showWaiting();
          const res = await ctx.addPairing({
            deviceId,
            desktopId: link.desktopId,
            pubkey,
            name,
            privateKey: kp.privateKey,
            linkKey,
            desktopName: existing?.desktopName ?? "",
            addedMs: Date.now(),
          });
          if (!res.ok) failure = { key: res.reason === "not_confirmed" ? "pair.notConfirmed" : "pair.error", hint: null };
        }
      }
    } catch {
      failure = { key: "pair.error", hint: null };
    }
    stripFragment();
    busy = false;
    if (failure) {
      showFailure(failure.key, failure.hint);
      return;
    }
    try {
      await navigator.storage?.persist?.();
    } catch {
      /* best effort: keeps the key from being evicted */
    }
    ctx.go("#"); // straight to the list
  }

  button.addEventListener("click", () => void start());
  showForm();

  return {
    el: h("main", { class: "center" }, h("h1", { class: "center__title" }, t("pair.title")), h("p", { class: "center__text" }, t("pair.intro")), body),
  };
}
