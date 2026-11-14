import { startApp } from "./app";
import { initLang } from "./i18n";

initLang();

const root = document.getElementById("app");
if (root) startApp(root);

if (import.meta.env.PROD && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => undefined);
  });
}
