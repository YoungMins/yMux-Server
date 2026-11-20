// Markdown tree -> DOM. Everything is built with h() and text nodes: no innerHTML, no attribute
// takes text from the message, nothing is a link or an image (PROTOCOL.md 5.2: a link is shown as
// its text and address).
import { h, type Child } from "./dom";
import { parseMarkdown, plainText, type Align, type Block, type Inline } from "./markdown";

const MAX_ADDR = 300;

const addr = (href: string): string => (href.length > MAX_ADDR ? `${href.slice(0, MAX_ADDR)}…` : href);

function inline(xs: readonly Inline[]): Child[] {
  return xs.map((x): Child => {
    switch (x.t) {
      case "text":
        return x.s;
      case "soft":
        return "\n";
      case "br":
        return h("br");
      case "code":
        return h("code", { class: "md-icode" }, x.s);
      case "strong":
        return h("strong", null, ...inline(x.c));
      case "em":
        return h("em", null, ...inline(x.c));
      case "del":
        return h("del", null, ...inline(x.c));
      case "link": {
        const same = x.href === "" || x.href === plainText(x.c);
        return h("span", { class: "md-link" }, ...inline(x.c), same ? null : h("span", { class: "md-addr" }, ` (${addr(x.href)})`));
      }
      case "image":
        return h("span", { class: "md-image" }, x.alt || x.href, x.alt && x.href ? h("span", { class: "md-addr" }, ` (${addr(x.href)})`) : null);
    }
  });
}

const alignClass = (a: Align): string | null => (a ? `md-al-${a}` : null);

function block(b: Block): Node {
  switch (b.t) {
    case "p":
      return h("p", { class: "md-p" }, ...inline(b.c));
    case "h":
      return h(`h${b.level}` as "h1", { class: `md-h md-h${b.level}` }, ...inline(b.c));
    case "hr":
      return h("hr", { class: "md-hr" });
    case "quote":
      return h("blockquote", { class: "md-quote" }, ...b.c.map(block));
    case "code":
      return h(
        "div",
        { class: "md-codeblock" },
        b.lang ? h("div", { class: "md-lang" }, b.lang) : null,
        h("pre", { class: "md-pre", tabindex: "0" }, h("code", null, b.s)),
      );
    case "list": {
      const items = b.items.map((it) =>
        h(
          "li",
          { class: it.task === null ? "md-li" : "md-li md-li--task" },
          it.task === null ? null : h("span", { class: "md-box" }, it.task ? "☑" : "☐"),
          ...it.c.map(block),
        ),
      );
      return b.ordered
        ? h("ol", { class: "md-list", start: b.start === 1 ? null : String(b.start) }, ...items)
        : h("ul", { class: "md-list" }, ...items);
    }
    case "table": {
      const cell = (tag: "th" | "td", xs: Inline[], a: Align): Node =>
        h(tag, { class: alignClass(a) }, h("div", { class: "md-cell" }, ...inline(xs)));
      return h(
        "div",
        { class: "md-tablewrap", tabindex: "0" },
        h(
          "table",
          { class: "md-table" },
          h("thead", null, h("tr", null, ...b.head.map((c, i) => cell("th", c, b.align[i] ?? null)))),
          h("tbody", null, ...b.rows.map((r) => h("tr", null, ...r.map((c, i) => cell("td", c, b.align[i] ?? null))))),
        ),
      );
    }
  }
}

/** The rendered message: one `div.md`. */
export function renderMarkdown(text: string): HTMLElement {
  return h("div", { class: "md" }, ...parseMarkdown(text).map(block));
}
