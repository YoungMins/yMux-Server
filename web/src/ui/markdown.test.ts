import { describe, expect, it } from "vitest";
import { MAX_DEPTH, MAX_NODES, parseMarkdown, plainText, type Block, type Inline } from "./markdown";

const t = (s: string): Inline => ({ t: "text", s });
const p = (...c: Inline[]): Block => ({ t: "p", c });

function depth(bs: readonly Block[]): number {
  let d = 0;
  for (const b of bs) {
    let n = 0;
    if (b.t === "quote") n = 1 + depth(b.c);
    else if (b.t === "list") n = 1 + Math.max(0, ...b.items.map((i) => depth(i.c)));
    d = Math.max(d, n);
  }
  return d;
}
function count(bs: readonly Block[]): number {
  let n = 0;
  const inl = (xs: readonly Inline[]): number =>
    xs.reduce((a, x) => a + 1 + ("c" in x ? inl(x.c) : 0), 0);
  for (const b of bs) {
    n++;
    if (b.t === "p" || b.t === "h") n += inl(b.c);
    else if (b.t === "quote") n += count(b.c);
    else if (b.t === "list") for (const i of b.items) n += 1 + count(i.c);
    else if (b.t === "table") {
      for (const c of b.head) n += 1 + inl(c);
      for (const r of b.rows) for (const c of r) n += 1 + inl(c);
    }
  }
  return n;
}

describe("markdown: paragraphs and breaks", () => {
  it("plain paragraphs split on blank lines", () => {
    expect(parseMarkdown("one\n\ntwo")).toEqual([p(t("one")), p(t("two"))]);
  });
  it("soft and hard line breaks", () => {
    expect(parseMarkdown("a\nb")).toEqual([p(t("a"), { t: "soft" }, t("b"))]);
    expect(parseMarkdown("a  \nb")).toEqual([p(t("a"), { t: "br" }, t("b"))]);
    expect(parseMarkdown("a\\\nb")).toEqual([p(t("a"), { t: "br" }, t("b"))]);
  });
  it("empty input is no blocks", () => {
    expect(parseMarkdown("")).toEqual([]);
    expect(parseMarkdown("\n\n  \n")).toEqual([]);
  });
});

describe("markdown: headings, rules, quotes", () => {
  it("ATX headings 1-6, closing hashes dropped, not a heading without a space", () => {
    expect(parseMarkdown("# One")).toEqual([{ t: "h", level: 1, c: [t("One")] }]);
    expect(parseMarkdown("###### Six ##")).toEqual([{ t: "h", level: 6, c: [t("Six")] }]);
    expect(parseMarkdown("####### seven")).toEqual([p(t("####### seven"))]);
    expect(parseMarkdown("#nospace")).toEqual([p(t("#nospace"))]);
    expect(parseMarkdown("#")).toEqual([{ t: "h", level: 1, c: [] }]);
  });
  it("horizontal rules", () => {
    for (const s of ["---", "***", "___", "- - -", "  ***  "]) expect(parseMarkdown(s), s).toEqual([{ t: "hr" }]);
    expect(parseMarkdown("--")).toEqual([p(t("--"))]);
  });
  it("blockquotes, nested", () => {
    expect(parseMarkdown("> a\n> b")).toEqual([{ t: "quote", c: [p(t("a"), { t: "soft" }, t("b"))] }]);
    expect(parseMarkdown("> a\n>> b")).toEqual([{ t: "quote", c: [p(t("a")), { t: "quote", c: [p(t("b"))] }] }]);
  });
});

describe("markdown: code", () => {
  it("fenced code is verbatim with a language label", () => {
    const src = "```rust\nfn main() {\n  **not bold**\n}\n```";
    expect(parseMarkdown(src)).toEqual([{ t: "code", lang: "rust", s: "fn main() {\n  **not bold**\n}" }]);
  });
  it("tilde fences, an unclosed fence runs to the end, a longer fence needs a longer close", () => {
    expect(parseMarkdown("~~~\na\n~~~")).toEqual([{ t: "code", lang: "", s: "a" }]);
    expect(parseMarkdown("```\na\nb")).toEqual([{ t: "code", lang: "", s: "a\nb" }]);
    expect(parseMarkdown("````\n```\nx\n````")).toEqual([{ t: "code", lang: "", s: "```\nx" }]);
  });
  it("inline code is verbatim", () => {
    expect(parseMarkdown("use `a*b*` now")).toEqual([p(t("use "), { t: "code", s: "a*b*" }, t(" now"))]);
    expect(parseMarkdown("``a`b``")).toEqual([p({ t: "code", s: "a`b" })]);
    expect(parseMarkdown("`unclosed")).toEqual([p(t("`unclosed"))]);
  });
});

describe("markdown: inline", () => {
  it("bold, italic, strikethrough, nested", () => {
    expect(parseMarkdown("**b** *i* _i2_ __b2__ ~~s~~")).toEqual([
      p(
        { t: "strong", c: [t("b")] },
        t(" "),
        { t: "em", c: [t("i")] },
        t(" "),
        { t: "em", c: [t("i2")] },
        t(" "),
        { t: "strong", c: [t("b2")] },
        t(" "),
        { t: "del", c: [t("s")] },
      ),
    ]);
    expect(parseMarkdown("***both***")).toEqual([p({ t: "em", c: [{ t: "strong", c: [t("both")] }] })]);
    expect(parseMarkdown("**a *b* c**")).toEqual([p({ t: "strong", c: [t("a "), { t: "em", c: [t("b")] }, t(" c")] })]);
  });
  it("leaves unmatched or non-flanking markers as text", () => {
    expect(parseMarkdown("2 * 3 * 4")).toEqual([p(t("2 * 3 * 4"))]);
    expect(parseMarkdown("snake_case_word")).toEqual([p(t("snake_case_word"))]);
    expect(parseMarkdown("**open")).toEqual([p(t("**open"))]);
  });
  it("backslash escapes", () => {
    expect(parseMarkdown("\\*not\\* \\# x")).toEqual([p(t("*not* # x"))]);
  });
  it("raw HTML is literal text", () => {
    expect(parseMarkdown("<b>x</b> <script>alert(1)</script>")).toEqual([p(t("<b>x</b> <script>alert(1)</script>"))]);
    expect(parseMarkdown("<img src=x onerror=alert(1)>")).toEqual([p(t("<img src=x onerror=alert(1)>"))]);
  });
});

describe("markdown: links and images are never live", () => {
  it("a link keeps its text and its address", () => {
    const r = parseMarkdown("see [the docs](https://example.com/a?b=1 \"title\") ok");
    expect(r).toEqual([p(t("see "), { t: "link", href: "https://example.com/a?b=1", c: [t("the docs")] }, t(" ok"))]);
  });
  it("javascript: addresses stay text and are the node's href only", () => {
    const r = parseMarkdown("[x](javascript:alert(1))");
    expect(r).toEqual([p({ t: "link", href: "javascript:alert(1)", c: [t("x")] })]);
  });
  it("autolinks and bare URLs", () => {
    expect(parseMarkdown("<https://a.example/x>")).toEqual([p({ t: "link", href: "https://a.example/x", c: [t("https://a.example/x")] })]);
    expect(parseMarkdown("go to https://a.example/x. Then")).toEqual([
      p(t("go to "), { t: "link", href: "https://a.example/x", c: [t("https://a.example/x")] }, t(". Then")),
    ]);
  });
  it("images become alt text plus address, never an image node", () => {
    const r = parseMarkdown("![a cat](https://e.example/c.png)");
    expect(r).toEqual([p({ t: "image", alt: "a cat", href: "https://e.example/c.png" })]);
    expect(JSON.stringify(r)).not.toContain('"img"');
  });
  it("plainText flattens an inline list", () => {
    const r = parseMarkdown("**a** `b` [c](http://x)")[0] as { c: Inline[] };
    expect(plainText(r.c)).toBe("a b c");
  });
});

describe("markdown: lists", () => {
  it("unordered and ordered with a start number", () => {
    expect(parseMarkdown("- a\n- b")).toEqual([
      { t: "list", ordered: false, start: 1, items: [{ task: null, c: [p(t("a"))] }, { task: null, c: [p(t("b"))] }] },
    ]);
    expect(parseMarkdown("3. a\n4) b")[0]).toMatchObject({ t: "list", ordered: true, start: 3 });
  });
  it("nests two and three levels", () => {
    const r = parseMarkdown("- a\n  - b\n    - c\n- d");
    expect(r).toHaveLength(1);
    const l = r[0] as Extract<Block, { t: "list" }>;
    expect(l.items).toHaveLength(2);
    const inner = l.items[0]!.c[1] as Extract<Block, { t: "list" }>;
    expect(inner.t).toBe("list");
    expect((inner.items[0]!.c[1] as Extract<Block, { t: "list" }>).t).toBe("list");
  });
  it("nests an ordered list under a numbered item indented by only two spaces", () => {
    const r = parseMarkdown("1. a\n  - b\n2. c");
    const l = r[0] as Extract<Block, { t: "list" }>;
    expect(l.items).toHaveLength(2);
    expect(l.items[0]!.c[1]!.t).toBe("list");
  });
  it("task items", () => {
    const l = parseMarkdown("- [ ] todo\n- [x] done\n- [X] done2")[0] as Extract<Block, { t: "list" }>;
    expect(l.items.map((i) => i.task)).toEqual([false, true, true]);
    expect(l.items[0]!.c).toEqual([p(t("todo"))]);
  });
  it("a loose list (blank lines between items) stays one list", () => {
    const r = parseMarkdown("- a\n\n- b\n\n- c");
    expect(r).toHaveLength(1);
    expect((r[0] as Extract<Block, { t: "list" }>).items).toHaveLength(3);
  });
  it("a list can interrupt a paragraph; a code block can sit in an item", () => {
    expect(parseMarkdown("Steps:\n- a")).toHaveLength(2);
    const l = parseMarkdown("- a\n  ```\n  code\n  ```")[0] as Extract<Block, { t: "list" }>;
    expect(l.items[0]!.c[1]).toEqual({ t: "code", lang: "", s: "code" });
  });
  it("a different bullet starts a new list", () => {
    expect(parseMarkdown("- a\n* b")).toHaveLength(2);
  });
});

describe("markdown: tables", () => {
  const src = "| Name | Qty | Note |\n|:-----|----:|:----:|\n| a | 1 | x |\n| b | 22 | y \\| z |\n";
  it("parses header, alignment and rows", () => {
    const [tb] = parseMarkdown(src) as [Extract<Block, { t: "table" }>];
    expect(tb.t).toBe("table");
    expect(tb.align).toEqual(["left", "right", "center"]);
    expect(tb.head.map(plainText)).toEqual(["Name", "Qty", "Note"]);
    expect(tb.rows.map((r) => r.map(plainText))).toEqual([
      ["a", "1", "x"],
      ["b", "22", "y | z"],
    ]);
  });
  it("works without outer pipes and pads or trims short and long rows", () => {
    const [tb] = parseMarkdown("a | b\n--|--\n1\n1 | 2 | 3") as [Extract<Block, { t: "table" }>];
    expect(tb.align).toEqual([null, null]);
    expect(tb.rows.map((r) => r.map(plainText))).toEqual([
      ["1", ""],
      ["1", "2"],
    ]);
  });
  it("inline markup works in cells", () => {
    const [tb] = parseMarkdown("| a |\n|---|\n| **b** `c` |") as [Extract<Block, { t: "table" }>];
    expect(tb.rows[0]![0]).toEqual([{ t: "strong", c: [t("b")] }, t(" "), { t: "code", s: "c" }]);
  });
  it("is not a table when the header and delimiter counts differ, or there is no delimiter", () => {
    expect(parseMarkdown("| a | b |\n|---|\n| 1 | 2 |")[0]!.t).toBe("p");
    expect(parseMarkdown("| a | b |\n| 1 | 2 |")[0]!.t).toBe("p");
  });
  it("ends at a blank line and a table can interrupt a paragraph", () => {
    const r = parseMarkdown("intro\n| a |\n|---|\n| 1 |\n\nafter");
    expect(r.map((b) => b.t)).toEqual(["p", "table", "p"]);
  });
  it("a table inside a list item or quote", () => {
    const r = parseMarkdown("- item\n  | a | b |\n  |---|---|\n  | 1 | 2 |");
    const l = r[0] as Extract<Block, { t: "list" }>;
    expect(l.items[0]!.c.map((b) => b.t)).toEqual(["p", "table"]);
  });
  it("CJK content", () => {
    const [tb] = parseMarkdown("| 이름 | 값 |\n|---|---|\n| 하나 | 일 |") as [Extract<Block, { t: "table" }>];
    expect(tb.rows[0]!.map(plainText)).toEqual(["하나", "일"]);
  });
});

describe("markdown: limits and adversarial input", () => {
  const KIB200 = 200 * 1024;
  const adversarial: [string, string][] = [
    ["stars", "*".repeat(KIB200)],
    ["double stars", "**".repeat(KIB200 / 2)],
    ["star word pairs", "*a ".repeat(KIB200 / 3)],
    ["mixed delimiters", "*_~*_~ a".repeat(KIB200 / 8)],
    ["tildes", "~~".repeat(KIB200 / 2)],
    ["open brackets", "[".repeat(KIB200)],
    ["links that never close", "[a](".repeat(KIB200 / 4)],
    ["bracket then paren", "[a]".repeat(KIB200 / 3) + "(" + ")".repeat(1000)],
    ["images", "![a](".repeat(KIB200 / 5)],
    ["pipes", "|".repeat(KIB200)],
    ["pipe rows", "| a | b |\n|---|---|\n".repeat(KIB200 / 20)],
    ["pipe header spam", ("|-".repeat(50) + "\n").repeat(KIB200 / 101)],
    ["backticks", "`".repeat(KIB200)],
    ["uneven backticks", "`a``b```c````".repeat(KIB200 / 13)],
    ["quotes", ">".repeat(KIB200)],
    ["spaced quotes", "> ".repeat(KIB200 / 2)],
    ["list markers", "- ".repeat(KIB200 / 2)],
    ["nested lists", Array.from({ length: 2000 }, (_, i) => `${"  ".repeat(i % 60)}- x`).join("\n")],
    ["mixed nests", "> - > - > - > - > - > - > - > - > - > - x\n".repeat(KIB200 / 40)],
    ["blank lines", "- a\n" + "\n".repeat(KIB200)],
    ["trailing spaces", "a" + " ".repeat(KIB200) + "\n"],
    ["hashes", "#".repeat(KIB200)],
    ["hash spaces", "# " + "# ".repeat(KIB200 / 2)],
    ["fences", "```\n".repeat(KIB200 / 4)],
    ["urls", "http://".repeat(KIB200 / 7)],
    ["angle", "<".repeat(KIB200)],
    ["backslashes", "\\".repeat(KIB200)],
  ];
  for (const [name, src] of adversarial) {
    it(`parses ${name} fast, capped in depth and size`, () => {
      const t0 = performance.now();
      const r = parseMarkdown(src);
      const ms = performance.now() - t0;
      expect(ms, `${name} took ${ms.toFixed(0)} ms`).toBeLessThan(1500);
      expect(depth(r)).toBeLessThanOrEqual(MAX_DEPTH);
      expect(count(r)).toBeLessThanOrEqual(MAX_NODES + 50);
    });
  }
  it("a bare URL followed by 100000 closing parentheses is linear", () => {
    const run = (n: number): number => {
      const t0 = performance.now();
      const r = parseMarkdown("https://x" + ")".repeat(n));
      const ms = performance.now() - t0;
      expect(JSON.stringify(r)).toContain('"href":"https://x"');
      return ms;
    };
    run(1000); // warm up
    const half = run(50_000);
    const full = run(100_000);
    expect(full).toBeLessThan(300);
    expect(full).toBeLessThan(half * 6 + 20);
  });
  it("keeps balanced parentheses in a bare URL and drops the sentence's one", () => {
    expect(parseMarkdown("(see https://a.example/x_(y))")[0]).toEqual({
      t: "p",
      c: [t("(see "), { t: "link", href: "https://a.example/x_(y)", c: [t("https://a.example/x_(y)")] }, t(")")],
    });
  });
  it("emphasis nested deeper than the cap loses its styling but keeps its text", () => {
    const n = 40;
    const r = parseMarkdown("*a ".repeat(n) + "x" + " a*".repeat(n));
    const inl = (xs: readonly Inline[]): number => Math.max(0, ...xs.map((x) => ("c" in x ? 1 + inl(x.c) : 0)));
    expect(inl((r[0] as { c: Inline[] }).c)).toBeLessThanOrEqual(MAX_DEPTH);
    expect(plainText((r[0] as { c: Inline[] }).c)).toContain("x");
  });
  it("deep nesting stays within the depth cap and keeps the text", () => {
    const r = parseMarkdown("> ".repeat(30) + "deep");
    expect(depth(r)).toBeLessThanOrEqual(MAX_DEPTH);
    expect(JSON.stringify(r)).toContain("deep");
  });
  it("past the node cap the rest is plain text, not dropped", () => {
    const src = Array.from({ length: 20000 }, (_, i) => `- item ${i}`).join("\n");
    const r = parseMarkdown(src);
    expect(count(r)).toBeLessThanOrEqual(MAX_NODES + 50);
    expect(JSON.stringify(r)).toContain("item 19999");
  });
});
