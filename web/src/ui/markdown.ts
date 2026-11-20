// A small Markdown parser for chat messages: text in, a tree of plain data out. No DOM here.
//
// It reads the CommonMark/GFM subset a coding agent writes (paragraphs, headings, fenced code,
// quotes, nested lists with task boxes, pipe tables, emphasis, code spans, links) and nothing else.
// Safety is a property of the tree: there is no node for raw HTML, nothing in it is ever turned
// into markup, links and images are plain data that the renderer shows as text with their address.
// Cost: block parsing makes a constant number of passes over the lines per nesting level (levels
// capped at MAX_DEPTH); inline parsing makes one pass per span plus one per nested link text (also
// capped), with look-ups for backtick runs and brackets prepared once per span. The only scans that
// can start again at nearby positions are link destinations/titles (each at most MAX_URL/MAX_TITLE
// characters, and a per-message work budget turns links off when it is spent) and nothing else
// rescans. Tokens are capped at MAX_NODES. No regex here has a nested quantifier.

export const MAX_DEPTH = 8;
export const MAX_NODES = 5000;
const MAX_COLS = 30;
const MAX_URL = 2000;
const MAX_TITLE = 500;
const MAX_SPACE_SKIP = 64;

export type Inline =
  | { t: "text"; s: string }
  | { t: "code"; s: string }
  | { t: "strong" | "em" | "del"; c: Inline[] }
  | { t: "br" }
  | { t: "soft" }
  | { t: "link"; href: string; c: Inline[] }
  | { t: "image"; alt: string; href: string };

export type Align = "left" | "center" | "right" | null;
export interface ListItem {
  /** null: not a task item; else whether the box is ticked. */
  task: boolean | null;
  c: Block[];
}
export type Block =
  | { t: "p"; c: Inline[] }
  | { t: "h"; level: number; c: Inline[] }
  | { t: "code"; lang: string; s: string }
  | { t: "quote"; c: Block[] }
  | { t: "list"; ordered: boolean; start: number; items: ListItem[] }
  | { t: "hr" }
  | { t: "table"; align: Align[]; head: Inline[][]; rows: Inline[][][] };

interface Budget {
  left: number;
}
const take = (b: Budget, n = 1): void => {
  b.left -= n;
};

/** The words of an inline list with all formatting removed (alt texts, link-vs-address checks). */
export function plainText(xs: readonly Inline[]): string {
  let out = "";
  for (const x of xs) {
    switch (x.t) {
      case "text":
      case "code":
        out += x.s;
        break;
      case "br":
      case "soft":
        out += " ";
        break;
      case "image":
        out += x.alt;
        break;
      default:
        out += plainText(x.c);
    }
  }
  return out;
}

export function parseMarkdown(src: string, maxNodes: number = MAX_NODES): Block[] {
  const bud: Budget = { left: maxNodes };
  return parseBlocks(src.split("\n"), 0, bud);
}

// ---- blocks --------------------------------------------------------------------------------

const isBlank = (l: string): boolean => l.trim() === "";

/** Leading columns of white space (a tab counts 4). */
function indentOf(l: string): number {
  let n = 0;
  for (let i = 0; i < l.length; i++) {
    const c = l[i];
    if (c === " ") n++;
    else if (c === "\t") n += 4;
    else break;
  }
  return n;
}

/** Removes up to `n` columns of leading white space. */
function stripIndent(l: string, n: number): string {
  let cols = 0;
  let i = 0;
  while (i < l.length && cols < n) {
    const c = l[i];
    if (c === " ") cols++;
    else if (c === "\t") cols += 4;
    else break;
    i++;
  }
  return l.slice(i);
}

interface Fence {
  ch: string;
  n: number;
  lang: string;
  indent: number;
}

function fenceOpen(l: string): Fence | null {
  const indent = indentOf(l);
  if (indent > 3) return null;
  const s = l.slice(indent);
  const ch = s[0];
  if (ch !== "`" && ch !== "~") return null;
  let n = 0;
  while (s[n] === ch) n++;
  if (n < 3) return null;
  const info = s.slice(n).trim();
  if (ch === "`" && info.includes("`")) return null;
  let e = 0;
  while (e < info.length && info[e] !== " " && info[e] !== "\t") e++;
  return { ch, n, lang: info.slice(0, e).slice(0, 40), indent };
}

function fenceClose(l: string, f: Fence): boolean {
  if (indentOf(l) > 3) return false;
  const s = l.trim();
  if (s.length < f.n) return false;
  for (let i = 0; i < s.length; i++) if (s[i] !== f.ch) return false;
  return true;
}

function atx(l: string): { level: number; text: string } | null {
  const indent = indentOf(l);
  if (indent > 3) return null;
  let i = indent;
  let level = 0;
  while (l[i] === "#" && level < 7) {
    level++;
    i++;
  }
  if (level < 1 || level > 6) return null;
  if (i < l.length && l[i] !== " " && l[i] !== "\t") return null;
  let text = l.slice(i).trim();
  let e = text.length;
  while (e > 0 && text[e - 1] === "#") e--;
  if (e < text.length && (e === 0 || text[e - 1] === " " || text[e - 1] === "\t")) text = text.slice(0, e).trim();
  return { level, text };
}

function isHr(l: string): boolean {
  if (indentOf(l) > 3) return false;
  let ch = "";
  let n = 0;
  for (let i = 0; i < l.length; i++) {
    const c = l[i]!;
    if (c === " " || c === "\t") continue;
    if (c !== "-" && c !== "*" && c !== "_") return false;
    if (ch === "") ch = c;
    else if (c !== ch) return false;
    n++;
  }
  return n >= 3;
}

const isQuote = (l: string): boolean => indentOf(l) <= 3 && l.trimStart()[0] === ">";
const unquote = (l: string): string => {
  const s = l.trimStart().slice(1);
  return s[0] === " " ? s.slice(1) : s;
};

interface Marker {
  indent: number;
  ordered: boolean;
  /** The bullet character, or the ordered delimiter. */
  ch: string;
  num: number;
  contentIndent: number;
  rest: string;
}

function marker(l: string): Marker | null {
  const indent = indentOf(l);
  if (indent > 3) return null;
  const s = l.trimStart();
  let ordered = false;
  let num = 1;
  let ch = s[0] ?? "";
  let len = 1;
  if (ch === "-" || ch === "+" || ch === "*") {
    /* bullet */
  } else if (ch >= "0" && ch <= "9") {
    let d = 0;
    while (d < s.length && d < 10 && s[d]! >= "0" && s[d]! <= "9") d++;
    if (d > 9 || (s[d] !== "." && s[d] !== ")")) return null;
    ordered = true;
    num = Number(s.slice(0, d));
    ch = s[d]!;
    len = d + 1;
  } else return null;
  const after = s[len];
  if (after !== undefined && after !== " " && after !== "\t") return null;
  let sp = 0;
  while (s[len + sp] === " ") sp++;
  const empty = len + sp >= s.length;
  const pad = empty || sp > 4 ? 1 : Math.max(sp, 1);
  return { indent, ordered, ch, num, contentIndent: indent + len + pad, rest: empty ? "" : s.slice(len + Math.min(sp, pad)) };
}

const sameList = (a: Marker, b: Marker): boolean => a.ordered === b.ordered && a.ch === b.ch;

/** Cells of a table row; stops after MAX_COLS + 1 cells. */
function splitRow(line: string): string[] {
  let s = line.trim();
  if (s[0] === "|") s = s.slice(1);
  if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1);
  const cells: string[] = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "\\" && s[i + 1] === "|") {
      cur += "|";
      i++;
    } else if (c === "|") {
      cells.push(cur.trim());
      cur = "";
      if (cells.length > MAX_COLS) return cells;
    } else cur += c;
  }
  cells.push(cur.trim());
  return cells;
}

const DELIM_CELL = /^:?-+:?$/;

function delimiterRow(line: string | undefined, cols: number): Align[] | null {
  if (line === undefined || !line.includes("-")) return null;
  const cells = splitRow(line);
  if (cells.length !== cols) return null;
  const out: Align[] = [];
  for (const c of cells) {
    if (!DELIM_CELL.test(c)) return null;
    const l = c.startsWith(":");
    const r = c.endsWith(":");
    out.push(l && r ? "center" : r ? "right" : l ? "left" : null);
  }
  return out;
}

function tableAt(lines: string[], i: number): Align[] | null {
  const head = lines[i]!;
  if (!head.includes("|")) return null;
  return delimiterRow(lines[i + 1], splitRow(head).length);
}

/** A line that begins a block of its own, so a paragraph or a table body ends before it. */
function startsBlock(l: string, orderedOnlyOne = true): boolean {
  if (fenceOpen(l) || atx(l) || isHr(l) || isQuote(l)) return true;
  const m = marker(l);
  return !!m && (!m.ordered || !orderedOnlyOne || m.num === 1);
}

const rest = (lines: string[]): Block => ({ t: "p", c: [{ t: "text", s: lines.join("\n") }] });

function parseBlocks(lines: string[], depth: number, bud: Budget): Block[] {
  const out: Block[] = [];
  const containers = depth < MAX_DEPTH;
  const n = lines.length;
  let i = 0;
  while (i < n) {
    if (bud.left <= 0) {
      out.push(rest(lines.slice(i)));
      break;
    }
    const line = lines[i]!;
    if (isBlank(line)) {
      i++;
      continue;
    }

    const f = fenceOpen(line);
    if (f) {
      const body: string[] = [];
      let j = i + 1;
      while (j < n && !fenceClose(lines[j]!, f)) body.push(stripIndent(lines[j++]!, f.indent));
      take(bud);
      out.push({ t: "code", lang: f.lang, s: body.join("\n") });
      i = j + 1;
      continue;
    }
    const h = atx(line);
    if (h) {
      take(bud);
      out.push({ t: "h", level: h.level, c: parseInline(h.text, bud) });
      i++;
      continue;
    }
    if (isHr(line)) {
      take(bud);
      out.push({ t: "hr" });
      i++;
      continue;
    }
    if (containers && isQuote(line)) {
      const inner: string[] = [];
      let j = i;
      while (j < n) {
        const l = lines[j]!;
        if (isQuote(l)) inner.push(unquote(l));
        else if (!isBlank(l) && inner.length > 0 && !isBlank(inner[inner.length - 1]!) && !startsBlock(l, false)) inner.push(l);
        else break;
        j++;
      }
      take(bud);
      out.push({ t: "quote", c: parseBlocks(inner, depth + 1, bud) });
      i = j;
      continue;
    }
    const m = containers ? marker(line) : null;
    if (m) {
      const [list, next] = parseList(lines, i, m, depth, bud);
      out.push(list);
      i = next;
      continue;
    }
    const aligns = tableAt(lines, i);
    if (aligns) {
      const [tb, next] = parseTable(lines, i, aligns, bud);
      out.push(tb);
      i = next;
      continue;
    }

    // paragraph
    const para: string[] = [line.trimStart()];
    let j = i + 1;
    while (j < n) {
      const l = lines[j]!;
      if (isBlank(l) || startsBlock(l) || tableAt(lines, j)) break;
      para.push(l.trimStart());
      j++;
    }
    take(bud);
    out.push({ t: "p", c: parseInline(para.join("\n"), bud) });
    i = j;
  }
  return out;
}

function parseList(lines: string[], start: number, first: Marker, depth: number, bud: Budget): [Block, number] {
  const n = lines.length;
  const items: ListItem[] = [];
  let j = start;
  let m: Marker = first;
  while (true) {
    if (bud.left <= 0) break;
    const threshold = Math.min(m.contentIndent, m.indent + 2);
    const body: string[] = [m.rest];
    let k = j + 1;
    while (k < n) {
      const ln = lines[k]!;
      if (isBlank(ln)) {
        let q = k + 1;
        while (q < n && isBlank(lines[q]!)) q++;
        if (q < n && indentOf(lines[q]!) >= threshold) {
          for (let b = k; b < q; b++) body.push("");
          k = q;
          continue;
        }
        break;
      }
      if (indentOf(ln) >= threshold) {
        body.push(stripIndent(ln, m.contentIndent));
        k++;
        continue;
      }
      const prev = body[body.length - 1]!;
      if (!isBlank(prev) && !startsBlock(ln, false) && !tableAt(lines, k)) {
        body.push(ln.trimStart());
        k++;
        continue;
      }
      break;
    }
    let task: boolean | null = null;
    const b0 = body[0]!;
    if (b0[0] === "[" && b0[2] === "]" && (b0[1] === " " || b0[1] === "x" || b0[1] === "X") && (b0.length === 3 || b0[3] === " " || b0[3] === "\t")) {
      task = b0[1] !== " ";
      body[0] = b0.slice(3).trimStart();
    }
    take(bud);
    items.push({ task, c: parseBlocks(body, depth + 1, bud) });
    j = k;
    // the list goes on when the next non-blank line is another item of the same kind
    let q = j;
    while (q < n && isBlank(lines[q]!)) q++;
    const nm = q < n ? marker(lines[q]!) : null;
    if (nm && sameList(first, nm) && !isHr(lines[q]!)) {
      j = q;
      m = nm;
      continue;
    }
    break;
  }
  take(bud);
  return [{ t: "list", ordered: first.ordered, start: first.ordered ? first.num : 1, items }, j];
}

function parseTable(lines: string[], i: number, align: Align[], bud: Budget): [Block, number] {
  const cols = Math.min(align.length, MAX_COLS);
  const cell = (s: string): Inline[] => {
    take(bud);
    return parseInline(s, bud);
  };
  const head = splitRow(lines[i]!)
    .slice(0, cols)
    .map(cell);
  const rows: Inline[][][] = [];
  let j = i + 2;
  while (j < lines.length && bud.left > 0) {
    const l = lines[j]!;
    if (isBlank(l) || startsBlock(l, false)) break;
    const cells = splitRow(l).slice(0, cols);
    while (cells.length < cols) cells.push("");
    rows.push(cells.map(cell));
    j++;
  }
  take(bud);
  return [{ t: "table", align: align.slice(0, cols), head, rows }, j];
}

// ---- inline --------------------------------------------------------------------------------

type Kind = "strong" | "em" | "del";
interface Delim {
  k: "d";
  ch: string;
  rem: number;
  opens: Kind[];
  closes: Kind[];
}
type Tok = { k: "n"; n: Inline } | Delim;

const WS = /\s/;
const PUNCT = /[\p{P}\p{S}]/u;
const isWs = (c: string): boolean => c === "" || WS.test(c);
const isPunct = (c: string): boolean => c !== "" && PUNCT.test(c);
const ASCII_PUNCT = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

interface Ctx {
  bud: Budget;
  /** Characters scanned for link destinations so far, against a cap proportional to the input. */
  work: number;
  workCap: number;
}

function parseInline(text: string, bud: Budget): Inline[] {
  const s = text.trimEnd();
  const ctx: Ctx = { bud, work: 0, workCap: 4 * s.length + 4000 };
  return inlineSpan(s, 0, s.length, 0, false, ctx);
}

/** `(dest "title")` starting right after the `(`; null when it is not a link target. */
function linkTarget(s: string, k: number, hi: number, ctx: Ctx): { href: string; next: number } | null {
  const skipWs = (p: number): number => {
    const stop = Math.min(hi, p + MAX_SPACE_SKIP);
    while (p < stop && (s[p] === " " || s[p] === "\t" || s[p] === "\n")) p++;
    return p;
  };
  let p = skipWs(k);
  let href = "";
  if (s[p] === "<") {
    const stop = Math.min(hi, p + MAX_URL);
    let e = p + 1;
    while (e < stop && s[e] !== ">" && s[e] !== "<" && s[e] !== "\n") e++;
    ctx.work += e - p;
    if (s[e] !== ">") return null;
    href = s.slice(p + 1, e);
    p = e + 1;
  } else {
    const start = p;
    const stop = Math.min(hi, p + MAX_URL);
    let depth = 0;
    while (p < stop) {
      const c = s[p]!;
      if (c === " " || c === "\t" || c === "\n") break;
      if (c === "\\" && p + 1 < hi) {
        p += 2;
        continue;
      }
      if (c === "(") depth++;
      else if (c === ")") {
        if (depth === 0) break;
        depth--;
      }
      p++;
    }
    ctx.work += p - start;
    if (depth !== 0 || p >= hi) return null;
    href = s.slice(start, p).replace(/\\([!-/:-@[-`{-~])/g, "$1");
  }
  p = skipWs(p);
  const q = s[p];
  if (q === '"' || q === "'" || q === "(") {
    const close = q === "(" ? ")" : q;
    const stop = Math.min(hi, p + MAX_TITLE);
    let e = p + 1;
    while (e < stop && s[e] !== close) e += s[e] === "\\" ? 2 : 1;
    ctx.work += e - p;
    if (s[e] !== close) return null;
    p = skipWs(e + 1);
  }
  return s[p] === ")" ? { href, next: p + 1 } : null;
}

function inlineSpan(s: string, lo: number, hi: number, depth: number, inLink: boolean, ctx: Ctx): Inline[] {
  const bud = ctx.bud;
  // code spans: the next run of backticks of the same length closes one
  const tickAt = new Map<number, number>();
  const tickPos: number[] = [];
  const tickLen: number[] = [];
  const bracket = new Map<number, number>();
  {
    const open: number[] = [];
    for (let i = lo; i < hi; i++) {
      const c = s[i]!;
      if (c === "\\") i++;
      else if (c === "`") {
        let e = i;
        while (e < hi && s[e] === "`") e++;
        tickAt.set(i, tickPos.length);
        tickPos.push(i);
        tickLen.push(e - i);
        i = e - 1;
      } else if (c === "[") open.push(i);
      else if (c === "]" && open.length) bracket.set(open.pop()!, i);
    }
  }
  const nextSame: number[] = new Array<number>(tickPos.length);
  {
    const seen = new Map<number, number>();
    for (let r = tickPos.length - 1; r >= 0; r--) {
      nextSame[r] = seen.get(tickLen[r]!) ?? -1;
      seen.set(tickLen[r]!, r);
    }
  }

  const toks: Tok[] = [];
  const stack: { d: Delim; ch: string }[] = [];
  const openCount: Record<string, number> = { "*": 0, _: 0, "~": 0 };
  let buf = "";
  const flush = (): void => {
    if (buf !== "") {
      take(bud);
      toks.push({ k: "n", n: { t: "text", s: buf } });
      buf = "";
    }
  };
  const push = (n: Inline): void => {
    flush();
    take(bud);
    toks.push({ k: "n", n });
  };

  let i = lo;
  while (i < hi) {
    if (bud.left <= 0) {
      buf += s.slice(i, hi);
      break;
    }
    const c = s[i]!;

    if (c === "\\") {
      const nx = s[i + 1];
      if (i + 1 < hi && nx === "\n") {
        push({ t: "br" });
        i += 2;
      } else if (i + 1 < hi && nx !== undefined && ASCII_PUNCT.includes(nx)) {
        buf += nx;
        i += 2;
      } else {
        buf += c;
        i++;
      }
      continue;
    }

    if (c === "\n") {
      let e = buf.length;
      while (e > 0 && buf[e - 1] === " ") e--;
      const hard = buf.length - e >= 2;
      buf = buf.slice(0, e);
      push(hard ? { t: "br" } : { t: "soft" });
      i++;
      continue;
    }

    if (c === "`") {
      const r = tickAt.get(i)!;
      const len = tickLen[r]!;
      const m = nextSame[r]!;
      if (m >= 0) {
        let code = s.slice(i + len, tickPos[m]!).replace(/\n/g, " ");
        if (code.length > 2 && code[0] === " " && code[code.length - 1] === " " && code.trim() !== "") code = code.slice(1, -1);
        push({ t: "code", s: code });
        i = tickPos[m]! + len;
      } else {
        buf += s.slice(i, i + len);
        i += len;
      }
      continue;
    }

    if (c === "[" || (c === "!" && s[i + 1] === "[" && i + 1 < hi)) {
      const isImg = c === "!";
      const lb = isImg ? i + 1 : i;
      const rb = bracket.get(lb);
      if (rb !== undefined && rb < hi && s[rb + 1] === "(" && ctx.work <= ctx.workCap) {
        const target = linkTarget(s, rb + 2, hi, ctx);
        if (target) {
          const kids = depth < MAX_DEPTH ? inlineSpan(s, lb + 1, rb, depth + 1, true, ctx) : [{ t: "text", s: s.slice(lb + 1, rb) } as Inline];
          if (isImg) push({ t: "image", alt: plainText(kids), href: target.href });
          else push({ t: "link", href: target.href, c: kids });
          i = target.next;
          continue;
        }
      }
      buf += c;
      i++;
      continue;
    }

    if (c === "<") {
      let e = i + 1;
      const stop = Math.min(hi, i + MAX_URL);
      while (e < stop && s[e] !== ">" && s[e] !== "<" && s[e] !== " " && s[e] !== "\n" && s[e] !== "\t") e++;
      const body = s.slice(i + 1, e);
      if (s[e] === ">" && /^(https?:\/\/|mailto:)./i.test(body)) {
        push({ t: "link", href: body, c: [{ t: "text", s: body }] });
        i = e + 1;
      } else {
        buf += c;
        i++;
      }
      continue;
    }

    if (c === "h" && !inLink && (s.startsWith("http://", i) || s.startsWith("https://", i)) && !/[\p{L}\p{N}]/u.test(s[i - 1] ?? "")) {
      // one pass: find the end and count parentheses (opened minus closed) on the way
      let e = i;
      let bal = 0;
      while (e < hi && !/[\s<]/.test(s[e]!)) {
        if (s[e] === "(") bal++;
        else if (s[e] === ")") bal--;
        e++;
      }
      // trailing punctuation belongs to the sentence, an unbalanced `)` too; dropping a `)` raises bal
      while (e > i) {
        const l = s[e - 1]!;
        if (".,;:!?\"'*_~".includes(l)) e--;
        else if (l === ")" && bal < 0) {
          e--;
          bal++;
        } else break;
      }
      const url = s.slice(i, e);
      if (url.length > "https://".length) {
        push({ t: "link", href: url, c: [{ t: "text", s: url }] });
        i = e;
        continue;
      }
    }

    if (c === "*" || c === "_" || c === "~") {
      let e = i;
      while (e < hi && s[e] === c) e++;
      const n = e - i;
      const prev = i > lo ? s[i - 1]! : "";
      const next = e < hi ? s[e]! : "";
      if (c === "~" && n !== 2) {
        buf += s.slice(i, e);
        i = e;
        continue;
      }
      const left = !isWs(next) && (!isPunct(next) || isWs(prev) || isPunct(prev));
      const right = !isWs(prev) && (!isPunct(prev) || isWs(next) || isPunct(next));
      const canOpen = c === "_" ? left && (!right || isPunct(prev)) : left;
      const canClose = c === "_" ? right && (!left || isPunct(next)) : right;
      if (!canOpen && !canClose) {
        buf += s.slice(i, e);
        i = e;
        continue;
      }
      flush();
      take(bud);
      const d: Delim = { k: "d", ch: c, rem: n, opens: [], closes: [] };
      toks.push(d);
      if (canClose) {
        while (d.rem > 0 && openCount[c]! > 0 && bud.left > 0) {
          while (stack[stack.length - 1]!.ch !== c) {
            openCount[stack.pop()!.ch]!--;
          }
          const o = stack[stack.length - 1]!.d;
          const use = c === "~" ? 2 : Math.min(o.rem, d.rem) >= 2 ? 2 : 1;
          const kind: Kind = c === "~" ? "del" : use === 2 ? "strong" : "em";
          take(bud);
          o.opens.push(kind);
          d.closes.push(kind);
          o.rem -= use;
          d.rem -= use;
          if (o.rem === 0) {
            stack.pop();
            openCount[c]!--;
          }
        }
      }
      if (canOpen && d.rem > 0) {
        stack.push({ d, ch: c });
        openCount[c]!++;
      }
      i = e;
      continue;
    }

    buf += c;
    i++;
  }
  flush();
  return build(toks);
}

function addText(list: Inline[], s: string): void {
  if (s === "") return;
  const last = list[list.length - 1];
  if (last && last.t === "text") last.s += s;
  else list.push({ t: "text", s });
}

/** Turns tokens into nodes; emphasis nested deeper than MAX_DEPTH loses its styling, not its text. */
function build(toks: Tok[]): Inline[] {
  const root: Inline[] = [];
  const stack: { kind: Kind | "flat"; c: Inline[] }[] = [];
  const cur = (): Inline[] => (stack.length ? stack[stack.length - 1]!.c : root);
  for (const t of toks) {
    if (t.k === "n") {
      if (t.n.t === "text") addText(cur(), t.n.s);
      else cur().push(t.n);
      continue;
    }
    for (let q = 0; q < t.closes.length; q++) {
      const top = stack.pop();
      if (!top) continue;
      if (top.kind === "flat") for (const x of top.c) x.t === "text" ? addText(cur(), x.s) : cur().push(x);
      else cur().push({ t: top.kind, c: top.c });
    }
    addText(cur(), t.ch.repeat(t.rem));
    for (let a = t.opens.length - 1; a >= 0; a--) stack.push({ kind: stack.length >= MAX_DEPTH ? "flat" : t.opens[a]!, c: [] });
  }
  while (stack.length) {
    // cannot happen: every opener has its closer. Keep the text if it ever does.
    const top = stack.pop()!;
    for (const x of top.c) x.t === "text" ? addText(cur(), x.s) : cur().push(x);
  }
  return root;
}
