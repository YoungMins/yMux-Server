// Inline SVG icons built with DOM APIs (no data: URLs, no inline styles). Decorative: the button
// that holds one carries the accessible name.
const NS = "http://www.w3.org/2000/svg";

export type IconName = "settings" | "back" | "send" | "stop" | "check";

type Shape = [tag: "path" | "circle" | "rect" | "line", attrs: Record<string, string>];

const SHAPES: Record<IconName, Shape[]> = {
  settings: [
    ["line", { x1: "4", y1: "7", x2: "20", y2: "7" }],
    ["line", { x1: "4", y1: "17", x2: "20", y2: "17" }],
    ["circle", { cx: "9", cy: "7", r: "2.5", class: "i-fill" }],
    ["circle", { cx: "15", cy: "17", r: "2.5", class: "i-fill" }],
  ],
  back: [["path", { d: "M15 5l-7 7 7 7" }]],
  send: [
    ["line", { x1: "12", y1: "19", x2: "12", y2: "6" }],
    ["path", { d: "M6.5 11.5L12 6l5.5 5.5" }],
  ],
  stop: [["rect", { x: "7", y: "7", width: "10", height: "10", rx: "2", class: "i-solid" }]],
  check: [["path", { d: "M6 12.5l4 4 8-9" }]],
};

export function icon(name: IconName): SVGElement {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  for (const [tag, attrs] of SHAPES[name]) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.append(el);
  }
  return svg;
}
