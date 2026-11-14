// Writes the PNG icons into public/icons. No dependencies: a tiny PNG encoder.
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "public", "icons");
mkdirSync(out, { recursive: true });

const BG = [17, 24, 39];
const FG = [52, 211, 153];

const crcTable = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function segDist(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
const W = 0.045; // half stroke width
function glyph(x, y) {
  return (
    segDist(x, y, 0.32, 0.36, 0.52, 0.52) <= W ||
    segDist(x, y, 0.52, 0.52, 0.32, 0.68) <= W ||
    segDist(x, y, 0.57, 0.68, 0.72, 0.68) <= W
  );
}
function inRounded(x, y, r) {
  const cx = Math.min(Math.max(x, r), 1 - r);
  const cy = Math.min(Math.max(y, r), 1 - r);
  return Math.hypot(x - cx, y - cy) <= r;
}

function render(size, { radius }) {
  const buf = Buffer.alloc(size * size * 4);
  const SS = 3;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let a = 0;
      let g = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const u = (x + (sx + 0.5) / SS) / size;
          const v = (y + (sy + 0.5) / SS) / size;
          if (radius === 0 || inRounded(u, v, radius)) {
            a++;
            if (glyph(u, v)) g++;
          }
        }
      }
      const n = SS * SS;
      const mix = a ? g / a : 0;
      const o = (y * size + x) * 4;
      buf[o] = Math.round(BG[0] + (FG[0] - BG[0]) * mix);
      buf[o + 1] = Math.round(BG[1] + (FG[1] - BG[1]) * mix);
      buf[o + 2] = Math.round(BG[2] + (FG[2] - BG[2]) * mix);
      buf[o + 3] = Math.round((a / n) * 255);
    }
  }
  return buf;
}

const jobs = [
  ["icon-192.png", 192, 0.2],
  ["icon-512.png", 512, 0.2],
  ["maskable-512.png", 512, 0],
  ["apple-touch-icon.png", 180, 0],
];
for (const [name, size, radius] of jobs) {
  writeFileSync(join(out, name), png(size, render(size, { radius })));
  console.log("wrote", name);
}
