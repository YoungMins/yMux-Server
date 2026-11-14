import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";
import { injectSw } from "./scripts/swInject";

function listFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p));
    else out.push(p);
  }
  return out;
}

// Fills the precache list, a build id and the notification strings into the copied public/sw.js.
function swPrecache(): Plugin {
  let outDir = "";
  return {
    name: "ymux-sw-precache",
    apply: "build",
    configResolved(c) {
      outDir = resolve(c.root, c.build.outDir);
    },
    closeBundle() {
      const swPath = join(outDir, "sw.js");
      const files = listFiles(outDir)
        .map((f) => relative(outDir, f).split("\\").join("/"))
        .filter((f) => f !== "sw.js")
        .sort();
      const hash = createHash("sha256");
      for (const f of files) hash.update(f).update(readFileSync(join(outDir, f)));
      const list = ["./", ...files];
      const sw = injectSw(readFileSync(swPath, "utf8"), list, hash.digest("hex").slice(0, 16));
      writeFileSync(swPath, sw);
    },
  };
}

const target = process.env.YMUX_SERVER;

export default defineConfig({
  base: "./",
  plugins: [swPrecache()],
  build: {
    outDir: "dist",
    target: "es2022",
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  server: target
    ? {
        proxy: {
          "/api": { target, changeOrigin: true },
          "/ws": { target, changeOrigin: true, ws: true },
        },
      }
    : {},
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
