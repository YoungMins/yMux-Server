import { defineConfig } from "vitest/config";

// Only the end-to-end device scripts (scripts/e2e.ps1 names one on the command line);
// `pnpm test` (vite.config.ts) never picks them up.
export default defineConfig({
  test: {
    include: ["scripts/e2e-device.ts", "scripts/e2e-fleet.ts"],
    environment: "node",
    testTimeout: 150000,
    hookTimeout: 30000,
    fileParallelism: false,
  },
});
