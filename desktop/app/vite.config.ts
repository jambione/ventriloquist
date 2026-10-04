import { defineConfig } from "vitest/config";

// Tauri serves the built files from `dist` (tauri.conf.json > build.frontendDist).
export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: {
    target: ["es2022", "safari15", "chrome105"],
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
