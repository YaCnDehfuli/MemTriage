import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "record.spec.ts",
  timeout: 30 * 60 * 1000,
  expect: { timeout: 60_000 },
  use: {
    baseURL: process.env.MEMTRIAGE_BASE_URL ?? "http://127.0.0.1:5173",
    viewport: { width: 1280, height: 800 },
    video: { mode: "on", size: { width: 1280, height: 800 } },
    screenshot: "off",
    trace: "off",
  },
  outputDir: "test-results",
});
