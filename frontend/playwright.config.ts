import { defineConfig } from "@playwright/test";

// Run against a live API: start it first (python launch.py --no-browser).
export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  use: { baseURL: process.env.NETSHIELD_URL ?? "http://127.0.0.1:8000", trace: "retain-on-failure" },
  reporter: [["list"]],
});
