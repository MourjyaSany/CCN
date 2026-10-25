// Capture a screenshot of every console page (light and dark) plus any page errors.
// Usage: node e2e/screens.mjs [outDir]
import { chromium } from "@playwright/test";

const out = process.argv[2] ?? "screens";
const base = process.env.NETSHIELD_URL ?? "http://127.0.0.1:8000";
const pages = ["", "network", "incidents", "alerts", "mitigations", "experiments", "research",
  "replay", "attack-builder", "topologies", "policy", "about"];
const browser = await chromium.launch();
for (const scheme of ["light", "dark"]) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: scheme });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log(`[${scheme}] pageerror:`, e.message));
  page.on("console", (m) => m.type() === "error" && console.log(`[${scheme}] console:`, m.text()));
  for (const p of pages) {
    await page.goto(`${base}/app/${p}`);
    await page.waitForTimeout(p === "network" || p === "replay" ? 3500 : 1800);
    const h1 = await page.locator("h1").first().textContent().catch(() => null);
    console.log(`[${scheme}] /${p} h1=${h1}`);
    await page.screenshot({ path: `${out}/${scheme}-${p || "overview"}.png`, fullPage: scheme === "light" });
  }
  await ctx.close();
}
await browser.close();
