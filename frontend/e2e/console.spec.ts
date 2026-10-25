import { expect, test } from "@playwright/test";

const PAGES: Array<[string, RegExp]> = [
  ["/app/", /Overview/],
  ["/app/network", /Live network/],
  ["/app/incidents", /Incident timeline/],
  ["/app/alerts", /Alerts/],
  ["/app/mitigations", /Mitigations/],
  ["/app/experiments", /Experiments/],
  ["/app/research", /Research results/],
  ["/app/replay", /Replay/],
  ["/app/attack-builder", /Attack builder/],
  ["/app/topologies", /Topologies/],
  ["/app/policy", /Policy/],
  ["/app/about", /About NetShield/],
];

test("every page renders without console errors", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  for (const [path, heading] of PAGES) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(heading);
  }
  expect(errors).toEqual([]);
});

test("command palette navigates", async ({ page }) => {
  await page.goto("/app/");
  await page.keyboard.press("Control+K");
  await page.getByPlaceholder("Type a page").fill("alerts");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/app\/alerts/);
});

test("a closed-loop run fills the timeline and topology", async ({ page }) => {
  await page.goto("/app/");
  await page.getByRole("combobox").first().selectOption("exp2_udp_flood");
  await page.getByRole("button", { name: "Start" }).click();
  await expect(page.getByText(/exp2_udp_flood/).first()).toBeVisible();
  await page.goto("/app/network");
  await expect(page.getByRole("img", { name: "Network topology graph" })).toBeVisible({ timeout: 30_000 });
  await page.goto("/app/incidents");
  await expect(page.getByText("Milestones", { exact: true })).toBeVisible();
  await expect(page.getByText(/attack starts|attack start/i).first()).toBeVisible({ timeout: 45_000 });
  await page.request.post("/api/simulation/stop");
});
