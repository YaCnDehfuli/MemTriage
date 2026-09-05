import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PAUSE_MS = 1500;
const SLIDER_PAUSE_MS = 4500;
const FIGURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "../figures");

const CACHED_PLUGINS = [
  "info",
  "pslist",
  "pstree",
  "psscan",
  "psxview",
  "malfind",
  "netscan",
  "scheduled_tasks",
  "registry.userassist",
  "registry.hivelist",
  "registry.hivescan",
];

async function pause(page: Page, ms = PAUSE_MS) {
  await page.waitForTimeout(ms);
}

async function shot(page: Page, name: string) {
  mkdirSync(FIGURES, { recursive: true });
  await page.screenshot({ path: path.join(FIGURES, name), fullPage: false });
}

async function openStage(page: Page, label: string) {
  await page.locator("aside").getByRole("button", { name: new RegExp(label, "i") }).click();
}

async function dismissAnalystNotice(page: Page) {
  const understand = page.getByRole("button", { name: /I understand/i });
  if (await understand.isVisible().catch(() => false)) {
    await understand.click();
    await expect(understand).toBeHidden();
  }
}

test("record the live MemTriage investigation path", async ({ page }) => {
  const dump = process.env.MEMTRIAGE_DUMP;
  const investigation = process.env.MEMTRIAGE_INVESTIGATION;
  test.setTimeout(30 * 60 * 1000);

  if (investigation) {
    await page.goto(`/?investigation=${investigation}`, { waitUntil: "load" });
    await expect(page.getByRole("heading", { name: /Memory image intake/i })).toBeVisible();
    await expect(page.getByText(/2580_5\.vmem/i)).toBeVisible({ timeout: 30_000 });
  } else {
    await page.goto("/", { waitUntil: "load" });
    await expect(page.getByText(/Drop memory images here/i)).toBeVisible();
  }

  await pause(page);
  await shot(page, "ingest.png");

  if (!investigation) {
    if (!dump) {
      throw new Error("Set MEMTRIAGE_DUMP or MEMTRIAGE_INVESTIGATION");
    }
    await page.locator("input[type=file]").setInputFiles(dump);
    await expect(page.getByText("Uploaded")).toBeVisible({ timeout: 30 * 60 * 1000 });
    await page.getByRole("button", { name: /Configure VolMemLyzer triage/i }).click();
    await page.getByRole("button", { name: /^Custom/i }).click();
    for (const plugin of CACHED_PLUGINS) {
      const box = page.getByRole("checkbox", { name: plugin, exact: true });
      if (!(await box.isChecked())) await box.check();
    }
    await page.getByRole("button", { name: /Prefer cache/i }).click();
    await page.getByRole("button", { name: /Run Custom triage/i }).click();
    await expect(page.getByText("Indicators of compromise")).toBeVisible({
      timeout: 30 * 60 * 1000,
    });
  } else {
    await openStage(page, "VolMemLyzer");
  }

  await dismissAnalystNotice(page);
  await expect(page.getByRole("heading", { name: "Scored objects" })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("heading", { name: "Scored objects" }).scrollIntoViewIfNeeded();

  const scoredTable = page.getByRole("table").filter({
    has: page.getByRole("columnheader", { name: "Object" }),
  });
  const leadRow = scoredTable.getByRole("row").filter({ hasText: /searchhost/i });
  if (await page.getByText(/Why this fired/i).isVisible()) {
    await leadRow.click();
    await expect(page.getByText(/Why this fired/i)).toBeHidden();
  }
  await pause(page);
  await shot(page, "triage-board.png");

  await leadRow.click();
  await expect(page.getByText(/Why this fired/i)).toBeVisible();
  await pause(page);
  await shot(page, "evidence-expansion.png");

  await page.getByRole("button", { name: /Advanced controls/i }).click();
  await expect(page.getByText("Confidence floor")).toBeVisible();
  const slider = page.locator('input[type=range][min="0"]');
  await slider.focus();
  await slider.fill("0.2");
  await page.getByRole("button", { name: /^Aggressive$/i }).click();
  await expect(page.getByText("Indicators of compromise")).toBeVisible();
  await pause(page, SLIDER_PAUSE_MS);

  await openStage(page, "Process inventory");
  await expect(page.getByRole("heading", { name: /Process inventory/i })).toBeVisible();
  await pause(page);

  const target = page.locator("table tbody tr").filter({ hasText: /SearchHost|5292/i }).first();
  const analyze = (await target.count())
    ? target.getByRole("button", { name: /Analyze/i })
    : page.getByRole("button", { name: /Analyze/i }).first();
  await expect(analyze).toBeEnabled();
  await analyze.click();
  await expect(
    page.getByText(/Attention overlay|Attention → VAD regions|Untrained structural placeholder|Model not loaded/i).first(),
  ).toBeVisible({ timeout: 120_000 });
  await pause(page);
  await shot(page, "attention-overlay.png");

  await page.locator("text=Phase 2 · Region analysis").scrollIntoViewIfNeeded();
  for (const tab of ["Disassembly", "Control flow", "Call graph", "Structure", "Hex"]) {
    const button = page.getByRole("button", { name: tab, exact: true });
    if (await button.count()) {
      await button.click();
      await pause(page);
    }
  }
});
