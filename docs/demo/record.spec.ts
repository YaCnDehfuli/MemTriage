import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CLICK_MS = 800;
const TRANSITION_MS = 1500;
const EVIDENCE_MS = 2500;
const FINAL_MS = 3000;
const FIGURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "../figures");

const QUICK_PLUGINS = [
  "info",
  "pslist",
  "pstree",
  "malfind",
  "scheduled_tasks",
  "registry.userassist",
  "registry.hivelist",
];

const EXCLUDED_SCANNERS = ["psscan", "psxview", "netscan", "registry.hivescan"];

async function pause(page: Page, ms: number) {
  await page.waitForTimeout(ms);
}

async function shot(page: Page, name: string) {
  mkdirSync(FIGURES, { recursive: true });
  await page.screenshot({ path: path.join(FIGURES, name), fullPage: false });
}

async function openStage(page: Page, label: string) {
  await page.locator("aside").getByRole("button", { name: new RegExp(label, "i") }).click();
  await pause(page, TRANSITION_MS);
}

async function dismissAnalystNotice(page: Page) {
  const understand = page.getByRole("button", { name: /I understand/i });
  if (await understand.isVisible().catch(() => false)) {
    await understand.click();
    await expect(understand).toBeHidden();
    await pause(page, CLICK_MS);
  }
}

async function selectQuickPlugins(page: Page) {
  await page.getByRole("button", { name: /^Custom/i }).click();
  await pause(page, CLICK_MS);
  for (const plugin of EXCLUDED_SCANNERS) {
    const box = page.getByRole("checkbox", { name: plugin, exact: true });
    if (await box.count() && (await box.isChecked())) await box.uncheck();
  }
  for (const plugin of QUICK_PLUGINS) {
    const box = page.getByRole("checkbox", { name: plugin, exact: true });
    if (await box.count() && !(await box.isChecked())) await box.check();
  }
  await page.getByRole("button", { name: /Prefer cache/i }).click();
  await pause(page, CLICK_MS);
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

  await pause(page, TRANSITION_MS);
  await shot(page, "ingest.png");

  if (!investigation) {
    if (!dump) {
      throw new Error("Set MEMTRIAGE_DUMP or MEMTRIAGE_INVESTIGATION");
    }
    await page.locator("input[type=file]").setInputFiles(dump);
    await expect(page.getByText("Uploaded")).toBeVisible({ timeout: 30 * 60 * 1000 });
    await pause(page, TRANSITION_MS);
    await page.getByRole("button", { name: /Configure VolMemLyzer triage/i }).click();
    await pause(page, CLICK_MS);
    await selectQuickPlugins(page);
    await page.getByRole("button", { name: /Run Custom triage/i }).click();
    await expect(page.getByText("Triage indicators")).toBeVisible({
      timeout: 30 * 60 * 1000,
    });
  } else {
    await openStage(page, "VolMemLyzer");
  }

  await dismissAnalystNotice(page);
  await expect(page.getByRole("heading", { name: "Scored objects" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Triage indicators")).toBeVisible();
  await page.getByRole("heading", { name: "Scored objects" }).scrollIntoViewIfNeeded();

  const scoredTable = page.getByRole("table").filter({
    has: page.getByRole("columnheader", { name: "Object" }),
  });
  await expect(scoredTable).not.toContainText("103.2");
  await expect(scoredTable).not.toContainText("5292");

  const leadRow = scoredTable.getByRole("row").filter({ hasText: /2580/ }).filter({ hasText: "14/30" }).first();
  await expect(leadRow).toBeVisible();
  await expect(leadRow).toContainText(/High/i);
  await leadRow.scrollIntoViewIfNeeded();

  if (await page.getByText(/Why this fired/i).isVisible()) {
    await leadRow.click();
    await expect(page.getByText(/Why this fired/i)).toBeHidden();
    await pause(page, CLICK_MS);
  }
  await pause(page, EVIDENCE_MS);
  await shot(page, "triage-board.png");

  await leadRow.click();
  await expect(page.getByText(/Why this fired/i)).toBeVisible();
  await expect(page.getByText(/loader|RWX|PEB|private/i).first()).toBeVisible();
  await pause(page, EVIDENCE_MS);
  await shot(page, "evidence-expansion.png");

  await openStage(page, "Process inventory");
  await expect(page.getByRole("heading", { name: /Process inventory/i })).toBeVisible();
  await page.getByPlaceholder("Filter name / PID").fill("2580");
  await pause(page, CLICK_MS);
  const inventoryRow = page.locator("table tbody tr").filter({ hasText: /2580/ }).first();
  await expect(inventoryRow).toBeVisible();
  await expect(inventoryRow).toContainText(/malware\.exe/i);
  await inventoryRow.scrollIntoViewIfNeeded();
  await pause(page, EVIDENCE_MS);

  await openStage(page, "VolMemLyzer");
  await expect(page.getByRole("heading", { name: "Scored objects" })).toBeVisible();
  await page.getByRole("heading", { name: "Scored objects" }).scrollIntoViewIfNeeded();
  await leadRow.scrollIntoViewIfNeeded();
  await expect(leadRow).toContainText("14/30");
  await pause(page, FINAL_MS);
});
