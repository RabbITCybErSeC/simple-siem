import type { Locator, Page } from "@playwright/test";
import { FIXTURE_NOW } from "./support/cases.ts";
import { APP_ORIGIN, expect, signIn, test } from "./support/test.ts";

test.beforeEach(async ({ page }) => {
  await page.clock.install({ time: FIXTURE_NOW });
});

function openTable(page: Page): Locator {
  return page.getByRole("table", { name: "Cases: Open, Mine" });
}

function tableWith(page: Page, tab: string, scope: string): Locator {
  return page.getByRole("table", { name: `Cases: ${tab}, ${scope}` });
}

function numberFromCell(text: string | null): number {
  const match = /^#(\d+)$/.exec((text ?? "").trim());
  if (match === null) {
    throw new Error(`not a case number cell: ${text ?? ""}`);
  }
  return Number(match[1]);
}

async function firstRowNumber(table: Locator): Promise<number> {
  return numberFromCell(
    await table.locator("tbody tr").first().locator("td").first().textContent(),
  );
}

function rowForNumber(page: Page, number: number): Locator {
  return page
    .getByRole("cell", { name: `#${number}`, exact: true })
    .locator("..");
}

function unassignedOpenRow(page: Page, table: Locator): Locator {
  return table
    .locator("tbody tr")
    .filter({ has: page.getByRole("cell", { name: "Unassigned", exact: true }) })
    .filter({ has: page.locator("td:nth-child(6) time") })
    .first();
}

test("opens by keyboard and returns to the row with Escape", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const number = await firstRowNumber(table);

  await table.locator("tbody tr").first().focus();
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(new RegExp(`/cases/${number}(\\?|$)`));
  const heading = page.getByRole("heading", {
    level: 2,
    name: new RegExp(`^#${number}\\b`),
  });
  await expect(heading).toBeFocused();
  await expect(page.getByRole("region", { name: `Case #${number}` })).toBeVisible();
  // The queue stays mounted with the same rows.
  await expect(table.locator("tbody tr")).toHaveCount(50);

  await page.keyboard.press("Escape");

  await expect(page).toHaveURL(/\/cases(\?|$)/);
  await expect(rowForNumber(page, number)).toBeFocused();
});

test("restores a deep link with its section and queue parameters", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases?tab=closed&scope=all");
  const closedTable = tableWith(page, "Closed", "All");
  await expect(closedTable.locator("tbody tr").first()).toBeVisible();
  const number = await firstRowNumber(closedTable);

  await page.goto(`/cases/${number}?view=timeline&tab=closed&scope=all`);

  await expect(page.getByRole("tab", { name: /^Closed/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByRole("radio", { name: /^All/ })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(page.getByRole("tab", { name: "Timeline" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(
    page.getByRole("region", { name: `Case #${number}` }),
  ).toBeVisible();
  await expect(
    page.getByRole("table", { name: "Evidence events" }).first(),
  ).toBeVisible();

  await page
    .getByRole("heading", {
      level: 2,
      name: new RegExp(`^#${number}\\b`),
    })
    .focus();
  await page.keyboard.press("Escape");

  await expect(page).toHaveURL(/tab=closed/);
  await expect(page).toHaveURL(/scope=all/);
  await expect(rowForNumber(page, number)).toBeFocused();
});

test("toggles the full page layout and back", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const number = await firstRowNumber(table);

  await table.locator("tbody tr").first().focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("region", { name: `Case #${number}` }),
  ).toBeVisible();

  const toggle = page.getByRole("button", { name: "Toggle full page" });
  await toggle.click();

  await expect(page).toHaveURL(/layout=full/);
  await expect(table).toBeHidden();
  await expect(
    page.getByRole("region", { name: `Case #${number}` }),
  ).toBeVisible();

  await toggle.click();

  await expect(page).not.toHaveURL(/layout=full/);
  await expect(table).toBeVisible();
  await expect(table.locator("tbody tr")).toHaveCount(50);
  await expect(
    page.getByRole("region", { name: `Case #${number}` }),
  ).toBeVisible();
});

test("assigns to me with a and shows the analyst after Show", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases?tab=all&scope=all&refresh=10s");
  const table = tableWith(page, "All", "All");
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const row = unassignedOpenRow(page, table);
  await expect(row).toBeVisible();
  const number = numberFromCell(
    await row.locator("td").first().textContent(),
  );

  await row.focus();
  await page.keyboard.press("a");

  await expect
    .poll(() =>
      api
        .caseRequests()
        .some((request) => request.startsWith(`/api/v1/cases/case_${number}`)),
    )
    .toBe(true);
  await expect(page.getByRole("alert")).toHaveCount(0);

  await page.clock.runFor(10_000);
  const banner = page
    .getByRole("status")
    .filter({ hasText: "new or updated case" });
  await expect(banner).toBeVisible();
  await banner.getByRole("button", { name: "Show" }).click();

  await expect(
    rowForNumber(page, number).getByRole("cell", {
      name: "Alice Analyst",
      exact: true,
    }),
  ).toBeVisible();
});

test("reports a conflict when another analyst changed the case", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases?tab=all&scope=all");
  const table = tableWith(page, "All", "All");
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const row = unassignedOpenRow(page, table);
  await expect(row).toBeVisible();
  const number = numberFromCell(
    await row.locator("td").first().textContent(),
  );

  api.bumpVersion(`case_${number}`);
  await row.focus();
  await page.keyboard.press("a");

  const alert = page.getByRole("alert");
  await expect(alert).toContainText("This case changed since you opened it.");
  await expect(
    alert.getByRole("button", { name: "Reload case" }),
  ).toBeVisible();

  await alert.getByRole("button", { name: "Reload case" }).click();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("copies the current view with absolute times", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: APP_ORIGIN,
  });
  await signIn(page);
  await page.goto("/cases");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const number = await firstRowNumber(table);

  await table.locator("tbody tr").first().focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("region", { name: `Case #${number}` }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Copy link" }).click();

  await expect(
    page.getByRole("status").filter({ hasText: "Link copied" }),
  ).toHaveText("Link copied");
  const copied = await page.evaluate(() =>
    (
      globalThis as unknown as {
        navigator: { clipboard: { readText: () => Promise<string> } };
      }
    ).navigator.clipboard.readText(),
  );
  expect(copied).toBe(
    `${APP_ORIGIN}/cases/${number}?from=2026-11-08T12:00:00Z&to=2026-11-09T12:00:00Z`,
  );
});

test("renders case #7's markup value as text", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases/7?view=timeline");
  const detail = page.getByRole("region", { name: "Case #7" });
  await expect(
    detail.getByRole("table", { name: "Evidence events" }).first(),
  ).toBeVisible();

  const value = detail
    .getByText("<img src=x onerror=alert(1)>", { exact: true })
    .first();
  await expect(value).toBeVisible();
  await expect(detail.locator("img")).toHaveCount(0);

  const row = value.locator("xpath=ancestor::tr");
  await row.getByRole("button", { name: /^Show fields for / }).click();
  await expect(detail.getByText("principal.user.userid")).toBeVisible();
  await expect(detail.locator("img")).toHaveCount(0);
});
