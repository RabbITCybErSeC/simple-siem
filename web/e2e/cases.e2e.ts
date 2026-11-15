import type { Page } from "@playwright/test";
import { FIXTURE_NOW } from "./support/cases.ts";
import { expect, signIn, test } from "./support/test.ts";

test.beforeEach(async ({ page }) => {
  await page.clock.install({ time: FIXTURE_NOW });
});

function listRequests(api: { caseRequests: () => string[] }) {
  return api
    .caseRequests()
    .filter((request) => request.startsWith("/api/v1/cases?"));
}

function openCases(page: Page) {
  return page.getByRole("table", { name: "Cases: Open, Mine" });
}

test("shows my open cases, counts, and the trend chart", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases");

  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  const table = openCases(page);
  await expect(table).toBeVisible();
  await expect(table.locator("tbody tr")).toHaveCount(50);
  await expect(
    page.getByText("Open work ignores the time range."),
  ).toBeVisible();
  await expect(page.locator(".recharts-wrapper")).toBeVisible();
  await expect(page.getByRole("tab", { name: "Open 120" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "In progress 60" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "Mine 55" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "Unassigned 30" })).toBeVisible();

  const request = listRequests(api)[0];
  expect(request).toBeDefined();
  const parameters = new URLSearchParams(request?.split("?")[1]);
  expect(parameters.get("status")).toBe("OPEN");
  expect(parameters.get("scope")).toBe("mine");
  expect(parameters.get("sort")).toBe("lastEventAt:desc");
  expect(parameters.has("from")).toBe(false);
});

test("restores a shared link and falls back for an invalid value", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases?tab=closed&scope=all&from=now-7d&field=closedAt");

  await expect(page.getByRole("tab", { name: /^Closed/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByRole("radio", { name: /^All/ })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(page.getByRole("button", { name: "Last 7 days" })).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "Time field" }),
  ).toContainText("Closed");
  await expect(
    page.getByRole("table", { name: "Cases: Closed, All" }),
  ).toBeVisible();

  await page.goto("/cases?tab=bogus&scope=unassigned");

  await expect(page.getByRole("tab", { name: /^Open/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(
    page.getByRole("radio", { name: /^Unassigned/ }),
  ).toHaveAttribute("aria-checked", "true");
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("Back steps through the views", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(openCases(page)).toBeVisible();

  await page.getByRole("tab", { name: /^Closed/ }).click();
  await expect(new URL(page.url()).searchParams.get("tab")).toBe("closed");

  await page.goBack();
  await expect(page).toHaveURL(/\/cases$/);

  await expect(page.getByRole("tab", { name: /^Open/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(openCases(page)).toBeVisible();
});

test("changes tabs, scopes, and rows with the keyboard", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  const table = openCases(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);

  const closedTab = page.getByRole("tab", { name: /^Closed/ });
  await closedTab.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("tab", { name: /^Closed/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(new URL(page.url()).searchParams.get("tab")).toBe("closed");

  const unassigned = page.getByRole("radio", { name: /^Unassigned/ });
  await unassigned.focus();
  await page.keyboard.press("Enter");
  await expect(new URL(page.url()).searchParams.get("scope")).toBe(
    "unassigned",
  );

  const mine = page.getByRole("radio", { name: /^Mine/ });
  await mine.focus();
  await page.keyboard.press("Enter");
  await expect(mine).toHaveAttribute("aria-checked", "true");
  await expect
    .poll(() => new URL(page.url()).searchParams.get("scope"))
    .toBeNull();

  const openTab = page.getByRole("tab", { name: /^Open/ });
  await openTab.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("tab", { name: /^Open/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  const openTable = openCases(page);
  await expect(openTable).toBeVisible();

  const rows = openTable.locator("tbody tr");
  await rows.first().focus();
  await page.keyboard.press("j");
  await page.keyboard.press("j");
  await expect(rows.nth(2)).toBeFocused();
  await page.keyboard.press("k");
  await expect(rows.nth(1)).toBeFocused();
});

test("applies a time range from the picker with the keyboard", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(openCases(page)).toBeVisible();

  const trigger = page.getByRole("button", { name: "Last 24 hours" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("group", { name: "Commonly used" }),
  ).toBeVisible();

  const lastFourHours = page
    .getByRole("group", { name: "Commonly used" })
    .getByRole("button", { name: "Last 4 hours" });
  await lastFourHours.focus();
  await page.keyboard.press("Enter");

  await expect
    .poll(() => new URL(page.url()).searchParams.get("from"))
    .toBe("now-4h");
  await expect(
    page.getByRole("group", { name: "Commonly used" }),
  ).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Last 4 hours" }),
  ).toBeVisible();
});

test("drags across the chart to set an absolute range", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(openCases(page)).toBeVisible();
  await expect(page.locator(".recharts-wrapper")).toBeVisible();

  const plot = page.locator(".recharts-wrapper");
  const plotBox = await plot.boundingBox();
  if (plotBox === null) {
    throw new Error("chart has no bounds");
  }
  const tick = (label: string) => page.getByText(label, { exact: true });
  const start = await tick("13:00").boundingBox();
  const end = await tick("14:00").boundingBox();
  if (start === null || end === null) {
    throw new Error("chart ticks have no bounds");
  }
  const y = plotBox.y + plotBox.height / 2;

  await page.mouse.move(start.x + start.width / 2, y);
  await expect(page.locator(".recharts-tooltip-wrapper")).toContainText(
    "2026-11-08T13:00:00",
  );
  await page.mouse.down();
  await page.mouse.move(end.x + end.width / 2, y, { steps: 5 });
  await expect(page.locator(".recharts-tooltip-wrapper")).toContainText(
    "2026-11-08T14:00:00",
  );
  await page.mouse.up();

  await expect
    .poll(() => new URL(page.url()).searchParams.get("from"))
    .toBe("2026-11-08T13:00:00Z");
  await expect
    .poll(() => new URL(page.url()).searchParams.get("to"))
    .toBe("2026-11-08T14:30:00Z");
});

test("announces a new case without moving the visible rows", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases?refresh=30s");
  const table = openCases(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);

  const rows = table.locator("tbody tr");
  const firstNumber = (await rows.first().locator("td:nth-child(2)").textContent())
    ?.trim();
  await rows.first().focus();

  api.addCase({ title: "Refresh arrival" });
  await page.clock.runFor(30_000);

  const banner = page.getByRole("status");
  await expect(banner).toContainText("1 new or updated case");
  await expect(page.getByText("Refresh arrival")).toBeHidden();
  await expect(rows).toHaveCount(50);
  await expect(rows.first()).toBeFocused();

  await banner.getByRole("button", { name: "Show" }).click();

  await expect(page.getByText("Refresh arrival")).toBeVisible();
  await expect(banner).toBeHidden();
  await expect(rows).toHaveCount(50);
  const focusedRow = page.locator("tbody tr:focus");
  await expect(focusedRow).toHaveCount(1);
  expect((await focusedRow.locator("td:nth-child(2)").textContent())?.trim()).toBe(
    firstNumber,
  );
});

test("pauses refresh while the command palette is open", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases?refresh=30s");
  await expect(openCases(page).locator("tbody tr")).toHaveCount(50);

  await page.keyboard.press("Control+k");
  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();
  const before = api.caseRequests().length;

  await page.clock.runFor(30_000);

  expect(api.caseRequests()).toHaveLength(before);
});
