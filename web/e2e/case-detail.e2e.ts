import type { Locator, Page } from "@playwright/test";
import type { AlertSummary } from "../src/features/cases/detail/types.ts";
import { FIXTURE_NOW } from "./support/cases.ts";
import {
  APP_ORIGIN,
  chooseOption,
  expect,
  expectNoSideScroll,
  signIn,
  storeSidebar,
  test,
  VIEWPORTS,
} from "./support/test.ts";

const CLOSE_CASE_ALERTS = 4;
const LONG_FIELD_VALUE = "a".repeat(400);
const THIRTY_ALERTS: AlertSummary[] = Array.from(
  { length: 30 },
  (_, index) => ({
    id: `alert_${index + 1}`,
    title: `Alert ${index + 1}`,
    severity: "HIGH",
    status: "OPEN",
    detectionId: "det_brute_force",
    detectionVersion: "0.1.0",
    evidenceCount: 3,
    occurrenceCount: 3,
    firstEventAt: "2026-11-09T08:00:00Z",
    lastEventAt: "2026-11-09T09:00:00Z",
    outcome: null,
    closureReason: null,
  }),
);

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
    await table.locator("tbody tr").first().locator("td:nth-child(2)").textContent(),
  );
}

function rowForNumber(page: Page, number: number): Locator {
  return page
    .getByRole("cell", { name: `#${number}`, exact: true })
    .locator("..");
}

async function waitForAnimations(locator: Locator): Promise<void> {
  await locator.evaluate((element) => {
    const animations = element.getAnimations() as {
      finished: Promise<unknown>;
    }[];
    return Promise.all(animations.map((animation) => animation.finished));
  });
}

async function findOpenCaseWithAlerts(
  page: Page,
  alerts: number,
): Promise<{ id: string; caseNumber: number }> {
  await page.goto("/cases");
  return page.evaluate(async (wanted) => {
    const headers = { "X-Requested-With": "simple-siem" };
    const listResponse = await fetch("/api/v1/cases?status=OPEN&limit=200", {
      headers,
    });
    const list = (await listResponse.json()) as { data: { id: string }[] };
    for (let index = 0; index < list.data.length; index += 20) {
      const details = await Promise.all(
        list.data.slice(index, index + 20).map(async (item) => {
          const detailResponse = await fetch(`/api/v1/cases/${item.id}`, {
            headers,
          });
          return (await detailResponse.json()) as {
            id: string;
            caseNumber: number;
            alertCount: number;
          };
        }),
      );
      const found = details.find((detail) => detail.alertCount === wanted);
      if (found !== undefined) {
        return { id: found.id, caseNumber: found.caseNumber };
      }
    }
    throw new Error(`no open case with ${wanted} alerts in the fixture`);
  }, alerts);
}

function unassignedOpenRow(page: Page, table: Locator): Locator {
  return table
    .locator("tbody tr")
    .filter({ has: page.getByRole("cell", { name: "Unassigned", exact: true }) })
    .filter({ has: page.locator("td:nth-child(7) time") })
    .first();
}

test.describe("split layout", () => {
  test.use({ viewport: VIEWPORTS.wide });

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
});

test("the detail header actions share the control height", async ({ page }) => {
  await signIn(page);
  const target = await findOpenCaseWithAlerts(page, 2);
  await page.goto(`/cases/${target.caseNumber}`);

  const region = page.getByRole("region", {
    name: `Case #${target.caseNumber}`,
  });
  const names: (string | RegExp)[] = [
    /^(Assign to me|Unassign)$/,
    "Close case",
    "Copy link",
    "Toggle full page",
    "Close case detail",
  ];
  for (const name of names) {
    const button = region.getByRole("button", { name, exact: true });
    await expect(button).toBeVisible();
    const box = await button.boundingBox();
    if (box === null) {
      throw new Error(`${name} has no box`);
    }
    expect(box.height, `${name} has the control height`).toBe(32);
  }
});

test("the evidence table scrolls inside its frame in the split", async ({
  page,
}) => {
  await page.setViewportSize(VIEWPORTS.desktop);
  await storeSidebar(page, true);
  await signIn(page);
  const target = await findOpenCaseWithAlerts(page, 2);
  await page.route(`**/api/v1/cases/${target.id}/timeline*`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        data: [
          {
            id: "tl_long",
            kind: "EVIDENCE",
            at: "2026-11-09T10:00:00Z",
            alertId: "alert_long",
            sourceId: "evt-long",
            udm: {
              metadata: { event_type: "USER_LOGIN" },
              principal: {
                user: { userid: LONG_FIELD_VALUE },
                hostname: "WS-014",
                ip: ["10.12.4.18"],
              },
            },
          },
        ],
        pagination: { limit: 50, nextCursor: null },
      }),
    }),
  );
  await page.goto(`/cases/${target.caseNumber}?view=timeline`);

  const frame = page.getByRole("region", { name: "Evidence events" });
  await expect(frame).toBeVisible();
  const overflow = await frame.evaluate((element) => ({
    scrollWidth: element.scrollWidth,
    clientWidth: element.clientWidth,
  }));
  expect(
    overflow.scrollWidth,
    "the evidence frame scrolls sideways",
  ).toBeGreaterThan(overflow.clientWidth);

  const widths = await page.evaluate(() => {
    const region = document.querySelector('section[aria-label^="Case #"]');
    const pane = region?.parentElement;
    const grid = pane?.parentElement;
    if (!pane || !grid) {
      return null;
    }
    const columns = getComputedStyle(grid)
      .gridTemplateColumns.split(" ")
      .map((value) => Number.parseFloat(value));
    return {
      detail: pane.getBoundingClientRect().width,
      column: columns[columns.length - 1] ?? 0,
    };
  });
  expect(widths).not.toBeNull();
  expect(
    widths?.detail,
    "the detail stays inside its grid column",
  ).toBeLessThanOrEqual((widths?.column ?? 0) + 1);
});

test("an open case does not scroll sideways on a phone", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS.phone);
  await signIn(page);
  await page.goto("/cases/7?view=timeline");
  await expect(
    page.getByRole("region", { name: "Case #7" }),
  ).toBeVisible();

  await expectNoSideScroll(page);
});

test("assigns to me with a and shows the analyst at once", async ({
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
    await row.locator("td:nth-child(2)").textContent(),
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

  // The returned case replaces the row in place: no refresh banner is needed.
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
    await row.locator("td:nth-child(2)").textContent(),
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
  const copied = await page.evaluate(() => navigator.clipboard.readText());
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
  await expect(
    detail.getByText("Event no longer cached").first(),
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

function focusedRowNumber(page: Page): Promise<number> {
  return page
    .locator("tbody tr:focus")
    .locator("td:nth-child(2)")
    .textContent()
    .then(numberFromCell);
}

test("closes a case by keyboard and shows the closed row after Show", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases?refresh=10s");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);

  await table.locator("tbody tr").first().focus();
  await page.keyboard.press("j");
  const number = await focusedRowNumber(page);

  await page.keyboard.press("e");
  const dialog = page.getByRole("dialog", {
    name: `Close case #${number}`,
    exact: true,
  });
  await expect(dialog).toBeVisible();

  await expect(dialog.locator(":focus")).toHaveAttribute(
    "id",
    "close-outcome-MALICIOUS",
  );
  await page.keyboard.down("ArrowRight");
  await page.clock.runFor(1);
  await page.keyboard.up("ArrowRight");
  await expect(
    dialog.getByRole("radio", { name: "Accepted" }),
  ).toHaveAttribute("aria-checked", "true");
  await page.keyboard.press("Tab");
  const reason = dialog.getByRole("combobox", {
    name: "Closure reason",
    exact: true,
  });
  await expect(reason).toBeFocused();
  await page.keyboard.press("a");
  await expect(reason).toHaveText("Authorized activity");

  const conclusion = dialog.getByLabel("Conclusion");
  let conclusionFocused = false;
  for (let index = 0; index < 14 && !conclusionFocused; index++) {
    if (
      (await dialog.locator(":focus").getAttribute("id")) ===
      "close-conclusion"
    ) {
      conclusionFocused = true;
      break;
    }
    await page.keyboard.press("Tab");
  }
  expect(conclusionFocused).toBe(true);
  await conclusion.pressSequentially("Authorized pentest by RedTeam.");

  let submitFocused = false;
  for (let index = 0; index < 12 && !submitFocused; index++) {
    await page.keyboard.press("Tab");
    submitFocused =
      (await dialog.locator(":focus").textContent())?.trim() === "Close case";
  }
  expect(submitFocused).toBe(true);
  await dialog
    .getByRole("button", { name: "Close case", exact: true })
    .click();

  await expect(dialog).toBeHidden();
  const detail = page.getByRole("region", { name: `Case #${number}` });
  await expect(detail.getByText("Authorized pentest by RedTeam.")).toBeVisible();
  await expect(
    page.getByRole("status").filter({ hasText: `Case #${number} closed` }),
  ).toHaveText(`Case #${number} closed`);

  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/cases(\?|$)/);

  await page.clock.runFor(10_000);
  const banner = page
    .getByRole("status")
    .filter({ hasText: "new or updated case" });
  await expect(banner).toBeVisible();
  await banner.getByRole("button", { name: "Show" }).click();

  await expect(
    table.getByRole("cell", { name: `#${number}`, exact: true }),
  ).toHaveCount(0);

  await page.getByRole("tab", { name: /^Closed/ }).click();
  const closedTable = tableWith(page, "Closed", "Mine");
  await expect(closedTable).toBeVisible();
  await expect(rowForNumber(page, number)).toBeVisible();
});

test("keeps the typed conclusion when the case changed", async ({
  page,
  api,
}) => {
  const added = api.addCase({ title: "Conflict case" });
  await signIn(page);
  await page.goto("/cases");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const row = rowForNumber(page, added.caseNumber);
  await row.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("region", { name: `Case #${added.caseNumber}` }),
  ).toBeVisible();

  const dialog = page.getByRole("dialog", {
    name: `Close case #${added.caseNumber}`,
    exact: true,
  });
  await page.getByRole("button", { name: "Close case", exact: true }).click();
  await expect(dialog).toBeVisible();

  await dialog
    .getByRole("radiogroup", { name: "Outcome" })
    .getByText("Accepted", { exact: true })
    .click();
  await chooseOption(
    page,
    dialog.getByRole("combobox", { name: "Closure reason", exact: true }),
    "Authorized activity",
  );
  await dialog.getByLabel("Conclusion").fill("Keep this conclusion.");

  api.bumpVersion(added.id);
  await dialog.getByRole("button", { name: "Close case", exact: true }).click();

  await expect(dialog.getByRole("alert")).toContainText(
    "This case changed since you opened it. Reload it and close again.",
  );
  await expect(dialog.getByLabel("Conclusion")).toHaveValue(
    "Keep this conclusion.",
  );

  await dialog.getByRole("button", { name: "Reload case" }).click();
  await expect
    .poll(
      () =>
        api
          .caseRequests()
          .filter(
            (request) =>
              request === `/api/v1/cases/${added.caseNumber}`,
          ).length,
    )
    .toBeGreaterThan(1);
  await expect(dialog.getByLabel("Conclusion")).toHaveValue(
    "Keep this conclusion.",
  );

  await dialog.getByRole("button", { name: "Close case", exact: true }).click();
  await expect(dialog).toBeHidden();
});

test("traps focus in the close dialog and returns it on Escape", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);
  await table.locator("tbody tr").first().focus();
  await page.keyboard.press("Enter");

  const opener = page.getByRole("button", { name: "Close case", exact: true });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: /^Close case #/ });
  await expect(dialog).toBeVisible();

  for (let index = 0; index < 20; index++) {
    await page.keyboard.press("Tab");
    await expect(dialog.locator(":focus")).toHaveCount(1);
  }
  await page.keyboard.press("Shift+Tab");
  await expect(dialog.locator(":focus")).toHaveCount(1);

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();
});

test("the close dialog fits a phone", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS.phone);
  await signIn(page);
  const target = await findOpenCaseWithAlerts(page, CLOSE_CASE_ALERTS);
  await page.goto(`/cases/${target.caseNumber}`);
  await page.getByRole("button", { name: "Close case", exact: true }).click();

  const dialog = page.getByRole("dialog", {
    name: `Close case #${target.caseNumber}`,
    exact: true,
  });
  const dispositions = dialog.getByRole("list", {
    name: "Alert dispositions",
  });
  await expect(dispositions.getByRole("listitem")).toHaveCount(
    CLOSE_CASE_ALERTS,
  );
  await waitForAnimations(dialog);

  for (const name of ["Cancel", "Close case"]) {
    const button = dialog.getByRole("button", { name, exact: true });
    await expect(button, `${name} is shown`).toBeVisible();
    const box = await button.boundingBox();
    if (box === null) {
      throw new Error(`${name} has no box`);
    }
    expect(box.x, `${name} starts inside the viewport`).toBeGreaterThanOrEqual(0);
    expect(box.y, `${name} starts inside the viewport`).toBeGreaterThanOrEqual(0);
    expect(
      box.x + box.width,
      `${name} ends inside the viewport`,
    ).toBeLessThanOrEqual(VIEWPORTS.phone.width);
    expect(
      box.y + box.height,
      `${name} ends inside the viewport`,
    ).toBeLessThanOrEqual(VIEWPORTS.phone.height);
  }

  const selects = dispositions.getByRole("combobox");
  await expect(selects).toHaveCount(CLOSE_CASE_ALERTS * 2);
  for (let index = 0; index < CLOSE_CASE_ALERTS * 2; index += 1) {
    const clipped = await selects
      .nth(index)
      .evaluate((element) => element.scrollWidth > element.clientWidth);
    expect(
      clipped,
      `per-alert select ${index + 1} shows its full label`,
    ).toBe(false);
  }
});

test("the close dialog keeps its footer visible on a short screen", async ({
  page,
}) => {
  // Deliberately shorter than VIEWPORTS.tablet: the scenario is a short screen.
  await page.setViewportSize({ width: 1024, height: 600 });
  await signIn(page);
  const target = await findOpenCaseWithAlerts(page, 2);
  await page.route(`**/api/v1/cases/${target.id}/alerts*`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        data: THIRTY_ALERTS,
        pagination: { limit: 100, nextCursor: null },
      }),
    }),
  );
  await page.goto(`/cases/${target.caseNumber}`);
  await page.getByRole("button", { name: "Close case", exact: true }).click();

  const dialog = page.getByRole("dialog", {
    name: `Close case #${target.caseNumber}`,
    exact: true,
  });
  const items = dialog
    .getByRole("list", { name: "Alert dispositions" })
    .getByRole("listitem");
  await expect(items).toHaveCount(THIRTY_ALERTS.length);
  await waitForAnimations(dialog);
  await items.last().scrollIntoViewIfNeeded();
  await expect(items.last()).toBeVisible();

  for (const name of ["Cancel", "Close case"]) {
    const button = dialog.getByRole("button", { name, exact: true });
    await expect(button, `${name} stays visible`).toBeVisible();
    const box = await button.boundingBox();
    if (box === null) {
      throw new Error(`${name} has no box`);
    }
    expect(box.y, `${name} starts inside the viewport`).toBeGreaterThanOrEqual(0);
    expect(
      box.y + box.height,
      `${name} ends inside the viewport`,
    ).toBeLessThanOrEqual(600);
  }
});

test("the close dialog controls share one height at 1440", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS.desktop);
  await signIn(page);
  const target = await findOpenCaseWithAlerts(page, CLOSE_CASE_ALERTS);
  await page.goto(`/cases/${target.caseNumber}`);
  await page.getByRole("button", { name: "Close case", exact: true }).click();

  const dialog = page.getByRole("dialog", {
    name: `Close case #${target.caseNumber}`,
    exact: true,
  });
  const dispositions = dialog.getByRole("list", {
    name: "Alert dispositions",
  });
  await expect(dispositions.getByRole("listitem")).toHaveCount(
    CLOSE_CASE_ALERTS,
  );
  await waitForAnimations(dialog);

  const controls = [
    dialog.getByRole("combobox", { name: "Closure reason", exact: true }),
    dispositions.getByRole("combobox").first(),
    dialog.getByRole("button", { name: "Cancel", exact: true }),
  ];
  const heights: number[] = [];
  for (const control of controls) {
    const box = await control.boundingBox();
    if (box === null) {
      throw new Error("a control has no box");
    }
    heights.push(box.height);
  }

  expect(heights[0]).toBe(32);
  expect(heights[1]).toBe(heights[0]);
  expect(heights[2]).toBe(heights[0]);
});

test("bulk closes selected rows and reports the changed one", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases");
  const table = openTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const rows = table.locator("tbody tr");
  const numbers: number[] = [];
  for (let index = 0; index < 3; index++) {
    numbers.push(
      numberFromCell(
        await rows.nth(index).locator("td:nth-child(2)").textContent(),
      ),
    );
  }

  await rows.first().focus();
  await page.keyboard.press("x");
  await page.keyboard.press("j");
  await page.keyboard.press("x");
  await page.keyboard.press("j");
  await page.keyboard.press("x");
  await expect(
    page.getByRole("toolbar", { name: "Selected cases" }),
  ).toContainText("3 selected");

  api.bumpVersion(`case_${numbers[1]}`);
  await page.getByRole("button", { name: "Close selected", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Close selected cases" });
  await expect(dialog).toBeVisible();

  await dialog
    .getByRole("radiogroup", { name: "Outcome" })
    .getByText("Accepted", { exact: true })
    .click();
  await chooseOption(
    page,
    dialog.getByRole("combobox", { name: "Closure reason", exact: true }),
    "Authorized activity",
  );
  await dialog.getByLabel("Conclusion").fill("Pentest, SEC-41.");
  await dialog.getByRole("button", { name: "Close selected cases" }).click();

  await expect(
    dialog.getByText("2 closed, 1 not closed"),
  ).toBeVisible();
  const results = dialog.getByRole("list", { name: "Bulk close results" });
  await expect(results).toContainText("Changed since loaded");

  await dialog.getByRole("button", { name: "Done" }).click();
  await expect(dialog).toBeHidden();
  await expect(
    page.getByRole("toolbar", { name: "Selected cases" }),
  ).toContainText("1 selected");
  await expect(
    rowForNumber(page, numbers[1]).getByRole("checkbox"),
  ).toBeChecked();
});
