import type { Page } from "@playwright/test";
import { expectAccessible } from "./support/accessibility.ts";
import { expect, signIn, test } from "./support/test.ts";

async function settleTheme(
  page: Page,
  scheme: "light" | "dark",
): Promise<void> {
  const html = page.locator("html");
  if (scheme === "dark") {
    await expect(html).toHaveClass(/dark/);
  } else {
    await expect(html).not.toHaveClass(/dark/);
  }
  // Let the colour transition finish before measuring contrast.
  await page.waitForTimeout(250);
}

async function expectAccessibleInBothThemes(page: Page): Promise<void> {
  await page.emulateMedia({ colorScheme: "light" });
  await settleTheme(page, "light");
  await expectAccessible(page);

  await page.emulateMedia({ colorScheme: "dark" });
  await settleTheme(page, "dark");
  await expectAccessible(page);
}

function numberFromCell(text: string | null): number {
  const match = /^#(\d+)$/.exec((text ?? "").trim());
  if (match === null) {
    throw new Error(`not a case number cell: ${text ?? ""}`);
  }
  return Number(match[1]);
}

test("the login screen is accessible empty and with an error", async ({
  page,
}) => {
  await page.goto("/login");
  await expect(
    page.getByRole("heading", { name: "Sign in to Simple SIEM" }),
  ).toBeVisible();
  await expectAccessibleInBothThemes(page);

  await page.emulateMedia({ colorScheme: "light" });
  await page.getByLabel("Email").fill("analyst@example.test");
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toBeVisible();

  await expectAccessibleInBothThemes(page);
});

test("the shell, palette, and shortcuts dialog are accessible", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  await expect(
    page.getByRole("table", { name: "Cases: Open, Mine" }),
  ).toBeVisible();
  await expect(
    page.getByRole("table", { name: "Cases: Open, Mine" }).locator("tbody tr"),
  ).toHaveCount(50);
  await expectAccessibleInBothThemes(page);

  await page.keyboard.press("Control+k");
  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();
  await expectAccessibleInBothThemes(page);

  await page.keyboard.press("Escape");
  await expect(page.getByPlaceholder("Type a command…")).toBeHidden();

  await page.keyboard.press("?");
  await expect(
    page.getByRole("dialog", { name: "Keyboard shortcuts" }),
  ).toBeVisible();
  await expectAccessibleInBothThemes(page);
});

test("the cases page is accessible empty and with the picker open", async ({
  page,
}) => {
  await signIn(page);

  await page.goto("/cases?tab=in_progress&scope=unassigned");
  await expect(
    page.getByText("No in progress unassigned cases."),
  ).toBeVisible();
  await expectAccessibleInBothThemes(page);

  await page.goto("/cases");
  await expect(
    page.getByRole("table", { name: "Cases: Open, Mine" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Last 24 hours" }).click();
  await expect(
    page.getByRole("group", { name: "Quick select" }),
  ).toBeVisible();
  await expectAccessibleInBothThemes(page);
});

test("the cases error state is accessible", async ({ page }) => {
  await page.route(/\/api\/v1\/cases\?/, (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "INTERNAL_ERROR", message: "boom", details: {} },
      }),
    }),
  );

  await signIn(page);
  await page.goto("/cases");

  await expect(page.getByRole("alert")).toBeVisible({ timeout: 10_000 });
  await expectAccessibleInBothThemes(page);
});

test("the case detail is accessible in every section and both themes", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  const table = page.getByRole("table", { name: "Cases: Open, Mine" });
  await expect(table.locator("tbody tr")).toHaveCount(50);
  const number = numberFromCell(
    await table.locator("tbody tr").first().locator("td").first().textContent(),
  );

  await page.goto(`/cases/${number}`);
  await expect(
    page.getByRole("region", { name: `Case #${number}` }),
  ).toBeVisible();
  await expectAccessibleInBothThemes(page);

  await page.getByRole("tab", { name: /^Alerts/ }).click();
  await expect(page.getByRole("table", { name: "Alerts" })).toBeVisible();
  await expectAccessibleInBothThemes(page);

  await page.getByRole("tab", { name: "Timeline" }).click();
  await expect(
    page.getByRole("table", { name: "Evidence events" }).first(),
  ).toBeVisible();
  await expectAccessibleInBothThemes(page);

  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("list", { name: "Activity" })).toBeVisible();
  await expectAccessibleInBothThemes(page);
});
