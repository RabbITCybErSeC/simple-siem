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
