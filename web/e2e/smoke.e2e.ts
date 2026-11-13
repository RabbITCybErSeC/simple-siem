import { expectAccessible } from "./support/accessibility.ts";
import { expect, test } from "./support/test.ts";

test("placeholder page is accessible in light and dark", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Simple SIEM" }),
  ).toBeVisible();

  await page.emulateMedia({ colorScheme: "light" });
  await expectAccessible(page);

  await page.emulateMedia({ colorScheme: "dark" });
  await expectAccessible(page);
});

test("an expected API 401 does not fail the test", async ({ page }) => {
  await page.goto("/");
  const status = await page.evaluate(async () => {
    const response = await fetch("/api/v1/me", {
      headers: { "X-Requested-With": "simple-siem" },
    });
    return response.status;
  });
  expect(status, "fixture response").toBe(401);
});

// These two tests prove the fixture guard fails a test; the failure is the point.
test.fail("an unknown API route fails the test", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(async () => {
    await fetch("/api/v1/unknown", {
      headers: { "X-Requested-With": "simple-siem" },
    });
  });
});

test.fail("an API request without the required header fails the test", async ({
  page,
}) => {
  await page.goto("/");
  await page.evaluate(async () => {
    await fetch("/api/v1/auth/logout", { method: "POST" });
  });
});
