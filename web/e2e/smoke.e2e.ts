import { expect, signIn, test } from "./support/test.ts";

test("an expected API 401 does not fail the test", async ({ page }) => {
  await page.goto("/");
  const status = await page.evaluate(async () => {
    const response = await fetch("/api/v1/me", {
      headers: { "X-Requested-With": "simple-siem" },
    });
    return response.status;
  });
  expect(status, "server response").toBe(401);
});

test("the server refuses a cookie request without the required header", async ({
  page,
}) => {
  await page.goto("/login");
  await signIn(page);
  const response = await page.request.post("/api/v1/auth/logout", {
    headers: { Origin: "http://127.0.0.1:8090" },
  });
  expect(response.status()).toBe(403);
  const body = (await response.json()) as { error: { code: string } };
  expect(body.error.code).toBe("FORBIDDEN");
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
