import {
  APP_ORIGIN,
  BROWSER_HEADERS,
  expect,
  signIn,
  test,
} from "./support/test.ts";

test("an expected API 401 does not fail the test", async ({ page }) => {
  await page.goto("/");
  const status = await page.evaluate(async (headers) => {
    const response = await fetch("/api/v1/me", { headers });
    return response.status;
  }, BROWSER_HEADERS);
  expect(status, "server response").toBe(401);
});

test("the server refuses a cookie request without the required header", async ({
  page,
}) => {
  await page.goto("/login");
  await signIn(page);
  const response = await page.request.post("/api/v1/auth/logout", {
    headers: { Origin: APP_ORIGIN },
  });
  expect(response.status()).toBe(403);
  const body = (await response.json()) as { error: { code: string } };
  expect(body.error.code).toBe("FORBIDDEN");

  const stillSignedIn = await page.request.get("/api/v1/me", {
    headers: BROWSER_HEADERS,
  });
  expect(stillSignedIn.status(), "session after the refused logout").toBe(200);
});

test("a case request without the session cookie is refused", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await page.context().clearCookies();

  const status = await page.evaluate(async (headers) => {
    const response = await fetch("/api/v1/cases", { headers });
    return response.status;
  }, BROWSER_HEADERS);
  expect(status, "case response without a session").toBe(401);
});

// These two tests prove the fixture guard fails a test; the failure is the point.
test.fail("an unknown API route fails the test", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(async (headers) => {
    await fetch("/api/v1/unknown", { headers });
  }, BROWSER_HEADERS);
});

test.fail("an API request without the required header fails the test", async ({
  page,
}) => {
  await page.goto("/");
  await page.evaluate(async () => {
    await fetch("/api/v1/auth/logout", { method: "POST" });
  });
});
