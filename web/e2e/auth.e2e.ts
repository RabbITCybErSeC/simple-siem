import { expect, signIn, test } from "./support/test.ts";

interface BrowserStorage {
  length: number;
  key(index: number): string | null;
  getItem(key: string): string | null;
}

interface BrowserGlobals {
  localStorage: BrowserStorage;
  sessionStorage: BrowserStorage;
  document: { cookie: string };
}

const EMAIL = "analyst@example.test";
const PASSWORD = "correct horse battery staple";
const LIMITED_EMAIL = "limited@example.test";

test("a signed-out visitor is sent to login with the next path", async ({
  page,
}) => {
  await page.goto("/cases");

  await expect(page).toHaveURL(/\/login\?next=%2Fcases$/);
  await expect(
    page.getByRole("heading", { name: "Sign in to Simple SIEM" }),
  ).toBeVisible();
});

test("signs in with the keyboard and keeps tokens out of storage", async ({
  page,
}) => {
  await page.goto("/cases");
  await expect(page).toHaveURL(/\/login\?next=%2Fcases$/);

  await page.keyboard.press("Tab");
  await page.keyboard.type(EMAIL);
  await page.keyboard.press("Tab");
  await page.keyboard.type(PASSWORD);
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  await expect(page.getByText("Alice Analyst")).toBeVisible();
  await expect(page).toHaveURL(/\/cases$/);

  const storage = await page.evaluate(() => {
    const browser = globalThis as unknown as BrowserGlobals;
    const values = (store: BrowserStorage) => {
      const items: string[] = [];
      for (let index = 0; index < store.length; index += 1) {
        const key = store.key(index);
        if (key !== null) {
          items.push(store.getItem(key) ?? "");
        }
      }
      return items;
    };
    return {
      local: values(browser.localStorage),
      session: values(browser.sessionStorage),
      cookie: browser.document.cookie,
    };
  });
  const stored = [...storage.local, ...storage.session, storage.cookie].join(
    " ",
  );
  expect(stored).not.toContain(PASSWORD);
  expect(stored).not.toContain(EMAIL);
  expect(stored).not.toMatch(/sessiontoken|bearer/i);

  const sessionCookie = (await page.context().cookies()).find(
    (cookie) => cookie.name === "simple_siem_session",
  );
  expect(sessionCookie?.httpOnly, "session cookie").toBe(true);
  expect(storage.cookie).not.toContain("simple_siem_session");
});

test("refuses a cross-site login and sets no session cookie", async ({
  page,
}) => {
  await page.goto("/login");
  const response = await page.request.post("/api/v1/auth/login", {
    headers: {
      "X-Requested-With": "simple-siem",
      Origin: "https://evil.example",
    },
    data: { email: EMAIL, password: PASSWORD },
  });

  expect(response.status()).toBe(403);
  const body = (await response.json()) as {
    error: { code: string };
  };
  expect(body.error.code).toBe("FORBIDDEN");
  expect(response.headers()["set-cookie"]).toBeUndefined();
});

test("an analyst cannot list users", async ({ page }) => {
  await signIn(page, "analyst");
  await page.goto("/cases");

  const response = await page.request.get("/api/v1/users", {
    headers: {
      "X-Requested-With": "simple-siem",
      Origin: "http://127.0.0.1:8090",
    },
  });

  expect(response.status()).toBe(403);
  const body = (await response.json()) as { error: { code: string } };
  expect(body.error.code).toBe("FORBIDDEN");
});

test("shows the generic message after a wrong password", async ({ page }) => {
  await page.goto("/login");

  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("alert")).toHaveText(
    "Email or password is incorrect.",
  );
  await expect(page.getByLabel("Password")).toHaveValue("");
  await expect(page.getByLabel("Email")).toHaveValue(EMAIL);
});

test("shows the rate-limit message on the eleventh failed login", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(LIMITED_EMAIL);

  for (let attempt = 0; attempt < 10; attempt += 1) {
    await page.getByLabel("Password").fill("not the password");
    const response = page.waitForResponse((candidate) =>
      candidate.url().endsWith("/api/v1/auth/login"),
    );
    await page.getByRole("button", { name: "Sign in" }).click();
    expect((await response).status(), `attempt ${attempt + 1}`).toBe(401);
    await expect(page.getByLabel("Password")).toHaveValue("");
  }

  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("alert")).toHaveText(
    "Too many attempts. Wait a minute and try again.",
  );
});

test("returns to login when the session expires and back to the next path", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.context().clearCookies();
  await page.keyboard.press("Control+k");
  await page.keyboard.type("cases");
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/\/login\?next=%2Fcases&reason=expired$/);
  await expect(
    page.getByText("Your session ended. Sign in again."),
  ).toBeVisible();

  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/cases$/);
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
});

test("signs out from the command palette", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("Control+k");
  await page.keyboard.type("sign out");
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/\/login$/);
  await expect(
    page.getByRole("heading", { name: "Sign in to Simple SIEM" }),
  ).toBeVisible();
});

test("keeps the shell and alerts when sign out fails", async ({ page }) => {
  await signIn(page);
  // The real server cannot be made to fail logout, so this test stubs it.
  await page.route("**/api/v1/auth/logout", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "INTERNAL_ERROR", message: "Internal server error" },
      }),
    }),
  );
  await page.goto("/cases");
  const heading = page.getByRole("heading", { name: "Cases" });
  await expect(heading).toBeVisible();

  await page.keyboard.press("Control+k");
  await page.keyboard.type("sign out");
  await page.keyboard.press("Enter");

  await expect(page.getByRole("alert")).toHaveText(
    "Sign out failed. Try again.",
  );
  await expect(page).toHaveURL(/\/cases$/);
  await expect(heading).toBeVisible();
});
