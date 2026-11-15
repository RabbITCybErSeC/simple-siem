import type { Page } from "@playwright/test";
import {
  APP_ORIGIN,
  BROWSER_HEADERS,
  expect,
  signIn,
  TEST_USERS,
  test,
} from "./support/test.ts";

interface BrowserStorage {
  length: number;
  key(index: number): string | null;
  getItem(key: string): string | null;
}

type BrowserKeyframe = Record<string, unknown>;

interface BrowserAnimation {
  effect: { getKeyframes(): BrowserKeyframe[] } | null;
  playState: string;
}

interface BrowserGlobals {
  localStorage: BrowserStorage;
  sessionStorage: BrowserStorage;
  document: {
    cookie: string;
    documentElement: { scrollWidth: number };
    getAnimations(): BrowserAnimation[];
  };
  innerWidth: number;
}

const ANALYST = TEST_USERS.analyst;
const LIMITED_EMAIL = "limited@example.test";

function runningAnimationKeyframes(page: Page): Promise<BrowserKeyframe[][]> {
  return page.evaluate(() => {
    const browser = globalThis as unknown as BrowserGlobals;
    return browser.document
      .getAnimations()
      .filter((animation) => animation.playState === "running")
      .map((animation) => animation.effect?.getKeyframes() ?? []);
  });
}

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
  await page.keyboard.type(ANALYST.email);
  await page.keyboard.press("Tab");
  await page.keyboard.type(ANALYST.password);
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  await expect(
    page.getByRole("button", { name: `Account: ${ANALYST.displayName}` }),
  ).toBeVisible();
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
  expect(stored).not.toContain(ANALYST.password);
  expect(stored).not.toContain(ANALYST.email);
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
    headers: { ...BROWSER_HEADERS, Origin: "https://evil.example" },
    data: { email: ANALYST.email, password: ANALYST.password },
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

  const response = await page.request.get("/api/v1/users", {
    headers: BROWSER_HEADERS,
  });

  expect(response.status()).toBe(403);
  const body = (await response.json()) as { error: { code: string } };
  expect(body.error.code).toBe("FORBIDDEN");
});

test("shows the generic message after a wrong password", async ({ page }) => {
  await page.goto("/login");

  await page.getByLabel("Email").fill(ANALYST.email);
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("alert")).toHaveText(
    "Email or password is incorrect.",
  );
  await expect(page.getByLabel("Password")).toHaveValue("");
  await expect(page.getByLabel("Email")).toHaveValue(ANALYST.email);
});

// The real server allows 10 failed logins per email and 30 per client address
// in a 15-minute window. The suite spends 10 here, 1 in the wrong-password
// test above, and 1 in accessibility.e2e.ts, so the per-address limit holds.
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

  await page.getByLabel("Email").fill(ANALYST.email);
  await page.getByLabel("Password").fill(ANALYST.password);
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

test.describe("login waves", () => {
  test.describe("with motion", () => {
    test.use({ reducedMotion: "no-preference" });

    test("runs only transform animations", async ({ page }) => {
      await page.goto("/login");
      await expect(
        page.getByRole("heading", { name: "Sign in to Simple SIEM" }),
      ).toBeVisible();

      const animations = await runningAnimationKeyframes(page);

      expect(animations.length, "running animations").toBeGreaterThan(0);
      for (const keyframes of animations) {
        for (const keyframe of keyframes) {
          const properties = Object.keys(keyframe).filter(
            (name) =>
              !["offset", "computedOffset", "easing", "composite"].includes(
                name,
              ),
          );
          expect(properties, "animated properties").toEqual(["transform"]);
        }
      }
    });
  });

  test.describe("with reduced motion", () => {
    test.use({ reducedMotion: "reduce" });

    test("shows the three waves without running animations", async ({
      page,
    }) => {
      await page.goto("/login");

      const waves = page.locator(".login-wave");
      await expect(waves).toHaveCount(3);
      for (const wave of await waves.all()) {
        await expect(wave).toBeVisible();
      }

      const running = (await runningAnimationKeyframes(page)).length;
      expect(running, "running animations under reduced motion").toBe(0);
    });
  });

  test("makes every request from the login page same-origin", async ({
    page,
  }) => {
    const requests: string[] = [];
    page.on("request", (request) => requests.push(request.url()));

    await page.goto("/login");
    await expect(
      page.getByRole("heading", { name: "Sign in to Simple SIEM" }),
    ).toBeVisible();

    expect(requests.length, "login page requests").toBeGreaterThan(0);
    for (const url of requests) {
      expect(new URL(url).origin, url).toBe(APP_ORIGIN);
    }
  });

  test.describe("at 390px", () => {
    test.use({ viewport: { width: 390, height: 844 } });

    test("fits without sideways scrolling", async ({ page }) => {
      await page.goto("/login");
      await expect(
        page.getByRole("heading", { name: "Sign in to Simple SIEM" }),
      ).toBeVisible();

      const card = page.locator("section");
      await expect(card).toBeVisible();

      const { scrollWidth, innerWidth } = await page.evaluate(() => {
        const browser = globalThis as unknown as BrowserGlobals;
        return {
          scrollWidth: browser.document.documentElement.scrollWidth,
          innerWidth: browser.innerWidth,
        };
      });
      expect(scrollWidth, "document width at 390px").toBeLessThanOrEqual(
        innerWidth,
      );

      const box = await card.boundingBox();
      if (box === null) {
        throw new Error("login card has no box");
      }
      const viewport = page.viewportSize();
      if (viewport === null) {
        throw new Error("no viewport");
      }
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.y).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      expect(box.y + box.height).toBeLessThanOrEqual(viewport.height);
    });
  });
});
