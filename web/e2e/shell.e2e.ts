import {
  expect,
  openCases,
  signIn,
  storeSidebar,
  test,
  VIEWPORTS,
} from "./support/test.ts";

test("palette opens without a CSP violation and locks scroll", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("Control+k");

  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();
  await expect(page.locator("body")).toHaveCSS("overflow", "hidden");
});

test("the skip link is the first tab stop and moves focus into main", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "Skip to content" });
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toBeVisible();

  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
});

test("runs a theme command and returns focus to the skip link", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "Skip to content" });
  await expect(skipLink).toBeFocused();

  await page.keyboard.press("Control+k");
  await page.keyboard.type("dark");
  await page.keyboard.press("Enter");

  await expect(page.locator("html")).toHaveClass(/dark/);
  await expect(page.getByPlaceholder("Type a command…")).toBeHidden();
  await expect(skipLink).toBeFocused();
});

test("Go to Cases leaves focus on the Cases heading", async ({ page }) => {
  await signIn(page);
  await page.goto("/nope");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to content" }),
  ).toBeFocused();
  await page.keyboard.press("Control+k");
  await page.keyboard.type("cases");
  await page.keyboard.press("Enter");

  const heading = page.getByRole("heading", { name: "Cases" });
  await expect(heading).toBeVisible();
  await expect(heading).toBeFocused();
});

test("reopening the palette right after Go to Cases still navigates", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/nope");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.keyboard.press("Control+k");
  await page.keyboard.type("go to cases");
  await page.keyboard.press("Enter");
  await page.keyboard.press("Control+k");

  await expect(page).toHaveURL(/\/cases$/);
});

test("Keyboard shortcuts leaves focus inside the shortcuts dialog", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("Control+k");
  await page.keyboard.type("keyboard");
  await page.keyboard.press("Enter");

  const dialog = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator(":focus")).toHaveCount(1);
});

test("Escape closes the palette opened from the header and returns focus", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  const paletteButton = page.getByRole("button", {
    name: /Search or run a command/,
  });
  await paletteButton.click();
  const input = page.getByPlaceholder("Type a command…");
  await expect(input).toBeVisible();

  await page.keyboard.press("Escape");

  await expect(input).toBeHidden();
  await expect(paletteButton).toBeFocused();
});

test("the shortcuts dialog traps Tab and closes with Escape", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("?");
  const dialog = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Show keyboard shortcuts")).toBeVisible();

  for (let index = 0; index < 10; index += 1) {
    await page.keyboard.press("Tab");
    await expect(dialog.locator(":focus")).toHaveCount(1);
  }

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});

test("an unknown path shows the not-found page inside the shell", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/nope");

  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Go to Cases" })).toBeVisible();
});

test("keeps the sidebar collapsed after a reload", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.getByRole("button", { name: "Collapse sidebar" }).click();

  const expand = page.getByRole("button", { name: "Expand sidebar" });
  await expect(expand).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("link", { name: "Cases" })).toHaveAttribute(
    "aria-label",
    "Cases",
  );

  await page.reload();

  await expect(
    page.getByRole("button", { name: "Expand sidebar" }),
  ).toHaveAttribute("aria-expanded", "false");
});

test("the sidebar is a rail on a phone and restores the stored state at 1440", async ({
  page,
}) => {
  await page.setViewportSize(VIEWPORTS.phone);
  await storeSidebar(page, false);

  await openCases(page);

  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(
    nav,
    "the sidebar is the 56px rail below md",
  ).toHaveCSS("width", "56px");
  await expect(page.getByRole("link", { name: "Cases" })).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: "Collapse sidebar",
      includeHidden: true,
    }),
    "the sidebar toggle is not shown on a phone",
  ).toBeHidden();

  await page.setViewportSize(VIEWPORTS.desktop);

  await expect(
    nav,
    "the stored expanded state applies again from md up",
  ).toHaveCSS("width", "224px");
  await expect(
    page.getByRole("button", { name: "Collapse sidebar" }),
  ).toBeVisible();
});

test("the palette and account buttons fit on a phone", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS.phone);
  await openCases(page);

  const buttons = [
    {
      label: "palette",
      locator: page.getByRole("button", {
        name: "Search or run a command…",
        exact: true,
      }),
    },
    {
      label: "account",
      locator: page.getByRole("button", {
        name: "Account: Alice Analyst",
        exact: true,
      }),
    },
  ];

  for (const { label, locator } of buttons) {
    await expect(locator, `the ${label} button is shown`).toBeVisible();
    const box = await locator.boundingBox();
    if (box === null) {
      throw new Error(`the ${label} button has no box`);
    }
    expect(box.x, `${label} starts inside the viewport`).toBeGreaterThanOrEqual(0);
    expect(box.y, `${label} starts inside the viewport`).toBeGreaterThanOrEqual(0);
    expect(
      box.x + box.width,
      `${label} ends inside the viewport`,
    ).toBeLessThanOrEqual(VIEWPORTS.phone.width);
    expect(
      box.y + box.height,
      `${label} ends inside the viewport`,
    ).toBeLessThanOrEqual(VIEWPORTS.phone.height);
  }
});

test("the palette is inset and its overlay does not blur on a phone", async ({
  page,
}) => {
  await page.setViewportSize(VIEWPORTS.phone);
  await openCases(page);

  await page.keyboard.press("Control+k");
  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();

  const palette = page.locator('[data-slot="dialog-content"]');
  const box = await palette.boundingBox();
  if (box === null) {
    throw new Error("the palette has no box");
  }
  expect(
    box.x,
    "the palette is at least 16px from the left edge",
  ).toBeGreaterThanOrEqual(16);
  expect(
    box.x + box.width,
    "the palette is at least 16px from the right edge",
  ).toBeLessThanOrEqual(VIEWPORTS.phone.width - 16);

  await expect(
    page.locator('[data-slot="dialog-overlay"]'),
    "the palette overlay does not blur the page",
  ).toHaveCSS("backdrop-filter", "none");
});
