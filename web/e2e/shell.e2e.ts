import { expect, test } from "./support/test.ts";

test("palette opens without a CSP violation and locks scroll", async ({
  page,
  api,
}) => {
  api.signIn();
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();

  await page.keyboard.press("Control+k");

  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();
  await expect(page.locator("body")).toHaveCSS("overflow", "hidden");
});

test("the skip link is the first tab stop and moves focus into main", async ({
  page,
  api,
}) => {
  api.signIn();
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
  api,
}) => {
  api.signIn();
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

test("Go to Cases leaves focus on the Cases heading", async ({ page, api }) => {
  api.signIn();
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

test("Keyboard shortcuts leaves focus inside the shortcuts dialog", async ({
  page,
  api,
}) => {
  api.signIn();
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
  api,
}) => {
  api.signIn();
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
  api,
}) => {
  api.signIn();
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
  api,
}) => {
  api.signIn();
  await page.goto("/nope");

  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Go to Cases" })).toBeVisible();
});

test("keeps the sidebar collapsed after a reload", async ({ page, api }) => {
  api.signIn();
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
