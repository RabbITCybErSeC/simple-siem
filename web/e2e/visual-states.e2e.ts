import type { Locator, Page } from "@playwright/test";
import { expect, openCases, signIn, test } from "./support/test.ts";

// The test tsconfig has Node types only, like auth.e2e.ts: a page callback
// reaches the browser's globals through one cast.
interface AnimatedElement {
  getAnimations(): unknown[];
}

interface ScrollableElement {
  clientWidth: number;
  scrollLeft: number;
  scrollWidth: number;
}

interface BrowserStyle {
  backgroundColor: string;
  getPropertyValue(name: string): string;
}

interface BrowserProbe {
  remove(): void;
  style: { backgroundColor: string };
}

interface BrowserGlobals {
  document: {
    body: { append(node: unknown): void };
    createElement(tagName: string): BrowserProbe;
    documentElement: unknown;
  };
  getComputedStyle(element: unknown): BrowserStyle;
}

// Tests that do not measure the queue table only need the shell and heading.
async function openShell(page: Page): Promise<void> {
  await signIn(page);
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
}

function readComputedProperty(
  locator: Locator,
  property: string,
): Promise<string> {
  return locator.evaluate((element, name) => {
    const browser = globalThis as unknown as BrowserGlobals;
    return browser.getComputedStyle(element).getPropertyValue(name);
  }, property);
}

function highlightedItemIndexes(items: Locator): Promise<number[]> {
  return items.evaluateAll((elements) => {
    const browser = globalThis as unknown as BrowserGlobals;
    const transparent = ["transparent", "rgba(0, 0, 0, 0)"];
    return elements.flatMap((element, index) =>
      transparent.includes(browser.getComputedStyle(element).backgroundColor)
        ? []
        : [index],
    );
  });
}

function colourAlpha(colour: string): number {
  const slashAlpha = /\s*\/\s*([\d.]+)(%?)\s*\)$/.exec(colour);
  if (slashAlpha !== null) {
    const value = Number(slashAlpha[1]);
    return slashAlpha[2] === "%" ? value / 100 : value;
  }
  const legacyAlpha = /^rgba\([^)]*,\s*([\d.]+)\s*\)$/.exec(colour);
  return legacyAlpha === null ? 1 : Number(legacyAlpha[1]);
}

function ringAlphaFromShadow(shadow: string): number | undefined {
  // Computed box-shadow is layers separated by commas outside colour functions.
  const layers = shadow.split(/,(?![^(]*\))/);
  for (const layer of layers) {
    const lengths = layer.match(/-?[\d.]+px/g) ?? [];
    if (lengths.at(-1) !== "3px") {
      continue;
    }
    const colour = /(?:rgba?|oklab|oklch)\([^)]*\)/.exec(layer);
    if (colour !== null) {
      return colourAlpha(colour[0]);
    }
  }
  return undefined;
}

test("the queue and detail tab lists sit above their panels", async ({
  page,
}) => {
  await openCases(page);

  const queueTabs = page
    .locator('[data-slot="tabs"]')
    .filter({ has: page.getByRole("tablist", { name: "Status" }) });
  await expect(queueTabs, "the queue has one Tabs root").toHaveCount(1);
  await expect(
    queueTabs,
    "the Status tab list is a column, so it sits above the case table",
  ).toHaveCSS("flex-direction", "column");

  await page.goto("/cases/7?layout=full");
  await expect(
    page.getByRole("tab", { name: "Overview" }),
    "the case detail renders its section tabs",
  ).toBeVisible();
  const sectionTabs = page
    .locator('[data-slot="tabs"]')
    .filter({ has: page.getByRole("tablist", { name: "Case sections" }) });
  await expect(sectionTabs, "the detail has one Tabs root").toHaveCount(1);
  await expect(
    sectionTabs,
    "the section tab list is a column, so it sits above its panel",
  ).toHaveCSS("flex-direction", "column");
});

test("the selected Status tab has a background of its own", async ({ page }) => {
  await openCases(page);

  const statusTabs = page.getByRole("tablist", { name: "Status" });
  const selected = statusTabs.getByRole("tab", { name: /^Open/ });
  const unselected = statusTabs.getByRole("tab", { name: /^Closed/ });
  await expect(selected).toHaveAttribute("aria-selected", "true");
  await expect(unselected).toHaveAttribute("aria-selected", "false");

  const selectedBackground = await readComputedProperty(
    selected,
    "background-color",
  );
  const unselectedBackground = await readComputedProperty(
    unselected,
    "background-color",
  );
  expect(
    selectedBackground,
    "the selected Status tab has a visible background",
  ).not.toBe("rgba(0, 0, 0, 0)");
  expect(
    selectedBackground,
    "the selected Status tab background differs from an unselected tab",
  ).not.toBe(unselectedBackground);
});

test("exactly one palette option is highlighted and ArrowDown moves it", async ({
  page,
}) => {
  await openShell(page);

  await page.keyboard.press("Control+k");
  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();
  const items = page.locator("[cmdk-item]");
  await expect(items.first()).toBeVisible();

  const highlightedAtOpen = await highlightedItemIndexes(items);
  expect(
    highlightedAtOpen,
    "exactly one palette option is highlighted when the palette opens",
  ).toHaveLength(1);

  await page.keyboard.press("ArrowDown");
  const highlightedAfterArrow = await highlightedItemIndexes(items);
  expect(
    highlightedAfterArrow,
    "exactly one palette option is highlighted after ArrowDown",
  ).toHaveLength(1);
  expect(
    highlightedAfterArrow[0],
    "ArrowDown highlights the palette option after the first",
  ).toBe(highlightedAtOpen[0] + 1);
});

test("a checked row checkbox is filled with the primary colour", async ({
  page,
}) => {
  const table = await openCases(page);

  const checkbox = table
    .locator("tbody tr")
    .first()
    .getByRole("checkbox", { name: /^Select case/ });
  await checkbox.click();
  await expect(checkbox).toHaveAttribute("data-state", "checked");

  const expected = await page.evaluate(() => {
    const browser = globalThis as unknown as BrowserGlobals;
    // Resolve the token the way the browser resolves it for bg-primary.
    const primary = browser
      .getComputedStyle(browser.document.documentElement)
      .getPropertyValue("--primary");
    const probe = browser.document.createElement("div");
    probe.style.backgroundColor = primary;
    browser.document.body.append(probe);
    const resolved = browser.getComputedStyle(probe).backgroundColor;
    probe.remove();
    return resolved;
  });

  // The checkbox transitions its colour, so wait for the settled value.
  await expect(
    checkbox,
    "the checked row checkbox background settles on the --primary colour",
  ).toHaveCSS("background-color", expected);
});

test("the shortcuts dialog content runs its open animation", async ({
  page,
}) => {
  await openShell(page);

  await page.keyboard.press("?");
  const content = page.locator('[data-slot="dialog-content"]');
  await expect(content, "the keyboard shortcuts dialog opened").toBeAttached();

  // Measured before the 100 ms open animation ends.
  const animations = await content.evaluate(
    (element) =>
      (element as unknown as AnimatedElement).getAnimations().length,
  );
  expect(
    animations,
    "the keyboard shortcuts dialog content runs an open animation",
  ).toBeGreaterThan(0);
});

test("the built stylesheet maps Radix state and orientation attributes", async ({
  page,
}) => {
  await openShell(page);

  const stylesheet = page.locator('link[rel="stylesheet"]');
  await expect(stylesheet, "the page links one stylesheet").toHaveCount(1);
  const href = await stylesheet.getAttribute("href");
  expect(href, "the stylesheet link has an href").not.toBeNull();

  const stylesheetUrl = href ?? "";
  const response = await page.request.get(stylesheetUrl);
  expect(response.status(), `GET ${stylesheetUrl}`).toBe(200);
  const css = await response.text();

  expect(
    css,
    'the built CSS contains a [data-state="active"] selector',
  ).toMatch(/\[data-state=(?:"active"|active)\]/);
  expect(
    css,
    'the built CSS contains a [data-orientation="horizontal"] selector',
  ).toMatch(/\[data-orientation=(?:"horizontal"|horizontal)\]/);
});

test("the Alerts table region takes keyboard focus and scrolls sideways", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases/7");
  await page.getByRole("tab", { name: /^Alerts/ }).click();
  await expect(page.getByRole("table", { name: "Alerts" })).toBeVisible();

  const region = page.getByRole("region", { name: "Alerts" });
  await expect(region, "the Alerts table is a labelled region").toBeVisible();

  const overflow = await region.evaluate((element) => {
    const scrollable = element as unknown as ScrollableElement;
    return {
      scrollWidth: scrollable.scrollWidth,
      clientWidth: scrollable.clientWidth,
    };
  });
  expect(
    overflow.scrollWidth,
    "the Alerts region is wider than its column, so it scrolls",
  ).toBeGreaterThan(overflow.clientWidth);

  await region.focus();
  await expect(
    region,
    "the Alerts region takes keyboard focus",
  ).toBeFocused();

  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("ArrowRight");
  await expect
    .poll(
      () =>
        region.evaluate(
          (element) => (element as unknown as ScrollableElement).scrollLeft,
        ),
      { message: "ArrowRight scrolls the focused Alerts region" },
    )
    .toBeGreaterThan(0);
});

test("a keyboard-focused button draws its ring at full alpha", async ({
  page,
}) => {
  await openShell(page);

  const focusedButton = page.locator('button[data-slot="button"]:focus');
  await expect
    .poll(
      async () => {
        if ((await focusedButton.count()) === 0) {
          await page.keyboard.press("Tab");
        }
        return focusedButton.count();
      },
      { message: "a button takes keyboard focus" },
    )
    .toBe(1);

  // The ring transitions in, so wait until it has its drawn 3px spread.
  await expect
    .poll(
      async () =>
        ringAlphaFromShadow(
          await readComputedProperty(focusedButton, "box-shadow"),
        ),
      { message: "the focused button ring draws at full alpha" },
    )
    .toBe(1);
});
