import type { Locator, Page } from "@playwright/test";
import { FIXTURE_NOW } from "./support/cases.ts";
import {
  expect,
  expectNoSideScroll,
  openCases,
  signIn,
  storeSidebar,
  test,
  VIEWPORTS,
} from "./support/test.ts";

type Rgba = [number, number, number, number];

interface ScopeColour {
  label: string;
  checked: boolean;
  text: string;
  background: string;
  groupBackground: string;
}

test.beforeEach(async ({ page }) => {
  await page.clock.install({ time: FIXTURE_NOW });
});

function listRequests(api: { caseRequests: () => string[] }) {
  return api
    .caseRequests()
    .filter((request) => request.startsWith("/api/v1/cases?"));
}

function openCasesTable(page: Page) {
  return page.getByRole("table", { name: "Cases: Open, Mine" });
}

async function controlHeights(page: Page): Promise<Record<string, number>> {
  const controls: Record<string, Locator> = {
    "Step back": page.getByRole("button", { name: "Step back" }),
    Range: page.getByRole("button", { name: "Last 24 hours" }),
    "Step forward": page.getByRole("button", { name: "Step forward" }),
    "Time field": page.getByRole("combobox", { name: "Time field" }),
    "Refresh now": page.getByRole("button", { name: "Refresh now" }),
    "Refresh interval": page.getByRole("combobox", {
      name: "Refresh interval",
    }),
    "Assignee scope": page.getByRole("radiogroup", {
      name: "Assignee scope",
    }),
    Sort: page.getByRole("combobox", { name: "Sort" }),
  };
  const heights: Record<string, number> = {};
  for (const [name, locator] of Object.entries(controls)) {
    const box = await locator.boundingBox();
    if (box === null) {
      throw new Error(`the ${name} control has no box`);
    }
    heights[name] = box.height;
  }
  return heights;
}

function readScopeColours(scope: Locator): Promise<ScopeColour[]> {
  return scope.evaluate((group) => {
    const canvas = document.createElement("canvas");
    canvas.width = 1;
    canvas.height = 1;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (context === null) {
      throw new Error("a 2d canvas context is required");
    }
    const normalise = (colour: string): string => {
      context.clearRect(0, 0, 1, 1);
      context.fillStyle = colour;
      context.fillRect(0, 0, 1, 1);
      const [red, green, blue, alpha] = Array.from(
        context.getImageData(0, 0, 1, 1).data,
      );
      return `rgba(${red}, ${green}, ${blue}, ${alpha / 255})`;
    };
    const groupBackground = normalise(
      getComputedStyle(group).backgroundColor,
    );
    return Array.from(group.querySelectorAll('[role="radio"]')).map(
      (option) => ({
        label: (option.textContent ?? "").trim(),
        checked: option.getAttribute("aria-checked") === "true",
        text: normalise(getComputedStyle(option).color),
        background: normalise(getComputedStyle(option).backgroundColor),
        groupBackground,
      }),
    );
  });
}

function parseColour(colour: string): Rgba {
  const match = /^rgba?\(([^)]+)\)$/.exec(colour);
  if (match === null) {
    throw new Error(`unrecognised colour ${colour}`);
  }
  const parts = match[1].split(/[,/]/).map((part) => part.trim());
  return [
    Number(parts[0]),
    Number(parts[1]),
    Number(parts[2]),
    parts[3] === undefined ? 1 : Number(parts[3]),
  ];
}

function composite(foreground: Rgba, background: Rgba): Rgba {
  const alpha = foreground[3] + background[3] * (1 - foreground[3]);
  if (alpha === 0) {
    return [0, 0, 0, 0];
  }
  return [
    (foreground[0] * foreground[3] +
      background[0] * background[3] * (1 - foreground[3])) /
      alpha,
    (foreground[1] * foreground[3] +
      background[1] * background[3] * (1 - foreground[3])) /
      alpha,
    (foreground[2] * foreground[3] +
      background[2] * background[3] * (1 - foreground[3])) /
      alpha,
    alpha,
  ];
}

function relativeLuminance([red, green, blue]: Rgba): number {
  const channel = (value: number) => {
    const normalised = value / 255;
    return normalised <= 0.04045
      ? normalised / 12.92
      : ((normalised + 0.055) / 1.055) ** 2.4;
  };
  return (
    0.2126 * channel(red) +
    0.7152 * channel(green) +
    0.0722 * channel(blue)
  );
}

function contrastRatio(foreground: Rgba, background: Rgba): number {
  const blended = composite(foreground, background);
  const first = relativeLuminance(blended);
  const second = relativeLuminance(background);
  return (
    (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05)
  );
}

function effectiveBackground(option: ScopeColour): Rgba {
  const group = parseColour(option.groupBackground);
  const own = parseColour(option.background);
  return own[3] === 0 ? group : composite(own, group);
}


test("shows my open cases, counts, and the trend chart", async ({
  page,
  api,
}) => {
  const table = await openCases(page);

  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  await expect(table).toBeVisible();
  await expect(
    page.getByText("Open work ignores the time range."),
  ).toBeVisible();
  await expect(page.locator(".recharts-wrapper")).toBeVisible();
  await expect(page.getByRole("tab", { name: "Open 120" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "In progress 60" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "Mine 55" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "Unassigned 30" })).toBeVisible();

  const request = listRequests(api)[0];
  expect(request).toBeDefined();
  const parameters = new URLSearchParams(request?.split("?")[1]);
  expect(parameters.get("status")).toBe("OPEN");
  expect(parameters.get("scope")).toBe("mine");
  expect(parameters.get("sort")).toBe("lastEventAt:desc");
  expect(parameters.has("from")).toBe(false);
});

test("opens the Sort select under the real CSP", async ({ page }) => {
  await openCases(page);

  const sort = page.getByRole("combobox", { name: "Sort" });
  await sort.click();
  await expect(page.getByRole("listbox")).toBeVisible();
  await page.getByRole("option", { name: "Oldest waiting first" }).click();

  await expect(sort).toHaveText("Oldest waiting first");
  await expect(page).toHaveURL(/[?&]sort=createdAt(%3A|:)asc/);
});

test("restores a shared link and falls back for an invalid value", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases?tab=closed&scope=all&from=now-7d&field=closedAt");

  await expect(page.getByRole("tab", { name: /^Closed/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByRole("radio", { name: /^All/ })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(page.getByRole("button", { name: "Last 7 days" })).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "Time field" }),
  ).toContainText("Closed");
  await expect(
    page.getByRole("table", { name: "Cases: Closed, All" }),
  ).toBeVisible();

  await page.goto("/cases?tab=bogus&scope=unassigned");

  await expect(page.getByRole("tab", { name: /^Open/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(
    page.getByRole("radio", { name: /^Unassigned/ }),
  ).toHaveAttribute("aria-checked", "true");
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("Back steps through the views", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(openCasesTable(page)).toBeVisible();

  await page.getByRole("tab", { name: /^Closed/ }).click();
  await expect(new URL(page.url()).searchParams.get("tab")).toBe("closed");

  await page.goBack();
  await expect(page).toHaveURL(/\/cases$/);

  await expect(page.getByRole("tab", { name: /^Open/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(openCasesTable(page)).toBeVisible();
});

test("changes tabs, scopes, and rows with the keyboard", async ({ page }) => {
  await openCases(page);

  const closedTab = page.getByRole("tab", { name: /^Closed/ });
  await closedTab.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("tab", { name: /^Closed/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(new URL(page.url()).searchParams.get("tab")).toBe("closed");

  const unassigned = page.getByRole("radio", { name: /^Unassigned/ });
  await unassigned.focus();
  await page.keyboard.press("Enter");
  await expect(new URL(page.url()).searchParams.get("scope")).toBe(
    "unassigned",
  );

  const mine = page.getByRole("radio", { name: /^Mine/ });
  await mine.focus();
  await page.keyboard.press("Enter");
  await expect(mine).toHaveAttribute("aria-checked", "true");
  await expect
    .poll(() => new URL(page.url()).searchParams.get("scope"))
    .toBeNull();

  const openTab = page.getByRole("tab", { name: /^Open/ });
  await openTab.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("tab", { name: /^Open/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  const openTable = openCasesTable(page);
  await expect(openTable).toBeVisible();

  const rows = openTable.locator("tbody tr");
  await rows.first().focus();
  await page.keyboard.press("j");
  await page.keyboard.press("j");
  await expect(rows.nth(2)).toBeFocused();
  await page.keyboard.press("k");
  await expect(rows.nth(1)).toBeFocused();
});

test("applies a time range from the picker with the keyboard", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(openCasesTable(page)).toBeVisible();

  const trigger = page.getByRole("button", { name: "Last 24 hours" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("group", { name: "Commonly used" }),
  ).toBeVisible();

  const lastFourHours = page
    .getByRole("group", { name: "Commonly used" })
    .getByRole("button", { name: "Last 4 hours" });
  await lastFourHours.focus();
  await page.keyboard.press("Enter");

  await expect
    .poll(() => new URL(page.url()).searchParams.get("from"))
    .toBe("now-4h");
  await expect(
    page.getByRole("group", { name: "Commonly used" }),
  ).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Last 4 hours" }),
  ).toBeVisible();
});

test("drags across the chart to set an absolute range", async ({ page }) => {
  await signIn(page);
  await page.goto("/cases");
  await expect(openCasesTable(page)).toBeVisible();
  await expect(page.locator(".recharts-wrapper")).toBeVisible();

  const plot = page.locator(".recharts-wrapper");
  const plotBox = await plot.boundingBox();
  if (plotBox === null) {
    throw new Error("chart has no bounds");
  }
  const tick = (label: string) => page.getByText(label, { exact: true });
  const start = await tick("13:00").boundingBox();
  const end = await tick("14:00").boundingBox();
  if (start === null || end === null) {
    throw new Error("chart ticks have no bounds");
  }
  const y = plotBox.y + plotBox.height / 2;

  await page.mouse.move(start.x + start.width / 2, y);
  await expect(page.locator(".recharts-tooltip-wrapper")).toContainText(
    "2026-11-08T13:00:00",
  );
  await page.mouse.down();
  await page.mouse.move(end.x + end.width / 2, y, { steps: 5 });
  await expect(page.locator(".recharts-tooltip-wrapper")).toContainText(
    "2026-11-08T14:00:00",
  );
  await page.mouse.up();

  await expect
    .poll(() => new URL(page.url()).searchParams.get("from"))
    .toBe("2026-11-08T13:00:00Z");
  await expect
    .poll(() => new URL(page.url()).searchParams.get("to"))
    .toBe("2026-11-08T14:30:00Z");
});

test("announces a new case without moving the visible rows", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases?refresh=30s");
  const table = openCasesTable(page);
  await expect(table.locator("tbody tr")).toHaveCount(50);

  const rows = table.locator("tbody tr");
  const firstNumber = (await rows.first().locator("td:nth-child(2)").textContent())
    ?.trim();
  await rows.first().focus();

  api.addCase({ title: "Refresh arrival" });
  await page.clock.runFor(30_000);

  const banner = page.getByRole("status");
  await expect(banner).toContainText("1 new or updated case");
  await expect(page.getByText("Refresh arrival")).toBeHidden();
  await expect(rows).toHaveCount(50);
  await expect(rows.first()).toBeFocused();

  await banner.getByRole("button", { name: "Show" }).click();

  await expect(page.getByText("Refresh arrival")).toBeVisible();
  await expect(banner).toBeHidden();
  await expect(rows).toHaveCount(50);
  const focusedRow = page.locator("tbody tr:focus");
  await expect(focusedRow).toHaveCount(1);
  expect((await focusedRow.locator("td:nth-child(2)").textContent())?.trim()).toBe(
    firstNumber,
  );
});

test("pauses refresh while the command palette is open", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/cases?refresh=30s");
  await expect(openCasesTable(page).locator("tbody tr")).toHaveCount(50);

  await page.keyboard.press("Control+k");
  await expect(page.getByPlaceholder("Type a command…")).toBeVisible();
  const before = api.caseRequests().length;

  await page.clock.runFor(30_000);

  expect(api.caseRequests()).toHaveLength(before);
});

test("the header and filter controls share one rendered height", async ({
  page,
}) => {
  await openCases(page);

  for (const viewport of [VIEWPORTS.desktop, VIEWPORTS.tablet]) {
    await page.setViewportSize(viewport);
    await expect(openCasesTable(page).locator("tbody tr")).toHaveCount(50);

    const heights = Object.entries(await controlHeights(page));
    const [referenceName, referenceHeight] = heights[0];
    for (const [name, height] of heights.slice(1)) {
      expect(
        Math.abs(height - referenceHeight),
        `at ${viewport.width}px, ${name} is as tall as ${referenceName}`,
      ).toBeLessThanOrEqual(1);
    }
  }
});

test("the time range sits with the heading and lines up with the table", async ({
  page,
}) => {
  await page.setViewportSize(VIEWPORTS.desktop);
  const table = await openCases(page);

  const heading = await page
    .getByRole("heading", { name: "Cases" })
    .boundingBox();
  const range = await page
    .getByRole("button", { name: "Last 24 hours" })
    .boundingBox();
  const refresh = await page
    .getByRole("combobox", { name: "Refresh interval" })
    .boundingBox();
  const frame = await table.boundingBox();
  if (heading === null || range === null || refresh === null || frame === null) {
    throw new Error("a header or table element has no box");
  }

  expect(
    Math.abs(
      heading.y + heading.height / 2 - (range.y + range.height / 2),
    ),
    "the time range is on the heading's row",
  ).toBeLessThanOrEqual(1);
  expect(
    Math.abs(refresh.x + refresh.width - (frame.x + frame.width)),
    "the header actions end with the table frame",
  ).toBeLessThanOrEqual(1);
});

test("the selected scope is distinct and its text passes contrast", async ({
  page,
}) => {
  await signIn(page);

  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("/cases");
    await expect(openCasesTable(page).locator("tbody tr")).toHaveCount(50);
    const html = page.locator("html");
    if (theme === "dark") {
      await expect(html).toHaveClass(/dark/);
    } else {
      await expect(html).not.toHaveClass(/dark/);
    }

    const options = await readScopeColours(
      page.getByRole("radiogroup", { name: "Assignee scope" }),
    );
    const selected = options.find((option) => option.checked);
    if (selected === undefined) {
      throw new Error(`no scope option is selected in ${theme}`);
    }
    const selectedBackground = effectiveBackground(selected).map(Math.round);

    for (const option of options) {
      expect(
        contrastRatio(parseColour(option.text), effectiveBackground(option)),
        `${theme}: ${option.label} text meets 4.5:1`,
      ).toBeGreaterThanOrEqual(4.5);
      if (!option.checked) {
        expect(
          effectiveBackground(option).map(Math.round),
          `${theme}: the selected ${selected.label} differs from ${option.label}`,
        ).not.toEqual(selectedBackground);
      }
    }
  }
});

test("the queue does not scroll sideways at 390", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS.phone);
  await openCases(page);

  await expectNoSideScroll(page);
});

test("the split keeps the timeline inside the detail pane", async ({ page }) => {
  await storeSidebar(page, true);
  await page.setViewportSize(VIEWPORTS.desktop);
  await signIn(page);
  await page.goto("/cases/7?scope=all&view=timeline");

  await expect(page.getByRole("region", { name: "Case #7" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Timeline" })).toBeVisible();

  const queue = await page.locator("[data-case-list]").boundingBox();
  const detail = await page.locator("[data-case-list] + div").boundingBox();
  if (queue === null || detail === null) {
    throw new Error("a split pane has no box");
  }
  expect(
    queue.x + queue.width,
    "the detail pane starts where the queue ends",
  ).toBeLessThanOrEqual(detail.x + 1);

  await expectNoSideScroll(page, "the split does not widen the document");
});

test("the split panes scroll on their own", async ({ page }) => {
  await storeSidebar(page, true);
  await page.setViewportSize(VIEWPORTS.wide);
  await signIn(page);
  await page.goto("/cases/7?scope=all&view=timeline");
  await expect(page.getByRole("list", { name: "Timeline" })).toBeVisible();

  const queuePane = page.locator("[data-case-list]");
  const detailPane = page.locator("[data-case-list] + div");
  await queuePane.evaluate((element) => {
    element.scrollTop = 120;
  });
  const queueScroll = await queuePane.evaluate(
    (element) => element.scrollTop,
  );
  expect(queueScroll, "the queue pane scrolled").toBeGreaterThan(0);

  await detailPane.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
  });
  await expect
    .poll(() => detailPane.evaluate((element) => element.scrollTop))
    .toBeGreaterThan(0);
  expect(
    await queuePane.evaluate((element) => element.scrollTop),
    "scrolling the detail leaves the queue where it was",
  ).toBe(queueScroll);
});

test("an open case fills the main area below the split width", async ({
  page,
}) => {
  const table = await openCases(page);

  for (const viewport of [VIEWPORTS.tablet, VIEWPORTS.desktop]) {
    await page.setViewportSize(viewport);
    await expect(table.locator("tbody tr")).toHaveCount(50);

    const row = table.locator("tbody tr").first();
    await row.focus();
    const number = (await row.locator("td").nth(1).textContent())?.trim();
    if (number === undefined) {
      throw new Error("the first row has no case number");
    }
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("region", { name: `Case ${number}` }),
    ).toBeVisible();
    await expect(
      page.locator("[data-case-list]"),
      `at ${viewport.width}px the queue makes room for the case`,
    ).toBeHidden();

    const main = await page.locator("main").boundingBox();
    const pane = await page.locator("[data-case-list] + div").boundingBox();
    if (main === null || pane === null) {
      throw new Error("the main area or detail pane has no box");
    }
    expect(
      Math.abs(pane.width - (main.width - 48)),
      `at ${viewport.width}px the detail pane fills the main content width`,
    ).toBeLessThanOrEqual(2);

    await page.keyboard.press("Escape");
    await expect(page.locator("[data-case-list]")).toBeVisible();
    const focused = page.locator("tbody tr:focus");
    await expect(focused).toHaveCount(1);
    expect((await focused.locator("td").nth(1).textContent())?.trim()).toBe(
      number,
    );
  }
});

test("a case opened by URL hides the queue without a Recharts warning", async ({
  page,
}) => {
  await page.setViewportSize(VIEWPORTS.tablet);
  await signIn(page);
  await page.goto("/cases/7");
  await expect(page.getByRole("region", { name: "Case #7" })).toBeVisible();
  await expect(
    page.locator("[data-case-list]"),
    "at the tablet width the queue makes room for the case",
  ).toBeHidden();

  await page.keyboard.press("Escape");
  await expect(page.locator("[data-case-list]")).toBeVisible();
  await expect(page.locator(".recharts-wrapper")).toBeVisible();
});

test("the select-all checkbox shows a minus for a partial selection", async ({
  page,
}) => {
  const table = await openCases(page);

  for (let index = 0; index < 3; index += 1) {
    await table
      .locator("tbody tr")
      .nth(index)
      .getByRole("checkbox", { name: /^Select case/ })
      .click();
  }

  const selectAll = table.getByRole("checkbox", {
    name: "Select all on this page",
  });
  await expect(selectAll).toHaveAttribute("aria-checked", "mixed");
  await expect(selectAll.locator("svg"), "the check mark is hidden").toBeHidden();

  const minusWidth = await selectAll.evaluate(
    (element) => getComputedStyle(element, "::before").width,
  );
  expect(
    Number.parseFloat(minusWidth),
    "the select-all minus has a width",
  ).toBeGreaterThan(0);
});
