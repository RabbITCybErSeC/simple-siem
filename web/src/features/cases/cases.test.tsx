import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "../../App";
import { writeTimeZone } from "../shell/timeZone";
import type { CaseDetail } from "./detail/types";
import type {
  CaseCounts,
  CaseHistogram,
  CaseListResponse,
  CaseSummary,
} from "./types";

type FetchFunction = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type Responder = (url: URL) => Response | Promise<Response>;

interface ApiStub {
  requests: string[];
  listRequests: () => string[];
}

const USER = {
  id: "user_1",
  email: "analyst@example.test",
  displayName: "Alice Analyst",
  roles: ["ANALYST"],
};

const COUNTS: CaseCounts = {
  status: { OPEN: 42, IN_PROGRESS: 7, CLOSED: 1000, ALL: 1000 },
  scope: { mine: 5, unassigned: 12, all: 49 },
  cap: 1000,
};

const HISTOGRAM: CaseHistogram = {
  interval: "1h",
  buckets: [
    { start: "2026-11-09T10:00:00Z", counts: { HIGH: 1, MEDIUM: 2, LOW: 3 } },
    { start: "2026-11-09T11:00:00Z", counts: { HIGH: 0, MEDIUM: 1, LOW: 0 } },
  ],
};

function caseSummary(partial: Partial<CaseSummary>): CaseSummary {
  return {
    id: "case_1",
    caseNumber: 1,
    title: "A case",
    status: "OPEN",
    severity: "MEDIUM",
    outcome: null,
    closureReason: null,
    assignee: null,
    firstEventAt: "2026-11-09T08:00:00Z",
    lastEventAt: "2026-11-09T11:00:00Z",
    createdAt: "2026-11-09T08:00:00Z",
    closedAt: null,
    version: 1,
    ...partial,
  };
}

const OPEN_CASES: CaseSummary[] = [
  caseSummary({
    id: "case_312",
    caseNumber: 312,
    title: "Brute force → success",
    severity: "HIGH",
    assignee: { id: "user_1", displayName: "Alice Analyst" },
    lastEventAt: "2026-11-09T11:45:00Z",
    createdAt: "2026-11-09T09:00:00Z",
  }),
  caseSummary({
    id: "case_311",
    caseNumber: 311,
    title: "Impossible travel",
    severity: "LOW",
    assignee: null,
    lastEventAt: "2026-11-09T11:30:00Z",
    createdAt: "2026-11-09T08:30:00Z",
  }),
];

const CLOSED_CASE = caseSummary({
  id: "case_290",
  caseNumber: 290,
  title: "Malware beacon",
  status: "CLOSED",
  severity: "MEDIUM",
  outcome: "MALICIOUS",
  closureReason: "CONFIRMED_THREAT",
  closedAt: "2026-11-09T10:00:00Z",
});

function caseDetail(summary: CaseSummary): CaseDetail {
  return {
    ...summary,
    lastActivityAt: summary.lastEventAt,
    closedBy: null,
    conclusion: null,
    alertCount: 2,
    linkedCases: [],
    mergedInto: null,
  };
}

const ALL_CASES = [...OPEN_CASES, CLOSED_CASE];

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function listResponse(
  data: CaseSummary[],
  nextCursor: string | null = null,
): CaseListResponse {
  return { data, pagination: { limit: 50, nextCursor } };
}

function stubApi(
  responders: {
    list?: Responder;
    counts?: Responder;
    histogram?: Responder;
    detail?: Responder;
    alerts?: Responder;
    timeline?: Responder;
  } = {},
): ApiStub {
  const requests: string[] = [];

  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input) => {
      const url = new URL(input.toString(), "http://localhost");
      if (url.pathname === "/api/v1/me") {
        return jsonResponse(USER);
      }
      requests.push(`${url.pathname}${url.search}`);

      switch (url.pathname) {
        case "/api/v1/cases":
          return (
            responders.list ??
            (() => jsonResponse(listResponse(OPEN_CASES)))
          )(url);
        case "/api/v1/cases/counts":
          return (responders.counts ?? (() => jsonResponse(COUNTS)))(url);
        case "/api/v1/cases/histogram":
          return (
            responders.histogram ?? (() => jsonResponse(HISTOGRAM))
          )(url);
      }

      const detail = /^\/api\/v1\/cases\/([^/]+)$/.exec(url.pathname);
      if (detail !== null) {
        return (responders.detail ?? defaultDetail)(url);
      }
      const alerts = /^\/api\/v1\/cases\/([^/]+)\/alerts$/.exec(url.pathname);
      if (alerts !== null) {
        return (
          responders.alerts ??
          (() => jsonResponse({ data: [], pagination: { limit: 50, nextCursor: null } }))
        )(url);
      }
      const timeline = /^\/api\/v1\/cases\/([^/]+)\/timeline$/.exec(
        url.pathname,
      );
      if (timeline !== null) {
        return (
          responders.timeline ??
          (() => jsonResponse({ data: [], pagination: { limit: 50, nextCursor: null } }))
        )(url);
      }

      throw new Error(`unexpected request ${url.pathname}`);
    }),
  );

  return {
    requests,
    listRequests: () =>
      requests.filter((request) => request.startsWith("/api/v1/cases?")),
  };
}

function defaultDetail(url: URL): Response {
  const caseRef = url.pathname.split("/").pop() ?? "";
  const found = ALL_CASES.find(
    (item) =>
      item.id === caseRef ||
      (/^\d+$/.test(caseRef) && item.caseNumber === Number(caseRef)),
  );
  if (found === undefined) {
    return jsonResponse(
      { error: { code: "NOT_FOUND", message: "Not found", details: {} } },
      404,
    );
  }
  return jsonResponse(caseDetail(found));
}

function renderCases(
  initialPath = "/cases",
  responders: Parameters<typeof stubApi>[0] = {},
) {
  const stub = stubApi(responders);
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return { ...stub, router };
}

function caseRow(table: HTMLElement, caseNumber: number): HTMLElement {
  const cell = within(table).getByText(`#${caseNumber}`);
  const row = cell.closest("tr");
  if (row === null) {
    throw new Error(`case #${caseNumber} is not in a row`);
  }
  return row;
}

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", ResizeObserverStub);
  Element.prototype.scrollIntoView = vi.fn();
  HTMLElement.prototype.hasPointerCapture = vi.fn(() => false);
  HTMLElement.prototype.setPointerCapture = vi.fn();
  HTMLElement.prototype.releasePointerCapture = vi.fn();
  window.localStorage.clear();
  writeTimeZone("local");
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("Cases page", () => {
  it("requests the default open, mine view without a time range", async () => {
    const { listRequests, requests } = renderCases();

    await screen.findByRole("table", { name: "Cases: Open, Mine" });
    await waitFor(() => {
      expect(listRequests()).toContain(
        "/api/v1/cases?status=OPEN&scope=mine&sort=lastEventAt%3Adesc&limit=50",
      );
    });

    expect(
      listRequests().every((request) => !request.includes("from=")),
    ).toBe(true);
    expect(requests).toContain(
      "/api/v1/cases/counts?status=OPEN&from=now-24h&to=now&timeField=lastEventAt",
    );
    expect(requests).toContain(
      "/api/v1/cases/histogram?status=OPEN&scope=mine&from=now-24h&to=now&timeField=lastEventAt&interval=auto&splitBy=severity",
    );
    expect(
      screen.getByText("Open work ignores the time range."),
    ).toBeInTheDocument();
  });

  it("lists the documented columns and row values", async () => {
    renderCases();

    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual([
      "Number",
      "Title",
      "Severity",
      "Assignee",
      "Last event",
      "Age",
    ]);
    expect(table.querySelector("caption")?.textContent).toBe(
      "Cases: Open, Mine",
    );

    await within(table).findByText("Brute force → success");

    const row = caseRow(table, 312);
    expect(within(row).getByText("Brute force → success")).toBeInTheDocument();
    const severity = within(row).getByText("HIGH");
    expect(severity).toHaveClass("bg-severity-high");
    expect(within(row).getByText("Alice Analyst")).toBeInTheDocument();

    const lastEvent = row.querySelector(
      'time[datetime="2026-11-09T11:45:00Z"]',
    );
    expect(lastEvent).not.toBeNull();
    expect(lastEvent).toHaveAttribute("title");

    const unassigned = caseRow(table, 311);
    expect(within(unassigned).getByText("Unassigned")).toBeInTheDocument();
  });

  it("shows the outcome instead of an age for closed cases", async () => {
    stubApi({
      list: () =>
        jsonResponse(listResponse([CLOSED_CASE])),
    });
    const router = createMemoryRouter(routes, {
      initialEntries: ["/cases?tab=closed&scope=all"],
    });
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );

    const table = await screen.findByRole("table", {
      name: "Cases: Closed, All",
    });
    await within(table).findByText("#290");
    const ageCell = caseRow(table, 290).querySelectorAll("td")[5];

    expect(ageCell).toHaveTextContent("Malicious");
    expect(ageCell.querySelector("time")).toBeNull();
  });

  it("shows tab and scope counts, with the cap as 1,000+", async () => {
    renderCases();

    expect(
      await screen.findByRole("tab", { name: "Open 42" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: "In progress 7" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: "Closed 1,000+" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: "All 1,000+" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("radio", { name: "Mine 5" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("radio", { name: "Unassigned 12" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("radio", { name: "All 49" }),
    ).toBeInTheDocument();
  });

  it("shows no count while the counts are loading", async () => {
    let resolveCounts: ((response: Response) => void) | undefined;
    const pendingCounts = new Promise<Response>((resolve) => {
      resolveCounts = resolve;
    });
    const router = createMemoryRouter(routes, { initialEntries: ["/cases"] });

    vi.stubGlobal(
      "fetch",
      vi.fn<FetchFunction>(async (input) => {
        const url = new URL(input.toString(), "http://localhost");
        if (url.pathname === "/api/v1/me") {
          return jsonResponse(USER);
        }
        if (url.pathname === "/api/v1/cases/counts") {
          return pendingCounts;
        }
        if (url.pathname === "/api/v1/cases") {
          return jsonResponse(listResponse(OPEN_CASES));
        }
        if (url.pathname === "/api/v1/cases/histogram") {
          return jsonResponse(HISTOGRAM);
        }
        throw new Error(`unexpected request ${url.pathname}`);
      }),
    );

    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );

    expect(
      await screen.findByRole("tab", { name: "Open" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "Open 42" }),
    ).not.toBeInTheDocument();

    resolveCounts?.(jsonResponse(COUNTS));

    expect(
      await screen.findByRole("tab", { name: "Open 42" }),
    ).toBeInTheDocument();
  });

  it("says the queue is empty for the tab and scope", async () => {
    stubApi({
      list: () => jsonResponse(listResponse([])),
    });
    const router = createMemoryRouter(routes, {
      initialEntries: ["/cases?scope=unassigned"],
    });
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );

    expect(
      await screen.findByText("No open unassigned cases."),
    ).toBeInTheDocument();
  });

  it("says there are no closed cases in the range", async () => {
    stubApi({
      list: () => jsonResponse(listResponse([])),
    });
    const router = createMemoryRouter(routes, {
      initialEntries: ["/cases?tab=closed&scope=all"],
    });
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );

    expect(
      await screen.findByText("No closed cases in this range."),
    ).toBeInTheDocument();
  });

  it("shows an error message and retries without raw response text", async () => {
    let listRequests = 0;

    renderCasesWithError(() => {
      listRequests += 1;
    });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The case queue is unavailable.");
    expect(alert).not.toHaveTextContent("boom");
    expect(listRequests).toBe(1);

    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));

    await waitFor(() => {
      expect(listRequests).toBe(2);
    });
  });

  it("appends the next page with Load more", async () => {
    stubApi({
      list: (url) => {
        if (url.searchParams.get("cursor") === "second") {
          return jsonResponse(
            listResponse([
              caseSummary({
                id: "case_310",
                caseNumber: 310,
                title: "Suspicious admin activity",
                assignee: { id: "user_1", displayName: "Alice Analyst" },
              }),
            ]),
          );
        }
        return jsonResponse(listResponse([OPEN_CASES[0]], "second"));
      },
    });
    const router = createMemoryRouter(routes, { initialEntries: ["/cases"] });
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );

    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    expect(within(table).getAllByRole("row")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));

    expect(
      await within(table).findByText("Suspicious admin activity"),
    ).toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(
      screen.queryByRole("button", { name: "Load more" }),
    ).not.toBeInTheDocument();
  });

  it("restarts from the first page when the cursor expires", async () => {
    let listCalls = 0;
    renderCases("/cases", {
      list: (url) => {
        listCalls += 1;
        if (url.searchParams.get("cursor") === "expired") {
          return jsonResponse(
            {
              error: {
                code: "VALIDATION_ERROR",
                message: "Invalid cursor",
                details: {},
              },
            },
            400,
          );
        }
        return jsonResponse(listResponse([OPEN_CASES[0]], "expired"));
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));

    await waitFor(() => {
      expect(listCalls).toBeGreaterThanOrEqual(3);
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    const restored = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    expect(
      within(restored).getByText("Brute force → success"),
    ).toBeInTheDocument();
  });

  it("does not reset twice for the same failing cursor", async () => {
    let listCalls = 0;
    renderCases("/cases", {
      list: (url) => {
        listCalls += 1;
        if (url.searchParams.get("cursor") === "expired") {
          return jsonResponse(
            {
              error: {
                code: "VALIDATION_ERROR",
                message: "Invalid cursor",
                details: {},
              },
            },
            400,
          );
        }
        return jsonResponse(listResponse([OPEN_CASES[0]], "expired"));
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => {
      expect(listCalls).toBe(3);
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "The queue could not be loaded with these filters.",
    );
    expect(listCalls).toBe(4);
  });

  it("sorts by oldest waiting first and replaces the URL entry", async () => {
    const { listRequests, router } = renderCases();
    await screen.findByRole("table", { name: "Cases: Open, Mine" });

    const sort = screen.getByRole("combobox", { name: "Sort" });
    fireEvent.pointerDown(sort, { button: 0, pointerType: "mouse" });
    fireEvent.click(
      await screen.findByRole("option", { name: "Oldest waiting first" }),
    );

    await waitFor(() => {
      expect(listRequests()).toContain(
        "/api/v1/cases?status=OPEN&scope=mine&sort=createdAt%3Aasc&limit=50",
      );
    });
    expect(
      new URLSearchParams(router.state.location.search).get("sort"),
    ).toBe("createdAt:asc");
    expect(sort).toHaveTextContent("Oldest waiting first");
  });
});

const KEYBOARD_CASES: CaseSummary[] = [
  caseSummary({ id: "case_303", caseNumber: 303, title: "First case" }),
  caseSummary({ id: "case_302", caseNumber: 302, title: "Second case" }),
  caseSummary({ id: "case_301", caseNumber: 301, title: "Third case" }),
];

function dataRows(table: HTMLElement): HTMLElement[] {
  return within(table).getAllByRole("row").slice(1);
}

describe("keyboard row navigation", () => {
  it("keeps one row in the tab order and moves with j, k, arrows, Home, End", async () => {
    renderCases("/cases", {
      list: () => jsonResponse(listResponse(KEYBOARD_CASES)),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("First case");
    const rows = dataRows(table);

    expect(rows.filter((row) => row.tabIndex === 0)).toHaveLength(1);
    expect(rows[0]).toHaveAttribute("tabindex", "0");

    fireEvent.keyDown(rows[0], { key: "j" });
    fireEvent.keyDown(rows[1], { key: "j" });
    expect(rows[2]).toHaveAttribute("tabindex", "0");
    expect(rows[2]).toHaveFocus();

    fireEvent.keyDown(rows[2], { key: "k" });
    expect(rows[1]).toHaveFocus();

    fireEvent.keyDown(rows[1], { key: "ArrowDown" });
    expect(rows[2]).toHaveFocus();

    fireEvent.keyDown(rows[2], { key: "ArrowUp" });
    expect(rows[1]).toHaveFocus();

    fireEvent.keyDown(rows[1], { key: "End" });
    expect(rows[2]).toHaveFocus();

    fireEvent.keyDown(rows[2], { key: "Home" });
    expect(rows[0]).toHaveFocus();
  });

  it("ignores j and k while focus is in a text field", async () => {
    renderCases("/cases", {
      list: () => jsonResponse(listResponse(KEYBOARD_CASES)),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("First case");
    const rows = dataRows(table);

    fireEvent.click(screen.getByRole("button", { name: "Last 24 hours" }));
    const input = screen.getByLabelText("Last");
    input.focus();

    fireEvent.keyDown(input, { key: "j" });
    fireEvent.keyDown(input, { key: "k" });

    expect(input).toHaveFocus();
    expect(rows[0]).toHaveAttribute("tabindex", "0");
    expect(rows[1]).toHaveAttribute("tabindex", "-1");
  });

  it("keeps the active row by id when Load more appends rows", async () => {
    renderCases("/cases", {
      list: (url) => {
        if (url.searchParams.get("cursor") === "second") {
          return jsonResponse(listResponse([KEYBOARD_CASES[2]]));
        }
        return jsonResponse(
          listResponse([KEYBOARD_CASES[0], KEYBOARD_CASES[1]], "second"),
        );
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("First case");

    fireEvent.keyDown(dataRows(table)[0], { key: "j" });
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await within(table).findByText("Third case");

    const rows = dataRows(table);
    expect(rows).toHaveLength(3);
    expect(rows[1]).toHaveAttribute("tabindex", "0");
    expect(rows[1]).toHaveTextContent("#302");
  });
});

const REFRESH_PATH = "/cases?refresh=30s";

describe("auto-refresh", () => {
  beforeEach(() => {
    vi.useFakeTimers({
      shouldAdvanceTime: true,
      now: new Date("2026-11-09T12:00:00Z"),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("refetches the latest page, counts, and chart on the interval", async () => {
    const { listRequests, requests } = renderCases(REFRESH_PATH);
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    const listCount = listRequests().length;
    const countsCount = requests.filter((request) =>
      request.startsWith("/api/v1/cases/counts?"),
    ).length;
    const histogramCount = requests.filter((request) =>
      request.startsWith("/api/v1/cases/histogram?"),
    ).length;

    await vi.advanceTimersByTimeAsync(30_000);

    await waitFor(() => {
      expect(listRequests().length).toBeGreaterThan(listCount);
    });
    await waitFor(() => {
      expect(
        requests.filter((request) =>
          request.startsWith("/api/v1/cases/counts?"),
        ).length,
      ).toBeGreaterThan(countsCount);
    });
    expect(
      requests.filter((request) =>
        request.startsWith("/api/v1/cases/histogram?"),
      ).length,
    ).toBeGreaterThan(histogramCount);
  });

  it("announces new and updated cases without changing the rows", async () => {
    let latest = OPEN_CASES;
    renderCases(REFRESH_PATH, {
      list: () => jsonResponse(listResponse(latest)),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    fireEvent.keyDown(caseRow(table, 312), { key: "j" });
    expect(caseRow(table, 311)).toHaveFocus();

    latest = [
      caseSummary({
        id: "case_320",
        caseNumber: 320,
        title: "New arrival",
        lastEventAt: "2026-11-09T12:00:00Z",
      }),
      { ...OPEN_CASES[0], version: 2 },
      OPEN_CASES[1],
    ];
    await vi.advanceTimersByTimeAsync(30_000);

    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent("2 new or updated cases");
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(screen.queryByText("New arrival")).not.toBeInTheDocument();
    expect(caseRow(table, 311)).toHaveFocus();

    fireEvent.click(within(banner).getByRole("button", { name: "Show" }));

    expect(await within(table).findByText("New arrival")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(caseRow(table, 311)).toHaveAttribute("tabindex", "0");
    expect(caseRow(table, 311)).toHaveFocus();
  });

  it("uses the singular for one new or updated case", async () => {
    let latest = OPEN_CASES;
    renderCases(REFRESH_PATH, {
      list: () => jsonResponse(listResponse(latest)),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    latest = [
      caseSummary({ id: "case_321", caseNumber: 321, title: "One arrival" }),
      ...OPEN_CASES,
    ];
    await vi.advanceTimersByTimeAsync(30_000);

    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent("1 new or updated case");
    expect(banner).not.toHaveTextContent("1 new or updated cases");
  });

  it("pauses while a text field has focus", async () => {
    const { listRequests } = renderCases(REFRESH_PATH);
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    fireEvent.click(screen.getByRole("button", { name: "Last 24 hours" }));
    screen.getByLabelText("Last").focus();
    const before = listRequests().length;

    await vi.advanceTimersByTimeAsync(30_000);

    expect(listRequests()).toHaveLength(before);
  });

  it("pauses while a dialog is open", async () => {
    const { listRequests } = renderCases(REFRESH_PATH);
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    await screen.findByPlaceholderText("Type a command…");
    const before = listRequests().length;

    await vi.advanceTimersByTimeAsync(30_000);

    expect(listRequests()).toHaveLength(before);
  });

  it("pauses while the browser tab is hidden", async () => {
    const { listRequests } = renderCases(REFRESH_PATH);
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    const before = listRequests().length;

    try {
      await vi.advanceTimersByTimeAsync(30_000);
      expect(listRequests()).toHaveLength(before);
    } finally {
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        get: () => "visible",
      });
    }
  });

  it("refreshes now even while paused", async () => {
    const { listRequests } = renderCases(REFRESH_PATH);
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    fireEvent.click(screen.getByRole("button", { name: "Last 24 hours" }));
    screen.getByLabelText("Last").focus();
    const before = listRequests().length;

    fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));

    await waitFor(() => {
      expect(listRequests().length).toBeGreaterThan(before);
    });
  });

  it("ignores a tick that resolves after the view changed", async () => {
    let releaseLatest: ((response: Response) => void) | undefined;
    let openListCalls = 0;
    const { router } = renderCases(REFRESH_PATH, {
      list: (url) => {
        openListCalls += 1;
        if (url.searchParams.get("status") === "OPEN" && openListCalls > 1) {
          return new Promise<Response>((resolve) => {
            releaseLatest = resolve;
          });
        }
        return jsonResponse(listResponse(OPEN_CASES));
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    await vi.advanceTimersByTimeAsync(30_000);
    await waitFor(() => expect(releaseLatest).toBeDefined());

    fireEvent.mouseDown(screen.getByRole("tab", { name: /^Closed/ }));
    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("tab"),
      ).toBe("closed");
    });

    await act(async () => {
      releaseLatest?.(
        jsonResponse(
          listResponse([
            caseSummary({
              id: "case_330",
              caseNumber: 330,
              title: "Stale arrival",
            }),
            ...OPEN_CASES,
          ]),
        ),
      );
    });

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("does not announce changes when the first page never loaded", async () => {
    let listCalls = 0;
    renderCases(REFRESH_PATH, {
      list: () => {
        listCalls += 1;
        if (listCalls === 1) {
          return jsonResponse(
            {
              error: {
                code: "INTERNAL_ERROR",
                message: "boom",
                details: {},
              },
            },
            503,
          );
        }
        return jsonResponse(
          listResponse([
            caseSummary({
              id: "case_331",
              caseNumber: 331,
              title: "Arrival",
            }),
            ...OPEN_CASES,
          ]),
        );
      },
    });

    expect(await screen.findByRole("alert")).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("keeps loaded pages and the active row when Show applies", async () => {
    const firstPage = [
      caseSummary({
        id: "case_320",
        caseNumber: 320,
        title: "First page case",
      }),
    ];
    const secondPage = [
      caseSummary({
        id: "case_310",
        caseNumber: 310,
        title: "Second page case",
      }),
      caseSummary({
        id: "case_309",
        caseNumber: 309,
        title: "Another page case",
      }),
    ];
    let latestFirstPage = firstPage;

    renderCases(REFRESH_PATH, {
      list: (url) =>
        jsonResponse(
          url.searchParams.get("cursor") === "second"
            ? listResponse(secondPage)
            : listResponse(latestFirstPage, "second"),
        ),
    });

    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("First page case");
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await within(table).findByText("Second page case");

    const active = caseRow(table, 310);
    active.focus();
    expect(active).toHaveFocus();

    latestFirstPage = [
      caseSummary({
        id: "case_330",
        caseNumber: 330,
        title: "New arrival",
      }),
      ...firstPage,
    ];
    await vi.advanceTimersByTimeAsync(30_000);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent("1 new or updated case");

    fireEvent.click(within(banner).getByRole("button", { name: "Show" }));

    expect(await within(table).findByText("New arrival")).toBeInTheDocument();
    expect(
      within(table).getByText("Second page case"),
    ).toBeInTheDocument();
    expect(caseRow(table, 310)).toHaveAttribute("tabindex", "0");
    expect(caseRow(table, 310)).toHaveFocus();
  });

  it("does not refresh when the interval is off", async () => {
    const { listRequests } = renderCases();
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    const before = listRequests().length;

    await vi.advanceTimersByTimeAsync(5 * 60_000);

    expect(listRequests()).toHaveLength(before);
  });
});

const UTC_EXACT = "Nov 9, 2026, 11:45:00 UTC";

async function runPaletteCommand(text: string): Promise<void> {
  fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
  const input = await screen.findByPlaceholderText("Type a command…");
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: "Enter" });
  await waitFor(() => {
    expect(
      screen.queryByPlaceholderText("Type a command…"),
    ).not.toBeInTheDocument();
  });
}

function lastEventCell(table: HTMLElement): Element {
  const cell = table.querySelector(
    'time[datetime="2026-11-09T11:45:00Z"]',
  );
  if (cell === null) {
    throw new Error("no last event cell for case #312");
  }
  return cell;
}

describe("time display and navigation commands", () => {
  it("switches exact timestamps to UTC from the palette and persists", async () => {
    renderCases();
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    expect(lastEventCell(table).querySelector(".sr-only")).not.toBeNull();
    expect(lastEventCell(table).querySelector(".sr-only")?.textContent).not.toBe(
      "",
    );

    await runPaletteCommand("Time zone: UTC");

    expect(window.localStorage.getItem("simple-siem.time-zone")).toBe("utc");
    expect(lastEventCell(table)).toHaveAttribute("title", UTC_EXACT);
    expect(
      lastEventCell(table).querySelector(".sr-only")?.textContent?.trim(),
    ).toBe(UTC_EXACT);

    cleanup();
    renderCases();
    const remounted = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(remounted).findByText("Brute force → success");
    expect(lastEventCell(remounted)).toHaveAttribute("title", UTC_EXACT);
  });

  it("marks the current time zone command", async () => {
    renderCases();
    await screen.findByRole("table", { name: "Cases: Open, Mine" });

    await runPaletteCommand("Time zone: UTC");

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByPlaceholderText("Type a command…");
    fireEvent.change(input, { target: { value: "time zone" } });

    expect(
      await screen.findByText("Time zone: UTC (current)"),
    ).toBeInTheDocument();
    expect(screen.getByText("Time zone: Local")).toBeInTheDocument();
  });

  it("changes the tab and scope from the palette", async () => {
    const { router, listRequests } = renderCases();
    await screen.findByRole("table", { name: "Cases: Open, Mine" });

    await runPaletteCommand("Cases: Closed");

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("tab"),
      ).toBe("closed");
    });
    await waitFor(() => {
      expect(
        listRequests().some((request) =>
          request.includes("status=CLOSED&scope=mine"),
        ),
      ).toBe(true);
    });

    await runPaletteCommand("Cases: Unassigned");

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("scope"),
      ).toBe("unassigned");
    });
    await waitFor(() => {
      expect(
        listRequests().some((request) =>
          request.includes("scope=unassigned"),
        ),
      ).toBe(true);
    });

    await runPaletteCommand("Cases: All assignees");

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("scope"),
      ).toBe("all");
    });
  });
});

function renderCasesWithError(onListRequest: () => void) {
  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input) => {
      const url = new URL(input.toString(), "http://localhost");
      if (url.pathname === "/api/v1/me") {
        return jsonResponse(USER);
      }
      if (url.pathname === "/api/v1/cases") {
        onListRequest();
        return jsonResponse(
          {
            error: {
              code: "INTERNAL_ERROR",
              message: "boom",
              details: {},
            },
          },
          500,
        );
      }
      if (url.pathname === "/api/v1/cases/counts") {
        return jsonResponse(COUNTS);
      }
      if (url.pathname === "/api/v1/cases/histogram") {
        return jsonResponse(HISTOGRAM);
      }
      throw new Error(`unexpected request ${url.pathname}`);
    }),
  );

  const router = createMemoryRouter(routes, { initialEntries: ["/cases"] });
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("case detail route and layout", () => {
  function listWrapper(): HTMLElement | null {
    return document.querySelector("[data-case-list]");
  }

  it("renders the queue and the detail at the case number, with focus on the heading", async () => {
    const { router } = renderCases("/cases/312?scope=all");

    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");

    const heading = await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
    expect(router.state.location.pathname).toBe("/cases/312");
    expect(screen.getByRole("region", { name: "Case #312" })).toBeInTheDocument();
  });

  it("opens with Enter on a row and keeps the queue parameters", async () => {
    const { router } = renderCases("/cases?scope=all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    const row = caseRow(table, 312);
    row.focus();

    fireEvent.keyDown(row, { key: "Enter" });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases/312");
    });
    expect(
      new URLSearchParams(router.state.location.search).get("scope"),
    ).toBe("all");
    const heading = await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
  });

  it("opens from a click on the title cell", async () => {
    const { router } = renderCases();
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    const title = await within(table).findByText("Brute force → success");

    fireEvent.click(title);

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases/312");
    });
  });

  it("closes with Escape and returns focus to the row", async () => {
    const { router } = renderCases("/cases/312?scope=all");
    const heading = await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });

    fireEvent.keyDown(heading, { key: "Escape" });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
    expect(
      new URLSearchParams(router.state.location.search).get("scope"),
    ).toBe("all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await waitFor(() => {
      expect(caseRow(table, 312)).toHaveFocus();
    });
  });

  it("hides the list in full layout and restores it, keeping the rows", async () => {
    const { router } = renderCases("/cases/312?scope=all&layout=full");

    await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    expect(listWrapper()).toHaveAttribute("hidden");

    fireEvent.click(
      screen.getByRole("button", { name: "Toggle full page" }),
    );

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).has("layout"),
      ).toBe(false);
    });
    expect(listWrapper()).not.toHaveAttribute("hidden");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    expect(within(table).getByText("Brute force → success")).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Toggle full page" }),
    );

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("layout"),
      ).toBe("full");
    });
    expect(listWrapper()).toHaveAttribute("hidden");
  });

  it("says a missing case was not found and keeps the queue usable", async () => {
    renderCases("/cases/99999", {
      detail: () =>
        jsonResponse(
          { error: { code: "NOT_FOUND", message: "Not found", details: {} } },
          404,
        ),
    });

    expect(
      await screen.findByText("Case #99999 was not found."),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("table", { name: "Cases: Open, Mine" }),
    ).toBeInTheDocument();
  });

  it("shows the not-found page for a case number that is not digits", async () => {
    const { requests } = renderCases("/cases/abc");

    expect(
      await screen.findByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
    expect(requests).toEqual([]);
  });

  it("drives the detail section from view and pushes tab changes", async () => {
    const { router } = renderCases("/cases/312?scope=all&view=timeline");

    expect(
      await screen.findByRole("tab", { name: "Timeline" }),
    ).toHaveAttribute("aria-selected", "true");

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Alerts 2" }));

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("view"),
      ).toBe("alerts");
    });
    expect(
      new URLSearchParams(router.state.location.search).get("scope"),
    ).toBe("all");
  });
});
