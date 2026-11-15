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
import { writeTimeZone } from "../shell/timeZone";import type { CaseDetail } from "./detail/types";
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
  recorded: RecordedRequest[];
  listRequests: () => string[];
}

interface RecordedRequest {
  method: string;
  path: string;
  body: unknown;
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
    assign?: Responder;
    alerts?: Responder;
    timeline?: Responder;
    bulkClose?: Responder;
  } = {},
): ApiStub {
  const requests: string[] = [];
  const recorded: RecordedRequest[] = [];

  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input, init) => {
      const url = new URL(input.toString(), "http://localhost");
      if (url.pathname === "/api/v1/me") {
        return jsonResponse(USER);
      }
      requests.push(`${url.pathname}${url.search}`);
      recorded.push({
        method: init?.method ?? "GET",
        path: `${url.pathname}${url.search}`,
        body:
          init?.body === undefined ? undefined : JSON.parse(String(init.body)),
      });

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
        case "/api/v1/cases/bulk-close":
          return (
            responders.bulkClose ?? (() => jsonResponse({ results: [] }))
          )(url);
      }

      const detail = /^\/api\/v1\/cases\/([^/]+)$/.exec(url.pathname);
      if (detail !== null && init?.method === "PATCH") {
        return (responders.assign ?? defaultDetail)(url);
      }
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
    recorded,
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
  queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  }),
) {
  const stub = stubApi(responders);
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return { ...stub, router, queryClient };
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
      "",
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
    const ageCell = caseRow(table, 290).querySelectorAll("td")[6];

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
      screen.getByRole("radio", { name: "Mine" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("radio", { name: "Mine 5" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "Open 42" }),
    ).not.toBeInTheDocument();

    resolveCounts?.(jsonResponse(COUNTS));

    expect(
      await screen.findByRole("tab", { name: "Open 42" }),
    ).toBeInTheDocument();
  });

  it("names the auto-refresh control after what it controls", async () => {
    renderCases();
    await screen.findByRole("table", { name: "Cases: Open, Mine" });

    expect(
      screen.getByText("Open work ignores the time range."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("combobox", { name: "Refresh interval" }),
    ).toHaveTextContent("Auto-refresh off");
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

  it("shows an alert with Retry when the histogram fails", async () => {
    let histogramCalls = 0;
    const { recorded } = renderCases("/cases", {
      histogram: () => {
        histogramCalls += 1;
        return histogramCalls === 1
          ? jsonResponse(
              {
                error: {
                  code: "INTERNAL_ERROR",
                  message: "boom",
                  details: {},
                },
              },
              500,
            )
          : jsonResponse(HISTOGRAM);
      },
    });

    expect(
      await screen.findByText("Could not load the trend."),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("No cases in this range."),
    ).not.toBeInTheDocument();
    const before = recorded.filter((request) =>
      request.path.startsWith("/api/v1/cases/histogram"),
    ).length;

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => {
      expect(
        recorded.filter((request) =>
          request.path.startsWith("/api/v1/cases/histogram"),
        ).length,
      ).toBeGreaterThan(before);
    });
    expect(
      await screen.findByRole("table", {
        name: "Cases over time by severity",
      }),
    ).toBeInTheDocument();
  });

  it("keeps the chart when a histogram refetch fails", async () => {
    let histogramCalls = 0;
    renderCases("/cases", {
      histogram: () => {
        histogramCalls += 1;
        return histogramCalls === 1
          ? jsonResponse(HISTOGRAM)
          : jsonResponse(
              {
                error: {
                  code: "INTERNAL_ERROR",
                  message: "boom",
                  details: {},
                },
              },
              500,
            );
      },
    });

    expect(
      await screen.findByRole("table", {
        name: "Cases over time by severity",
      }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));

    await waitFor(() => {
      expect(histogramCalls).toBeGreaterThan(1);
    });
    await act(async () => {});
    expect(
      screen.queryByText("Could not load the trend."),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("table", { name: "Cases over time by severity" }),
    ).toBeInTheDocument();
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

function rowCheckbox(table: HTMLElement, caseNumber: number): HTMLElement {
  return within(caseRow(table, caseNumber)).getByRole("checkbox", {
    name: `Select case #${caseNumber}`,
  });
}

function selectionToolbar(): HTMLElement | null {
  return screen.queryByRole("toolbar", { name: "Selected cases" });
}

describe("case selection", () => {
  it("toggles a row with x and shows the selected count", async () => {
    renderCases();
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    const row = caseRow(table, 312);
    row.focus();

    fireEvent.keyDown(row, { key: "x" });

    expect(rowCheckbox(table, 312)).toHaveAttribute("aria-checked", "true");
    expect(selectionToolbar()).toHaveTextContent("1 selected");
    expect(
      within(selectionToolbar() as HTMLElement).getByRole("button", {
        name: "Close selected",
      }),
    ).toBeEnabled();

    fireEvent.keyDown(row, { key: "x" });

    expect(rowCheckbox(table, 312)).toHaveAttribute("aria-checked", "false");
    expect(selectionToolbar()).not.toBeInTheDocument();
  });

  it("selects the page from the header and shows the mixed state", async () => {
    renderCases();
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    const header = within(table).getByRole("checkbox", {
      name: "Select all on this page",
    });

    fireEvent.click(header);

    expect(header).toHaveAttribute("aria-checked", "true");
    expect(rowCheckbox(table, 312)).toHaveAttribute("aria-checked", "true");
    expect(rowCheckbox(table, 311)).toHaveAttribute("aria-checked", "true");
    expect(selectionToolbar()).toHaveTextContent("2 selected");

    fireEvent.click(rowCheckbox(table, 311));

    expect(header).toHaveAttribute("aria-checked", "mixed");
    expect(selectionToolbar()).toHaveTextContent("1 selected");

    fireEvent.click(header);

    expect(header).toHaveAttribute("aria-checked", "true");
    expect(selectionToolbar()).toHaveTextContent("2 selected");
  });

  it("clears the selection when the tab changes", async () => {
    renderCases();
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    expect(selectionToolbar()).toHaveTextContent("1 selected");

    fireEvent.mouseDown(screen.getByRole("tab", { name: /^Closed/ }));

    const closedTable = await screen.findByRole("table", {
      name: "Cases: Closed, Mine",
    });
    await within(closedTable).findByText("Brute force → success");
    expect(selectionToolbar()).not.toBeInTheDocument();
    expect(rowCheckbox(closedTable, 312)).toHaveAttribute(
      "aria-checked",
      "false",
    );
  });

  it("clears the selection when the filters change outside the tab control", async () => {
    const { router } = renderCases("/cases?scope=all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    expect(selectionToolbar()).toHaveTextContent("1 selected");

    // A link or a palette command changes the filters, not the tab control.
    await act(async () => {
      await router.navigate("/cases?scope=all&tab=closed");
    });
    const closedTable = await screen.findByRole("table", {
      name: "Cases: Closed, All",
    });
    await within(closedTable).findByText("Brute force → success");
    expect(selectionToolbar()).not.toBeInTheDocument();

    await act(async () => {
      await router.navigate(-1);
    });
    const openTable = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(openTable).findByText("Brute force → success");
    expect(selectionToolbar()).not.toBeInTheDocument();
    expect(rowCheckbox(openTable, 312)).toHaveAttribute("aria-checked", "false");
  });

  it("keeps the selection cleared after switching filters and back", async () => {
    renderCases("/cases?scope=all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    expect(selectionToolbar()).toHaveTextContent("1 selected");

    fireEvent.mouseDown(screen.getByRole("tab", { name: /^Closed/ }));
    const closedTable = await screen.findByRole("table", {
      name: "Cases: Closed, All",
    });
    await within(closedTable).findByText("Brute force → success");
    expect(selectionToolbar()).not.toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: /^Open/ }));
    const openTable = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(openTable).findByText("Brute force → success");
    expect(selectionToolbar()).not.toBeInTheDocument();
    expect(rowCheckbox(openTable, 312)).toHaveAttribute("aria-checked", "false");
  });

  it("keeps listed ids across Show and drops the ids that left", async () => {
    vi.useFakeTimers({
      shouldAdvanceTime: true,
      now: new Date("2026-11-09T12:00:00Z"),
    });
    let latest = OPEN_CASES;
    renderCases("/cases?refresh=30s", {
      list: () => jsonResponse(listResponse(latest)),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    fireEvent.click(rowCheckbox(table, 311));
    expect(selectionToolbar()).toHaveTextContent("2 selected");

    latest = [{ ...OPEN_CASES[0], version: 2 }];
    await vi.advanceTimersByTimeAsync(30_000);
    const banner = await screen.findByRole("status");
    fireEvent.click(within(banner).getByRole("button", { name: "Show" }));

    await waitFor(() => {
      expect(within(table).queryByText("#311")).not.toBeInTheDocument();
    });
    expect(selectionToolbar()).toHaveTextContent("1 selected");
    expect(rowCheckbox(table, 312)).toHaveAttribute("aria-checked", "true");
  });

  it("disables Close selected above 100 cases", async () => {
    const many = Array.from({ length: 101 }, (_, index) =>
      caseSummary({
        id: `case_${1000 + index}`,
        caseNumber: 1000 + index,
        title: `Case ${index}`,
      }),
    );
    renderCases("/cases", {
      list: () => jsonResponse(listResponse(many)),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Case 0");

    fireEvent.click(
      within(table).getByRole("checkbox", {
        name: "Select all on this page",
      }),
    );

    expect(selectionToolbar()).toHaveTextContent("101 selected");
    expect(
      within(selectionToolbar() as HTMLElement).getByRole("button", {
        name: "Close selected (max 100)",
      }),
    ).toBeDisabled();
  });
});

async function openBulkCloseDialog(): Promise<HTMLElement> {
  fireEvent.click(screen.getByRole("button", { name: "Close selected" }));
  return screen.findByRole("dialog", { name: "Close selected cases" });
}

async function fillBulkClosureFields(dialog: HTMLElement): Promise<void> {
  fireEvent.click(within(dialog).getByRole("radio", { name: "Accepted" }));
  fireEvent.change(
    within(dialog).getByRole("combobox", { name: "Closure reason" }),
    { target: { value: "AUTHORIZED_ACTIVITY" } },
  );
  fireEvent.change(within(dialog).getByLabelText("Conclusion"), {
    target: { value: "Pentest, SEC-41." },
  });
}

function bulkCloseRequests(recorded: RecordedRequest[]): RecordedRequest[] {
  return recorded.filter(
    (request) => request.path === "/api/v1/cases/bulk-close",
  );
}

describe("bulk close", () => {
  it("sends each loaded version and reports the summary", async () => {
    const { recorded } = renderCases("/cases", {
      bulkClose: () =>
        jsonResponse({
          results: [
            { caseId: "case_312", status: "CLOSED" },
            { caseId: "case_311", status: "CLOSED" },
          ],
        }),
      detail: (url) => {
        const caseId = url.pathname.split("/").pop();
        const found = OPEN_CASES.find((item) => item.id === caseId);
        return found === undefined
          ? jsonResponse(
              { error: { code: "NOT_FOUND", message: "Not found", details: {} } },
              404,
            )
          : jsonResponse({
              ...caseDetail(found),
              status: "CLOSED",
              outcome: "ACCEPTED",
              closureReason: "AUTHORIZED_ACTIVITY",
              closedAt: "2026-11-09T12:00:00Z",
              version: 2,
            });
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    fireEvent.click(rowCheckbox(table, 311));

    const dialog = await openBulkCloseDialog();
    const countsBefore = recorded.filter(
      (request) => request.path.startsWith("/api/v1/cases/counts"),
    ).length;
    const histogramBefore = recorded.filter(
      (request) => request.path.startsWith("/api/v1/cases/histogram"),
    ).length;

    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    expect(
      await within(dialog).findByRole("status"),
    ).toHaveTextContent("2 closed, 0 not closed");
    expect(bulkCloseRequests(recorded)).toHaveLength(1);
    expect(bulkCloseRequests(recorded)[0].body).toEqual({
      cases: [
        { id: "case_312", version: 1 },
        { id: "case_311", version: 1 },
      ],
      outcome: "ACCEPTED",
      closureReason: "AUTHORIZED_ACTIVITY",
      conclusion: "Pentest, SEC-41.",
    });

    await waitFor(() => {
      expect(
        recorded.filter((request) =>
          request.path.startsWith("/api/v1/cases/counts"),
        ).length,
      ).toBeGreaterThan(countsBefore);
      expect(
        recorded.filter((request) =>
          request.path.startsWith("/api/v1/cases/histogram"),
        ).length,
      ).toBeGreaterThan(histogramBefore);
    });

    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));

    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Close selected cases" }),
      ).not.toBeInTheDocument();
    });
    expect(selectionToolbar()).not.toBeInTheDocument();
    expect(within(caseRow(table, 312)).getByText("Accepted")).toBeInTheDocument();
    expect(within(caseRow(table, 311)).getByText("Accepted")).toBeInTheDocument();
  });

  it("sends the newest cached version when the caches disagree", async () => {
    const newest = { ...OPEN_CASES[0], version: 5 };
    const { recorded, queryClient } = renderCases("/cases", {
      list: () => jsonResponse(listResponse([newest])),
      bulkClose: () =>
        jsonResponse({
          results: [{ caseId: "case_312", status: "CLOSED" }],
        }),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");

    // Another filter's page still holds the old version and is iterated last.
    queryClient.setQueryData(["cases", "list", "stale-filter"], {
      pages: [listResponse([{ ...OPEN_CASES[0], version: 3 }])],
      pageParams: [null],
    });
    queryClient.setQueryData(["cases", "latest", "refresh"], {
      data: [{ ...OPEN_CASES[0], version: 6 }],
      pagination: { limit: 50, nextCursor: null },
    });

    fireEvent.click(rowCheckbox(table, 312));
    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    await waitFor(() => {
      expect(bulkCloseRequests(recorded)).toHaveLength(1);
    });
    expect(bulkCloseRequests(recorded)[0].body).toMatchObject({
      cases: [{ id: "case_312", version: 6 }],
    });
  });

  it("does not report the analyst's own bulk close as news", async () => {
    const open = [
      caseSummary({
        id: "case_312",
        caseNumber: 312,
        title: "Brute force → success",
        version: 2,
      }),
      caseSummary({
        id: "case_311",
        caseNumber: 311,
        title: "Impossible travel",
        version: 2,
      }),
    ];
    const closed = open.map((item) => ({
      ...item,
      status: "CLOSED" as const,
      outcome: "ACCEPTED" as const,
      closureReason: "AUTHORIZED_ACTIVITY",
      closedAt: "2026-11-09T12:00:00Z",
      version: 3,
    }));
    let isClosed = false;
    const { recorded } = renderCases("/cases", {
      list: () => jsonResponse(listResponse(isClosed ? closed : open)),
      bulkClose: () => {
        isClosed = true;
        return jsonResponse({
          results: [
            { caseId: "case_312", status: "CLOSED" },
            { caseId: "case_311", status: "CLOSED" },
          ],
        });
      },
      detail: (url) => {
        const caseId = url.pathname.split("/").pop();
        const found = closed.find((item) => item.id === caseId);
        return found === undefined
          ? jsonResponse(
              { error: { code: "NOT_FOUND", message: "Not found", details: {} } },
              404,
            )
          : jsonResponse(caseDetail(found));
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    fireEvent.click(rowCheckbox(table, 311));

    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );
    expect(await within(dialog).findByRole("status")).toHaveTextContent(
      "2 closed, 0 not closed",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));
    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Close selected cases" }),
      ).not.toBeInTheDocument();
    });

    const countsBefore = recorded.filter((request) =>
      request.path.startsWith("/api/v1/cases/counts"),
    ).length;
    fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));

    await waitFor(() => {
      expect(
        recorded.filter((request) =>
          request.path.startsWith("/api/v1/cases/counts"),
        ).length,
      ).toBeGreaterThan(countsBefore);
    });
    expect(screen.queryByText(/new or updated case/)).not.toBeInTheDocument();
  });

  it("shows the results without waiting for the version refreshes", async () => {
    renderCases("/cases", {
      bulkClose: () =>
        jsonResponse({
          results: [{ caseId: "case_312", status: "CLOSED" }],
        }),
      detail: () => new Promise<Response>(() => {}),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));

    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    expect(await within(dialog).findByRole("status")).toHaveTextContent(
      "1 closed, 0 not closed",
    );
  });

  it("keeps the cases that did not close selected for a retry", async () => {
    renderCases("/cases", {
      bulkClose: () =>
        jsonResponse({
          results: [
            { caseId: "case_312", status: "CLOSED" },
            { caseId: "case_311", status: "VERSION_CONFLICT" },
          ],
        }),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    fireEvent.click(rowCheckbox(table, 311));

    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    expect(
      await within(dialog).findByRole("status"),
    ).toHaveTextContent("1 closed, 1 not closed");
    const resultList = within(dialog).getByRole("list", {
      name: "Bulk close results",
    });
    expect(resultList).toHaveTextContent("#312");
    expect(resultList).toHaveTextContent("Closed");
    expect(resultList).toHaveTextContent("#311");
    expect(resultList).toHaveTextContent("Changed since loaded");

    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));

    await waitFor(() => {
      expect(selectionToolbar()).toHaveTextContent("1 selected");
    });
    expect(rowCheckbox(table, 312)).toHaveAttribute("aria-checked", "false");
    expect(rowCheckbox(table, 311)).toHaveAttribute("aria-checked", "true");
  });

  it("bulk closes with the version the assign returned", async () => {
    const { recorded } = renderCases("/cases", {
      assign: () =>
        jsonResponse({
          ...caseDetail(OPEN_CASES[1]),
          status: "IN_PROGRESS",
          assignee: { id: USER.id, displayName: USER.displayName },
          version: 2,
        }),
      bulkClose: () =>
        jsonResponse({
          results: [{ caseId: "case_311", status: "CLOSED" }],
        }),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Impossible travel");
    const row = caseRow(table, 311);
    row.focus();

    fireEvent.keyDown(row, { key: "a" });

    await waitFor(() => {
      expect(
        recorded.filter((request) => request.method === "PATCH"),
      ).toHaveLength(1);
    });
    await waitFor(() => {
      expect(within(row).getByText("Alice Analyst")).toBeInTheDocument();
    });

    fireEvent.click(rowCheckbox(table, 311));
    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    await waitFor(() => {
      expect(bulkCloseRequests(recorded)).toHaveLength(1);
    });
    expect(bulkCloseRequests(recorded)[0].body).toMatchObject({
      cases: [{ id: "case_311", version: 2 }],
    });
  });

  it("retries a conflicted case with its fresh version", async () => {
    let attempts = 0;
    const { recorded } = renderCases("/cases", {
      bulkClose: () => {
        attempts += 1;
        return jsonResponse({
          results: [
            {
              caseId: "case_311",
              status: attempts === 1 ? "VERSION_CONFLICT" : "CLOSED",
            },
          ],
        });
      },
      detail: () =>
        jsonResponse({
          ...caseDetail(OPEN_CASES[1]),
          version: 5,
        }),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Impossible travel");
    fireEvent.click(rowCheckbox(table, 311));

    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );
    expect(
      await within(dialog).findByRole("list", { name: "Bulk close results" }),
    ).toHaveTextContent("Changed since loaded");
    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));

    const retryDialog = await openBulkCloseDialog();
    await fillBulkClosureFields(retryDialog);
    fireEvent.click(
      within(retryDialog).getByRole("button", { name: "Close selected cases" }),
    );

    await waitFor(() => {
      expect(bulkCloseRequests(recorded)).toHaveLength(2);
    });
    expect(bulkCloseRequests(recorded)[1].body).toMatchObject({
      cases: [{ id: "case_311", version: 5 }],
    });
    expect(
      await within(retryDialog).findByRole("status"),
    ).toHaveTextContent("1 closed, 0 not closed");
  });

  it("keeps the form open with a message when the request fails", async () => {
    renderCases("/cases", {
      bulkClose: () =>
        jsonResponse(
          {
            error: {
              code: "INTERNAL_ERROR",
              message: "boom",
              details: {},
            },
          },
          500,
        ),
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));

    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Something went wrong. Try again.",
    );
    expect(within(dialog).getByLabelText("Conclusion")).toHaveValue(
      "Pentest, SEC-41.",
    );
  });
});

describe("review fixes: row shortcuts and detail state", () => {
  it("ignores row shortcuts with meta, ctrl, or alt", async () => {
    const { recorded, router } = renderCases("/cases?scope=all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    await screen.findByRole("button", { name: "Account: Alice Analyst" });
    const rows = dataRows(table);
    rows[0].focus();

    fireEvent.keyDown(rows[0], { key: "a", ctrlKey: true });
    fireEvent.keyDown(rows[0], { key: "x", metaKey: true });
    fireEvent.keyDown(rows[0], { key: "e", altKey: true });
    fireEvent.keyDown(rows[0], { key: "Enter", ctrlKey: true });
    fireEvent.keyDown(rows[0], { key: "j", metaKey: true });
    fireEvent.keyDown(rows[0], { key: "k", altKey: true });

    expect(recorded.filter((request) => request.method === "PATCH")).toHaveLength(
      0,
    );
    expect(rowCheckbox(table, 312)).toHaveAttribute("aria-checked", "false");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/cases");
    expect(rows[0]).toHaveAttribute("tabindex", "0");
    expect(rows[1]).toHaveAttribute("tabindex", "-1");
  });

  it("keeps the open case view and layout when a queue filter changes", async () => {
    const { router } = renderCases(
      "/cases/312?scope=all&view=timeline&layout=full",
    );
    await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });

    fireEvent.mouseDown(
      screen.getByRole("tab", { name: /^Closed/, hidden: true }),
    );

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("tab"),
      ).toBe("closed");
    });
    const parameters = new URLSearchParams(router.state.location.search);
    expect(parameters.get("view")).toBe("timeline");
    expect(parameters.get("layout")).toBe("full");
  });

  it("drops the close dialog state when another case opens", async () => {
    const { router } = renderCases("/cases/312?scope=all");
    await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    fireEvent.click(screen.getByRole("button", { name: "Close case" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Close case #312",
    });
    fireEvent.change(within(dialog).getByLabelText("Conclusion"), {
      target: { value: "draft for 312" },
    });

    await act(async () => {
      await router.navigate("/cases/311?scope=all");
    });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases/311");
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("does not open the close dialog for a case already closed", async () => {
    const { router } = renderCases("/cases?scope=all", {
      detail: (url) => {
        const caseRef = url.pathname.split("/").pop();
        if (caseRef === "311") {
          return jsonResponse(caseDetail(OPEN_CASES[1]));
        }
        return jsonResponse(
          caseDetail({
            ...OPEN_CASES[0],
            status: "CLOSED",
            outcome: "MALICIOUS",
            closureReason: "CONFIRMED_THREAT",
            closedAt: "2026-11-09T12:00:00Z",
          }),
        );
      },
    });
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    const row = caseRow(table, 312);
    row.focus();

    fireEvent.keyDown(row, { key: "e" });

    await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await act(async () => {
      await router.navigate("/cases/311?scope=all");
    });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases/311");
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("invalidates the alerts and timeline after a bulk close and refreshes the details", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    renderCases(
      "/cases",
      {
        bulkClose: () =>
          jsonResponse({
            results: [
              { caseId: "case_312", status: "CLOSED" },
              { caseId: "case_311", status: "CLOSED" },
            ],
          }),
        detail: (url) => {
          const caseId = url.pathname.split("/").pop();
          const found = OPEN_CASES.find((item) => item.id === caseId);
          return found === undefined
            ? jsonResponse(
                {
                  error: { code: "NOT_FOUND", message: "Not found", details: {} },
                },
                404,
              )
            : jsonResponse({
                ...caseDetail(found),
                status: "CLOSED",
                outcome: "ACCEPTED",
                closureReason: "AUTHORIZED_ACTIVITY",
                closedAt: "2026-11-09T12:00:00Z",
                version: 2,
              });
        },
      },
      queryClient,
    );
    const table = await screen.findByRole("table", {
      name: "Cases: Open, Mine",
    });
    await within(table).findByText("Brute force → success");
    fireEvent.click(rowCheckbox(table, 312));
    fireEvent.click(rowCheckbox(table, 311));

    const dialog = await openBulkCloseDialog();
    await fillBulkClosureFields(dialog);
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close selected cases" }),
    );

    expect(
      await within(dialog).findByText("2 closed, 0 not closed"),
    ).toBeInTheDocument();
    const keys = invalidate.mock.calls.map(
      ([filters]) => filters?.queryKey,
    );
    expect(keys).toEqual(
      expect.arrayContaining([
        ["case", "case_312", "alerts"],
        ["case", "case_312", "timeline"],
        ["case", "case_311", "alerts"],
        ["case", "case_311", "timeline"],
      ]),
    );
    expect(keys).not.toContainEqual(["case", 312]);
    expect(keys).not.toContainEqual(["case", 311]);
    expect(
      queryClient.getQueryData<CaseDetail>(["case", 312])?.status,
    ).toBe("CLOSED");
  });
});
