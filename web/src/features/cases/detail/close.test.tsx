import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "../../../App";
import type { CaseSummary } from "../types";
import type { AlertSummary, CaseDetail } from "./types";

type FetchFunction = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

interface RequestLog {
  method: string;
  path: string;
  search: URLSearchParams;
  body: unknown;
}

interface Responders {
  detail?: () => Response;
  alerts?: (search: URLSearchParams) => Response;
  close?: (body: unknown) => Response;
  bulkClose?: (body: unknown) => Response;
}

const USER = {
  id: "user_1",
  email: "analyst@example.test",
  displayName: "Alice Analyst",
  roles: ["ANALYST"],
};

const ALICE = { id: "user_1", displayName: "Alice Analyst" };

const SUMMARY: CaseSummary = {
  id: "case_312",
  caseNumber: 312,
  title: "Brute force → success",
  status: "OPEN",
  severity: "HIGH",
  outcome: null,
  closureReason: null,
  assignee: null,
  firstEventAt: "2026-11-09T08:00:00Z",
  lastEventAt: "2026-11-09T11:00:00Z",
  createdAt: "2026-11-09T07:30:00Z",
  closedAt: null,
  version: 3,
};

function makeDetail(partial: Partial<CaseDetail> = {}): CaseDetail {
  return {
    ...SUMMARY,
    lastActivityAt: "2026-11-09T11:30:00Z",
    closedBy: null,
    conclusion: null,
    alertCount: 3,
    linkedCases: [],
    mergedInto: null,
    ...partial,
  };
}

function makeAlert(partial: Partial<AlertSummary>): AlertSummary {
  return {
    id: "alert_1",
    title: "Brute force",
    severity: "HIGH",
    status: "OPEN",
    detectionId: "det_brute_force",
    detectionVersion: "0.1.0",
    evidenceCount: 12,
    occurrenceCount: 3,
    firstEventAt: "2026-11-09T08:05:00Z",
    lastEventAt: "2026-11-09T09:00:00Z",
    outcome: null,
    closureReason: null,
    ...partial,
  };
}

const ALERTS: AlertSummary[] = [
  makeAlert({ id: "alert_1", title: "Brute force" }),
  makeAlert({ id: "alert_2", title: "Impossible travel", severity: "LOW" }),
  makeAlert({ id: "alert_3", title: "Malware beacon", severity: "MEDIUM" }),
];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(
  status: number,
  code: string,
  message: string,
): Response {
  return jsonResponse({ error: { code, message, details: {} } }, status);
}

function pageResponse<T>(data: T[]): Response {
  return jsonResponse({ data, pagination: { limit: 50, nextCursor: null } });
}

const COUNTS = {
  status: { OPEN: 42, IN_PROGRESS: 7, CLOSED: 1000, ALL: 1000 },
  scope: { mine: 5, unassigned: 12, all: 49 },
  cap: 1000,
};

const HISTOGRAM = {
  interval: "1h",
  buckets: [
    { start: "2026-11-09T10:00:00Z", counts: { HIGH: 1, MEDIUM: 2, LOW: 3 } },
  ],
};

function stubApi(responders: Responders = {}) {
  const requests: RequestLog[] = [];

  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input, init) => {
      const url = new URL(input.toString(), "http://localhost");
      if (url.pathname === "/api/v1/me") {
        return jsonResponse(USER);
      }

      const method = init?.method ?? "GET";
      const body =
        init?.body === undefined ? undefined : JSON.parse(String(init.body));
      requests.push({
        method,
        path: url.pathname,
        search: url.searchParams,
        body,
      });

      if (url.pathname === "/api/v1/cases") {
        return jsonResponse({
          data: [SUMMARY],
          pagination: { limit: 50, nextCursor: null },
        });
      }
      if (url.pathname === "/api/v1/cases/counts") {
        return jsonResponse(COUNTS);
      }
      if (url.pathname === "/api/v1/cases/histogram") {
        return jsonResponse(HISTOGRAM);
      }
      if (method === "POST" && url.pathname === "/api/v1/cases/case_312/close") {
        return (responders.close ?? (() => jsonResponse(makeDetail())))(body);
      }
      if (method === "POST" && url.pathname === "/api/v1/cases/bulk-close") {
        return (responders.bulkClose ?? (() => jsonResponse({ results: [] })))(
          body,
        );
      }
      if (url.pathname === "/api/v1/cases/312") {
        return (responders.detail ?? (() => jsonResponse(makeDetail())))();
      }
      if (url.pathname === "/api/v1/cases/case_312/alerts") {
        return (responders.alerts ?? (() => pageResponse(ALERTS)))(
          url.searchParams,
        );
      }
      if (url.pathname === "/api/v1/cases/case_312/timeline") {
        return pageResponse([]);
      }

      throw new Error(`unexpected request ${method} ${url.pathname}`);
    }),
  );

  return {
    requests,
    requestsFor: (path: string) =>
      requests.filter((request) => request.path === path),
  };
}

function renderClose(
  responders: Responders = {},
  initialPath = "/cases/312?scope=all",
  queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  }),
) {
  const api = stubApi(responders);
  const router = createMemoryRouter(routes, {
    initialEntries: [initialPath],
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { api, router, queryClient };
}

async function openCloseDialog(): Promise<HTMLElement> {
  const opener = await screen.findByRole("button", { name: "Close case" });
  opener.focus();
  fireEvent.click(opener);
  return screen.findByRole("dialog", { name: "Close case #312" });
}

async function chooseOption(trigger: HTMLElement, name: string): Promise<void> {
  fireEvent.pointerDown(trigger, { button: 0, pointerType: "mouse" });
  fireEvent.click(await screen.findByRole("option", { name }));
}

async function fillClosureFields(
  dialog: HTMLElement,
  conclusion = "Authorized pentest by RedTeam.",
): Promise<void> {
  fireEvent.click(within(dialog).getByRole("radio", { name: "Accepted" }));
  await chooseOption(
    within(dialog).getByRole("combobox", { name: "Closure reason" }),
    "Authorized activity",
  );
  fireEvent.change(within(dialog).getByLabelText("Conclusion"), {
    target: { value: conclusion },
  });
}

function closeRequests(api: ReturnType<typeof stubApi>): RequestLog[] {
  return api
    .requestsFor("/api/v1/cases/case_312/close")
    .filter((request) => request.method === "POST");
}

function descriptionValue(term: string): HTMLElement {
  const dt = screen.getByText(term, { selector: "dt" });
  const dd = dt.nextElementSibling;
  if (!(dd instanceof HTMLElement)) {
    throw new Error(`no value for ${term}`);
  }
  return dd;
}

beforeEach(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  Element.prototype.scrollIntoView = vi.fn();
  HTMLElement.prototype.hasPointerCapture = vi.fn(() => false);
  HTMLElement.prototype.setPointerCapture = vi.fn();
  HTMLElement.prototype.releasePointerCapture = vi.fn();
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("close case dialog", () => {
  it("sends nothing and focuses Outcome when submitted empty", async () => {
    const { api } = renderClose();
    const dialog = await openCloseDialog();

    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    await waitFor(() => {
      expect(within(dialog).getByRole("radio", { name: "Malicious" })).toHaveFocus();
    });
    expect(within(dialog).getByText("Choose an outcome.")).toBeInTheDocument();
    expect(
      within(dialog).getByText("Choose a closure reason."),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("Write a conclusion.")).toBeInTheDocument();
    expect(closeRequests(api)).toHaveLength(0);
  });

  it("focuses the closure reason when only it is missing", async () => {
    const { api } = renderClose();
    const dialog = await openCloseDialog();

    fireEvent.click(within(dialog).getByRole("radio", { name: "Accepted" }));
    fireEvent.change(within(dialog).getByLabelText("Conclusion"), {
      target: { value: "Authorized pentest." },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    const reason = within(dialog).getByRole("combobox", {
      name: "Closure reason",
    });
    await waitFor(() => {
      expect(reason).toHaveFocus();
    });
    expect(reason).toHaveAttribute("aria-invalid", "true");
    const describedBy = reason.getAttribute("aria-describedby");
    if (describedBy === null) {
      throw new Error("the closure reason has no described-by id");
    }
    expect(document.getElementById(describedBy)).toHaveTextContent(
      "Choose a closure reason.",
    );
    expect(closeRequests(api)).toHaveLength(0);
  });

  it("closes on Cancel without a request and focuses Close case", async () => {
    const { api } = renderClose();
    const dialog = await openCloseDialog();

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Close case #312" }),
      ).not.toBeInTheDocument();
    });
    expect(closeRequests(api)).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Close case" })).toHaveFocus();
  });

  it("checks the radio when its label is clicked", async () => {
    renderClose();
    const dialog = await openCloseDialog();
    const malicious = within(dialog).getByRole("radio", {
      name: "Malicious",
    });
    expect(malicious).toHaveAttribute("aria-checked", "false");

    fireEvent.click(within(dialog).getByText("Malicious"));

    expect(malicious).toHaveAttribute("aria-checked", "true");
  });

  it("moves and selects the outcome with the arrow keys", async () => {
    renderClose();
    const dialog = await openCloseDialog();
    const malicious = within(dialog).getByRole("radio", {
      name: "Malicious",
    });
    malicious.focus();

    fireEvent.keyDown(malicious, { key: "ArrowRight" });

    await waitFor(() => {
      expect(
        within(dialog).getByRole("radio", { name: "Accepted" }),
      ).toHaveAttribute("aria-checked", "true");
    });
    expect(
      within(dialog).getByRole("radio", { name: "Accepted" }),
    ).toHaveFocus();
    expect(
      within(dialog).getByRole("radio", { name: "Accepted" }),
    ).toHaveFocus();
  });

  it("offers the seven reasons, not Merged, and sends the chosen values", async () => {
    const { api } = renderClose({
      close: () => jsonResponse(makeDetail()),
    });
    const dialog = await openCloseDialog();
    const reason = within(dialog).getByRole("combobox", {
      name: "Closure reason",
    });

    expect(reason).toHaveTextContent("Choose a reason");
    fireEvent.pointerDown(reason, { button: 0, pointerType: "mouse" });
    expect(
      (await screen.findAllByRole("option")).map((option) => option.textContent),
    ).toEqual([
      "False positive",
      "Benign true positive",
      "Authorized activity",
      "Duplicate",
      "Insufficient evidence",
      "Confirmed threat",
      "Other",
    ]);
    expect(
      screen.queryByRole("option", { name: "Merged" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("option", { name: "Authorized activity" }));
    expect(reason).toHaveTextContent("Authorized activity");

    fireEvent.click(within(dialog).getByRole("radio", { name: "Accepted" }));
    fireEvent.change(within(dialog).getByLabelText("Conclusion"), {
      target: { value: "Authorized pentest by RedTeam, ticket SEC-41." },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    await waitFor(() => {
      expect(closeRequests(api)).toHaveLength(1);
    });
    expect(closeRequests(api)[0].body).toEqual({
      outcome: "ACCEPTED",
      closureReason: "AUTHORIZED_ACTIVITY",
      conclusion: "Authorized pentest by RedTeam, ticket SEC-41.",
      version: 3,
    });
  });

  it("rejects a conclusion over 10,000 characters", async () => {
    const { api } = renderClose();
    const dialog = await openCloseDialog();

    await fillClosureFields(dialog, "x".repeat(10_001));
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    expect(
      await within(dialog).findByText("The conclusion is too long."),
    ).toBeInTheDocument();
    expect(closeRequests(api)).toHaveLength(0);
  });

  it("shows no dispositions list for a single alert", async () => {
    renderClose({ detail: () => jsonResponse(makeDetail({ alertCount: 1 })) });
    const dialog = await openCloseDialog();

    expect(
      within(dialog).queryByRole("list", { name: "Alert dispositions" }),
    ).not.toBeInTheDocument();
  });

  it("lists every alert over two cursor pages", async () => {
    const alerts = Array.from({ length: 101 }, (_, index) =>
      makeAlert({
        id: `alert_${index + 1}`,
        title: `Alert ${index + 1}`,
      }),
    );
    const { api } = renderClose({
      detail: () => jsonResponse(makeDetail({ alertCount: 101 })),
      alerts: (search) =>
        search.get("cursor") === "next-alerts"
          ? jsonResponse({
              data: alerts.slice(100),
              pagination: { limit: 100, nextCursor: null },
            })
          : jsonResponse({
              data: alerts.slice(0, 100),
              pagination: { limit: 100, nextCursor: "next-alerts" },
            }),
    });
    const dialog = await openCloseDialog();

    const list = await within(dialog).findByRole("list", {
      name: "Alert dispositions",
    });
    expect(within(list).getAllByRole("listitem")).toHaveLength(101);
    expect(within(list).getByText("Alert 101")).toBeInTheDocument();
    const requests = api
      .requestsFor("/api/v1/cases/case_312/alerts")
      .filter((request) => request.method === "GET");
    expect(requests).toHaveLength(2);
    expect(requests[1].search.get("cursor")).toBe("next-alerts");
  });

  it("stops when the alert cursor repeats", async () => {
    let calls = 0;
    renderClose({
      alerts: () => {
        calls += 1;
        if (calls > 4) {
          throw new Error("cursor did not advance");
        }
        return jsonResponse({
          data: ALERTS,
          pagination: { limit: 100, nextCursor: "same-cursor" },
        });
      },
    });
    const dialog = await openCloseDialog();

    expect(
      await within(dialog).findByText("Could not load the case alerts."),
    ).toBeInTheDocument();
    expect(calls).toBeLessThanOrEqual(2);
  });

  it("sends only the overridden alert rows", async () => {
    const { api } = renderClose({
      close: () => jsonResponse(makeDetail()),
    });
    const dialog = await openCloseDialog();
    const list = await within(dialog).findByRole("list", {
      name: "Alert dispositions",
    });
    expect(within(list).getAllByRole("listitem")).toHaveLength(3);

    const bruteForce = within(list).getByText("Brute force").closest("li");
    const impossibleTravel = within(list)
      .getByText("Impossible travel")
      .closest("li");
    if (bruteForce === null || impossibleTravel === null) {
      throw new Error("the alert rows are missing");
    }

    await chooseOption(
      within(bruteForce).getByRole("combobox", {
        name: "Outcome for Brute force",
      }),
      "Malicious",
    );
    expect(
      within(bruteForce).getByRole("combobox", {
        name: "Outcome for Brute force",
      }),
    ).toHaveTextContent("Malicious");
    await chooseOption(
      within(bruteForce).getByRole("combobox", {
        name: "Closure reason for Brute force",
      }),
      "Confirmed threat",
    );

    await chooseOption(
      within(impossibleTravel).getByRole("combobox", {
        name: "Closure reason for Impossible travel",
      }),
      "Duplicate",
    );

    fireEvent.click(within(dialog).getByRole("radio", { name: "Accepted" }));
    await chooseOption(
      within(dialog).getByRole("combobox", { name: "Closure reason" }),
      "Authorized activity",
    );
    fireEvent.change(within(dialog).getByLabelText("Conclusion"), {
      target: { value: "Mostly authorized." },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    await waitFor(() => {
      expect(closeRequests(api)).toHaveLength(1);
    });
    expect(closeRequests(api)[0].body).toEqual({
      outcome: "ACCEPTED",
      closureReason: "AUTHORIZED_ACTIVITY",
      conclusion: "Mostly authorized.",
      version: 3,
      alertDispositions: [
        {
          alertId: "alert_1",
          outcome: "MALICIOUS",
          closureReason: "CONFIRMED_THREAT",
        },
        {
          alertId: "alert_2",
          outcome: "ACCEPTED",
          closureReason: "DUPLICATE",
        },
      ],
    });
  });

  it("closes, updates the detail, focuses the heading and announces", async () => {
    const { api } = renderClose({
      close: () =>
        jsonResponse(
          makeDetail({
            status: "CLOSED",
            outcome: "ACCEPTED",
            closureReason: "AUTHORIZED_ACTIVITY",
            closedAt: "2026-11-09T12:00:00Z",
            closedBy: ALICE,
            conclusion: "Authorized pentest.",
            version: 4,
          }),
        ),
    });
    const dialog = await openCloseDialog();
    const countsBefore = api.requestsFor("/api/v1/cases/counts").length;
    const histogramBefore = api.requestsFor("/api/v1/cases/histogram").length;

    await fillClosureFields(dialog, "Authorized pentest.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Close case #312" }),
      ).not.toBeInTheDocument();
    });
    const heading = screen.getByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
    expect(
      await within(screen.getByRole("region", { name: "Case #312" })).findByRole(
        "status",
      ),
    ).toHaveTextContent("Case #312 closed");
    expect(descriptionValue("Status")).toHaveTextContent("Closed");
    expect(descriptionValue("Conclusion")).toHaveTextContent(
      "Authorized pentest.",
    );

    await waitFor(() => {
      expect(api.requestsFor("/api/v1/cases/counts").length).toBeGreaterThan(
        countsBefore,
      );
      expect(
        api.requestsFor("/api/v1/cases/histogram").length,
      ).toBeGreaterThan(histogramBefore);
    });
  });

  it("keeps every input on a version conflict and reloads the case", async () => {
    const { api } = renderClose({
      close: () => errorResponse(409, "VERSION_CONFLICT", "Version conflict"),
    });
    const dialog = await openCloseDialog();

    await fillClosureFields(dialog, "Keep this conclusion.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent(
      "This case changed since you opened it. Reload it and close again.",
    );
    expect(within(dialog).getByLabelText("Conclusion")).toHaveValue(
      "Keep this conclusion.",
    );
    expect(
      within(dialog).getByRole("radio", { name: "Accepted" }),
    ).toHaveAttribute("aria-checked", "true");

    const detailRequests = api.requestsFor("/api/v1/cases/312").length;
    fireEvent.click(within(alert).getByRole("button", { name: "Reload case" }));

    await waitFor(() => {
      expect(api.requestsFor("/api/v1/cases/312").length).toBe(
        detailRequests + 1,
      );
    });
    expect(within(dialog).getByLabelText("Conclusion")).toHaveValue(
      "Keep this conclusion.",
    );
  });

  it("says the case is already closed on a state conflict", async () => {
    renderClose({
      close: () => errorResponse(409, "STATE_CONFLICT", "State conflict"),
    });
    const dialog = await openCloseDialog();

    await fillClosureFields(dialog);
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "This case is already closed.",
    );
  });

  it("says when closing is forbidden", async () => {
    renderClose({
      close: () => errorResponse(403, "FORBIDDEN", "Forbidden"),
    });
    const dialog = await openCloseDialog();

    await fillClosureFields(dialog);
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "You do not have permission to close this case.",
    );
  });

  it("opens from e on the focused queue row", async () => {
    renderClose({}, "/cases?scope=all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    const row = within(table).getByText("#312").closest("tr");
    if (row === null) {
      throw new Error("no row for case 312");
    }
    row.focus();

    fireEvent.keyDown(row, { key: "e" });

    expect(
      await screen.findByRole("dialog", { name: "Close case #312" }),
    ).toBeInTheDocument();
  });

  it("opens from the palette Close case command", async () => {
    renderClose();
    await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByPlaceholderText("Type a command…");
    fireEvent.change(input, { target: { value: "close case" } });
    fireEvent.click(await screen.findByText("Close case…"));

    expect(
      await screen.findByRole("dialog", { name: "Close case #312" }),
    ).toBeInTheDocument();
  });
});

describe("bulk close dialog", () => {
  it("keeps the selection when Cancel closes it without a request", async () => {
    const { api } = renderClose({}, "/cases?scope=all");
    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    await within(table).findByText("Brute force → success");
    const checkbox = within(table).getByRole("checkbox", {
      name: "Select case #312",
    });
    fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole("button", { name: "Close selected" }));

    const dialog = await screen.findByRole("dialog", {
      name: "Close selected cases",
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Close selected cases" }),
      ).not.toBeInTheDocument();
    });
    expect(api.requestsFor("/api/v1/cases/bulk-close")).toHaveLength(0);
    expect(
      screen.getByRole("toolbar", { name: "Selected cases" }),
    ).toHaveTextContent("1 selected");
    expect(checkbox).toHaveAttribute("aria-checked", "true");
  });
});

describe("review fixes: close invalidation", () => {
  it("invalidates the case alerts and timeline after closing", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    renderClose(
      {
        close: () =>
          jsonResponse(
            makeDetail({
              status: "CLOSED",
              outcome: "ACCEPTED",
              closureReason: "AUTHORIZED_ACTIVITY",
              closedAt: "2026-11-09T12:00:00Z",
              closedBy: ALICE,
              conclusion: "Authorized pentest.",
              version: 4,
            }),
          ),
      },
      "/cases/312?scope=all&view=alerts",
      queryClient,
    );
    const dialog = await openCloseDialog();
    await fillClosureFields(dialog);
    fireEvent.click(within(dialog).getByRole("button", { name: "Close case" }));
    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Close case #312" }),
      ).not.toBeInTheDocument();
    });

    const keys = invalidate.mock.calls.map(
      ([filters]) => filters?.queryKey,
    );
    expect(keys).toEqual(
      expect.arrayContaining([
        ["case", "case_312", "alerts"],
        ["case", "case_312", "timeline"],
      ]),
    );
  });
});
