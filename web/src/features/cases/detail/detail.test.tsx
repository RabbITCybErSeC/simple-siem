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
import type { Mock } from "vitest";
import { routes } from "../../../App";
import { writeTimeZone } from "../../shell/timeZone";
import type { CaseSummary } from "../types";
import type {
  AlertSummary,
  CaseDetail,
  TimelineActivityEntry,
  TimelineEntry,
  TimelineEvidenceEntry,
} from "./types";

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
  timeline?: (search: URLSearchParams) => Response;
  assign?: (body: unknown) => Response;
}

interface RenderDetailResult {
  api: {
    requests: RequestLog[];
    requestsFor: (path: string) => RequestLog[];
  };
  router: ReturnType<typeof createMemoryRouter>;
}

const USER = {
  id: "user_1",
  email: "analyst@example.test",
  displayName: "Alice Analyst",
  roles: ["ANALYST"],
};

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

const MARKUP_CONCLUSION =
  "Authorized pentest by RedTeam.\n<img src=x onerror=alert(1)>";

const ALICE = { id: "user_1", displayName: "Alice Analyst" };

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

const CLOSED_DETAIL = makeDetail({
  status: "CLOSED",
  outcome: "ACCEPTED",
  closureReason: "AUTHORIZED_ACTIVITY",
  closedAt: "2026-11-09T11:45:00Z",
  closedBy: { id: "user_2", displayName: "Bob Responder" },
  conclusion: MARKUP_CONCLUSION,
  linkedCases: [
    {
      id: "case_12",
      caseNumber: 12,
      title: "Earlier login",
      status: "CLOSED",
    },
  ],
});

function makeAlert(partial: Partial<AlertSummary>): AlertSummary {
  return {
    id: "alert_1",
    title: "Brute force",
    severity: "HIGH",
    status: "CLOSED",
    detectionId: "det_brute_force",
    detectionVersion: "0.1.0",
    evidenceCount: 12,
    occurrenceCount: 3,
    firstEventAt: "2026-11-09T08:05:00Z",
    lastEventAt: "2026-11-09T09:00:00Z",
    outcome: "MALICIOUS",
    closureReason: "CONFIRMED_THREAT",
    ...partial,
  };
}

const ALERTS: AlertSummary[] = [
  makeAlert({ id: "alert_1", title: "Brute force" }),
  makeAlert({
    id: "alert_2",
    title: "Impossible travel",
    severity: "LOW",
    detectionId: "det_impossible_travel",
    outcome: "ACCEPTED",
    closureReason: "FALSE_POSITIVE",
    firstEventAt: "2026-11-09T09:10:00Z",
    lastEventAt: "2026-11-09T09:30:00Z",
  }),
  makeAlert({ id: "alert_3", title: "Malware beacon" }),
];

const ASSIGNED: TimelineActivityEntry = {
  id: "tl_assigned",
  kind: "ACTIVITY",
  at: "2026-11-09T10:00:00Z",
  actor: { id: "user_1", displayName: "Alice Analyst" },
  action: "ASSIGNED",
  details: { assignee: { id: "user_2", displayName: "Bob Responder" } },
};

const EVIDENCE_A: TimelineEvidenceEntry = {
  id: "tl_ev_a",
  kind: "EVIDENCE",
  at: "2026-11-09T10:04:00Z",
  alertId: "alert_1",
  sourceId: "evt-a",
  udm: {
    metadata: { event_type: "USER_LOGIN" },
    principal: {
      user: { userid: "evt-user-a" },
      hostname: "WS-014",
      ip: ["10.12.4.18"],
    },
  },
};

const EVIDENCE_B: TimelineEvidenceEntry = {
  id: "tl_ev_b",
  kind: "EVIDENCE",
  at: "2026-11-09T10:06:00Z",
  alertId: "alert_2",
  sourceId: "evt-b",
  udm: {
    metadata: { event_type: "PROCESS_LAUNCH" },
    principal: {
      user: { userid: "evt-user-b" },
      hostname: "WS-027",
      ip: ["10.12.4.33"],
    },
  },
};

const STATUS_CHANGED: TimelineActivityEntry = {
  id: "tl_status",
  kind: "ACTIVITY",
  at: "2026-11-09T10:10:00Z",
  actor: { id: "user_1", displayName: "Alice Analyst" },
  action: "STATUS_CHANGED",
  details: { from: "OPEN", to: "IN_PROGRESS" },
};

const TIMELINE: TimelineEntry[] = [
  STATUS_CHANGED,
  EVIDENCE_B,
  ASSIGNED,
  EVIDENCE_A,
];

const ACTIVITY: TimelineActivityEntry[] = [
  {
    id: "tl_created",
    kind: "ACTIVITY",
    at: "2026-11-09T07:30:00Z",
    actor: null,
    action: "CASE_CREATED",
    details: {},
  },
  {
    id: "tl_alert",
    kind: "ACTIVITY",
    at: "2026-11-09T07:40:00Z",
    actor: null,
    action: "ALERT_ADDED",
    details: { alertId: "alert_1" },
  },
  ASSIGNED,
  {
    id: "tl_unassigned",
    kind: "ACTIVITY",
    at: "2026-11-09T10:20:00Z",
    actor: null,
    action: "UNASSIGNED",
    details: {},
  },
  STATUS_CHANGED,
  {
    id: "tl_closed",
    kind: "ACTIVITY",
    at: "2026-11-09T11:45:00Z",
    actor: { id: "user_2", displayName: "Bob Responder" },
    action: "CLOSED",
    details: { outcome: "ACCEPTED", closureReason: "AUTHORIZED_ACTIVITY" },
  },
  {
    id: "tl_recurrence",
    kind: "ACTIVITY",
    at: "2026-11-09T11:50:00Z",
    actor: null,
    action: "RECURRENCE_LINKED",
    details: { caseId: "case_9", caseNumber: 9 },
  },
  {
    id: "tl_unknown",
    kind: "ACTIVITY",
    at: "2026-11-09T11:55:00Z",
    actor: { id: "user_3", displayName: "Carol Console" },
    action: "FOOBAR",
    details: {},
  },
];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function listResponse(data: CaseSummary[]): Response {
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

function stubApi(responders: Responders = {}): RenderDetailResult["api"] {
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
        return listResponse([SUMMARY]);
      }
      if (url.pathname === "/api/v1/cases/counts") {
        return jsonResponse(COUNTS);
      }
      if (url.pathname === "/api/v1/cases/histogram") {
        return jsonResponse(HISTOGRAM);
      }
      if (method === "PATCH" && url.pathname === "/api/v1/cases/case_312") {
        return (responders.assign ?? (() => jsonResponse(makeDetail())))(body);
      }
      if (url.pathname === "/api/v1/cases/312") {
        return (responders.detail ?? (() => jsonResponse(makeDetail())))();
      }
      if (url.pathname === "/api/v1/cases/case_312/alerts") {
        return (responders.alerts ?? (() => emptyPage()))(url.searchParams);
      }
      if (url.pathname === "/api/v1/cases/case_312/timeline") {
        return (responders.timeline ?? (() => emptyPage()))(url.searchParams);
      }

      throw new Error(`unexpected request ${url.pathname}`);
    }),
  );

  return {
    requests,
    requestsFor: (path: string) =>
      requests.filter((request) => request.path === path),
  };
}

function emptyPage(): Response {
  return jsonResponse({ data: [], pagination: { limit: 50, nextCursor: null } });
}

function renderDetail(
  initialPath = "/cases/312?scope=all",
  responders: Responders = {},
): RenderDetailResult {
  const api = stubApi(responders);
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return { api, router };
}

function detailRegion(): HTMLElement {
  return screen.getByRole("region", { name: "Case #312" });
}

function descriptionValue(term: string): HTMLElement {
  const dt = screen.getByText(term, { selector: "dt" });
  const dd = dt.nextElementSibling;
  if (!(dd instanceof HTMLElement)) {
    throw new Error(`no value for ${term}`);
  }
  return dd;
}

function timelineEntries(search: URLSearchParams): TimelineEntry[] {
  return search.get("kind") === "ACTIVITY" ? ACTIVITY : TIMELINE;
}

function pageResponse<T>(data: T[], nextCursor: string | null = null): Response {
  return jsonResponse({
    data,
    pagination: { limit: 50, nextCursor },
  });
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
  writeTimeZone("local");
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, "clipboard");
  window.history.replaceState({}, "", "/");
  window.localStorage.clear();
});

function stubClipboard(writeText?: (text: string) => Promise<void>): Mock | undefined {
  if (writeText === undefined) {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: undefined,
    });
    return undefined;
  }

  const clipboard = vi.fn(writeText);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: clipboard },
  });
  return clipboard;
}

describe("case overview", () => {
  it("lists the summary fields and renders the conclusion as text", async () => {
    renderDetail("/cases/312?scope=all", {
      detail: () => jsonResponse(CLOSED_DETAIL),
    });

    await screen.findByRole("heading", {
      name: "#312 Brute force → success",
      level: 2,
    });

    expect(descriptionValue("Status")).toHaveTextContent("Closed");
    expect(descriptionValue("Severity")).toHaveTextContent("HIGH");
    expect(descriptionValue("Assignee")).toHaveTextContent("Unassigned");
    expect(descriptionValue("Created").querySelector("time")).toHaveAttribute(
      "datetime",
      "2026-11-09T07:30:00Z",
    );
    expect(
      descriptionValue("First event").querySelector("time"),
    ).toHaveAttribute("datetime", "2026-11-09T08:00:00Z");
    expect(descriptionValue("Last event").querySelector("time")).toHaveAttribute(
      "datetime",
      "2026-11-09T11:00:00Z",
    );
    expect(descriptionValue("Closed by")).toHaveTextContent("Bob Responder");
    expect(descriptionValue("Outcome")).toHaveTextContent("Accepted");
    expect(descriptionValue("Closure reason")).toHaveTextContent(
      "Authorized activity",
    );

    const conclusion = descriptionValue("Conclusion");
    expect(conclusion.textContent).toBe(MARKUP_CONCLUSION);
    expect(conclusion.querySelector("p")).toHaveClass("whitespace-pre-wrap");
    expect(detailRegion().querySelector("img")).toBeNull();

    const linked = within(descriptionValue("Linked cases")).getByRole("link", {
      name: "#12 Earlier login",
    });
    expect(linked).toHaveAttribute("href", "/cases/12?scope=all");
  });
});

describe("case alerts", () => {
  it("shows the alerts table and loads the next page", async () => {
    renderDetail("/cases/312?scope=all&view=alerts", {
      alerts: (search) =>
        search.get("cursor") === "next-alerts"
          ? pageResponse([ALERTS[2]])
          : pageResponse([ALERTS[0], ALERTS[1]], "next-alerts"),
    });

    const region = await screen.findByRole("region", { name: "Case #312" });
    const table = await within(region).findByRole("table", { name: "Alerts" });

    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual([
      "Title",
      "Severity",
      "Detection",
      "Evidence",
      "Occurrences",
      "First event",
      "Last event",
      "Disposition",
    ]);

    const firstRow = within(table).getByText("Brute force").closest("tr");
    if (firstRow === null) {
      throw new Error("the alert has no row");
    }
    expect(within(firstRow).getByText("HIGH")).toBeInTheDocument();
    expect(within(firstRow).getByText("det_brute_force")).toBeInTheDocument();
    expect(within(firstRow).getByText("0.1.0")).toBeInTheDocument();
    expect(within(firstRow).getByText("12")).toBeInTheDocument();
    expect(within(firstRow).getByText("3")).toBeInTheDocument();
    expect(
      within(firstRow).getByText("Malicious, Confirmed threat"),
    ).toBeInTheDocument();

    fireEvent.click(within(region).getByRole("button", { name: "Load more" }));

    expect(
      await within(table).findByText("Malware beacon"),
    ).toBeInTheDocument();
    expect(
      within(region).queryByRole("button", { name: "Load more" }),
    ).not.toBeInTheDocument();
  });
});

describe("case timeline", () => {
  it("shows evidence and activity in ascending order with the event viewer", async () => {
    renderDetail("/cases/312?scope=all&view=timeline", {
      timeline: (search) => pageResponse(timelineEntries(search)),
    });

    const region = await screen.findByRole("region", { name: "Case #312" });
    const list = await within(region).findByRole("list", {
      name: "Timeline",
    });
    const text = list.textContent ?? "";

    const assigned = text.indexOf(
      "Alice Analyst assigned the case to Bob Responder",
    );
    const firstEvidence = text.indexOf("evt-user-a");
    const secondEvidence = text.indexOf("evt-user-b");
    const status = text.indexOf("Status changed from Open to In progress");
    expect(assigned).toBeGreaterThanOrEqual(0);
    expect(assigned).toBeLessThan(firstEvidence);
    expect(firstEvidence).toBeLessThan(secondEvidence);
    expect(secondEvidence).toBeLessThan(status);

    expect(
      within(region).getByRole("table", { name: "Evidence events" }),
    ).toBeInTheDocument();
  });

  it("loads more timeline entries on the cursor", async () => {
    const later: TimelineActivityEntry = {
      ...STATUS_CHANGED,
      id: "tl_later",
      at: "2026-11-09T11:00:00Z",
      action: "CASE_CREATED",
      details: {},
      actor: null,
    };
    renderDetail("/cases/312?scope=all&view=timeline", {
      timeline: (search) =>
        search.get("cursor") === "next-timeline"
          ? pageResponse([later])
          : pageResponse([EVIDENCE_A, ASSIGNED], "next-timeline"),
    });

    const region = await screen.findByRole("region", { name: "Case #312" });
    await within(region).findByText("evt-user-a");

    fireEvent.click(within(region).getByRole("button", { name: "Load more" }));

    expect(await within(region).findByText("Case created")).toBeInTheDocument();
  });
});

describe("case activity", () => {
  it("requests activity only and shows a sentence per action", async () => {
    renderDetail("/cases/312?scope=all&view=activity", {
      timeline: (search) => pageResponse(timelineEntries(search)),
    });

    const region = await screen.findByRole("region", { name: "Case #312" });
    const list = await within(region).findByRole("list", { name: "Activity" });

    expect(within(list).getByText("Case created")).toBeInTheDocument();
    expect(within(list).getByText("Alert added")).toBeInTheDocument();
    expect(
      within(list).getByText(
        "Alice Analyst assigned the case to Bob Responder",
      ),
    ).toBeInTheDocument();
    expect(within(list).getByText("System unassigned the case")).toBeInTheDocument();
    expect(
      within(list).getByText("Status changed from Open to In progress"),
    ).toBeInTheDocument();
    expect(
      within(list).getByText("Closed as Accepted: Authorized activity"),
    ).toBeInTheDocument();
    expect(
      within(list).getByText("Linked to recurrence #9"),
    ).toBeInTheDocument();
    expect(within(list).getByText("Activity: FOOBAR")).toBeInTheDocument();
    expect(
      list.querySelector('time[datetime="2026-11-09T10:00:00Z"]'),
    ).not.toBeNull();
  });
});

describe("case detail errors", () => {
  it("says the analyst has no permission to view a forbidden case", async () => {
    renderDetail("/cases/312?scope=all", {
      detail: () =>
        jsonResponse(
          { error: { code: "FORBIDDEN", message: "No", details: {} } },
          403,
        ),
    });

    expect(
      await screen.findByText("You do not have permission to view this case."),
    ).toBeInTheDocument();
  });
});

function patchRequests(api: RenderDetailResult["api"]): RequestLog[] {
  return api
    .requestsFor("/api/v1/cases/case_312")
    .filter((request) => request.method === "PATCH");
}

function errorResponse(
  status: number,
  code: string,
  message: string,
): Response {
  return jsonResponse({ error: { code, message, details: {} } }, status);
}

describe("assign to me", () => {
  it("assigns from the header with the case version and my id", async () => {
    const { api } = renderDetail("/cases/312?scope=all", {
      detail: () => jsonResponse(makeDetail()),
      assign: () =>
        jsonResponse(
          makeDetail({
            status: "IN_PROGRESS",
            assignee: ALICE,
            version: 4,
          }),
        ),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Assign to me" }),
    );

    expect(
      await screen.findByRole("button", { name: "Unassign" }),
    ).toBeInTheDocument();
    expect(patchRequests(api)).toHaveLength(1);
    expect(patchRequests(api)[0].body).toEqual({
      assigneeId: "user_1",
      version: 3,
    });
  });

  it("unassigns with null when the case is mine", async () => {
    const { api } = renderDetail("/cases/312?scope=all", {
      detail: () =>
        jsonResponse(
          makeDetail({
            status: "IN_PROGRESS",
            assignee: ALICE,
            version: 4,
          }),
        ),
      assign: () =>
        jsonResponse(
          makeDetail({
            status: "IN_PROGRESS",
            assignee: null,
            version: 5,
          }),
        ),
    });

    fireEvent.click(await screen.findByRole("button", { name: "Unassign" }));

    expect(
      await screen.findByRole("button", { name: "Assign to me" }),
    ).toBeInTheDocument();
    expect(patchRequests(api)[0].body).toEqual({
      assigneeId: null,
      version: 4,
    });
  });

  it("assigns from the queue with a and refreshes counts and the chart only", async () => {
    const { api } = renderDetail("/cases?scope=all", {
      assign: () =>
        jsonResponse(
          makeDetail({
            status: "IN_PROGRESS",
            assignee: ALICE,
            version: 4,
          }),
        ),
    });

    const table = await screen.findByRole("table", {
      name: "Cases: Open, All",
    });
    const cell = await within(table).findByText("#312");
    const row = cell.closest("tr");
    if (row === null) {
      throw new Error("no row for case 312");
    }
    row.focus();

    const before = {
      list: api.requestsFor("/api/v1/cases").length,
      counts: api.requestsFor("/api/v1/cases/counts").length,
      histogram: api.requestsFor("/api/v1/cases/histogram").length,
    };

    fireEvent.keyDown(row, { key: "a" });

    await waitFor(() => {
      expect(patchRequests(api)).toHaveLength(1);
    });
    expect(patchRequests(api)[0].body).toEqual({
      assigneeId: "user_1",
      version: 3,
    });

    await waitFor(() => {
      expect(api.requestsFor("/api/v1/cases/counts").length).toBeGreaterThan(
        before.counts,
      );
      expect(
        api.requestsFor("/api/v1/cases/histogram").length,
      ).toBeGreaterThan(before.histogram);
    });
    expect(api.requestsFor("/api/v1/cases")).toHaveLength(before.list);
  });

  it("offers a reload on a version conflict", async () => {
    const { api } = renderDetail("/cases/312?scope=all", {
      assign: () =>
        errorResponse(409, "VERSION_CONFLICT", "Version conflict"),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Assign to me" }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("This case changed since you opened it.");
    const detailRequests = api.requestsFor("/api/v1/cases/312").length;

    fireEvent.click(within(alert).getByRole("button", { name: "Reload case" }));

    await waitFor(() => {
      expect(api.requestsFor("/api/v1/cases/312").length).toBe(
        detailRequests + 1,
      );
    });
  });

  it("says the case is closed on a state conflict", async () => {
    renderDetail("/cases/312?scope=all", {
      assign: () =>
        errorResponse(409, "STATE_CONFLICT", "State conflict"),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Assign to me" }),
    );

    expect(
      await screen.findByRole("alert"),
    ).toHaveTextContent("This case is closed.");
  });

  it("says when assigning is forbidden", async () => {
    renderDetail("/cases/312?scope=all", {
      assign: () => errorResponse(403, "FORBIDDEN", "Forbidden"),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Assign to me" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "You do not have permission to assign this case.",
    );
  });

  it("says when the user cannot be assigned", async () => {
    renderDetail("/cases/312?scope=all", {
      assign: () => errorResponse(400, "VALIDATION_ERROR", "Inactive user"),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Assign to me" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This user cannot be assigned.",
    );
  });
});

describe("case commands", () => {
  it("copies the current view with absolute times", async () => {
    vi.useFakeTimers({
      shouldAdvanceTime: true,
      now: new Date("2026-11-09T12:00:00Z"),
    });
    const writeText = stubClipboard(async () => undefined);
    window.history.replaceState({}, "", "/cases/312?scope=all");
    renderDetail("/cases/312?scope=all");

    fireEvent.click(await screen.findByRole("button", { name: "Copy link" }));

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledTimes(1);
    });
    expect(writeText?.mock.calls[0][0]).toBe(
      `${window.location.origin}/cases/312?scope=all&from=2026-11-08T12:00:00Z&to=2026-11-09T12:00:00Z`,
    );
    expect(
      within(detailRegion()).getByRole("status"),
    ).toHaveTextContent("Link copied");
  });

  it("offers the link for copying when the clipboard is unavailable", async () => {
    vi.useFakeTimers({
      shouldAdvanceTime: true,
      now: new Date("2026-11-09T12:00:00Z"),
    });
    stubClipboard();
    window.history.replaceState({}, "", "/cases/312");
    renderDetail("/cases/312");

    fireEvent.click(await screen.findByRole("button", { name: "Copy link" }));

    const input = await screen.findByLabelText("Case link");
    expect(input).toHaveFocus();
    expect(input).toHaveValue(
      `${window.location.origin}/cases/312?from=2026-11-08T12:00:00Z&to=2026-11-09T12:00:00Z`,
    );
  });

  it("assigns from the palette command", async () => {
    const { api } = renderDetail("/cases/312?scope=all", {
      assign: () =>
        jsonResponse(
          makeDetail({
            status: "IN_PROGRESS",
            assignee: ALICE,
            version: 4,
          }),
        ),
    });
    await screen.findByRole("button", { name: "Assign to me" });

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByPlaceholderText("Type a command…");
    fireEvent.change(input, { target: { value: "assign to me" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => {
      expect(patchRequests(api)).toHaveLength(1);
    });
    expect(patchRequests(api)[0].body).toEqual({
      assigneeId: "user_1",
      version: 3,
    });
  });

  it("closes the detail from the palette command", async () => {
    const { router } = renderDetail("/cases/312?scope=all");
    await screen.findByRole("button", { name: "Assign to me" });

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByPlaceholderText("Type a command…");
    fireEvent.change(input, { target: { value: "close case detail" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
  });
});
