// Fake /cases server self-test, not API coverage; removed with that route when case-core lands.
import type { Page } from "@playwright/test";
import type { ErrorEnvelope } from "../src/api/types.ts";
import type {
  BulkCloseRequest,
  BulkCloseResponse,
  CaseAlertsResponse,
  CaseDetail,
  CaseTimelineResponse,
  CloseRequest,
  TimelineActivityEntry,
  TimelineEntry,
  TimelineEvidenceEntry,
} from "../src/features/cases/detail/types.ts";
import type {
  CaseListResponse,
  CaseSummary,
} from "../src/features/cases/types.ts";
import { expect, signIn, test } from "./support/test.ts";

const MARKUP_USERID = "<img src=x onerror=alert(1)>";

interface JsonResponse<T> {
  status: number;
  body: T;
}

interface UdmDocument {
  metadata: { event_type: string; event_timestamp: string };
  principal: {
    user: { userid: string };
    hostname: string;
    ip: string[];
  };
  target: { hostname: string };
  security_result: { action: string };
}

async function requestJson<T>(
  page: Page,
  method: "GET" | "PATCH" | "POST",
  path: string,
  body?: object,
): Promise<JsonResponse<T>> {
  return page.evaluate(
    async ({ method, path, body }): Promise<JsonResponse<T>> => {
      const response = await fetch(path, {
        method,
        headers: {
          "X-Requested-With": "simple-siem",
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      return {
        status: response.status,
        body: (text === "" ? undefined : JSON.parse(text)) as T,
      };
    },
    { method, path, body },
  );
}

function fetchJson<T>(page: Page, path: string): Promise<JsonResponse<T>> {
  return requestJson<T>(page, "GET", path);
}

async function listCases(
  page: Page,
  parameters: Record<string, string> = {},
): Promise<CaseSummary[]> {
  const query = new URLSearchParams({ limit: "200", ...parameters });
  const response = await fetchJson<CaseListResponse>(
    page,
    `/api/v1/cases?${query.toString()}`,
  );
  expect(response.status).toBe(200);
  return response.body.data;
}

async function caseDetail(page: Page, caseRef: string): Promise<CaseDetail> {
  const response = await fetchJson<CaseDetail>(
    page,
    `/api/v1/cases/${caseRef}`,
  );
  expect(response.status, `detail of ${caseRef}`).toBe(200);
  return response.body;
}

function evidenceEntries(entries: TimelineEntry[]): TimelineEvidenceEntry[] {
  return entries.filter(
    (entry): entry is TimelineEvidenceEntry => entry.kind === "EVIDENCE",
  );
}

function activityEntries(entries: TimelineEntry[]): TimelineActivityEntry[] {
  return entries.filter(
    (entry): entry is TimelineActivityEntry => entry.kind === "ACTIVITY",
  );
}

function expectAscending<T>(
  entries: T[],
  timeOf: (entry: T) => string,
): void {
  for (const [index, entry] of entries.entries()) {
    if (index === 0) {
      continue;
    }
    expect(Date.parse(timeOf(entry))).toBeGreaterThanOrEqual(
      Date.parse(timeOf(entries[index - 1])),
    );
  }
}

async function firstOpenCase(page: Page): Promise<CaseSummary> {
  const open = await listCases(page, { status: "OPEN" });
  expect(open.length).toBeGreaterThan(0);
  return open[0];
}

async function firstCaseWithAlerts(
  page: Page,
  minimum: number,
): Promise<CaseDetail> {
  const candidates = await listCases(page, { limit: "50" });
  for (const item of candidates) {
    const detail = await caseDetail(page, item.id);
    if (detail.alertCount >= minimum) {
      return detail;
    }
  }
  throw new Error(`no fixture case with ${minimum} alerts`);
}

function udmOf(entry: TimelineEvidenceEntry): UdmDocument {
  return entry.udm as unknown as UdmDocument;
}

test("serves a case detail by number and by id", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const first = (await listCases(page, { limit: "5" }))[0];
  const byNumber = await fetchJson<CaseDetail>(
    page,
    `/api/v1/cases/${first.caseNumber}`,
  );
  expect(byNumber.status).toBe(200);
  expect(byNumber.body).toMatchObject({
    id: first.id,
    caseNumber: first.caseNumber,
    title: first.title,
    status: first.status,
    severity: first.severity,
    version: first.version,
  });
  expect(byNumber.body.alertCount).toBeGreaterThanOrEqual(1);
  expect(byNumber.body.lastActivityAt).not.toBe("");
  expect(byNumber.body.linkedCases).toEqual([]);
  expect(byNumber.body.mergedInto).toBeNull();

  const byId = await fetchJson<CaseDetail>(page, `/api/v1/cases/${first.id}`);
  expect(byId.status).toBe(200);
  expect(byId.body).toEqual(byNumber.body);

  const linked = await caseDetail(page, "12");
  expect(linked.linkedCases.map((item) => item.caseNumber)).toContain(213);
  const back = await caseDetail(page, "213");
  expect(back.linkedCases.map((item) => item.caseNumber)).toContain(12);

  const closed = (await listCases(page, { status: "CLOSED", limit: "1" }))[0];
  const closedDetail = await caseDetail(page, closed.id);
  expect(closedDetail.closedBy).not.toBeNull();
  expect(closedDetail.conclusion).not.toBeNull();
});

test("answers not found for an unknown case", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const missing = await fetchJson<ErrorEnvelope>(
    page,
    "/api/v1/cases/99999",
  );
  expect(missing.status).toBe(404);
  expect(missing.body.error.code).toBe("NOT_FOUND");
});

test("lists a case's alerts and timeline in ascending time", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/");

  const target = await firstCaseWithAlerts(page, 3);
  const caseId = target.id;

  const alerts = await fetchJson<CaseAlertsResponse>(
    page,
    `/api/v1/cases/${caseId}/alerts?limit=200`,
  );
  expect(alerts.status).toBe(200);
  expect(alerts.body.data).toHaveLength(target.alertCount);
  expectAscending(alerts.body.data, (alert) => alert.firstEventAt);
  const alertIds = new Set(alerts.body.data.map((alert) => alert.id));
  for (const alert of alerts.body.data) {
    expect(alert.id).not.toBe("");
    expect(["HIGH", "MEDIUM", "LOW"]).toContain(alert.severity);
    expect(["OPEN", "SUPPRESSED", "CLOSED"]).toContain(alert.status);
    expect(alert.detectionId).not.toBe("");
    expect(alert.detectionVersion).toBe("0.1.0");
    expect(alert.evidenceCount).toBeGreaterThan(0);
    expect(alert.occurrenceCount).toBeGreaterThan(0);
  }

  const alertPage = await fetchJson<CaseAlertsResponse>(
    page,
    `/api/v1/cases/${caseId}/alerts?limit=2`,
  );
  expect(alertPage.body.data).toEqual(alerts.body.data.slice(0, 2));
  const alertCursor = alertPage.body.pagination.nextCursor;
  expect(alertCursor).not.toBeNull();
  const alertPageTwo = await fetchJson<CaseAlertsResponse>(
    page,
    `/api/v1/cases/${caseId}/alerts?limit=2&cursor=${alertCursor ?? ""}`,
  );
  expect(alertPageTwo.body.data).toEqual(alerts.body.data.slice(2, 4));

  const timeline = await fetchJson<CaseTimelineResponse>(
    page,
    `/api/v1/cases/${caseId}/timeline?limit=200`,
  );
  expect(timeline.status).toBe(200);
  expectAscending(timeline.body.data, (entry) => entry.at);
  const evidence = evidenceEntries(timeline.body.data);
  expect(evidence.length).toBeGreaterThanOrEqual(3);
  expect(evidence.length).toBeLessThanOrEqual(30);
  let cachedCount = 0;
  for (const entry of evidence) {
    expect(alertIds.has(entry.alertId)).toBe(true);
    expect(entry.sourceId).not.toBe("");
    if (entry.udm === null) {
      continue;
    }
    cachedCount += 1;
    const udm = udmOf(entry);
    expect(udm.metadata.event_type).not.toBe("");
    expect(udm.metadata.event_timestamp).toBe(entry.at);
    expect(udm.principal.user.userid).not.toBe("");
    expect(udm.principal.hostname).not.toBe("");
    expect(Array.isArray(udm.principal.ip)).toBe(true);
    expect(udm.principal.ip.length).toBeGreaterThan(0);
    expect(udm.target.hostname).not.toBe("");
    expect(udm.security_result.action).not.toBe("");
  }
  expect(cachedCount).toBeGreaterThan(0);

  const activity = activityEntries(timeline.body.data);
  const actions = activity.map((entry) => entry.action);
  expect(actions).toContain("CASE_CREATED");
  expect(
    actions.filter((action) => action === "ALERT_ADDED").length,
  ).toBe(alerts.body.data.length);
  const created = activity.find((entry) => entry.action === "CASE_CREATED");
  expect(created?.actor).toBeNull();

  const activityOnly = await fetchJson<CaseTimelineResponse>(
    page,
    `/api/v1/cases/${caseId}/timeline?kind=ACTIVITY&limit=200`,
  );
  expect(activityOnly.body.data).toHaveLength(activity.length);
  expect(
    activityOnly.body.data.every((entry) => entry.kind === "ACTIVITY"),
  ).toBe(true);

  const timelinePage = await fetchJson<CaseTimelineResponse>(
    page,
    `/api/v1/cases/${caseId}/timeline?limit=3`,
  );
  expect(timelinePage.body.data).toEqual(timeline.body.data.slice(0, 3));
  const timelineCursor = timelinePage.body.pagination.nextCursor;
  expect(timelineCursor).not.toBeNull();
  const timelinePageTwo = await fetchJson<CaseTimelineResponse>(
    page,
    `/api/v1/cases/${caseId}/timeline?limit=3&cursor=${timelineCursor ?? ""}`,
  );
  expect(timelinePageTwo.body.data).toEqual(timeline.body.data.slice(3, 6));
});

test("keeps markup in a UDM value literal", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const detail = await caseDetail(page, "7");
  const timeline = await fetchJson<CaseTimelineResponse>(
    page,
    `/api/v1/cases/${detail.id}/timeline?kind=EVIDENCE&limit=200`,
  );
  expect(timeline.status).toBe(200);
  const markup = timeline.body.data.find((entry) => {
    if (entry.kind !== "EVIDENCE" || entry.udm === null) {
      return false;
    }
    return udmOf(entry).principal.user.userid === MARKUP_USERID;
  });
  expect(markup).toBeDefined();
});

test("assigns and unassigns with optimistic concurrency", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/");

  const me = await api.currentUser();
  const open = await listCases(page, {
    status: "OPEN",
    scope: "unassigned",
  });
  const target = open.find((item) => item.assignee === null);
  expect(target).toBeDefined();
  const before = await caseDetail(page, target?.id ?? "");

  const assigned = await requestJson<CaseDetail>(
    page,
    "PATCH",
    `/api/v1/cases/${before.id}`,
    { assigneeId: me.id, version: before.version },
  );
  expect(assigned.status).toBe(200);
  expect(assigned.body).toMatchObject({
    status: "IN_PROGRESS",
    assignee: me,
    version: before.version + 1,
  });

  const unassigned = await requestJson<CaseDetail>(
    page,
    "PATCH",
    `/api/v1/cases/${before.id}`,
    { assigneeId: null, version: assigned.body.version },
  );
  expect(unassigned.status).toBe(200);
  expect(unassigned.body).toMatchObject({
    status: "IN_PROGRESS",
    assignee: null,
    version: assigned.body.version + 1,
  });

  const stale = await requestJson<ErrorEnvelope>(
    page,
    "PATCH",
    `/api/v1/cases/${before.id}`,
    { assigneeId: me.id, version: before.version },
  );
  expect(stale.status).toBe(409);
  expect(stale.body.error.code).toBe("VERSION_CONFLICT");

  const inactive = await requestJson<ErrorEnvelope>(
    page,
    "PATCH",
    `/api/v1/cases/${before.id}`,
    { assigneeId: "user_999", version: unassigned.body.version },
  );
  expect(inactive.status).toBe(400);
  expect(inactive.body.error.code).toBe("VALIDATION_ERROR");

  const activity = await fetchJson<CaseTimelineResponse>(
    page,
    `/api/v1/cases/${before.id}/timeline?kind=ACTIVITY&limit=200`,
  );
  const entries = activity.body.data;
  const assignedEntry = entries.find(
    (entry): entry is TimelineActivityEntry =>
      entry.kind === "ACTIVITY" && entry.action === "ASSIGNED",
  );
  expect(assignedEntry?.actor).toEqual(me);
  expect(assignedEntry?.details).toEqual({ assignee: me });
  const statusChanged = entries.find(
    (entry): entry is TimelineActivityEntry =>
      entry.kind === "ACTIVITY" && entry.action === "STATUS_CHANGED",
  );
  expect(statusChanged?.details).toEqual({ from: "OPEN", to: "IN_PROGRESS" });
  const unassignedEntry = entries.find(
    (entry): entry is TimelineActivityEntry =>
      entry.kind === "ACTIVITY" && entry.action === "UNASSIGNED",
  );
  expect(unassignedEntry).toBeDefined();
});

test("closes a case once and rejects MERGED", async ({ page, api }) => {
  await signIn(page);
  await page.goto("/");

  const me = await api.currentUser();
  const target = await firstOpenCase(page);
  const before = await caseDetail(page, target.id);
  const initialAlerts = await fetchJson<CaseAlertsResponse>(
    page,
    `/api/v1/cases/${target.id}/alerts?limit=200`,
  );
  const overridden = initialAlerts.body.data[0];
  if (overridden === undefined) {
    throw new Error("the fixture case has no alerts");
  }
  const close: CloseRequest = {
    outcome: "ACCEPTED",
    closureReason: "AUTHORIZED_ACTIVITY",
    conclusion: "Approved change, CHG-41.",
    alertDispositions: [
      {
        alertId: overridden.id,
        outcome: "MALICIOUS",
        closureReason: "CONFIRMED_THREAT",
      },
    ],
    version: before.version,
  };

  const merged = await requestJson<ErrorEnvelope>(
    page,
    "POST",
    `/api/v1/cases/${target.id}/close`,
    { ...close, closureReason: "MERGED" },
  );
  expect(merged.status).toBe(400);
  expect(merged.body.error.code).toBe("VALIDATION_ERROR");

  const closed = await requestJson<CaseDetail>(
    page,
    "POST",
    `/api/v1/cases/${target.id}/close`,
    close,
  );
  expect(closed.status).toBe(200);
  expect(closed.body).toMatchObject({
    status: "CLOSED",
    outcome: "ACCEPTED",
    closureReason: "AUTHORIZED_ACTIVITY",
    conclusion: close.conclusion,
    closedBy: me,
    version: before.version + 1,
  });
  expect(closed.body.closedAt).not.toBeNull();

  const alerts = await fetchJson<CaseAlertsResponse>(
    page,
    `/api/v1/cases/${target.id}/alerts?limit=200`,
  );
  for (const alert of alerts.body.data) {
    expect(alert.status).toBe("CLOSED");
    if (alert.id === overridden.id) {
      expect(alert.outcome).toBe("MALICIOUS");
      expect(alert.closureReason).toBe("CONFIRMED_THREAT");
    } else {
      expect(alert.outcome).toBe("ACCEPTED");
      expect(alert.closureReason).toBe("AUTHORIZED_ACTIVITY");
    }
  }

  const again = await requestJson<ErrorEnvelope>(
    page,
    "POST",
    `/api/v1/cases/${target.id}/close`,
    { ...close, version: closed.body.version },
  );
  expect(again.status).toBe(409);
  expect(again.body.error.code).toBe("STATE_CONFLICT");

  const assignClosed = await requestJson<ErrorEnvelope>(
    page,
    "PATCH",
    `/api/v1/cases/${target.id}`,
    { assigneeId: me.id, version: closed.body.version },
  );
  expect(assignClosed.status).toBe(409);
  expect(assignClosed.body.error.code).toBe("STATE_CONFLICT");
});

test("a simulated concurrent change makes a version stale", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/");

  const me = await api.currentUser();
  const target = await firstOpenCase(page);
  const before = await caseDetail(page, target.id);
  api.bumpVersion(target.id);

  const stale = await requestJson<ErrorEnvelope>(
    page,
    "PATCH",
    `/api/v1/cases/${target.id}`,
    { assigneeId: me.id, version: before.version },
  );
  expect(stale.status).toBe(409);
  expect(stale.body.error.code).toBe("VERSION_CONFLICT");

  const detail = await caseDetail(page, target.id);
  expect(detail.version).toBe(before.version + 1);
});

test("failNextClose answers once", async ({ page, api }) => {
  await signIn(page);
  await page.goto("/");

  const target = await firstOpenCase(page);
  const before = await caseDetail(page, target.id);
  const close: CloseRequest = {
    outcome: "MALICIOUS",
    closureReason: "CONFIRMED_THREAT",
    conclusion: "Confirmed credential theft.",
    version: before.version,
  };

  api.failNextClose("INTERNAL_ERROR");
  const failed = await requestJson<ErrorEnvelope>(
    page,
    "POST",
    `/api/v1/cases/${target.id}/close`,
    close,
  );
  expect(failed.status).toBe(500);
  expect(failed.body.error.code).toBe("INTERNAL_ERROR");

  const closed = await requestJson<CaseDetail>(
    page,
    "POST",
    `/api/v1/cases/${target.id}/close`,
    close,
  );
  expect(closed.status).toBe(200);
  expect(closed.body.status).toBe("CLOSED");
});

test("bulk close reports each case's result in request order", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/");

  const open = await listCases(page, { status: "OPEN" });
  expect(open.length).toBeGreaterThanOrEqual(3);
  const chosen = open.slice(0, 3);
  const before: CaseDetail[] = [];
  for (const item of chosen) {
    before.push(await caseDetail(page, item.id));
  }
  api.bumpVersion(chosen[1].id);

  const request: BulkCloseRequest = {
    cases: chosen.map((item, index) => ({
      id: item.id,
      version: before[index].version,
    })),
    outcome: "MALICIOUS",
    closureReason: "CONFIRMED_THREAT",
    conclusion: "Confirmed on the host.",
  };
  const response = await requestJson<BulkCloseResponse>(
    page,
    "POST",
    "/api/v1/cases/bulk-close",
    request,
  );
  expect(response.status).toBe(200);
  expect(response.body.results).toEqual([
    { caseId: chosen[0].id, status: "CLOSED" },
    { caseId: chosen[1].id, status: "VERSION_CONFLICT" },
    { caseId: chosen[2].id, status: "CLOSED" },
  ]);

  const closed = await caseDetail(page, chosen[0].id);
  expect(closed.status).toBe("CLOSED");
  expect(closed.version).toBe(before[0].version + 1);
  const conflicted = await caseDetail(page, chosen[1].id);
  expect(conflicted.status).toBe("OPEN");

  const empty = await requestJson<ErrorEnvelope>(
    page,
    "POST",
    "/api/v1/cases/bulk-close",
    { ...request, cases: [] },
  );
  expect(empty.status).toBe(400);
  expect(empty.body.error.code).toBe("VALIDATION_ERROR");
});

test("a write is visible in the next case list", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const target = await firstOpenCase(page);
  const before = await caseDetail(page, target.id);
  const closed = await requestJson<CaseDetail>(
    page,
    "POST",
    `/api/v1/cases/${target.id}/close`,
    {
      outcome: "ACCEPTED",
      closureReason: "OTHER",
      conclusion: "Handled with the asset owner.",
      version: before.version,
    },
  );
  expect(closed.status).toBe(200);

  const listed = await listCases(page, { status: "CLOSED" });
  const found = listed.find((item) => item.id === target.id);
  expect(found).toMatchObject({
    status: "CLOSED",
    outcome: "ACCEPTED",
    closureReason: "OTHER",
    version: before.version + 1,
  });
  expect(found?.closedAt).not.toBeNull();
});

test("rejects an unknown timeline kind", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const target = await firstOpenCase(page);
  const response = await fetchJson<ErrorEnvelope>(
    page,
    `/api/v1/cases/${target.id}/timeline?kind=BOGUS`,
  );
  expect(response.status).toBe(400);
  expect(response.body.error.code).toBe("VALIDATION_ERROR");
});

// This proves the fixture guard fails a test on a contract violation; the failure is the point.
test.fail(
  "an unknown case detail parameter fails the test",
  async ({ page }) => {
    await signIn(page);
    await page.goto("/");
    await fetchJson(page, "/api/v1/cases/312?foo=1");
  },
);
