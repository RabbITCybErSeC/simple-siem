// Fake /cases server self-test, not API coverage; removed with that route when case-core lands.
import type { Page } from "@playwright/test";
import type { ErrorEnvelope } from "../src/api/types.ts";
import type {
  CaseCounts,
  CaseHistogram,
  CaseListResponse,
  CaseSummary,
} from "../src/features/cases/types.ts";
import { FIXTURE_NOW } from "./support/cases.ts";
import { expect, signIn, test } from "./support/test.ts";

const DAY_MS = 24 * 60 * 60 * 1000;

interface JsonResponse<T> {
  status: number;
  body: T;
}

async function fetchJson<T>(
  page: Page,
  path: string,
): Promise<JsonResponse<T>> {
  return page.evaluate(async (url): Promise<JsonResponse<T>> => {
    const response = await fetch(url, {
      headers: { "X-Requested-With": "simple-siem" },
    });
    const body = (await response.json()) as T;
    return { status: response.status, body };
  }, path);
}

async function listAll(
  page: Page,
  parameters: Record<string, string>,
): Promise<CaseSummary[]> {
  const cases: CaseSummary[] = [];
  let cursor: string | null = null;
  do {
    const query = new URLSearchParams(parameters);
    query.set("limit", "200");
    if (cursor !== null) {
      query.set("cursor", cursor);
    }
    const response = await fetchJson<CaseListResponse>(
      page,
      `/api/v1/cases?${query.toString()}`,
    );
    expect(response.status, `list ${query.toString()}`).toBe(200);
    cases.push(...response.body.data);
    cursor = response.body.pagination.nextCursor;
  } while (cursor !== null);
  return cases;
}

function milliseconds(value: string | null): number {
  if (value === null) {
    throw new Error("expected a timestamp");
  }
  return Date.parse(value);
}

function expectNewestFirst(cases: CaseSummary[]): void {
  for (const [index, item] of cases.entries()) {
    if (index === 0) {
      continue;
    }
    expect(Date.parse(item.lastEventAt)).toBeLessThanOrEqual(
      Date.parse(cases[index - 1].lastEventAt),
    );
  }
}

test("lists my open cases newest first and pages with the cursor", async ({
  page,
  api,
}) => {
  await signIn(page);
  await page.goto("/");

  const first = await fetchJson<CaseListResponse>(
    page,
    "/api/v1/cases?status=OPEN&scope=mine&limit=10",
  );
  expect(first.status).toBe(200);
  expect(first.body.pagination.limit).toBe(10);
  expect(first.body.pagination.nextCursor).not.toBeNull();
  expect(first.body.data).toHaveLength(10);
  const me = await api.currentUser();
  for (const item of first.body.data) {
    expect(item.status).toBe("OPEN");
    expect(item.assignee?.id).toBe(me.id);
  }
  expectNewestFirst(first.body.data);

  const cursor = first.body.pagination.nextCursor;
  if (cursor === null) {
    throw new Error("expected a next cursor");
  }
  const second = await fetchJson<CaseListResponse>(
    page,
    `/api/v1/cases?status=OPEN&scope=mine&limit=10&cursor=${cursor}`,
  );
  expect(second.status).toBe(200);
  expect(second.body.data).toHaveLength(10);
  const firstIds = new Set(first.body.data.map((item) => item.id));
  expect(second.body.data.some((item) => firstIds.has(item.id))).toBe(false);
  expectNewestFirst(second.body.data);
  expect(Date.parse(second.body.data[0].lastEventAt)).toBeLessThanOrEqual(
    Date.parse(first.body.data[9].lastEventAt),
  );

  const defaultPage = await fetchJson<CaseListResponse>(
    page,
    "/api/v1/cases?status=OPEN&scope=mine",
  );
  expect(defaultPage.status).toBe(200);
  expect(defaultPage.body.pagination.limit).toBe(50);
  expect(defaultPage.body.data).toHaveLength(50);
  expect(defaultPage.body.pagination.nextCursor).not.toBeNull();

  const all = await listAll(page, { status: "OPEN", scope: "mine" });
  expect(all.length).toBeGreaterThan(50);
  const oldLastEventAt = new Date(
    FIXTURE_NOW.getTime() - 40 * DAY_MS,
  ).toISOString();
  const oldOpen = all.find((item) => item.lastEventAt === oldLastEventAt);
  expect(oldOpen?.status).toBe("OPEN");
  expect(oldOpen?.assignee?.id).toBe(me.id);
  expect(api.caseRequests()).toContain(
    "/api/v1/cases?status=OPEN&scope=mine&limit=10",
  );
});

test("filters closed cases on closedAt", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const closed = await listAll(page, {
    status: "CLOSED",
    from: "now-7d",
    to: "now",
    timeField: "closedAt",
  });
  expect(closed.length).toBeGreaterThan(0);
  const from = FIXTURE_NOW.getTime() - 7 * DAY_MS;
  const to = FIXTURE_NOW.getTime();
  for (const item of closed) {
    expect(item.status).toBe("CLOSED");
    expect(item.closedAt).not.toBeNull();
    expect(milliseconds(item.closedAt)).toBeGreaterThanOrEqual(from);
    expect(milliseconds(item.closedAt)).toBeLessThanOrEqual(to);
  }
});

test("lists only unassigned cases in the unassigned scope", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const unassigned = await listAll(page, { scope: "unassigned" });
  expect(unassigned.length).toBeGreaterThan(0);
  for (const item of unassigned) {
    expect(item.assignee).toBeNull();
  }
});

test("counts match the list totals", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const range = { from: "now-7d", to: "now", timeField: "closedAt" };
  const response = await fetchJson<CaseCounts>(
    page,
    `/api/v1/cases/counts?${new URLSearchParams(range).toString()}`,
  );
  expect(response.status).toBe(200);
  expect(response.body.cap).toBe(1000);

  const [open, inProgress, closed, every] = await Promise.all([
    listAll(page, { status: "OPEN" }),
    listAll(page, { status: "IN_PROGRESS" }),
    listAll(page, { status: "CLOSED", ...range }),
    listAll(page, range),
  ]);
  expect(open.length).toBeGreaterThan(0);
  expect(inProgress.length).toBeGreaterThan(0);
  expect(closed.length).toBeGreaterThan(0);
  expect(response.body.status).toEqual({
    OPEN: open.length,
    IN_PROGRESS: inProgress.length,
    CLOSED: closed.length,
    ALL: every.length,
  });

  const [mine, unassigned, all] = await Promise.all([
    listAll(page, { scope: "mine", ...range }),
    listAll(page, { scope: "unassigned", ...range }),
    listAll(page, { scope: "all", ...range }),
  ]);
  expect(response.body.scope).toEqual({
    mine: mine.length,
    unassigned: unassigned.length,
    all: all.length,
  });
});

test("histogram buckets add up to the matching list", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const response = await fetchJson<CaseHistogram>(
    page,
    "/api/v1/cases/histogram?from=now-24h&to=now",
  );
  expect(response.status).toBe(200);
  expect(response.body.interval).toBe("30m");
  expect(response.body.buckets.length).toBeGreaterThan(0);
  for (const bucket of response.body.buckets) {
    expect(Date.parse(bucket.start) % (30 * 60_000)).toBe(0);
  }
  const total = response.body.buckets.reduce(
    (sum, bucket) =>
      sum + bucket.counts.HIGH + bucket.counts.MEDIUM + bucket.counts.LOW,
    0,
  );
  const matching = await listAll(page, { from: "now-24h", to: "now" });
  expect(matching.length).toBeGreaterThan(0);
  expect(total).toBe(matching.length);
});

test("rejects a malformed cursor and an invalid time", async ({ page }) => {
  await signIn(page);
  await page.goto("/");

  const cursorQuery = new URLSearchParams({ cursor: "not-base64!" });
  const badCursor = await fetchJson<ErrorEnvelope>(
    page,
    `/api/v1/cases?${cursorQuery.toString()}`,
  );
  expect(badCursor.status).toBe(400);
  expect(badCursor.body.error.code).toBe("VALIDATION_ERROR");

  const badTime = await fetchJson<ErrorEnvelope>(
    page,
    "/api/v1/cases?from=yesterday",
  );
  expect(badTime.status).toBe(400);
  expect(badTime.body.error.code).toBe("VALIDATION_ERROR");
});

test("adds and updates a case in the fixture", async ({ page, api }) => {
  await signIn(page);
  await page.goto("/");

  const added = api.addCase({ title: "New arrival" });
  expect(added.caseNumber).toBe(301);
  expect(added.status).toBe("OPEN");
  const me = await api.currentUser();
  expect(added.assignee?.id).toBe(me.id);

  const first = await fetchJson<CaseListResponse>(
    page,
    "/api/v1/cases?status=OPEN&scope=mine&limit=10",
  );
  expect(first.status).toBe(200);
  expect(first.body.data[0].id).toBe(added.id);
  expect(first.body.data[0].title).toBe("New arrival");

  const updated = api.updateCase(added.id, {
    title: "Updated arrival",
    severity: "HIGH",
  });
  expect(updated.version).toBe(2);

  const after = await fetchJson<CaseListResponse>(
    page,
    "/api/v1/cases?status=OPEN&scope=mine&limit=10",
  );
  expect(after.body.data[0]).toMatchObject({
    id: added.id,
    title: "Updated arrival",
    severity: "HIGH",
    version: 2,
  });
});

test("moves the fixture clock", async ({ page, api }) => {
  await signIn(page);
  await page.goto("/");

  const later = new Date(FIXTURE_NOW.getTime() + 60 * 60 * 1000);
  api.setNow(later);
  const added = api.addCase({ title: "After the clock" });
  expect(added.createdAt).toBe(later.toISOString());
  expect(added.lastEventAt).toBe(later.toISOString());

  const updated = api.updateCase(added.id, {
    title: "Updated after the clock",
  });
  expect(updated.lastEventAt).toBe(later.toISOString());
});

// This proves the fixture guard fails a test on a contract violation; the failure is the point.
test.fail("an unknown case query parameter fails the test", async ({ page }) => {
  await signIn(page);
  await page.goto("/");
  await fetchJson(page, "/api/v1/cases?foo=1");
});
