// shortcut: case fixtures, use the real case API when case-core and case-close are on main.
import type { Route } from "@playwright/test";
import type { ErrorEnvelope } from "../../src/api/types.ts";
import type {
  CaseAssignee,
  CaseCounts,
  CaseHistogram,
  CaseListResponse,
  CaseSeverity,
  CaseStatus,
  CaseSummary,
} from "../../src/features/cases/types.ts";

export const FIXTURE_NOW = new Date("2026-11-09T12:00:00Z");

const DAY_MS = 24 * 60 * 60 * 1000;
const CASE_COUNT = 300;
const COUNT_CAP = 1000;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const MAX_BUCKETS = 60;

const ALICE: CaseAssignee = { id: "user_1", displayName: "Alice Analyst" };
const BOB: CaseAssignee = { id: "user_2", displayName: "Bob Responder" };

const TITLES = [
  "Brute force → success",
  "Impossible travel",
  "Suspicious admin activity",
  "Malware beacon to unknown host",
  "Data exfiltration over DNS",
  "Privilege escalation attempt",
  "Repeated failed logins",
  "Unusual cloud API call",
];

const CLOSURE_REASONS = [
  "FALSE_POSITIVE",
  "BENIGN_TRUE_POSITIVE",
  "AUTHORIZED_ACTIVITY",
  "DUPLICATE",
  "INSUFFICIENT_EVIDENCE",
  "CONFIRMED_THREAT",
  "OTHER",
];

const TIME_FIELD_NAMES = new Set([
  "lastEventAt",
  "firstEventAt",
  "createdAt",
  "closedAt",
]);

type TimeField = "lastEventAt" | "firstEventAt" | "createdAt" | "closedAt";
type Scope = "mine" | "unassigned" | "all";
type Sort = "lastEventAt:desc" | "createdAt:asc";

interface Interval {
  name: string;
  milliseconds: number;
}

const INTERVALS: Interval[] = [
  { name: "1m", milliseconds: 60_000 },
  { name: "5m", milliseconds: 5 * 60_000 },
  { name: "15m", milliseconds: 15 * 60_000 },
  { name: "30m", milliseconds: 30 * 60_000 },
  { name: "1h", milliseconds: 60 * 60_000 },
  { name: "3h", milliseconds: 3 * 60 * 60_000 },
  { name: "6h", milliseconds: 6 * 60 * 60_000 },
  { name: "12h", milliseconds: 12 * 60 * 60_000 },
  { name: "1d", milliseconds: DAY_MS },
];

const LIST_PARAMETERS = [
  "status",
  "scope",
  "from",
  "to",
  "timeField",
  "sort",
  "cursor",
  "limit",
];
const COUNT_PARAMETERS = ["status", "from", "to", "timeField"];
const HISTOGRAM_PARAMETERS = [
  "status",
  "scope",
  "from",
  "to",
  "timeField",
  "interval",
  "splitBy",
];

const ALLOWED_PARAMETERS: Record<string, string[]> = {
  "/api/v1/cases": LIST_PARAMETERS,
  "/api/v1/cases/counts": COUNT_PARAMETERS,
  "/api/v1/cases/histogram": HISTOGRAM_PARAMETERS,
};

class InvalidQueryError extends Error {}

function errorEnvelope(code: string, message: string): ErrorEnvelope {
  return { error: { code, message } };
}

const VALIDATION_ERROR = errorEnvelope("VALIDATION_ERROR", "Invalid request");

function mulberry32(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let value = Math.imul(state ^ (state >>> 15), 1 | state);
    value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffled<T>(values: T[], random: () => number): T[] {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(random() * (index + 1));
    const current = result[index];
    result[index] = result[swapIndex];
    result[swapIndex] = current;
  }
  return result;
}

function iso(milliseconds: number): string {
  return new Date(milliseconds).toISOString();
}

function severityFor(value: number): CaseSeverity {
  if (value < 0.2) {
    return "HIGH";
  }
  if (value < 0.55) {
    return "MEDIUM";
  }
  return "LOW";
}

function generateCases(): CaseSummary[] {
  const random = mulberry32(20261109);
  const statuses = shuffled(
    [
      ...Array<CaseStatus>(120).fill("OPEN"),
      ...Array<CaseStatus>(60).fill("IN_PROGRESS"),
      ...Array<CaseStatus>(120).fill("CLOSED"),
    ],
    random,
  );
  const assignees: Record<CaseStatus, (CaseAssignee | null)[]> = {
    OPEN: shuffled(
      [
        ...Array<CaseAssignee>(55).fill(ALICE),
        ...Array<CaseAssignee>(35).fill(BOB),
        ...Array<null>(30).fill(null),
      ],
      random,
    ),
    IN_PROGRESS: shuffled(
      [
        ...Array<CaseAssignee>(30).fill(ALICE),
        ...Array<CaseAssignee>(30).fill(BOB),
      ],
      random,
    ),
    CLOSED: shuffled(
      [
        ...Array<CaseAssignee>(20).fill(ALICE),
        ...Array<CaseAssignee>(25).fill(BOB),
        ...Array<null>(75).fill(null),
      ],
      random,
    ),
  };
  const nextAssignee: Record<CaseStatus, number> = {
    OPEN: 0,
    IN_PROGRESS: 0,
    CLOSED: 0,
  };
  const now = FIXTURE_NOW.getTime();
  const cases: CaseSummary[] = [];

  for (let caseNumber = 1; caseNumber <= CASE_COUNT; caseNumber += 1) {
    const status = statuses[caseNumber - 1];
    const assignee = assignees[status][nextAssignee[status]];
    nextAssignee[status] += 1;

    const createdAt = now - random() * 30 * DAY_MS;
    const firstEventAt = createdAt - random() * 2 * 60 * 60 * 1000;
    const lastEventAt = firstEventAt + random() * (now - firstEventAt);
    const closed = status === "CLOSED";
    const closedAt = closed
      ? lastEventAt + random() * (now - lastEventAt)
      : null;

    cases.push({
      id: `case_${caseNumber}`,
      caseNumber,
      title: TITLES[Math.floor(random() * TITLES.length)],
      status,
      severity: severityFor(random()),
      outcome: closed ? (random() < 0.5 ? "MALICIOUS" : "ACCEPTED") : null,
      closureReason: closed
        ? CLOSURE_REASONS[Math.floor(random() * CLOSURE_REASONS.length)]
        : null,
      assignee,
      firstEventAt: iso(firstEventAt),
      lastEventAt: iso(lastEventAt),
      createdAt: iso(createdAt),
      closedAt: closedAt === null ? null : iso(closedAt),
      version: 1,
    });
  }

  const oldOpen = cases.find(
    (item) => item.status === "OPEN" && item.assignee?.id === ALICE.id,
  );
  if (oldOpen === undefined) {
    throw new Error("fixture generator needs an open case assigned to user_1");
  }
  const oldLastEventAt = now - 40 * DAY_MS;
  oldOpen.lastEventAt = iso(oldLastEventAt);
  oldOpen.firstEventAt = iso(oldLastEventAt - 2 * 60 * 60 * 1000);
  oldOpen.createdAt = iso(oldLastEventAt - 60 * 60 * 1000);

  return cases;
}

function isCaseStatus(value: string): value is CaseStatus {
  return value === "OPEN" || value === "IN_PROGRESS" || value === "CLOSED";
}

function isTimeField(value: string): value is TimeField {
  return TIME_FIELD_NAMES.has(value);
}

function startOfUtcDay(milliseconds: number): number {
  return Math.floor(milliseconds / DAY_MS) * DAY_MS;
}

function startOfUtcWeek(milliseconds: number): number {
  const day = startOfUtcDay(milliseconds);
  const weekday = new Date(day).getUTCDay();
  return day - ((weekday + 6) % 7) * DAY_MS;
}

function unitMilliseconds(unit: string): number {
  switch (unit) {
    case "m":
      return 60_000;
    case "h":
      return 60 * 60_000;
    case "d":
      return DAY_MS;
    case "w":
      return 7 * DAY_MS;
    default:
      throw new InvalidQueryError();
  }
}

function parseTime(value: string, now: Date): number {
  if (value === "now") {
    return now.getTime();
  }
  if (value === "now/d") {
    return startOfUtcDay(now.getTime());
  }
  if (value === "now/w") {
    return startOfUtcWeek(now.getTime());
  }
  const relative = /^now-([1-9]\d*)([mhdw])$/.exec(value);
  if (relative !== null) {
    return (
      now.getTime() - Number(relative[1]) * unitMilliseconds(relative[2])
    );
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) {
    throw new InvalidQueryError();
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new InvalidQueryError();
  }
  return parsed;
}

function parseOptionalTime(value: string | null, now: Date): number | null {
  if (value === null) {
    return null;
  }
  return parseTime(value, now);
}

function parseStatuses(value: string | null): CaseStatus[] | null {
  if (value === null) {
    return null;
  }
  const statuses = value.split(",");
  if (!statuses.every(isCaseStatus)) {
    throw new InvalidQueryError();
  }
  return statuses;
}

function parseSingleStatus(value: string): CaseStatus {
  if (!isCaseStatus(value)) {
    throw new InvalidQueryError();
  }
  return value;
}

function parseScope(value: string | null): Scope | null {
  if (value === null) {
    return null;
  }
  if (value === "mine" || value === "unassigned" || value === "all") {
    return value;
  }
  throw new InvalidQueryError();
}

function parseTimeField(value: string | null): TimeField {
  if (value === null) {
    return "lastEventAt";
  }
  if (!isTimeField(value)) {
    throw new InvalidQueryError();
  }
  return value;
}

function parseSort(value: string | null): Sort {
  if (value === null) {
    return "lastEventAt:desc";
  }
  if (value === "lastEventAt:desc" || value === "createdAt:asc") {
    return value;
  }
  throw new InvalidQueryError();
}

function parseLimit(value: string | null): number {
  if (value === null) {
    return DEFAULT_LIMIT;
  }
  if (!/^\d+$/.test(value)) {
    throw new InvalidQueryError();
  }
  const limit = Number(value);
  if (limit < 1 || limit > MAX_LIMIT) {
    throw new InvalidQueryError();
  }
  return limit;
}

function encodeCursor(offset: number): string {
  return Buffer.from(String(offset), "utf8").toString("base64url");
}

function decodeCursor(cursor: string): number {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) {
    throw new InvalidQueryError();
  }
  const decoded = Buffer.from(cursor, "base64url").toString("utf8");
  if (
    !/^\d+$/.test(decoded) ||
    Buffer.from(decoded, "utf8").toString("base64url") !== cursor
  ) {
    throw new InvalidQueryError();
  }
  return Number(decoded);
}

function inRange(
  item: CaseSummary,
  timeField: TimeField,
  from: number | null,
  to: number | null,
): boolean {
  if (from === null && to === null) {
    return true;
  }
  const value = item[timeField];
  if (value === null) {
    return false;
  }
  const milliseconds = Date.parse(value);
  return (
    (from === null || milliseconds >= from) &&
    (to === null || milliseconds <= to)
  );
}

function compareCases(
  left: CaseSummary,
  right: CaseSummary,
  sort: Sort,
): number {
  const leftTime = Date.parse(
    sort === "lastEventAt:desc" ? left.lastEventAt : left.createdAt,
  );
  const rightTime = Date.parse(
    sort === "lastEventAt:desc" ? right.lastEventAt : right.createdAt,
  );
  const difference =
    sort === "lastEventAt:desc" ? rightTime - leftTime : leftTime - rightTime;
  return difference !== 0 ? difference : left.caseNumber - right.caseNumber;
}

function capped(value: number): number {
  return Math.min(value, COUNT_CAP);
}

function intervalBucketCount(
  interval: Interval,
  from: number,
  to: number,
): number {
  return (
    Math.floor(to / interval.milliseconds) -
    Math.floor(from / interval.milliseconds) +
    1
  );
}

function autoInterval(from: number, to: number): Interval {
  return (
    INTERVALS.find(
      (interval) => intervalBucketCount(interval, from, to) <= MAX_BUCKETS,
    ) ?? INTERVALS[INTERVALS.length - 1]
  );
}

function parseInterval(value: string | null): Interval | "auto" {
  if (value === null || value === "auto") {
    return "auto";
  }
  const interval = INTERVALS.find((item) => item.name === value);
  if (interval === undefined) {
    throw new InvalidQueryError();
  }
  return interval;
}

export class CaseFixtureRoutes {
  readonly violations: string[];
  private readonly cases: CaseSummary[] = generateCases();
  private readonly requests: string[] = [];
  private now = FIXTURE_NOW;
  private nextCaseNumber = CASE_COUNT + 1;

  constructor(violations: string[]) {
    this.violations = violations;
  }

  addCase(partial: Partial<CaseSummary>): CaseSummary {
    const caseNumber = this.nextCaseNumber;
    this.nextCaseNumber += 1;
    const now = this.now.toISOString();
    const added: CaseSummary = {
      title: "New case",
      status: "OPEN",
      severity: "MEDIUM",
      outcome: null,
      closureReason: null,
      assignee: ALICE,
      firstEventAt: now,
      lastEventAt: now,
      createdAt: now,
      closedAt: null,
      version: 1,
      ...partial,
      id: `case_${caseNumber}`,
      caseNumber,
    };
    this.cases.push(added);
    return added;
  }

  updateCase(id: string, partial: Partial<CaseSummary>): CaseSummary {
    const index = this.cases.findIndex((item) => item.id === id);
    if (index < 0) {
      throw new Error(`no fixture case ${id}`);
    }
    const existing = this.cases[index];
    const updated: CaseSummary = {
      ...existing,
      ...partial,
      id: existing.id,
      caseNumber: existing.caseNumber,
      lastEventAt: this.now.toISOString(),
      version: existing.version + 1,
    };
    this.cases[index] = updated;
    return updated;
  }

  setNow(date: Date): void {
    this.now = date;
  }

  caseRequests(): string[] {
    return this.requests;
  }

  async handle(
    route: Route,
    path: string,
    searchParams: URLSearchParams,
  ): Promise<void> {
    this.requests.push(
      searchParams.size === 0 ? path : `${path}?${searchParams.toString()}`,
    );

    const allowed = ALLOWED_PARAMETERS[path];
    if (allowed === undefined) {
      this.violations.push(
        `${route.request().method()} ${path}: no fixture for this route`,
      );
      await this.respond(route, 404, errorEnvelope("NOT_FOUND", "Not found"));
      return;
    }
    if (!this.checkParameters(route, path, searchParams, allowed)) {
      await this.respond(route, 400, VALIDATION_ERROR);
      return;
    }

    try {
      switch (path) {
        case "/api/v1/cases":
          await this.list(route, searchParams);
          return;
        case "/api/v1/cases/counts":
          await this.counts(route, searchParams);
          return;
        default:
          await this.histogram(route, searchParams);
          return;
      }
    } catch (error) {
      if (error instanceof InvalidQueryError) {
        await this.respond(route, 400, VALIDATION_ERROR);
        return;
      }
      throw error;
    }
  }

  private checkParameters(
    route: Route,
    path: string,
    searchParams: URLSearchParams,
    allowed: string[],
  ): boolean {
    let valid = true;
    for (const name of new Set(searchParams.keys())) {
      if (!allowed.includes(name)) {
        this.violations.push(
          `${route.request().method()} ${path}: unknown parameter ${name}`,
        );
        valid = false;
      }
    }
    return valid;
  }

  private async list(
    route: Route,
    searchParams: URLSearchParams,
  ): Promise<void> {
    const statuses = parseStatuses(searchParams.get("status"));
    const scope = parseScope(searchParams.get("scope"));
    const timeField = parseTimeField(searchParams.get("timeField"));
    const sort = parseSort(searchParams.get("sort"));
    const from = parseOptionalTime(searchParams.get("from"), this.now);
    const to = parseOptionalTime(searchParams.get("to"), this.now);
    const limit = parseLimit(searchParams.get("limit"));
    const cursor = searchParams.get("cursor");
    const offset = cursor === null ? 0 : decodeCursor(cursor);
    if (from !== null && to !== null && from > to) {
      throw new InvalidQueryError();
    }

    const matching = this.cases
      .filter((item) =>
        this.matches(item, statuses, scope, timeField, from, to),
      )
      .sort((left, right) => compareCases(left, right, sort));
    const data = matching.slice(offset, offset + limit);
    const nextOffset = offset + data.length;
    const response: CaseListResponse = {
      data,
      pagination: {
        limit,
        nextCursor:
          nextOffset < matching.length ? encodeCursor(nextOffset) : null,
      },
    };
    await this.respond(route, 200, response);
  }

  private async counts(
    route: Route,
    searchParams: URLSearchParams,
  ): Promise<void> {
    const statusValue = searchParams.get("status");
    const status =
      statusValue === null || statusValue === "ALL"
        ? null
        : parseSingleStatus(statusValue);
    const timeField = parseTimeField(searchParams.get("timeField"));
    const from = parseOptionalTime(searchParams.get("from"), this.now);
    const to = parseOptionalTime(searchParams.get("to"), this.now);
    if (from !== null && to !== null && from > to) {
      throw new InvalidQueryError();
    }

    const withinRange = (item: CaseSummary) =>
      inRange(item, timeField, from, to);
    const ofStatus = (wanted: CaseStatus) =>
      this.cases.filter((item) => item.status === wanted);
    const scopeCases = status === null ? this.cases : ofStatus(status);
    const scoped =
      status === null || status === "CLOSED"
        ? scopeCases.filter(withinRange)
        : scopeCases;
    const response: CaseCounts = {
      status: {
        OPEN: capped(ofStatus("OPEN").length),
        IN_PROGRESS: capped(ofStatus("IN_PROGRESS").length),
        CLOSED: capped(ofStatus("CLOSED").filter(withinRange).length),
        ALL: capped(this.cases.filter(withinRange).length),
      },
      scope: {
        mine: capped(
          scoped.filter((item) => item.assignee?.id === ALICE.id).length,
        ),
        unassigned: capped(
          scoped.filter((item) => item.assignee === null).length,
        ),
        all: capped(scoped.length),
      },
      cap: COUNT_CAP,
    };
    await this.respond(route, 200, response);
  }

  private async histogram(
    route: Route,
    searchParams: URLSearchParams,
  ): Promise<void> {
    const statuses = parseStatuses(searchParams.get("status"));
    const scope = parseScope(searchParams.get("scope"));
    const timeField = parseTimeField(searchParams.get("timeField"));
    const fromValue = searchParams.get("from");
    const toValue = searchParams.get("to");
    if (fromValue === null || toValue === null) {
      throw new InvalidQueryError();
    }
    const from = parseTime(fromValue, this.now);
    const to = parseTime(toValue, this.now);
    if (from > to) {
      throw new InvalidQueryError();
    }
    const splitBy = searchParams.get("splitBy");
    if (splitBy !== null && splitBy !== "severity") {
      throw new InvalidQueryError();
    }
    const requested = parseInterval(searchParams.get("interval"));
    const interval = requested === "auto" ? autoInterval(from, to) : requested;
    const first =
      Math.floor(from / interval.milliseconds) * interval.milliseconds;
    const last =
      Math.floor(to / interval.milliseconds) * interval.milliseconds;
    const buckets: CaseHistogram["buckets"] = [];
    for (
      let start = first;
      start <= last;
      start += interval.milliseconds
    ) {
      buckets.push({
        start: iso(start),
        counts: { HIGH: 0, MEDIUM: 0, LOW: 0 },
      });
    }

    for (const item of this.cases) {
      if (!this.matches(item, statuses, scope, timeField, from, to)) {
        continue;
      }
      const value = item[timeField];
      if (value === null) {
        continue;
      }
      const index = Math.floor(
        (Date.parse(value) - first) / interval.milliseconds,
      );
      if (index < 0 || index >= buckets.length) {
        continue;
      }
      buckets[index].counts[item.severity] += 1;
    }

    const response: CaseHistogram = { interval: interval.name, buckets };
    await this.respond(route, 200, response);
  }

  private matches(
    item: CaseSummary,
    statuses: CaseStatus[] | null,
    scope: Scope | null,
    timeField: TimeField,
    from: number | null,
    to: number | null,
  ): boolean {
    if (statuses !== null && !statuses.includes(item.status)) {
      return false;
    }
    if (scope === "mine" && item.assignee?.id !== ALICE.id) {
      return false;
    }
    if (scope === "unassigned" && item.assignee !== null) {
      return false;
    }
    return inRange(item, timeField, from, to);
  }

  private async respond(
    route: Route,
    status: number,
    body: object,
  ): Promise<void> {
    await route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  }
}
