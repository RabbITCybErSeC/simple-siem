// shortcut: case fixtures, use the real case API when case-core and case-close are on main.
import type { Route } from "@playwright/test";
import type {
  CursorListResponse,
  ErrorEnvelope,
} from "../../src/api/types.ts";
import type {
  AlertDisposition,
  AlertSummary,
  AssignRequest,
  BulkCloseRequest,
  BulkCloseResponse,
  BulkCloseStatus,
  CaseAlertsResponse,
  CaseDetail,
  CaseTimelineResponse,
  CloseRequest,
  ClosureReason,
  LinkedCase,
  StoredClosureReason,
  TimelineActivityEntry,
  TimelineEntry,
  TimelineEvidenceEntry,
} from "../../src/features/cases/detail/types.ts";
import type {
  CaseAssignee,
  CaseCounts,
  CaseHistogram,
  CaseListResponse,
  CaseOutcome,
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

export type CloseFailure =
  | "VERSION_CONFLICT"
  | "STATE_CONFLICT"
  | "INTERNAL_ERROR";

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

const CLOSURE_REASONS: ClosureReason[] = [
  "FALSE_POSITIVE",
  "BENIGN_TRUE_POSITIVE",
  "AUTHORIZED_ACTIVITY",
  "DUPLICATE",
  "INSUFFICIENT_EVIDENCE",
  "CONFIRMED_THREAT",
  "OTHER",
];

const LINKED_CASE_NUMBERS = [12, 213];
const MARKUP_USERID = "<img src=x onerror=alert(1)>";

const DETECTIONS = [
  { id: "det_brute_force", title: "Brute force" },
  { id: "det_impossible_travel", title: "Impossible travel" },
  { id: "det_malware_beacon", title: "Malware beacon" },
  { id: "det_dns_exfiltration", title: "DNS exfiltration" },
  { id: "det_privilege_escalation", title: "Privilege escalation" },
];

// From internal/udm/types.go: the fixture emits only UDM values the server can.
const EVENT_TYPES = ["USER_LOGIN", "USER_LOGOUT", "GENERIC_EVENT"];
const USER_IDS = ["jdoe", "asmith", "bwilliams", "svc_backup"];
const HOSTNAMES = ["WS-014", "WS-027", "SRV-DC-01", "LT-102"];
const IP_ADDRESSES = ["10.12.4.18", "10.12.4.33", "192.0.2.54", "203.0.113.9"];
const TARGET_HOSTNAMES = ["SRV-DC-01", "fileserver-2", "api.internal", "unknown-host"];
const SECURITY_ACTIONS = ["ALLOW", "BLOCK", "UNKNOWN_ACTION"];

const CONCLUSIONS = [
  "Validated with the asset owner; no further action.",
  "Handled during the incident response exercise.",
  "Duplicate of an earlier case; closed as duplicate.",
  "Log source was misconfigured; corrected.",
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

const ALERT_PARAMETERS = ["cursor", "limit"];
const TIMELINE_PARAMETERS = ["kind", "cursor", "limit"];
const NO_PARAMETERS: string[] = [];

type CaseRoute =
  | { name: "list" }
  | { name: "counts" }
  | { name: "histogram" }
  | { name: "bulk-close" }
  | { name: "detail"; caseRef: string }
  | { name: "alerts"; caseId: string }
  | { name: "timeline"; caseId: string }
  | { name: "assign"; caseId: string }
  | { name: "close"; caseId: string };

function matchCaseRoute(method: string, path: string): CaseRoute | null {
  if (method === "GET" && path === "/api/v1/cases") {
    return { name: "list" };
  }
  if (method === "GET" && path === "/api/v1/cases/counts") {
    return { name: "counts" };
  }
  if (method === "GET" && path === "/api/v1/cases/histogram") {
    return { name: "histogram" };
  }
  if (method === "POST" && path === "/api/v1/cases/bulk-close") {
    return { name: "bulk-close" };
  }

  const nested = /^\/api\/v1\/cases\/([^/]+)\/(alerts|timeline|close)$/.exec(
    path,
  );
  if (nested !== null) {
    const caseId = nested[1];
    const action = nested[2];
    if (action === "alerts" && method === "GET") {
      return { name: "alerts", caseId };
    }
    if (action === "timeline" && method === "GET") {
      return { name: "timeline", caseId };
    }
    if (action === "close" && method === "POST") {
      return { name: "close", caseId };
    }
    return null;
  }

  const single = /^\/api\/v1\/cases\/([^/]+)$/.exec(path);
  if (single !== null) {
    if (method === "GET") {
      return { name: "detail", caseRef: single[1] };
    }
    if (method === "PATCH") {
      return { name: "assign", caseId: single[1] };
    }
  }
  return null;
}

function allowedParameters(route: CaseRoute): string[] {
  switch (route.name) {
    case "list":
      return LIST_PARAMETERS;
    case "counts":
      return COUNT_PARAMETERS;
    case "histogram":
      return HISTOGRAM_PARAMETERS;
    case "alerts":
      return ALERT_PARAMETERS;
    case "timeline":
      return TIMELINE_PARAMETERS;
    default:
      return NO_PARAMETERS;
  }
}

interface CaseHistory {
  closedBy: CaseAssignee | null;
  conclusion: string | null;
  alerts: AlertSummary[] | null;
  timeline: TimelineEntry[] | null;
}

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

function parseCursor(value: string | null): number {
  return value === null ? 0 : decodeCursor(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseOutcome(value: unknown): CaseOutcome {
  if (value === "MALICIOUS" || value === "ACCEPTED") {
    return value;
  }
  throw new InvalidQueryError();
}

const CLOSURE_REASON_NAMES = new Set<string>(CLOSURE_REASONS);

function parseClosureReason(value: unknown): ClosureReason {
  if (typeof value !== "string" || !CLOSURE_REASON_NAMES.has(value)) {
    throw new InvalidQueryError();
  }
  return value as ClosureReason;
}

function parseConclusion(value: unknown): string {
  if (typeof value !== "string") {
    throw new InvalidQueryError();
  }
  const conclusion = value.trim();
  if (conclusion.length < 1 || conclusion.length > 10_000) {
    throw new InvalidQueryError();
  }
  return conclusion;
}

function parseVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new InvalidQueryError();
  }
  return value;
}

function parseDisposition(value: unknown): AlertDisposition {
  if (!isRecord(value) || typeof value.alertId !== "string") {
    throw new InvalidQueryError();
  }
  if (value.alertId === "") {
    throw new InvalidQueryError();
  }
  return {
    alertId: value.alertId,
    outcome: parseOutcome(value.outcome),
    closureReason: parseClosureReason(value.closureReason),
  };
}

function parseAlertDispositions(value: unknown): AlertDisposition[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new InvalidQueryError();
  }
  return value.map(parseDisposition);
}

function parseAssignRequest(body: unknown): AssignRequest {
  if (!isRecord(body)) {
    throw new InvalidQueryError();
  }
  const assigneeId = body.assigneeId;
  if (assigneeId !== null && typeof assigneeId !== "string") {
    throw new InvalidQueryError();
  }
  return { assigneeId, version: parseVersion(body.version) };
}

function parseCloseRequest(body: unknown): CloseRequest {
  if (!isRecord(body)) {
    throw new InvalidQueryError();
  }
  return {
    outcome: parseOutcome(body.outcome),
    closureReason: parseClosureReason(body.closureReason),
    conclusion: parseConclusion(body.conclusion),
    alertDispositions: parseAlertDispositions(body.alertDispositions),
    version: parseVersion(body.version),
  };
}

function parseBulkCloseRequest(body: unknown): BulkCloseRequest {
  if (!isRecord(body) || !Array.isArray(body.cases)) {
    throw new InvalidQueryError();
  }
  if (body.cases.length < 1 || body.cases.length > 100) {
    throw new InvalidQueryError();
  }
  const cases = body.cases.map((value) => {
    if (
      !isRecord(value) ||
      typeof value.id !== "string" ||
      value.id === ""
    ) {
      throw new InvalidQueryError();
    }
    return { id: value.id, version: parseVersion(value.version) };
  });
  return {
    cases,
    outcome: parseOutcome(body.outcome),
    closureReason: parseClosureReason(body.closureReason),
    conclusion: parseConclusion(body.conclusion),
  };
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

function pick<T>(values: T[], random: () => number): T {
  return values[Math.floor(random() * values.length)];
}

function buildUdm(
  caseNumber: number,
  sequence: number,
  at: number,
): Record<string, unknown> {
  const random = mulberry32(caseNumber * 1000 + sequence);
  const userid =
    caseNumber === 7 && sequence === 1
      ? MARKUP_USERID
      : pick(USER_IDS, random);
  return {
    metadata: {
      event_type: pick(EVENT_TYPES, random),
      event_timestamp: iso(at),
    },
    principal: {
      user: { userid },
      hostname: pick(HOSTNAMES, random),
      ip: [pick(IP_ADDRESSES, random)],
    },
    target: { hostname: pick(TARGET_HOSTNAMES, random) },
    security_result: { action: pick(SECURITY_ACTIONS, random) },
  };
}

function compareTimelineEntries(
  left: TimelineEntry,
  right: TimelineEntry,
): number {
  const difference = Date.parse(left.at) - Date.parse(right.at);
  return difference !== 0 ? difference : left.id.localeCompare(right.id);
}

function latestActivityAt(fallback: string, entries: TimelineEntry[]): string {
  let latest = fallback;
  for (const entry of entries) {
    if (
      entry.kind === "ACTIVITY" &&
      Date.parse(entry.at) > Date.parse(latest)
    ) {
      latest = entry.at;
    }
  }
  return latest;
}

export class CaseFixtureRoutes {
  readonly violations: string[];
  private readonly cases: CaseSummary[] = generateCases();
  private readonly requests: string[] = [];
  private now = FIXTURE_NOW;
  private nextCaseNumber = CASE_COUNT + 1;
  private me: CaseAssignee = ALICE;
  private readonly histories = new Map<string, CaseHistory>();
  private readonly activityIds = new Map<string, number>();
  private pendingCloseFailure: CloseFailure | null = null;

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
      assignee: this.me,
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

  private findCaseById(id: string): CaseSummary | undefined {
    return this.cases.find((item) => item.id === id);
  }

  private findCaseByRef(caseRef: string): CaseSummary | undefined {
    if (/^\d+$/.test(caseRef)) {
      return this.cases.find(
        (item) => item.caseNumber === Number(caseRef),
      );
    }
    return this.findCaseById(caseRef);
  }

  private requireCase(id: string): CaseSummary {
    const found = this.findCaseById(id);
    if (found === undefined) {
      throw new Error(`no fixture case ${id}`);
    }
    return found;
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

  currentUser(): CaseAssignee {
    return this.me;
  }

  // The seeded data calls the analyst user_1; the page signs in as a real
  // user, so the fixture adopts the real id and display name for user_1.
  setMe(me: CaseAssignee): void {
    if (me.id === this.me.id) {
      return;
    }
    this.me = me;
    for (const item of this.cases) {
      if (item.assignee?.id === ALICE.id) {
        item.assignee = me;
      }
    }
    for (const history of this.histories.values()) {
      if (history.closedBy?.id === ALICE.id) {
        history.closedBy = me;
      }
      for (const entry of history.timeline ?? []) {
        if (entry.kind !== "ACTIVITY" || entry.actor?.id !== ALICE.id) {
          continue;
        }
        entry.actor = me;
        if (
          entry.action === "ASSIGNED" &&
          isRecord(entry.details.assignee) &&
          entry.details.assignee.id === ALICE.id
        ) {
          entry.details = { ...entry.details, assignee: me };
        }
      }
    }
  }

  failNextClose(code: CloseFailure): void {
    this.pendingCloseFailure = code;
  }

  private takeCloseFailure(): CloseFailure | null {
    const failure = this.pendingCloseFailure;
    this.pendingCloseFailure = null;
    return failure;
  }

  bumpVersion(id: string): void {
    this.requireCase(id).version += 1;
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

    const method = route.request().method();
    const matched = matchCaseRoute(method, path);
    if (matched === null) {
      this.violations.push(`${method} ${path}: no fixture for this route`);
      await this.respond(route, 404, errorEnvelope("NOT_FOUND", "Not found"));
      return;
    }
    if (
      !this.checkParameters(route, path, searchParams, allowedParameters(matched))
    ) {
      await this.respond(route, 400, VALIDATION_ERROR);
      return;
    }

    try {
      switch (matched.name) {
        case "list":
          await this.list(route, searchParams);
          return;
        case "counts":
          await this.counts(route, searchParams);
          return;
        case "histogram":
          await this.histogram(route, searchParams);
          return;
        case "detail":
          await this.detail(route, matched.caseRef);
          return;
        case "alerts":
          await this.alerts(route, matched.caseId, searchParams);
          return;
        case "timeline":
          await this.timeline(route, matched.caseId, searchParams);
          return;
        case "assign":
          await this.assign(route, matched.caseId);
          return;
        case "close":
          await this.close(route, matched.caseId);
          return;
        case "bulk-close":
          await this.bulkClose(route);
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

  private resolveAssignee(id: string): CaseAssignee | undefined {
    if (id === this.me.id || id === ALICE.id) {
      return this.me;
    }
    if (id === BOB.id) {
      return BOB;
    }
    return undefined;
  }

  private async notFound(route: Route): Promise<void> {
    await this.respond(route, 404, errorEnvelope("NOT_FOUND", "Not found"));
  }

  private readBody(route: Route): unknown {
    try {
      return route.request().postDataJSON() as unknown;
    } catch {
      throw new InvalidQueryError();
    }
  }

  private cursorPage<T>(
    items: T[],
    limit: number,
    offset: number,
  ): CursorListResponse<T> {
    const data = items.slice(offset, offset + limit);
    const nextOffset = offset + data.length;
    return {
      data,
      pagination: {
        limit,
        nextCursor:
          nextOffset < items.length ? encodeCursor(nextOffset) : null,
      },
    };
  }

  private async respondCloseFailure(
    route: Route,
    failure: CloseFailure,
  ): Promise<void> {
    if (failure === "INTERNAL_ERROR") {
      await this.respond(
        route,
        500,
        errorEnvelope("INTERNAL_ERROR", "Internal error"),
      );
      return;
    }
    if (failure === "VERSION_CONFLICT") {
      await this.respondVersionConflict(route);
      return;
    }
    await this.respondStateConflict(route);
  }

  private async respondVersionConflict(route: Route): Promise<void> {
    await this.respond(
      route,
      409,
      errorEnvelope("VERSION_CONFLICT", "Version conflict"),
    );
  }

  private async respondStateConflict(route: Route): Promise<void> {
    await this.respond(
      route,
      409,
      errorEnvelope("STATE_CONFLICT", "State conflict"),
    );
  }

  private detailFor(item: CaseSummary): CaseDetail {
    const history = this.historyFor(item);
    const timeline = this.timelineFor(item);
    return {
      ...item,
      lastActivityAt: latestActivityAt(item.lastEventAt, timeline),
      closedBy: history.closedBy,
      conclusion: history.conclusion,
      alertCount: this.alertsFor(item).length,
      linkedCases: this.linkedCasesFor(item),
      mergedInto: null,
    };
  }

  private linkedCasesFor(item: CaseSummary): LinkedCase[] {
    if (!LINKED_CASE_NUMBERS.includes(item.caseNumber)) {
      return [];
    }
    const otherNumber = LINKED_CASE_NUMBERS.find(
      (number) => number !== item.caseNumber,
    );
    if (otherNumber === undefined) {
      return [];
    }
    const other = this.cases.find(
      (candidate) => candidate.caseNumber === otherNumber,
    );
    if (other === undefined) {
      return [];
    }
    return [
      {
        id: other.id,
        caseNumber: other.caseNumber,
        title: other.title,
        status: other.status,
      },
    ];
  }

  private historyFor(item: CaseSummary): CaseHistory {
    const existing = this.histories.get(item.id);
    if (existing !== undefined) {
      return existing;
    }
    const closed = item.status === "CLOSED";
    const history: CaseHistory = {
      closedBy: closed ? (item.assignee ?? this.me) : null,
      conclusion: closed
        ? CONCLUSIONS[item.caseNumber % CONCLUSIONS.length]
        : null,
      alerts: null,
      timeline: null,
    };
    this.histories.set(item.id, history);
    return history;
  }

  private alertsFor(item: CaseSummary): AlertSummary[] {
    const history = this.historyFor(item);
    if (history.alerts === null) {
      history.alerts = this.generateAlerts(item);
    }
    return history.alerts;
  }

  private generateAlerts(item: CaseSummary): AlertSummary[] {
    const random = mulberry32(item.caseNumber * 100 + 1);
    const count = 1 + Math.floor(random() * 4);
    const first = Date.parse(item.firstEventAt);
    const last = Date.parse(item.lastEventAt);
    const span = Math.max(last - first, 1);
    const closed = item.status === "CLOSED";
    const alerts: AlertSummary[] = [];
    for (let index = 0; index < count; index += 1) {
      const start = first + Math.floor((span * (index + random())) / count);
      const end = Math.min(
        last,
        start + Math.floor(random() * (last - start + 1)),
      );
      const detection = pick(DETECTIONS, random);
      const evidenceCount = 1 + Math.floor(random() * 250);
      alerts.push({
        id: `alert_${item.caseNumber}_${index + 1}`,
        title: detection.title,
        severity: severityFor(random()),
        status: closed ? "CLOSED" : "OPEN",
        detectionId: detection.id,
        detectionVersion: "0.1.0",
        evidenceCount,
        occurrenceCount: 1 + Math.floor(random() * evidenceCount),
        firstEventAt: iso(start),
        lastEventAt: iso(end),
        outcome: closed ? item.outcome : null,
        closureReason: closed
          ? (item.closureReason as StoredClosureReason | null)
          : null,
      });
    }
    return alerts;
  }

  private historyTimeline(item: CaseSummary): TimelineEntry[] {
    const history = this.historyFor(item);
    if (history.timeline === null) {
      history.timeline = this.generateTimeline(item, this.alertsFor(item));
    }
    return history.timeline;
  }

  private timelineFor(item: CaseSummary): TimelineEntry[] {
    return [...this.historyTimeline(item)].sort(compareTimelineEntries);
  }

  private generateTimeline(
    item: CaseSummary,
    alerts: AlertSummary[],
  ): TimelineEntry[] {
    const random = mulberry32(item.caseNumber * 100 + 2);
    const count = 3 + Math.floor(random() * 28);
    const first = Date.parse(item.firstEventAt);
    const last = Date.parse(item.lastEventAt);
    const span = Math.max(last - first, 1);
    const entries: TimelineEntry[] = [];
    // The oldest evidence has left the dataset cache; case #7 keeps its
    // first event cached because the markup-value test reads it.
    const firstUncached = item.caseNumber === 7 ? 1 : 0;
    for (let index = 0; index < count; index += 1) {
      const at = first + Math.floor((span * (index + random())) / count);
      const alert = pick(alerts, random);
      const uncached = index === firstUncached || index === firstUncached + 1;
      const entry: TimelineEvidenceEntry = {
        id: `tl_${item.caseNumber}_evt_${index + 1}`,
        kind: "EVIDENCE",
        at: iso(at),
        alertId: alert.id,
        sourceId: `evt-${item.caseNumber}-${index + 1}`,
        udm: uncached ? null : buildUdm(item.caseNumber, index + 1, at),
      };
      entries.push(entry);
    }
    entries.push(...this.seedActivity(item, alerts));
    return entries;
  }

  private seedActivity(
    item: CaseSummary,
    alerts: AlertSummary[],
  ): TimelineActivityEntry[] {
    const entries: TimelineActivityEntry[] = [
      {
        id: `tl_${item.caseNumber}_created`,
        kind: "ACTIVITY",
        at: item.createdAt,
        actor: null,
        action: "CASE_CREATED",
        details: {},
      },
    ];
    alerts.forEach((alert, index) => {
      entries.push({
        id: `tl_${item.caseNumber}_alert_${index + 1}`,
        kind: "ACTIVITY",
        at: alert.firstEventAt,
        actor: null,
        action: "ALERT_ADDED",
        details: { alertId: alert.id },
      });
    });
    const createdAt = Date.parse(item.createdAt);
    if (item.assignee !== null) {
      entries.push({
        id: `tl_${item.caseNumber}_assigned`,
        kind: "ACTIVITY",
        at: iso(createdAt + 60_000),
        actor: this.me,
        action: "ASSIGNED",
        details: { assignee: item.assignee },
      });
    }
    if (item.status === "IN_PROGRESS") {
      entries.push({
        id: `tl_${item.caseNumber}_status`,
        kind: "ACTIVITY",
        at: iso(createdAt + 120_000),
        actor: this.me,
        action: "STATUS_CHANGED",
        details: { from: "OPEN", to: "IN_PROGRESS" },
      });
    }
    if (item.status === "CLOSED" && item.closedAt !== null) {
      entries.push({
        id: `tl_${item.caseNumber}_closed`,
        kind: "ACTIVITY",
        at: item.closedAt,
        actor: this.historyFor(item).closedBy,
        action: "CLOSED",
        details: {
          outcome: item.outcome,
          closureReason: item.closureReason,
        },
      });
    }
    return entries;
  }

  private appendAssignActivity(
    item: CaseSummary,
    assignee: CaseAssignee | null,
    previousStatus: CaseStatus,
  ): void {
    if (assignee === null) {
      this.appendActivity(item, {
        action: "UNASSIGNED",
        actor: this.me,
        details: {},
      });
    } else {
      this.appendActivity(item, {
        action: "ASSIGNED",
        actor: this.me,
        details: { assignee },
      });
    }
    if (previousStatus !== item.status) {
      this.appendActivity(item, {
        action: "STATUS_CHANGED",
        actor: this.me,
        details: { from: previousStatus, to: item.status },
      });
    }
  }

  private appendActivity(
    item: CaseSummary,
    entry: {
      action: string;
      actor: CaseAssignee | null;
      details: Record<string, unknown>;
    },
  ): void {
    const count = (this.activityIds.get(item.id) ?? 0) + 1;
    this.activityIds.set(item.id, count);
    this.historyTimeline(item).push({
      id: `tl_${item.caseNumber}_write_${String(count).padStart(2, "0")}`,
      kind: "ACTIVITY",
      at: this.now.toISOString(),
      actor: entry.actor,
      action: entry.action,
      details: entry.details,
    });
  }

  private applyClose(
    item: CaseSummary,
    outcome: CaseOutcome,
    closureReason: ClosureReason,
    conclusion: string,
    dispositions: AlertDisposition[],
  ): void {
    item.status = "CLOSED";
    item.outcome = outcome;
    item.closureReason = closureReason;
    item.closedAt = this.now.toISOString();
    item.version += 1;
    const history = this.historyFor(item);
    history.closedBy = this.me;
    history.conclusion = conclusion;
    for (const alert of this.alertsFor(item)) {
      const disposition = dispositions.find(
        (candidate) => candidate.alertId === alert.id,
      );
      alert.status = "CLOSED";
      alert.outcome = disposition?.outcome ?? outcome;
      alert.closureReason = disposition?.closureReason ?? closureReason;
    }
    this.appendActivity(item, {
      action: "CLOSED",
      actor: this.me,
      details: { outcome, closureReason },
    });
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
    const offset = parseCursor(searchParams.get("cursor"));
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

  private async detail(route: Route, caseRef: string): Promise<void> {
    const item = this.findCaseByRef(caseRef);
    if (item === undefined) {
      await this.notFound(route);
      return;
    }
    await this.respond(route, 200, this.detailFor(item));
  }

  private async alerts(
    route: Route,
    caseId: string,
    searchParams: URLSearchParams,
  ): Promise<void> {
    const item = this.findCaseById(caseId);
    if (item === undefined) {
      await this.notFound(route);
      return;
    }
    const response: CaseAlertsResponse = this.cursorPage(
      this.alertsFor(item),
      parseLimit(searchParams.get("limit")),
      parseCursor(searchParams.get("cursor")),
    );
    await this.respond(route, 200, response);
  }

  private async timeline(
    route: Route,
    caseId: string,
    searchParams: URLSearchParams,
  ): Promise<void> {
    const item = this.findCaseById(caseId);
    if (item === undefined) {
      await this.notFound(route);
      return;
    }
    const kind = searchParams.get("kind");
    if (kind !== null && kind !== "EVIDENCE" && kind !== "ACTIVITY") {
      throw new InvalidQueryError();
    }
    const entries = this.timelineFor(item).filter(
      (entry) => kind === null || entry.kind === kind,
    );
    const response: CaseTimelineResponse = this.cursorPage(
      entries,
      parseLimit(searchParams.get("limit")),
      parseCursor(searchParams.get("cursor")),
    );
    await this.respond(route, 200, response);
  }

  private async assign(route: Route, caseId: string): Promise<void> {
    const request = parseAssignRequest(this.readBody(route));
    const item = this.findCaseById(caseId);
    if (item === undefined) {
      await this.notFound(route);
      return;
    }

    let assignee: CaseAssignee | null;
    if (request.assigneeId === null) {
      assignee = null;
    } else {
      const resolved = this.resolveAssignee(request.assigneeId);
      if (resolved === undefined) {
        await this.respond(route, 400, VALIDATION_ERROR);
        return;
      }
      assignee = resolved;
    }

    if (request.version !== item.version) {
      await this.respondVersionConflict(route);
      return;
    }
    if (item.status === "CLOSED") {
      await this.respondStateConflict(route);
      return;
    }

    const previousStatus = item.status;
    item.assignee = assignee;
    if (assignee !== null && item.status === "OPEN") {
      item.status = "IN_PROGRESS";
    }
    item.version += 1;
    this.appendAssignActivity(item, assignee, previousStatus);
    await this.respond(route, 200, this.detailFor(item));
  }

  private async close(route: Route, caseId: string): Promise<void> {
    const failure = this.takeCloseFailure();
    if (failure !== null) {
      await this.respondCloseFailure(route, failure);
      return;
    }

    const request = parseCloseRequest(this.readBody(route));
    const item = this.findCaseById(caseId);
    if (item === undefined) {
      await this.notFound(route);
      return;
    }
    const alerts = this.alertsFor(item);
    const dispositions = request.alertDispositions ?? [];
    for (const disposition of dispositions) {
      if (!alerts.some((alert) => alert.id === disposition.alertId)) {
        throw new InvalidQueryError();
      }
    }

    if (request.version !== item.version) {
      await this.respondVersionConflict(route);
      return;
    }
    if (item.status === "CLOSED") {
      await this.respondStateConflict(route);
      return;
    }

    this.applyClose(
      item,
      request.outcome,
      request.closureReason,
      request.conclusion,
      dispositions,
    );
    await this.respond(route, 200, this.detailFor(item));
  }

  private async bulkClose(route: Route): Promise<void> {
    const failure = this.takeCloseFailure();
    if (failure !== null) {
      await this.respondCloseFailure(route, failure);
      return;
    }

    const request = parseBulkCloseRequest(this.readBody(route));
    const results: { caseId: string; status: BulkCloseStatus }[] = [];
    for (const requested of request.cases) {
      const item = this.findCaseById(requested.id);
      if (item === undefined) {
        results.push({ caseId: requested.id, status: "NOT_FOUND" });
        continue;
      }
      if (requested.version !== item.version) {
        results.push({ caseId: item.id, status: "VERSION_CONFLICT" });
        continue;
      }
      if (item.status === "CLOSED") {
        results.push({ caseId: item.id, status: "STATE_CONFLICT" });
        continue;
      }
      this.applyClose(
        item,
        request.outcome,
        request.closureReason,
        request.conclusion,
        [],
      );
      results.push({ caseId: item.id, status: "CLOSED" });
    }

    const response: BulkCloseResponse = { results };
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
          scoped.filter((item) => item.assignee?.id === this.me.id).length,
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
    if (scope === "mine" && item.assignee?.id !== this.me.id) {
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
