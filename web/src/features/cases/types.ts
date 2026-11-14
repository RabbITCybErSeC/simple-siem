import type { CursorListResponse } from "../../api/types.ts";

export type CaseStatus = "OPEN" | "IN_PROGRESS" | "CLOSED";
export type CaseTab = "open" | "in_progress" | "closed" | "all";
export type CaseScope = "mine" | "unassigned" | "all";
export type TimeField =
  | "lastEventAt"
  | "firstEventAt"
  | "createdAt"
  | "closedAt";
export type CaseSort = "lastEventAt:desc" | "createdAt:asc";
export type RefreshInterval = "off" | "10s" | "30s" | "1m" | "5m";

export interface TimeRange {
  from: string;
  to: string;
}

export interface CaseQueueState {
  tab: CaseTab;
  scope: CaseScope;
  range: TimeRange;
  field: TimeField;
  sort: CaseSort;
  refresh: RefreshInterval;
}

export type CaseSeverity = "HIGH" | "MEDIUM" | "LOW";
export type CaseOutcome = "MALICIOUS" | "ACCEPTED";

export interface CaseAssignee {
  id: string;
  displayName: string;
}

export interface CaseSummary {
  id: string;
  caseNumber: number;
  title: string;
  status: CaseStatus;
  severity: CaseSeverity;
  outcome: CaseOutcome | null;
  closureReason: string | null;
  assignee: CaseAssignee | null;
  firstEventAt: string;
  lastEventAt: string;
  createdAt: string;
  closedAt: string | null;
  version: number;
}

export type CaseListResponse = CursorListResponse<CaseSummary>;

export interface CaseCounts {
  status: Record<CaseStatus | "ALL", number>;
  scope: Record<CaseScope, number>;
  cap: number;
}

export interface CaseHistogram {
  interval: string;
  buckets: {
    start: string;
    counts: Record<CaseSeverity, number>;
  }[];
}
