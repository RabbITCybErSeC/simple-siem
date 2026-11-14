import type { CursorListResponse } from "../../api/types.ts";

export type CaseStatus = "OPEN" | "IN_PROGRESS" | "CLOSED";
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
  scope: Record<"mine" | "unassigned" | "all", number>;
  cap: number;
}

export interface CaseHistogram {
  interval: string;
  buckets: {
    start: string;
    counts: Record<CaseSeverity, number>;
  }[];
}
