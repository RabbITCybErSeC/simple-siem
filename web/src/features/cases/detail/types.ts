import type { CursorListResponse } from "../../../api/types.ts";
import type {
  CaseAssignee,
  CaseOutcome,
  CaseSeverity,
  CaseStatus,
  CaseSummary,
} from "../types.ts";

export type ClosureReason =
  | "FALSE_POSITIVE"
  | "BENIGN_TRUE_POSITIVE"
  | "AUTHORIZED_ACTIVITY"
  | "DUPLICATE"
  | "INSUFFICIENT_EVIDENCE"
  | "CONFIRMED_THREAT"
  | "OTHER";

/** `MERGED` is stored on an old case but never accepted from a client. */
export type StoredClosureReason = ClosureReason | "MERGED";

export interface LinkedCase {
  id: string;
  caseNumber: number;
  title: string;
  status: CaseStatus;
}

export interface CaseDetail extends CaseSummary {
  lastActivityAt: string;
  closedBy: CaseAssignee | null;
  conclusion: string | null;
  alertCount: number;
  linkedCases: LinkedCase[];
  mergedInto: { id: string; caseNumber: number } | null;
}

export type AlertStatus = "OPEN" | "SUPPRESSED" | "CLOSED";

export interface AlertSummary {
  id: string;
  title: string;
  severity: CaseSeverity;
  status: AlertStatus;
  detectionId: string;
  detectionVersion: string;
  evidenceCount: number;
  occurrenceCount: number;
  firstEventAt: string;
  lastEventAt: string;
  outcome: CaseOutcome | null;
  closureReason: StoredClosureReason | null;
}

export type CaseAlertsResponse = CursorListResponse<AlertSummary>;

export type ActivityAction =
  | "CASE_CREATED"
  | "ALERT_ADDED"
  | "ASSIGNED"
  | "UNASSIGNED"
  | "STATUS_CHANGED"
  | "CLOSED"
  | "RECURRENCE_LINKED";

export interface TimelineEvidenceEntry {
  id: string;
  kind: "EVIDENCE";
  at: string;
  alertId: string;
  sourceId: string;
  /** Null when the event has left the dataset cache. */
  udm: Record<string, unknown> | null;
}

export interface TimelineActivityEntry {
  id: string;
  kind: "ACTIVITY";
  at: string;
  actor: CaseAssignee | null;
  /** A string, so an action this console does not know still parses. */
  action: string;
  details: Record<string, unknown>;
}

export type TimelineEntry = TimelineEvidenceEntry | TimelineActivityEntry;

export type CaseTimelineResponse = CursorListResponse<TimelineEntry>;

export interface AssignRequest {
  assigneeId: string | null;
  version: number;
}

export interface AlertDisposition {
  alertId: string;
  outcome: CaseOutcome;
  closureReason: ClosureReason;
}

export interface CloseRequest {
  outcome: CaseOutcome;
  closureReason: ClosureReason;
  conclusion: string;
  alertDispositions?: AlertDisposition[];
  version: number;
}

export interface BulkCloseRequest {
  cases: { id: string; version: number }[];
  outcome: CaseOutcome;
  closureReason: ClosureReason;
  conclusion: string;
}

export type BulkCloseStatus =
  | "CLOSED"
  | "VERSION_CONFLICT"
  | "STATE_CONFLICT"
  | "NOT_FOUND"
  | "FORBIDDEN";

export interface BulkCloseResponse {
  results: { caseId: string; status: BulkCloseStatus }[];
}
