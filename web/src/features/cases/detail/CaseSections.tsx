import type { ReactNode } from "react";
import { Link } from "react-router";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../../components/ui/table";
import type { TimeZoneSetting } from "../../shell/types";
import {
  OUTCOME_LABELS,
  SEVERITY_STYLES,
  TimeCell,
  useMinuteNow,
} from "../CaseTable";
import { caseDetailPath, defaultCaseDetailState } from "../urlState";
import type {
  CaseOutcome,
  CaseQueueState,
  CaseStatus,
} from "../types";
import { closureReasonLabel } from "./CloseCaseDialog";
import { copyText } from "./clipboard";
import { EventViewer } from "./EventViewer";
import { useCaseAlerts, useCaseTimeline } from "./queries";
import type {
  AlertSummary,
  CaseDetail as CaseDetailData,
  TimelineActivityEntry,
  TimelineEntry,
  TimelineEvidenceEntry,
} from "./types";

interface OverviewProps {
  detail: CaseDetailData;
  queueState: CaseQueueState;
  timeZone: TimeZoneSetting;
}

export const STATUS_LABELS: Record<CaseStatus, string> = {
  OPEN: "Open",
  IN_PROGRESS: "In progress",
  CLOSED: "Closed",
};

interface DescriptionProps {
  term: string;
  children: ReactNode;
}

type TimelineItem =
  | { kind: "evidence"; entries: TimelineEvidenceEntry[] }
  | { kind: "activity"; entry: TimelineActivityEntry };

export function Overview({ detail, queueState, timeZone }: OverviewProps) {
  const now = useMinuteNow();

  return (
    <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm">
      <Description term="Status">{STATUS_LABELS[detail.status]}</Description>
      <Description term="Severity">
        {SEVERITY_STYLES[detail.severity].label}
      </Description>
      <Description term="Assignee">
        {detail.assignee?.displayName ?? "Unassigned"}
      </Description>
      <Description term="Created">
        <TimeCell value={detail.createdAt} timeZone={timeZone} now={now} />
      </Description>
      <Description term="First event">
        <TimeCell value={detail.firstEventAt} timeZone={timeZone} now={now} />
      </Description>
      <Description term="Last event">
        <TimeCell value={detail.lastEventAt} timeZone={timeZone} now={now} />
      </Description>
      {detail.closedAt === null ? null : (
        <Description term="Closed">
          <TimeCell value={detail.closedAt} timeZone={timeZone} now={now} />
        </Description>
      )}
      {detail.closedBy === null ? null : (
        <Description term="Closed by">
          {detail.closedBy.displayName}
        </Description>
      )}
      {detail.outcome === null ? null : (
        <Description term="Outcome">
          {OUTCOME_LABELS[detail.outcome]}
        </Description>
      )}
      {detail.closureReason === null ? null : (
        <Description term="Closure reason">
          {closureReasonLabel(detail.closureReason)}
        </Description>
      )}
      {detail.conclusion === null ? null : (
        <Description term="Conclusion">
          <p className="whitespace-pre-wrap">{detail.conclusion}</p>
        </Description>
      )}
      {detail.linkedCases.length === 0 ? null : (
        <Description term="Linked cases">
          <div className="flex flex-col gap-1">
            {detail.linkedCases.map((linked) => (
              <Link
                key={linked.id}
                to={caseDetailPath(
                  linked.caseNumber,
                  queueState,
                  defaultCaseDetailState,
                )}
                className="text-primary underline-offset-4 hover:underline"
              >
                {`#${linked.caseNumber} ${linked.title}`}
              </Link>
            ))}
          </div>
        </Description>
      )}
    </dl>
  );
}

function Description({ term, children }: DescriptionProps) {
  return (
    <>
      <dt className="text-muted-foreground">{term}</dt>
      <dd>{children}</dd>
    </>
  );
}

interface AlertsSectionProps {
  caseId: string;
  timeZone: TimeZoneSetting;
}

export function AlertsSection({ caseId, timeZone }: AlertsSectionProps) {
  const alertQuery = useCaseAlerts(caseId);
  const now = useMinuteNow();
  const alerts = alertQuery.data?.pages.flatMap((page) => page.data) ?? [];

  if (alertQuery.isPending) {
    return (
      <p aria-busy="true" className="text-sm text-muted-foreground">
        Loading alerts…
      </p>
    );
  }
  if (alertQuery.isError) {
    return (
      <SectionError
        message="Could not load the case alerts."
        onRetry={() => void alertQuery.refetch()}
      />
    );
  }
  if (alerts.length === 0) {
    return <p className="text-sm text-muted-foreground">No alerts.</p>;
  }

  return (
    <div>
      <Table aria-busy={alertQuery.isFetchingNextPage}>
        <TableCaption>Alerts</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Title</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Detection</TableHead>
            <TableHead>Evidence</TableHead>
            <TableHead>Occurrences</TableHead>
            <TableHead>First event</TableHead>
            <TableHead>Last event</TableHead>
            <TableHead>Disposition</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {alerts.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              timeZone={timeZone}
              now={now}
            />
          ))}
        </TableBody>
      </Table>
      {alertQuery.hasNextPage ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3"
          disabled={alertQuery.isFetchingNextPage}
          onClick={() => void alertQuery.fetchNextPage()}
        >
          Load more
        </Button>
      ) : null}
    </div>
  );
}

interface AlertRowProps {
  alert: AlertSummary;
  timeZone: TimeZoneSetting;
  now: Date;
}

function AlertRow({ alert, timeZone, now }: AlertRowProps) {
  const severity = SEVERITY_STYLES[alert.severity];

  return (
    <TableRow>
      <TableCell className="font-medium">{alert.title}</TableCell>
      <TableCell>
        <Badge className={severity.className}>{severity.label}</Badge>
      </TableCell>
      <TableCell>
        <span className="font-mono">{alert.detectionId}</span>{" "}
        <span className="text-muted-foreground">{alert.detectionVersion}</span>
      </TableCell>
      <TableCell>{alert.evidenceCount}</TableCell>
      <TableCell>{alert.occurrenceCount}</TableCell>
      <TableCell>
        <TimeCell value={alert.firstEventAt} timeZone={timeZone} now={now} />
      </TableCell>
      <TableCell>
        <TimeCell value={alert.lastEventAt} timeZone={timeZone} now={now} />
      </TableCell>
      <TableCell>{alertDisposition(alert)}</TableCell>
    </TableRow>
  );
}

interface TimelineSectionProps {
  caseId: string;
  kind?: "ACTIVITY";
  timeZone: TimeZoneSetting;
}

export function TimelineSection({
  caseId,
  kind,
  timeZone,
}: TimelineSectionProps) {
  const timelineQuery = useCaseTimeline(caseId, kind);
  const now = useMinuteNow();
  const entries = ascending(
    timelineQuery.data?.pages.flatMap((page) => page.data) ?? [],
  );
  const items = timelineItems(entries);
  const activityOnly = kind === "ACTIVITY";

  if (timelineQuery.isPending) {
    return (
      <p aria-busy="true" className="text-sm text-muted-foreground">
        {activityOnly ? "Loading activity…" : "Loading timeline…"}
      </p>
    );
  }
  if (timelineQuery.isError) {
    return (
      <SectionError
        message={
          activityOnly
            ? "Could not load the case activity."
            : "Could not load the case timeline."
        }
        onRetry={() => void timelineQuery.refetch()}
      />
    );
  }
  if (entries.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {activityOnly ? "No activity." : "No timeline entries."}
      </p>
    );
  }

  return (
    <div>
      <ol
        aria-label={activityOnly ? "Activity" : "Timeline"}
        className="flex flex-col gap-3"
      >
        {items.map((item) =>
          item.kind === "evidence" ? (
            <li key={item.entries[0].id}>
              <EventViewer
                entries={item.entries}
                timeZone={timeZone}
                now={now}
                onCopy={copyText}
              />
            </li>
          ) : (
            <ActivityItem
              key={item.entry.id}
              entry={item.entry}
              timeZone={timeZone}
              now={now}
            />
          ),
        )}
      </ol>
      {timelineQuery.hasNextPage ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3"
          disabled={timelineQuery.isFetchingNextPage}
          onClick={() => void timelineQuery.fetchNextPage()}
        >
          Load more
        </Button>
      ) : null}
    </div>
  );
}

interface ActivityItemProps {
  entry: TimelineActivityEntry;
  timeZone: TimeZoneSetting;
  now: Date;
}

function ActivityItem({ entry, timeZone, now }: ActivityItemProps) {
  return (
    <li className="flex items-baseline gap-3 text-sm">
      <TimeCell value={entry.at} timeZone={timeZone} now={now} />
      <span>{activitySentence(entry)}</span>
    </li>
  );
}

interface SectionErrorProps {
  message: string;
  onRetry: () => void;
}

export function SectionError({ message, onRetry }: SectionErrorProps) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-foreground"
    >
      <p>{message}</p>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="mt-3"
        onClick={onRetry}
      >
        Retry
      </Button>
    </div>
  );
}

function alertDisposition(alert: AlertSummary): string {
  const outcome =
    alert.outcome === null ? undefined : OUTCOME_LABELS[alert.outcome];
  const reason =
    alert.closureReason === null
      ? undefined
      : closureReasonLabel(alert.closureReason);
  const words = [outcome, reason].filter((word) => word !== undefined);
  return words.length === 0 ? "—" : words.join(", ");
}

function ascending(entries: TimelineEntry[]): TimelineEntry[] {
  return [...entries].sort((left, right) => {
    const difference = Date.parse(left.at) - Date.parse(right.at);
    return difference !== 0 ? difference : left.id.localeCompare(right.id);
  });
}

function timelineItems(entries: TimelineEntry[]): TimelineItem[] {
  const items: TimelineItem[] = [];
  for (const entry of entries) {
    if (entry.kind === "EVIDENCE") {
      const last = items[items.length - 1];
      if (last?.kind === "evidence") {
        last.entries.push(entry);
      } else {
        items.push({ kind: "evidence", entries: [entry] });
      }
    } else {
      items.push({ kind: "activity", entry });
    }
  }
  return items;
}

function activitySentence(entry: TimelineActivityEntry): string {
  const actor = entry.actor?.displayName ?? "System";

  switch (entry.action) {
    case "CASE_CREATED":
      return "Case created";
    case "ALERT_ADDED":
      return "Alert added";
    case "ASSIGNED": {
      const assignee = nameOf(entry.details.assignee) ?? "Unassigned";
      return `${actor} assigned the case to ${assignee}`;
    }
    case "UNASSIGNED":
      return `${actor} unassigned the case`;
    case "STATUS_CHANGED":
      return `Status changed from ${statusLabel(entry.details.from)} to ${statusLabel(entry.details.to)}`;
    case "CLOSED":
      return `Closed as ${outcomeLabel(entry.details.outcome)}: ${closureReasonLabel(entry.details.closureReason)}`;
    case "RECURRENCE_LINKED": {
      const recurrenceNumber = entry.details.caseNumber;
      return `Linked to recurrence #${
        typeof recurrenceNumber === "number" ? recurrenceNumber : "?"
      }`;
    }
    default:
      return `Activity: ${entry.action}`;
  }
}

function nameOf(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const name = (value as { displayName?: unknown }).displayName;
  return typeof name === "string" ? name : undefined;
}

function statusLabel(value: unknown): string {
  if (typeof value === "string" && value in STATUS_LABELS) {
    return STATUS_LABELS[value as CaseStatus];
  }
  return typeof value === "string" ? value : "unknown";
}

function outcomeLabel(value: unknown): string {
  if (typeof value === "string" && value in OUTCOME_LABELS) {
    return OUTCOME_LABELS[value as CaseOutcome];
  }
  return typeof value === "string" ? value : "unknown";
}
