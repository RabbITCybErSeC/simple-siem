import { useCallback, useEffect, useRef, useState } from "react";
import type {
  KeyboardEvent as ReactKeyboardEvent,
  ReactNode,
} from "react";
import { Link } from "react-router";
import { ApiError } from "../../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { Input } from "../../../components/ui/input";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../../components/ui/table";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "../../../components/ui/tabs";
import type { TimeZoneSetting } from "../../shell/types";
import { setCaseCommands } from "../../shell/commands";
import {
  OUTCOME_LABELS,
  SEVERITY_STYLES,
  TimeCell,
  useMinuteNow,
} from "../CaseTable";
import { caseDetailPath, defaultCaseDetailState } from "../urlState";
import type {
  CaseDetailLayout,
  CaseDetailView,
  CaseOutcome,
  CaseQueueState,
  CaseStatus,
} from "../types";
import { absoluteLink, copyText } from "./clipboard";
import { CloseCaseDialog, closureReasonLabel } from "./CloseCaseDialog";
import { EventViewer } from "./EventViewer";
import {
  useAssignCase,
  useCaseAlerts,
  useCaseDetail,
  useCaseTimeline,
} from "./queries";
import type {
  AlertSummary,
  CaseDetail as CaseDetailData,
  TimelineActivityEntry,
  TimelineEntry,
  TimelineEvidenceEntry,
} from "./types";

export interface CaseDetailProps {
  caseNumber: number;
  view: CaseDetailView;
  layout: CaseDetailLayout;
  queueState: CaseQueueState;
  timeZone: TimeZoneSetting;
  /** A row's `e` asks for the close dialog once this detail has loaded. */
  closeRequested?: boolean;
  onCloseRequestHandled?: () => void;
  onViewChange: (view: CaseDetailView) => void;
  onLayoutChange: (layout: CaseDetailLayout) => void;
  onClose: () => void;
}

interface DetailFailure {
  message: string;
  retry: boolean;
}

export interface CaseActionFailure {
  message: string;
  reload: boolean;
}

export interface CaseActionAlertProps {
  failure: CaseActionFailure;
  onReload: () => void;
}

interface DescriptionProps {
  term: string;
  children: ReactNode;
}

type TimelineItem =
  | { kind: "evidence"; entries: TimelineEvidenceEntry[] }
  | { kind: "activity"; entry: TimelineActivityEntry };

const STATUS_LABELS: Record<CaseStatus, string> = {
  OPEN: "Open",
  IN_PROGRESS: "In progress",
  CLOSED: "Closed",
};

const COPY_STATUS_MILLISECONDS = 2_000;

export function describeAssignFailure(error: Error): CaseActionFailure {
  if (error instanceof ApiError) {
    if (error.status === 409 && error.code === "VERSION_CONFLICT") {
      return { message: "This case changed since you opened it.", reload: true };
    }
    if (error.status === 409 && error.code === "STATE_CONFLICT") {
      return { message: "This case is closed.", reload: false };
    }
    if (error.status === 403) {
      return {
        message: "You do not have permission to assign this case.",
        reload: false,
      };
    }
    if (error.status === 400) {
      return { message: "This user cannot be assigned.", reload: false };
    }
    if (error.code === "NETWORK_ERROR") {
      return {
        message: "Cannot reach Simple SIEM. Try again.",
        reload: false,
      };
    }
  }
  return { message: "Something went wrong. Try again.", reload: false };
}

export function CaseActionAlert({ failure, onReload }: CaseActionAlertProps) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-foreground"
    >
      <p>{failure.message}</p>
      {failure.reload ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={onReload}
        >
          Reload case
        </Button>
      ) : null}
    </div>
  );
}

export function CaseDetail({
  caseNumber,
  view,
  layout,
  queueState,
  timeZone,
  closeRequested = false,
  onCloseRequestHandled,
  onViewChange,
  onLayoutChange,
  onClose,
}: CaseDetailProps) {
  const detailQuery = useCaseDetail(caseNumber);
  const detail = detailQuery.data;
  const { data: me } = useCurrentUser();
  const {
    mutate: assignCaseMutation,
    isPending: assignPending,
  } = useAssignCase();
  const [assignFailed, setAssignFailed] = useState<CaseActionFailure | null>(
    null,
  );
  const [closeOpen, setCloseOpen] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const fallbackInputRef = useRef<HTMLInputElement>(null);
  const copyTimer = useRef<number | undefined>(undefined);
  const [announcement, setAnnouncement] = useState<string | null>(null);
  const [fallbackLink, setFallbackLink] = useState<string | null>(null);

  const announce = useCallback((message: string) => {
    setAnnouncement(message);
    window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(
      () => setAnnouncement(null),
      COPY_STATUS_MILLISECONDS,
    );
  }, []);

  useEffect(() => {
    headingRef.current?.focus();
  }, [caseNumber]);

  useEffect(() => {
    return () => window.clearTimeout(copyTimer.current);
  }, []);

  useEffect(() => {
    if (fallbackLink !== null) {
      fallbackInputRef.current?.focus();
      fallbackInputRef.current?.select();
    }
  }, [fallbackLink]);

  const copyLink = useCallback(async () => {
    const link = absoluteLink(window.location, new Date());
    const copied = await copyText(link);
    if (!copied) {
      setFallbackLink(link);
      setAnnouncement(null);
      return;
    }

    setFallbackLink(null);
    announce("Link copied");
  }, [announce]);

  const closeCase = useCallback(
    (closed: CaseDetailData) => {
      setCloseOpen(false);
      onCloseRequestHandled?.();
      headingRef.current?.focus();
      announce(`Case #${closed.caseNumber} closed`);
    },
    [announce, onCloseRequestHandled],
  );

  const changeCloseOpen = (open: boolean) => {
    if (!open && closeRequested) {
      onCloseRequestHandled?.();
    }
    setCloseOpen(open);
  };

  const closeDialogOpen =
    closeOpen ||
    (closeRequested && detail !== undefined && detail.status !== "CLOSED");

  const assignCase = useCallback(() => {
    if (detail === undefined || me === undefined) {
      return;
    }
    setAssignFailed(null);
    assignCaseMutation(
      {
        caseId: detail.id,
        caseNumber,
        request: {
          assigneeId: detail.assignee?.id === me.id ? null : me.id,
          version: detail.version,
        },
      },
      { onError: (error) => setAssignFailed(describeAssignFailure(error)) },
    );
  }, [assignCaseMutation, caseNumber, detail, me]);

  // The palette runs the same actions as the pane, so the detail stays the
  // single owner of assign, close, copy link, and the layout toggle.
  useEffect(() => {
    if (detail === undefined) {
      return;
    }
    setCaseCommands({
      caseNumber: detail.caseNumber,
      assignLabel:
        detail.assignee?.id === me?.id ? "Unassign" : "Assign to me",
      assign: assignCase,
      canClose: detail.status !== "CLOSED",
      close: () => setCloseOpen(true),
      copyLink: () => void copyLink(),
      closeDetail: onClose,
      toggleFullPage: () =>
        onLayoutChange(layout === "full" ? "split" : "full"),
    });
    return () => setCaseCommands(undefined);
  }, [
    assignCase,
    copyLink,
    detail,
    layout,
    me,
    onClose,
    onLayoutChange,
  ]);

  function handleKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Escape" || overlayOpen()) {
      return;
    }
    event.preventDefault();
    onClose();
  }

  const loadFailure =
    detailQuery.isError && detailQuery.error !== null
      ? describeDetailFailure(detailQuery.error, caseNumber)
      : null;

  return (
    <section
      aria-label={`Case #${caseNumber}`}
      onKeyDown={handleKeyDown}
      className="min-w-0"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2
            ref={headingRef}
            tabIndex={-1}
            className="text-xl font-semibold tracking-tight outline-none"
          >
            #{caseNumber}
            {detail === undefined ? "" : ` ${detail.title}`}
          </h2>
          {detail === undefined ? null : (
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <Badge className={SEVERITY_STYLES[detail.severity].className}>
                {SEVERITY_STYLES[detail.severity].label}
              </Badge>
              <span>{STATUS_LABELS[detail.status]}</span>
              <span aria-hidden="true">·</span>
              <span>{detail.assignee?.displayName ?? "Unassigned"}</span>
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {detail === undefined || detail.status === "CLOSED" ? null : (
            <Button
              type="button"
              size="sm"
              disabled={assignPending || me === undefined}
              onClick={assignCase}
            >
              {detail.assignee?.id === me?.id ? "Unassign" : "Assign to me"}
            </Button>
          )}
          {detail === undefined || detail.status === "CLOSED" ? null : (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setCloseOpen(true)}
            >
              Close case
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void copyLink()}
          >
            Copy link
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            aria-label="Toggle full page"
            aria-pressed={layout === "full"}
            onClick={() =>
              onLayoutChange(layout === "full" ? "split" : "full")
            }
          >
            ⤢
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            aria-label="Close case detail"
            onClick={onClose}
          >
            ×
          </Button>
        </div>
      </div>

      <p role="status" className="sr-only">
        {announcement}
      </p>
      {assignFailed === null ? null : (
        <div className="mt-3">
          <CaseActionAlert
            failure={assignFailed}
            onReload={() => {
              setAssignFailed(null);
              void detailQuery.refetch();
            }}
          />
        </div>
      )}
      {fallbackLink === null ? null : (
        <div className="mt-3">
          <label htmlFor="case-link" className="text-xs text-muted-foreground">
            Case link
          </label>
          <Input
            id="case-link"
            ref={fallbackInputRef}
            readOnly
            value={fallbackLink}
            className="mt-1 font-mono text-xs"
            onFocus={(event) => event.currentTarget.select()}
          />
        </div>
      )}

      {loadFailure === null ? null : (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-foreground"
        >
          <p>{loadFailure.message}</p>
          {loadFailure.retry ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => void detailQuery.refetch()}
            >
              Retry
            </Button>
          ) : null}
        </div>
      )}

      {detail === undefined ? (
        loadFailure === null ? (
          <p aria-busy="true" className="mt-4 text-sm text-muted-foreground">
            Loading case…
          </p>
        ) : null
      ) : (
        <Tabs
          value={view}
          onValueChange={(value) => onViewChange(value as CaseDetailView)}
          className="mt-4"
        >
          <TabsList aria-label="Case sections">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="alerts">
              {`Alerts ${detail.alertCount}`}
            </TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>
          <TabsContent value="overview">
            <Overview
              detail={detail}
              queueState={queueState}
              timeZone={timeZone}
            />
          </TabsContent>
          <TabsContent value="alerts">
            <AlertsSection caseId={detail.id} timeZone={timeZone} />
          </TabsContent>
          <TabsContent value="timeline">
            <TimelineSection caseId={detail.id} timeZone={timeZone} />
          </TabsContent>
          <TabsContent value="activity">
            <TimelineSection
              caseId={detail.id}
              kind="ACTIVITY"
              timeZone={timeZone}
            />
          </TabsContent>
        </Tabs>
      )}

      {detail === undefined ? null : (
        <CloseCaseDialog
          detail={detail}
          open={closeDialogOpen}
          onOpenChange={changeCloseOpen}
          onReload={() => void detailQuery.refetch()}
          onClosed={closeCase}
        />
      )}
    </section>
  );
}

interface OverviewProps {
  detail: CaseDetailData;
  queueState: CaseQueueState;
  timeZone: TimeZoneSetting;
}

function Overview({ detail, queueState, timeZone }: OverviewProps) {
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

function AlertsSection({ caseId, timeZone }: AlertsSectionProps) {
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

function TimelineSection({ caseId, kind, timeZone }: TimelineSectionProps) {
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

function SectionError({ message, onRetry }: SectionErrorProps) {
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

function describeDetailFailure(
  error: Error,
  caseNumber: number,
): DetailFailure {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return {
        message: `Case #${caseNumber} was not found.`,
        retry: false,
      };
    }
    if (error.status === 403) {
      return {
        message: "You do not have permission to view this case.",
        retry: false,
      };
    }
    if (error.code === "NETWORK_ERROR") {
      return { message: "Cannot reach Simple SIEM. Try again.", retry: true };
    }
  }
  return { message: "Something went wrong. Try again.", retry: true };
}

function overlayOpen(): boolean {
  return (
    document.querySelector(
      '[role="dialog"], [data-radix-popper-content-wrapper]',
    ) !== null
  );
}
