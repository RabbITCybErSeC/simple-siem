import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { ApiError } from "../../api/client";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import type { TimeZoneSetting } from "../shell/types";
import { formatExact, relativeTime } from "./timeRange";
import type {
  CaseOutcome,
  CaseScope,
  CaseSeverity,
  CaseSummary,
  CaseTab,
} from "./types";

export interface CaseTableProps {
  cases: CaseSummary[];
  tab: CaseTab;
  scope: CaseScope;
  timeZone: TimeZoneSetting;
  loading: boolean;
  error: Error | null;
  onRetry: () => void;
  onOpen?: (item: CaseSummary) => void;
  onAssign?: (item: CaseSummary) => void;
}

export interface CaseTableHandle {
  /** Focus a row by case id; used when the detail closes back to the list. */
  focusCase: (caseId: string) => void;
}

export interface SeverityStyle {
  label: string;
  className: string;
}

export const SEVERITY_STYLES: Record<CaseSeverity, SeverityStyle> = {
  HIGH: {
    label: "HIGH",
    className: "bg-severity-high text-severity-high-foreground",
  },
  MEDIUM: {
    label: "MEDIUM",
    className: "bg-severity-medium text-severity-medium-foreground",
  },
  LOW: {
    label: "LOW",
    className: "bg-severity-low text-severity-low-foreground",
  },
};

export const OUTCOME_LABELS: Record<CaseOutcome, string> = {
  MALICIOUS: "Malicious",
  ACCEPTED: "Accepted",
};

const TAB_LABELS: Record<CaseTab, string> = {
  open: "Open",
  in_progress: "In progress",
  closed: "Closed",
  all: "All",
};

const SCOPE_LABELS: Record<CaseScope, string> = {
  mine: "Mine",
  unassigned: "Unassigned",
  all: "All",
};

const SKELETON_ROWS = 5;
const MINUTE_MILLISECONDS = 60_000;

export const CaseTable = forwardRef<CaseTableHandle, CaseTableProps>(
  function CaseTable(
    {
      cases,
      tab,
      scope,
      timeZone,
      loading,
      error,
      onRetry,
      onOpen,
      onAssign,
    },
    ref,
  ) {
    const now = useMinuteNow();
    const containerRef = useRef<HTMLDivElement>(null);
    const [activeId, setActiveId] = useState<string | undefined>(undefined);
    const activeIndex = cases.findIndex((item) => item.id === activeId);
    // A filter or Show can remove the active row; the first row then takes over.
    const currentIndex = activeIndex === -1 ? 0 : activeIndex;

    const focusRow = useCallback(
      (index: number) => {
        const target = cases[index];
        if (target === undefined) {
          return;
        }
        setActiveId(target.id);
        containerRef.current
          ?.querySelector<HTMLElement>(`[data-case-id="${target.id}"]`)
          ?.focus();
      },
      [cases],
    );

    useImperativeHandle(
      ref,
      () => ({
        focusCase(caseId: string) {
          const index = cases.findIndex((item) => item.id === caseId);
          if (index >= 0) {
            focusRow(index);
          }
        },
      }),
      [cases, focusRow],
    );

    function handleRowKeyDown(
      event: ReactKeyboardEvent<HTMLTableSectionElement>,
    ) {
      if (cases.length === 0 || isTextEntryTarget(event.target)) {
        return;
      }

      const target = cases[currentIndex];
      let nextIndex: number;
      switch (event.key) {
        case "j":
        case "ArrowDown":
          nextIndex = Math.min(currentIndex + 1, cases.length - 1);
          break;
        case "k":
        case "ArrowUp":
          nextIndex = Math.max(currentIndex - 1, 0);
          break;
        case "Home":
          nextIndex = 0;
          break;
        case "End":
          nextIndex = cases.length - 1;
          break;
        case "Enter":
          if (
            !(event.target instanceof HTMLTableRowElement) ||
            target === undefined ||
            onOpen === undefined
          ) {
            return;
          }
          event.preventDefault();
          onOpen(target);
          return;
        case "a":
          if (target === undefined) {
            return;
          }
          event.preventDefault();
          onAssign?.(target);
          return;
        default:
          return;
      }

      event.preventDefault();
      focusRow(nextIndex);
    }

    if (error !== null) {
      return (
        <div
          role="alert"
          className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-foreground"
        >
          <p>{caseErrorMessage(error)}</p>
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

    return (
      <div ref={containerRef}>
        <Table aria-busy={loading}>
          <TableCaption>{caption(tab, scope)}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Number</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Assignee</TableHead>
              <TableHead>Last event</TableHead>
              <TableHead>Age</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody onKeyDown={handleRowKeyDown}>
            {loading ? (
              <SkeletonRows />
            ) : cases.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-muted-foreground">
                  {emptyMessage(tab, scope)}
                </TableCell>
              </TableRow>
            ) : (
              cases.map((item, index) => (
                <CaseRow
                  key={item.id}
                  item={item}
                  timeZone={timeZone}
                  now={now}
                  active={index === currentIndex}
                  onFocus={() => setActiveId(item.id)}
                  onOpen={onOpen}
                />
              ))
            )}
          </TableBody>
        </Table>
      </div>
    );
  },
);

interface CaseRowProps {
  item: CaseSummary;
  timeZone: TimeZoneSetting;
  now: Date;
  active: boolean;
  onFocus: () => void;
  onOpen: ((item: CaseSummary) => void) | undefined;
}

function CaseRow({
  item,
  timeZone,
  now,
  active,
  onFocus,
  onOpen,
}: CaseRowProps) {
  const severity = SEVERITY_STYLES[item.severity];

  return (
    <TableRow
      data-case-id={item.id}
      tabIndex={active ? 0 : -1}
      onFocus={onFocus}
    >
      <TableCell className="font-mono">#{item.caseNumber}</TableCell>
      <TableCell
        className={
          onOpen === undefined
            ? "font-medium"
            : "cursor-pointer font-medium underline-offset-4 hover:underline"
        }
        onClick={onOpen === undefined ? undefined : () => onOpen(item)}
      >
        {item.title}
      </TableCell>
      <TableCell>
        <Badge className={severity.className}>{severity.label}</Badge>
      </TableCell>
      <TableCell>{item.assignee?.displayName ?? "Unassigned"}</TableCell>
      <TableCell>
        <TimeCell value={item.lastEventAt} timeZone={timeZone} now={now} />
      </TableCell>
      <TableCell>
        {item.status === "CLOSED" ? (
          outcomeLabel(item.outcome)
        ) : (
          <TimeCell value={item.createdAt} timeZone={timeZone} now={now} />
        )}
      </TableCell>
    </TableRow>
  );
}

interface TimeCellProps {
  value: string;
  timeZone: TimeZoneSetting;
  now: Date;
}

export function TimeCell({ value, timeZone, now }: TimeCellProps) {
  const exact = formatExact(value, timeZone, "timestamp");

  return (
    <time dateTime={value} title={exact}>
      {relativeTime(value, now)}
      <span className="sr-only">{` ${exact}`}</span>
    </time>
  );
}

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: SKELETON_ROWS }, (_, index) => (
        <TableRow key={index}>
          {Array.from({ length: 6 }, (_cell, cellIndex) => (
            <TableCell key={cellIndex}>
              <div className="h-4 w-full animate-pulse rounded bg-muted" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}

function caption(tab: CaseTab, scope: CaseScope): string {
  return `Cases: ${TAB_LABELS[tab]}, ${SCOPE_LABELS[scope]}`;
}

function emptyMessage(tab: CaseTab, scope: CaseScope): string {
  const tabLabel = TAB_LABELS[tab].toLowerCase();

  if (tab === "closed" || tab === "all") {
    switch (scope) {
      case "mine":
        return `No ${tabLabel} cases assigned to you in this range.`;
      case "unassigned":
        return `No unassigned ${tabLabel} cases in this range.`;
      case "all":
        return `No ${tabLabel} cases in this range.`;
    }
  }

  switch (scope) {
    case "mine":
      return `No ${tabLabel} cases assigned to you.`;
    case "unassigned":
      return `No ${tabLabel} unassigned cases.`;
    case "all":
      return `No ${tabLabel} cases.`;
  }
}

function outcomeLabel(outcome: CaseOutcome | null): string {
  return outcome === null ? "—" : OUTCOME_LABELS[outcome];
}

export function isTextEntryTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  const tagName = target.tagName.toLowerCase();
  return (
    tagName === "input" ||
    tagName === "textarea" ||
    tagName === "select" ||
    target.isContentEditable
  );
}

function caseErrorMessage(error: Error): string {
  if (error instanceof ApiError) {
    if (error.code === "NETWORK_ERROR") {
      return "Cannot reach Simple SIEM. Try again.";
    }
    if (error.status === 403) {
      return "You do not have permission to view this queue.";
    }
    if (error.status === 404) {
      return "The case queue is not available.";
    }
    if (error.code === "VALIDATION_ERROR") {
      return "The queue could not be loaded with these filters.";
    }
    if (error.status >= 500) {
      return "The case queue is unavailable. Try again.";
    }
  }
  return "Something went wrong. Try again.";
}

/** Relative labels tick once a minute while the list stays open. */
export function useMinuteNow(): Date {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(
      () => setNow(new Date()),
      MINUTE_MILLISECONDS,
    );
    return () => window.clearInterval(timer);
  }, []);

  return now;
}
