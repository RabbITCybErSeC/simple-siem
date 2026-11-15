import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import type {
  KeyboardEvent as ReactKeyboardEvent,
  ReactNode,
} from "react";
import { InboxIcon, TriangleAlertIcon } from "lucide-react";
import { ApiError } from "../../api/client";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
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
import { EmptyState } from "../shell/EmptyState";
import { cn } from "@/lib/utils";
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
  selectedIds: ReadonlySet<string>;
  onRetry: () => void;
  onScopeChange: (scope: CaseScope) => void;
  onLoadMore?: () => void;
  loadingMore: boolean;
  onSelectCase: (item: CaseSummary, selected: boolean) => void;
  onSelectAll: (selected: boolean) => void;
  onOpen?: (item: CaseSummary) => void;
  onAssign?: (item: CaseSummary) => void;
  onClose?: (item: CaseSummary) => void;
}

export interface CaseTableHandle {
  /** Focus a row by case id; used when the detail closes back to the list. */
  focusCase: (caseId: string) => void;
}

export interface SeverityStyle {
  label: string;
  className: string;
}

const SEVERITY_BADGE_CLASSES =
  "h-5 rounded-md px-1.5 text-[11px] font-semibold tracking-wide";

export const SEVERITY_STYLES: Record<CaseSeverity, SeverityStyle> = {
  HIGH: {
    label: "HIGH",
    className: `bg-severity-high text-severity-high-foreground ${SEVERITY_BADGE_CLASSES}`,
  },
  MEDIUM: {
    label: "MEDIUM",
    className: `bg-severity-medium text-severity-medium-foreground ${SEVERITY_BADGE_CLASSES}`,
  },
  LOW: {
    label: "LOW",
    className: `bg-severity-low text-severity-low-foreground ${SEVERITY_BADGE_CLASSES}`,
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
      selectedIds,
      onRetry,
      onScopeChange,
      onLoadMore,
      loadingMore,
      onSelectCase,
      onSelectAll,
      onOpen,
      onAssign,
      onClose,
    },
    ref,
  ) {
    const now = useMinuteNow();
    const containerRef = useRef<HTMLDivElement>(null);
    const [activeId, setActiveId] = useState<string | undefined>(undefined);
    const activeIndex = cases.findIndex((item) => item.id === activeId);
    // A filter or Show can remove the active row; the first row then takes over.
    const currentIndex = activeIndex === -1 ? 0 : activeIndex;
    const selectedCount = selectedIds.size;
    const allSelected = cases.length > 0 && selectedCount === cases.length;

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
      if (
        cases.length === 0 ||
        isTextEntryTarget(event.target) ||
        dialogOpen() ||
        event.metaKey ||
        event.ctrlKey ||
        event.altKey
      ) {
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
        case "x":
          if (target === undefined) {
            return;
          }
          event.preventDefault();
          onSelectCase(target, !selectedIds.has(target.id));
          return;
        case "e":
          if (target === undefined || onClose === undefined) {
            return;
          }
          event.preventDefault();
          onClose(target);
          return;
        default:
          return;
      }

      event.preventDefault();
      focusRow(nextIndex);
    }

    return (
      <div
        ref={containerRef}
        data-slot="case-table-frame"
        className="overflow-hidden rounded-xl border"
      >
        <Table
          aria-busy={loading}
          className="[&_td]:px-3 [&_th]:h-9 [&_th]:px-3"
        >
          <TableCaption className="sr-only">
            {caption(tab, scope)}
          </TableCaption>
          <TableHeader className="bg-muted/50 text-xs font-medium">
            <TableRow className="h-9">
              <TableHead className="w-10">
                <Checkbox
                  aria-label="Select all on this page"
                  disabled={error !== null}
                  checked={
                    allSelected
                      ? true
                      : selectedCount > 0
                        ? "indeterminate"
                        : false
                  }
                  className="data-indeterminate:border-primary data-indeterminate:bg-primary data-indeterminate:text-primary-foreground data-indeterminate:[&_svg]:hidden data-indeterminate:before:h-0.5 data-indeterminate:before:w-2 data-indeterminate:before:rounded-full data-indeterminate:before:bg-current"
                  onCheckedChange={(checked) =>
                    onSelectAll(checked === true)
                  }
                />
              </TableHead>
              <TableHead className="w-px text-muted-foreground">
                Number
              </TableHead>
              <TableHead className="w-full max-w-0 min-w-40 truncate text-muted-foreground">
                Title
              </TableHead>
              <TableHead className="w-px text-muted-foreground">
                Severity
              </TableHead>
              <TableHead className="w-px text-muted-foreground">
                Assignee
              </TableHead>
              <TableHead className="w-px text-right text-muted-foreground">
                Last event
              </TableHead>
              <TableHead className="w-px text-right text-muted-foreground">
                {lastColumnLabel(tab)}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody onKeyDown={handleRowKeyDown}>
            {loading ? (
              <SkeletonRows />
            ) : error !== null ? (
              <StateRow>
                <EmptyState
                  tone="error"
                  icon={TriangleAlertIcon}
                  title={caseErrorMessage(error)}
                  onRetry={onRetry}
                />
              </StateRow>
            ) : cases.length === 0 ? (
              <StateRow>
                <EmptyState
                  icon={InboxIcon}
                  title={emptyMessage(tab, scope)}
                  description={
                    scope === "mine"
                      ? "Cases assigned to you show up here."
                      : undefined
                  }
                  action={
                    scope === "mine" ? (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => onScopeChange("unassigned")}
                      >
                        Show unassigned cases
                      </Button>
                    ) : undefined
                  }
                />
              </StateRow>
            ) : (
              cases.map((item, index) => (
                <CaseRow
                  key={item.id}
                  item={item}
                  timeZone={timeZone}
                  now={now}
                  active={index === currentIndex}
                  selected={selectedIds.has(item.id)}
                  onFocus={() => setActiveId(item.id)}
                  onSelect={onSelectCase}
                  onOpen={onOpen}
                />
              ))
            )}
          </TableBody>
        </Table>
        {onLoadMore === undefined ? null : (
          <div className="flex justify-center border-t py-2">
            <Button
              type="button"
              variant="outline"
              disabled={loadingMore}
              onClick={onLoadMore}
            >
              Load more
            </Button>
          </div>
        )}
      </div>
    );
  },
);

interface StateRowProps {
  children: ReactNode;
}

function StateRow({ children }: StateRowProps) {
  return (
    <TableRow>
      <TableCell colSpan={7} className="p-0">
        {children}
      </TableCell>
    </TableRow>
  );
}

interface CaseRowProps {
  item: CaseSummary;
  timeZone: TimeZoneSetting;
  now: Date;
  active: boolean;
  selected: boolean;
  onFocus: () => void;
  onSelect: (item: CaseSummary, selected: boolean) => void;
  onOpen: ((item: CaseSummary) => void) | undefined;
}

function CaseRow({
  item,
  timeZone,
  now,
  active,
  selected,
  onFocus,
  onSelect,
  onOpen,
}: CaseRowProps) {
  const severity = SEVERITY_STYLES[item.severity];

  return (
    <TableRow
      data-case-id={item.id}
      tabIndex={active ? 0 : -1}
      onFocus={onFocus}
      className="h-9 focus:bg-muted focus:ring-2 focus:ring-ring focus:ring-inset"
    >
      <TableCell className="w-10">
        <Checkbox
          aria-label={`Select case #${item.caseNumber}`}
          checked={selected}
          onCheckedChange={(checked) => onSelect(item, checked === true)}
        />
      </TableCell>
      <TableCell className="w-px font-mono text-[13px]">
        #{item.caseNumber}
      </TableCell>
      <TableCell
        className={cn(
          "w-full max-w-0 min-w-40 truncate font-medium",
          onOpen !== undefined &&
            "cursor-pointer underline-offset-4 hover:underline",
        )}
        onClick={onOpen === undefined ? undefined : () => onOpen(item)}
      >
        {item.title}
      </TableCell>
      <TableCell className="w-px">
        <Badge className={severity.className}>{severity.label}</Badge>
      </TableCell>
      <TableCell className="w-px">
        {item.assignee?.displayName ?? "Unassigned"}
      </TableCell>
      <TableCell className="w-px text-right tabular-nums">
        <TimeCell value={item.lastEventAt} timeZone={timeZone} now={now} />
      </TableCell>
      <TableCell className="w-px text-right tabular-nums">
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
        <TableRow key={index} className="h-9">
          <TableCell className="w-10">
            <div className="skeleton size-4" />
          </TableCell>
          <TableCell className="w-px">
            <div className="skeleton h-4 w-9" />
          </TableCell>
          <TableCell className="w-full max-w-0 min-w-40">
            <div className="skeleton h-4 w-3/5" />
          </TableCell>
          <TableCell className="w-px">
            <div className="skeleton h-5 w-14" />
          </TableCell>
          <TableCell className="w-px">
            <div className="skeleton h-4 w-20" />
          </TableCell>
          <TableCell className="w-px">
            <div className="skeleton h-4 w-12" />
          </TableCell>
          <TableCell className="w-px">
            <div className="skeleton h-4 w-12" />
          </TableCell>
        </TableRow>
      ))}
    </>
  );
}

function caption(tab: CaseTab, scope: CaseScope): string {
  return `Cases: ${TAB_LABELS[tab]}, ${SCOPE_LABELS[scope]}`;
}

function lastColumnLabel(tab: CaseTab): string {
  if (tab === "closed") {
    return "Outcome";
  }
  if (tab === "all") {
    return "Age / Outcome";
  }
  return "Age";
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

function dialogOpen(): boolean {
  return document.querySelector('[role="dialog"]') !== null;
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
