import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { Button } from "../../components/ui/button";
import { Label } from "../../components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../../components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "../../components/ui/tabs";
import { useTimeZone } from "../shell/timeZone";
import { CaseTable, isTextEntryTarget } from "./CaseTable";
import { TimeRangePicker } from "./TimeRangePicker";
import { TrendChart } from "./TrendChart";
import {
  caseListQueryKey,
  countNewOrUpdated,
  fetchLatestFirstPage,
  useCaseCounts,
  useCaseHistogram,
  useCaseList,
} from "./queries";
import type { CaseCounts, CaseSummary } from "./types";
import {
  caseQueueSearch,
  parseCaseQueueState,
  refreshMilliseconds,
  type CaseQueueState,
  type CaseScope,
  type CaseSort,
  type CaseTab,
  type RefreshInterval,
} from "./urlState";

const TAB_OPTIONS: { value: CaseTab; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In progress" },
  { value: "closed", label: "Closed" },
  { value: "all", label: "All" },
];

const SCOPE_OPTIONS: { value: CaseScope; label: string }[] = [
  { value: "mine", label: "Mine" },
  { value: "unassigned", label: "Unassigned" },
  { value: "all", label: "All" },
];

const STATUS_KEYS: Record<CaseTab, keyof CaseCounts["status"]> = {
  open: "OPEN",
  in_progress: "IN_PROGRESS",
  closed: "CLOSED",
  all: "ALL",
};

const SORT_OPTIONS: { value: CaseSort; label: string }[] = [
  { value: "lastEventAt:desc", label: "Last event (newest first)" },
  { value: "createdAt:asc", label: "Oldest waiting first" },
];

const REFRESH_OPTIONS: { value: RefreshInterval; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "10s", label: "10 seconds" },
  { value: "30s", label: "30 seconds" },
  { value: "1m", label: "1 minute" },
  { value: "5m", label: "5 minutes" },
];

export function CasesPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const state = parseCaseQueueState(searchParams);
  const listQuery = useCaseList(state);
  const countsQuery = useCaseCounts(state);
  const histogramQuery = useCaseHistogram(state);
  const queryClient = useQueryClient();
  const timeZone = useTimeZone();
  const [pendingChanges, setPendingChanges] = useState(0);
  const stateRef = useRef(state);
  const firstPageRef = useRef<CaseSummary[]>([]);
  const restoreFocus = useRef(false);

  useEffect(() => {
    stateRef.current = state;
    firstPageRef.current = listQuery.data?.pages[0]?.data ?? [];
  });

  const updateState = (
    changes: Partial<CaseQueueState>,
    replace: boolean,
  ) => {
    // Defaults are omitted from the URL so the default view is /cases.
    const next = { ...state, ...changes };
    const search = caseQueueSearch(next);
    // Radix tabs can report the same selection twice (focus and pointer);
    // one history entry per view is what Back steps through.
    if (sameSearch(search, window.location.search)) {
      return;
    }
    setPendingChanges(0);
    setSearchParams(new URLSearchParams(search), { replace });
  };

  // One tick for the interval and Refresh now: fetch the latest first page,
  // announce how it differs, and refresh the counts and chart in place.
  const refreshTick = useCallback(
    async (force: boolean) => {
      if (!force && refreshPaused()) {
        return;
      }

      const current = stateRef.current;
      const snapshot = firstPageRef.current;
      try {
        const latest = await fetchLatestFirstPage(queryClient, current);
        setPendingChanges(countNewOrUpdated(snapshot, latest.data));
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ["cases", "counts"] }),
          queryClient.invalidateQueries({ queryKey: ["cases", "histogram"] }),
        ]);
      } catch {
        // The visible rows stay; the next tick tries again.
      }
    },
    [queryClient],
  );

  useEffect(() => {
    if (state.refresh === "off") {
      return;
    }
    const timer = window.setInterval(
      () => void refreshTick(false),
      refreshMilliseconds[state.refresh],
    );
    return () => window.clearInterval(timer);
  }, [refreshTick, state.refresh]);

  useEffect(() => {
    if (!restoreFocus.current) {
      return;
    }
    restoreFocus.current = false;
    document
      .querySelector<HTMLElement>("[data-case-id][tabindex='0']")
      ?.focus();
  }, [listQuery.data]);

  const showPendingChanges = async () => {
    const current = stateRef.current;
    try {
      const latest = await fetchLatestFirstPage(queryClient, current);
      queryClient.setQueryData(caseListQueryKey(current), {
        pages: [latest],
        pageParams: [null],
      });
      restoreFocus.current = true;
      setPendingChanges(0);
    } catch {
      // Keep the banner so the analyst can try again.
    }
  };

  const cases = listQuery.data?.pages.flatMap((page) => page.data) ?? [];
  const listError =
    listQuery.isError && listQuery.data === undefined
      ? listQuery.error
      : null;
  const counts = countsQuery.data;

  return (
    <>
      <title>Cases · Simple SIEM</title>
      <h1
        tabIndex={-1}
        className="text-2xl font-semibold tracking-tight outline-none"
      >
        Cases
      </h1>

      <div className="mt-4 flex flex-wrap items-end gap-3">
        <div
          role="radiogroup"
          aria-label="Assignee scope"
          className="flex gap-1 rounded-lg bg-muted p-1"
        >
          {SCOPE_OPTIONS.map((option) => {
            const selected = state.scope === option.value;
            const count = countLabel(counts?.scope[option.value], counts?.cap);
            return (
              <Button
                key={option.value}
                type="button"
                role="radio"
                aria-checked={selected}
                variant={selected ? "secondary" : "ghost"}
                size="sm"
                onClick={() => updateState({ scope: option.value }, false)}
              >
                {withCount(option.label, count)}
              </Button>
            );
          })}
        </div>

        <TimeRangePicker
          range={state.range}
          field={state.field}
          timeZone={timeZone}
          onRangeChange={(range) => updateState({ range }, false)}
          onFieldChange={(field) => updateState({ field }, false)}
        />

        <div className="flex items-center gap-2">
          <Label htmlFor="case-refresh" className="sr-only">
            Refresh interval
          </Label>
          <Select
            value={state.refresh}
            onValueChange={(value) =>
              updateState({ refresh: value as RefreshInterval }, true)
            }
          >
            <SelectTrigger id="case-refresh" size="sm" className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {REFRESH_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void refreshTick(true)}
          >
            Refresh now
          </Button>
        </div>

        <div className="flex items-center gap-2">
          <Label htmlFor="case-sort" className="sr-only">
            Sort
          </Label>
          <Select
            value={state.sort}
            onValueChange={(value) =>
              updateState({ sort: value as CaseSort }, true)
            }
          >
            <SelectTrigger id="case-sort" size="sm" className="w-56">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SORT_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {usesTimeRange(state.tab) ? null : (
        <p className="mt-2 text-xs text-muted-foreground">
          Open work ignores the time range.
        </p>
      )}

      <div className="mt-4">
        <TrendChart
          histogram={histogramQuery.data}
          timeZone={timeZone}
          loading={histogramQuery.isPending}
          onZoom={(range) => updateState({ range }, false)}
        />
      </div>

      <Tabs
        value={state.tab}
        onValueChange={(value) =>
          updateState({ tab: value as CaseTab }, false)
        }
        className="mt-4"
      >
        <TabsList aria-label="Status">
          {TAB_OPTIONS.map((option) => (
            <TabsTrigger key={option.value} value={option.value}>
              {withCount(
                option.label,
                countLabel(
                  counts?.status[STATUS_KEYS[option.value]],
                  counts?.cap,
                ),
              )}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value={state.tab}>
          {pendingChanges > 0 && (
            <div
              role="status"
              className="mb-3 flex items-center gap-3 rounded-lg border border-border bg-muted px-3 py-2 text-sm"
            >
              <span>{pendingLabel(pendingChanges)}</span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void showPendingChanges()}
              >
                Show
              </Button>
            </div>
          )}
          <CaseTable
            cases={cases}
            tab={state.tab}
            scope={state.scope}
            timeZone={timeZone}
            loading={listQuery.isPending}
            error={listError}
            onRetry={() => void listQuery.refetch()}
          />
          {listQuery.hasNextPage && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="mt-3"
              disabled={listQuery.isFetchingNextPage}
              onClick={() => void listQuery.fetchNextPage()}
            >
              Load more
            </Button>
          )}
        </TabsContent>
      </Tabs>
    </>
  );
}

function countLabel(
  value: number | undefined,
  cap: number | undefined,
): string {
  if (value === undefined || cap === undefined) {
    return "";
  }
  if (value >= cap) {
    return `${cap.toLocaleString("en-US")}+`;
  }
  return value.toLocaleString("en-US");
}

function withCount(label: string, count: string): string {
  return count === "" ? label : `${label} ${count}`;
}

function pendingLabel(count: number): string {
  return `${count} new or updated case${count === 1 ? "" : "s"}`;
}

function refreshPaused(): boolean {
  if (document.visibilityState === "hidden") {
    return true;
  }
  if (isTextEntryTarget(document.activeElement)) {
    return true;
  }
  return (
    document.querySelector(
      '[role="dialog"], [data-radix-popper-content-wrapper]',
    ) !== null
  );
}

function usesTimeRange(tab: CaseTab): boolean {
  return tab === "closed" || tab === "all";
}

function sameSearch(left: string, right: string): boolean {
  const leftParameters = new URLSearchParams(left);
  const rightParameters = new URLSearchParams(right);
  if (leftParameters.size !== rightParameters.size) {
    return false;
  }
  for (const [key, value] of leftParameters) {
    if (rightParameters.get(key) !== value) {
      return false;
    }
  }
  return true;
}
