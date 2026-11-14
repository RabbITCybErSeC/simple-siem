import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";
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
import { NotFoundPage } from "../shell/AppShell";
import { useTimeZone } from "../shell/timeZone";
import { useCurrentUser } from "../auth/session";
import { CaseTable, isTextEntryTarget } from "./CaseTable";
import type { CaseTableHandle } from "./CaseTable";
import {
  CaseActionAlert,
  CaseDetail,
  describeAssignFailure,
} from "./detail/CaseDetail";
import type { CaseActionFailure } from "./detail/CaseDetail";
import { useAssignCase } from "./detail/queries";
import { TimeRangePicker } from "./TimeRangePicker";
import { TrendChart } from "./TrendChart";
import {
  countNewOrUpdated,
  fetchLatestFirstPage,
  useCaseCounts,
  useCaseHistogram,
  useCaseList,
} from "./queries";
import type {
  CaseCounts,
  CaseDetailLayout,
  CaseDetailView,
  CaseQueueState,
  CaseScope,
  CaseSort,
  CaseSummary,
  CaseTab,
  RefreshInterval,
} from "./types";
import {
  caseDetailPath,
  caseQueuePath,
  caseQueueSearch,
  defaultCaseDetailState,
  listParams,
  parseCaseDetailState,
  parseCaseNumber,
  parseCaseQueueState,
  refreshMilliseconds,
  usesTimeRange,
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

/**
 * The route wrapper: an invalid case number is a page that does not exist,
 * before the queue starts loading anything.
 */
export function CasesPage() {
  const { caseNumber: caseNumberParameter } = useParams();
  const caseNumber = parseCaseNumber(caseNumberParameter);

  if (caseNumberParameter !== undefined && caseNumber === undefined) {
    return <NotFoundPage />;
  }

  return <CaseQueuePage caseNumber={caseNumber} />;
}

interface CaseQueuePageProps {
  caseNumber: number | undefined;
}

function CaseQueuePage({ caseNumber }: CaseQueuePageProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const state = parseCaseQueueState(searchParams);
  const detailState = parseCaseDetailState(searchParams);
  const listQuery = useCaseList(state);
  const countsQuery = useCaseCounts(state);
  const histogramQuery = useCaseHistogram(state);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const timeZone = useTimeZone();
  const { data: me } = useCurrentUser();
  const assignRowMutation = useAssignCase();
  const [pendingChanges, setPendingChanges] = useState(0);
  const [rowAssignFailure, setRowAssignFailure] =
    useState<CaseActionFailure | null>(null);
  const stateRef = useRef(state);
  const firstPageRef = useRef<CaseSummary[] | undefined>(undefined);
  const restoreFocus = useRef(false);
  const tableRef = useRef<CaseTableHandle>(null);
  const pendingRowFocus = useRef<string | undefined>(undefined);

  useEffect(() => {
    stateRef.current = state;
    firstPageRef.current = listQuery.data?.pages[0]?.data;
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
    setRowAssignFailure(null);
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
      const parameters = listParams(current).toString();
      // Without a loaded first page there is no snapshot to compare against.
      const snapshot = firstPageRef.current;
      if (snapshot === undefined) {
        return;
      }

      try {
        const latest = await fetchLatestFirstPage(queryClient, current);
        // The analyst may have changed the view while the page was in flight.
        if (listParams(stateRef.current).toString() !== parameters) {
          return;
        }
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

  // Escape hands focus back to the row the detail was opened from. The list
  // stays mounted while the detail is open, so the row is already there.
  useEffect(() => {
    if (caseNumber !== undefined) {
      return;
    }
    const caseId = pendingRowFocus.current;
    if (caseId === undefined) {
      return;
    }
    pendingRowFocus.current = undefined;
    tableRef.current?.focusCase(caseId);
  }, [caseNumber]);

  const showPendingChanges = async () => {
    // Refetching the infinite query keeps every loaded page; replacing it
    // with the latest first page would drop the pages Load more added.
    restoreFocus.current = true;
    const result = await listQuery.refetch();
    if (result.isError) {
      // Keep the banner so the analyst can try again.
      restoreFocus.current = false;
      return;
    }
    setPendingChanges(0);
  };

  const openCase = (item: CaseSummary) => {
    navigate(caseDetailPath(item.caseNumber, state, defaultCaseDetailState));
  };

  const cases = listQuery.data?.pages.flatMap((page) => page.data) ?? [];
  const listError = listQuery.isError ? listQuery.error : null;

  const assignRow = (item: CaseSummary) => {
    if (me === undefined) {
      return;
    }
    setRowAssignFailure(null);
    assignRowMutation.mutate(
      {
        caseId: item.id,
        caseNumber: item.caseNumber,
        request: {
          assigneeId: item.assignee?.id === me.id ? null : me.id,
          version: item.version,
        },
      },
      { onError: (error) => setRowAssignFailure(describeAssignFailure(error)) },
    );
  };

  const reloadRow = () => {
    setRowAssignFailure(null);
    void listQuery.refetch();
  };

  const closeDetail = () => {
    const listed = cases.find((item) => item.caseNumber === caseNumber);
    pendingRowFocus.current = listed?.id;
    navigate(caseQueuePath(state));
  };

  const changeView = (view: CaseDetailView) => {
    if (caseNumber === undefined) {
      return;
    }
    navigate(caseDetailPath(caseNumber, state, { ...detailState, view }));
  };

  const changeLayout = (layout: CaseDetailLayout) => {
    if (caseNumber === undefined) {
      return;
    }
    navigate(caseDetailPath(caseNumber, state, { ...detailState, layout }), {
      replace: true,
    });
  };

  const counts = countsQuery.data;
  const detailOpen = caseNumber !== undefined;
  const listHidden = detailOpen && detailState.layout === "full";

  return (
    <>
      <title>
        {detailOpen ? `Case #${caseNumber} · Simple SIEM` : "Cases · Simple SIEM"}
      </title>
      <div
        className={detailOpen ? layoutGridClass(detailState.layout) : undefined}
      >
        <div data-case-list hidden={listHidden} className="min-w-0">
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
                const count = countLabel(
                  counts?.scope[option.value],
                  counts?.cap,
                );
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

          {listHidden ? null : (
            <div className="mt-4">
              <TrendChart
                histogram={histogramQuery.data}
                timeZone={timeZone}
                loading={histogramQuery.isPending}
                onZoom={(range) => updateState({ range }, false)}
              />
            </div>
          )}

          {caseNumber === undefined && rowAssignFailure !== null ? (
            <div className="mt-4">
              <CaseActionAlert
                failure={rowAssignFailure}
                onReload={reloadRow}
              />
            </div>
          ) : null}

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
                ref={tableRef}
                cases={cases}
                tab={state.tab}
                scope={state.scope}
                timeZone={timeZone}
                loading={listQuery.isPending}
                error={listError}
                onRetry={() => void listQuery.refetch()}
                onOpen={openCase}
                onAssign={assignRow}
              />
              {listQuery.hasNextPage && listError === null && (
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
        </div>

        {caseNumber === undefined ? null : (
          <div className="min-w-0">
            {rowAssignFailure === null ? null : (
              <div className="mb-3">
                <CaseActionAlert
                  failure={rowAssignFailure}
                  onReload={reloadRow}
                />
              </div>
            )}
            <CaseDetail
              caseNumber={caseNumber}
              view={detailState.view}
              layout={detailState.layout}
              queueState={state}
              timeZone={timeZone}
              onViewChange={changeView}
              onLayoutChange={changeLayout}
              onClose={closeDetail}
            />
          </div>
        )}
      </div>
    </>
  );
}

function layoutGridClass(layout: CaseDetailLayout): string {
  return layout === "full"
    ? "grid gap-6"
    : "grid gap-6 xl:grid-cols-[minmax(0,45fr)_minmax(0,55fr)]";
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
