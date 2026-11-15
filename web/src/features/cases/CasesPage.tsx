import { useQueryClient } from "@tanstack/react-query";
import { RefreshCwIcon } from "lucide-react";
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
import type {
  CaseActionFailure,
  CaseDetail as CaseDetailData,
} from "./detail/types";
import { BulkCloseDialog } from "./detail/BulkCloseDialog";
import { caseQueryKey, useAssignCase } from "./detail/queries";
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
  caseDetailSearch,
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
  { value: "off", label: "Auto-refresh off" },
  { value: "10s", label: "10 seconds" },
  { value: "30s", label: "30 seconds" },
  { value: "1m", label: "1 minute" },
  { value: "5m", label: "5 minutes" },
];

interface CaseSelection {
  filterKey: string;
  ids: ReadonlySet<string>;
  bulkCloseOpen: boolean;
}

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
  const filterKey = queueFilterKey(state);
  const [selection, setSelection] = useState<CaseSelection>({
    filterKey,
    ids: new Set(),
    bulkCloseOpen: false,
  });

  // The selection belongs to one set of filters, however the URL changed
  // (tabs, links, Back/Forward, the palette). An error hides the rows, so a
  // selection would act on cases the analyst cannot see.
  if (
    selection.filterKey !== filterKey ||
    (listQuery.isError && selection.ids.size > 0)
  ) {
    setSelection({ filterKey, ids: new Set(), bulkCloseOpen: false });
  }
  const [closeRequestedFor, setCloseRequestedFor] = useState<
    number | undefined
  >();
  const [bulkCloseKey, setBulkCloseKey] = useState(0);
  const stateRef = useRef(state);
  const firstPageRef = useRef<CaseSummary[] | undefined>(undefined);
  const restoreFocus = useRef(false);
  const tableRef = useRef<CaseTableHandle>(null);
  const pendingRowFocus = useRef<string | undefined>(undefined);
  const pendingAssignments = useRef<Set<string>>(new Set());

  useEffect(() => {
    stateRef.current = state;
    firstPageRef.current = listQuery.data?.pages[0]?.data;
  });

  const updateState = (
    changes: Partial<CaseQueueState>,
    replace: boolean,
  ) => {
    // Defaults are omitted from the URL so the default view is /cases. The
    // detail parameters stay when the queue is filtered under an open case.
    const next = { ...state, ...changes };
    const search =
      caseNumber === undefined
        ? caseQueueSearch(next)
        : caseDetailSearch(next, detailState);
    // Radix tabs can report the same selection twice (focus and pointer);
    // one history entry per view is what Back steps through. window.location
    // is already updated by the first push, unlike the rendered router state.
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
    setCloseRequestedFor(undefined);
    navigate(caseDetailPath(item.caseNumber, state, defaultCaseDetailState));
  };

  const cases = listQuery.data?.pages.flatMap((page) => page.data) ?? [];
  const listError = listQuery.isError ? listQuery.error : null;
  const listedIds = new Set(cases.map((item) => item.id));
  const selectedIds = new Set(
    [...selection.ids].filter((id) => listedIds.has(id)),
  );
  const selectedCases = cases.filter((item) => selectedIds.has(item.id));
  const bulkCloseOpen = selection.bulkCloseOpen;

  const changeSelection = (change: (ids: Set<string>) => Set<string>) => {
    setSelection((current) => ({
      filterKey,
      ids: change(new Set([...current.ids].filter((id) => listedIds.has(id)))),
      bulkCloseOpen: current.bulkCloseOpen,
    }));
  };

  const selectCase = (item: CaseSummary, selected: boolean) => {
    changeSelection((ids) => {
      const next = new Set(ids);
      if (selected) {
        next.add(item.id);
      } else {
        next.delete(item.id);
      }
      return next;
    });
  };

  const selectPage = (selected: boolean) => {
    changeSelection((ids) => {
      const next = new Set(ids);
      for (const item of cases) {
        if (selected) {
          next.add(item.id);
        } else {
          next.delete(item.id);
        }
      }
      return next;
    });
  };

  const clearSelection = () => {
    setSelection({ filterKey, ids: new Set(), bulkCloseOpen: false });
  };

  const openBulkClose = () => {
    setBulkCloseKey((key) => key + 1);
    setSelection((current) => ({
      filterKey,
      ids: current.ids,
      bulkCloseOpen: true,
    }));
  };

  const setBulkCloseOpen = (open: boolean) => {
    setSelection((current) => ({ ...current, bulkCloseOpen: open }));
  };

  const requestClose = (item: CaseSummary) => {
    if (item.status === "CLOSED") {
      return;
    }
    if (caseNumber !== item.caseNumber) {
      openCase(item);
    }
    setCloseRequestedFor(item.caseNumber);
  };

  const assignRow = (item: CaseSummary) => {
    if (me === undefined || pendingAssignments.current.has(item.id)) {
      return;
    }
    const cached = queryClient.getQueryData<CaseDetailData>(
      caseQueryKey(item.caseNumber),
    );
    const assignee = cached?.assignee ?? item.assignee;
    const version = cached?.version ?? item.version;
    setRowAssignFailure(null);
    pendingAssignments.current.add(item.id);
    assignRowMutation.mutate(
      {
        caseId: item.id,
        caseNumber: item.caseNumber,
        request: {
          assigneeId: assignee?.id === me.id ? null : me.id,
          version,
        },
      },
      {
        onError: (error) => setRowAssignFailure(describeAssignFailure(error)),
        onSettled: () => pendingAssignments.current.delete(item.id),
      },
    );
  };

  const reloadRow = () => {
    setRowAssignFailure(null);
    void listQuery.refetch();
  };

  const closeDetail = () => {
    const listed = cases.find((item) => item.caseNumber === caseNumber);
    pendingRowFocus.current = listed?.id;
    setCloseRequestedFor(undefined);
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
      <div className="@container">
        <div
          className={
            detailOpen ? layoutGridClass(detailState.layout) : undefined
          }
        >
          <div
            data-case-list
            hidden={listHidden}
            className={listPaneClass(detailOpen, detailState.layout)}
          >
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
              <h1
                tabIndex={-1}
                className="text-xl leading-8 font-semibold tracking-tight outline-none"
              >
                Cases
              </h1>
              <div className="flex min-w-0 flex-wrap items-center gap-2 sm:ml-auto sm:justify-end">
                {usesTimeRange(state.tab) ? null : (
                  <span className="text-xs text-muted-foreground max-lg:sr-only">
                    Open work ignores the time range.
                  </span>
                )}
                <TimeRangePicker
                  range={state.range}
                  field={state.field}
                  timeZone={timeZone}
                  onRangeChange={(range) => updateState({ range }, false)}
                  onFieldChange={(field) => updateState({ field }, false)}
                />
                <div className="control-group">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    aria-label="Refresh now"
                    onClick={() => void refreshTick(true)}
                  >
                    <RefreshCwIcon aria-hidden="true" />
                  </Button>
                  <Select
                    value={state.refresh}
                    onValueChange={(value) =>
                      updateState({ refresh: value as RefreshInterval }, true)
                    }
                  >
                    <SelectTrigger
                      aria-label="Refresh interval"
                      className="w-40 border-0 bg-transparent dark:bg-transparent"
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent align="end">
                      {REFRESH_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>

            <Tabs
              value={state.tab}
              onValueChange={(value) =>
                updateState({ tab: value as CaseTab }, false)
              }
              className="mt-4 gap-4"
            >
              <div className="-mx-4 overflow-x-auto border-b border-border px-4 sm:mx-0 sm:px-0">
                <TabsList
                  variant="line"
                  aria-label="Status"
                  className="h-10 gap-4 p-0"
                >
                  {TAB_OPTIONS.map((option) => {
                    const count = countLabel(
                      counts?.status[STATUS_KEYS[option.value]],
                      counts?.cap,
                    );
                    return (
                      <TabsTrigger
                        key={option.value}
                        value={option.value}
                        className="group/status h-10 flex-none gap-2 px-0.5 after:bottom-[-1px]"
                      >
                        {option.label}
                        {count === "" ? null : (
                          <>
                            {" "}
                            <span className="inline-flex h-5 min-w-6 items-center justify-center rounded-md bg-muted px-1.5 text-xs font-medium tabular-nums text-muted-foreground group-data-active/status:bg-foreground group-data-active/status:text-background">
                              {count}
                            </span>
                          </>
                        )}
                      </TabsTrigger>
                    );
                  })}
                </TabsList>
              </div>

              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <div
                  role="radiogroup"
                  aria-label="Assignee scope"
                  className="segmented"
                >
                  {SCOPE_OPTIONS.map((option) => {
                    const count = countLabel(
                      counts?.scope[option.value],
                      counts?.cap,
                    );
                    return (
                      <button
                        key={option.value}
                        type="button"
                        role="radio"
                        aria-checked={state.scope === option.value}
                        className="segmented-item"
                        onClick={() =>
                          updateState({ scope: option.value }, false)
                        }
                      >
                        {option.label}
                        {count === "" ? null : (
                          <>
                            {" "}
                            <span className="text-xs text-muted-foreground tabular-nums">
                              {count}
                            </span>
                          </>
                        )}
                      </button>
                    );
                  })}
                </div>

                <div className="flex items-center gap-2 sm:ml-auto">
                  <Label
                    htmlFor="case-sort"
                    className="text-sm font-normal text-muted-foreground"
                  >
                    Sort
                  </Label>
                  <Select
                    value={state.sort}
                    onValueChange={(value) =>
                      updateState({ sort: value as CaseSort }, true)
                    }
                  >
                    <SelectTrigger id="case-sort" className="w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent align="end">
                      {SORT_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {listHidden ? null : (
                <div>
                  <TrendChart
                    histogram={histogramQuery.data}
                    timeZone={timeZone}
                    loading={histogramQuery.isPending}
                    error={histogramQuery.isError}
                    onRetry={() => void histogramQuery.refetch()}
                    onZoom={(range) => updateState({ range }, false)}
                  />
                </div>
              )}

              {caseNumber === undefined && rowAssignFailure !== null ? (
                <CaseActionAlert
                  failure={rowAssignFailure}
                  onReload={reloadRow}
                />
              ) : null}

              <TabsContent value={state.tab}>
                {selectedIds.size > 0 ? (
                  <div
                    role="toolbar"
                    aria-label="Selected cases"
                    className="mb-3 flex flex-wrap items-center gap-3 rounded-lg border border-border bg-muted px-3 py-2 text-sm"
                  >
                    <span>{`${selectedIds.size} selected`}</span>
                    <Button
                      type="button"
                      disabled={selectedIds.size > 100}
                      onClick={openBulkClose}
                    >
                      {selectedIds.size > 100
                        ? "Close selected (max 100)"
                        : "Close selected"}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={clearSelection}
                    >
                      Clear selection
                    </Button>
                  </div>
                ) : null}
                {pendingChanges > 0 && (
                  <div
                    role="status"
                    className="mb-3 flex items-center gap-3 rounded-lg border border-border bg-muted px-3 py-2 text-sm"
                  >
                    <span>{pendingLabel(pendingChanges)}</span>
                    <Button
                      type="button"
                      variant="outline"
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
                  selectedIds={selectedIds}
                  onRetry={() => void listQuery.refetch()}
                  onScopeChange={(next) => updateState({ scope: next }, false)}
                  onLoadMore={
                    listQuery.hasNextPage && listError === null
                      ? () => void listQuery.fetchNextPage()
                      : undefined
                  }
                  loadingMore={listQuery.isFetchingNextPage}
                  onSelectCase={selectCase}
                  onSelectAll={selectPage}
                  onOpen={openCase}
                  onAssign={assignRow}
                  onClose={requestClose}
                />
              </TabsContent>
            </Tabs>
          </div>

          {caseNumber === undefined ? null : (
            <div className={detailPaneClass(detailState.layout)}>
              {rowAssignFailure === null ? null : (
                <div className="mb-3">
                  <CaseActionAlert
                    failure={rowAssignFailure}
                    onReload={reloadRow}
                  />
                </div>
              )}
              <CaseDetail
                key={caseNumber}
                caseNumber={caseNumber}
                view={detailState.view}
                layout={detailState.layout}
                queueState={state}
                timeZone={timeZone}
                closeRequested={closeRequestedFor === caseNumber}
                onCloseRequestHandled={() => setCloseRequestedFor(undefined)}
                onViewChange={changeView}
                onLayoutChange={changeLayout}
                onClose={closeDetail}
              />
            </div>
          )}
        </div>
      </div>

      <BulkCloseDialog
        key={bulkCloseKey}
        cases={selectedCases}
        open={bulkCloseOpen}
        onOpenChange={setBulkCloseOpen}
        onClosed={(closedIds) => {
          changeSelection((ids) =>
            new Set([...ids].filter((id) => !closedIds.includes(id))),
          );
        }}
      />
    </>
  );
}

/** The filters the selection and its bulk action belong to. */
function queueFilterKey(state: CaseQueueState): string {
  return [
    state.tab,
    state.scope,
    state.range.from,
    state.range.to,
    state.field,
    state.sort,
  ].join("|");
}

const SPLIT_PANE_HEIGHT =
  "@[80rem]:h-[calc(100svh-3.5rem-3rem)] @[80rem]:overflow-y-auto";

function layoutGridClass(layout: CaseDetailLayout): string {
  return layout === "full"
    ? "grid gap-6"
    : "grid gap-6 @max-[80rem]:gap-0 @[80rem]:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]";
}

function listPaneClass(
  detailOpen: boolean,
  layout: CaseDetailLayout,
): string {
  if (!detailOpen || layout === "full") {
    return "min-w-0";
  }
  return `min-w-0 @max-[80rem]:invisible @max-[80rem]:h-0 @max-[80rem]:overflow-hidden ${SPLIT_PANE_HEIGHT}`;
}

function detailPaneClass(layout: CaseDetailLayout): string {
  return layout === "split"
    ? `min-w-0 overflow-x-hidden ${SPLIT_PANE_HEIGHT}`
    : "min-w-0 overflow-x-hidden";
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
