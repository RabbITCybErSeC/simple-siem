import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type InfiniteData,
  type QueryClient,
} from "@tanstack/react-query";
import { apiRequest, get } from "../../../api/client";
import { casesLatestPrefix, casesListPrefix } from "../queries";
import type { CaseListResponse, CaseSummary } from "../types";
import type {
  AlertSummary,
  AssignCaseVariables,
  BulkCloseRequest,
  BulkCloseResponse,
  CaseAlertsResponse,
  CaseDetail,
  CaseTimelineResponse,
  CloseCaseVariables,
} from "./types";

const PAGE_LIMIT = 50;
const ALL_ALERTS_PAGE_LIMIT = 100;

export interface BulkCloseVariables {
  request: BulkCloseRequest;
  /** Case numbers by id, for the per-case detail cache keys. */
  caseNumbers: Record<string, number>;
}

/** One cache key per case number for the detail and the actions on it. */
export function caseQueryKey(caseNumber: number) {
  return ["case", caseNumber] as const;
}

export function useCaseDetail(caseNumber: number) {
  return useQuery({
    queryKey: caseQueryKey(caseNumber),
    queryFn: () => get<CaseDetail>(`/cases/${caseNumber}`),
  });
}

export function useAssignCase() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ caseId, request }: AssignCaseVariables) =>
      apiRequest<CaseDetail>("PATCH", `/cases/${caseId}`, request),
    onSuccess: (detail, variables) => {
      queryClient.setQueryData(caseQueryKey(variables.caseNumber), detail);
      mergeCaseIntoQueue(queryClient, detail);
      void queryClient.invalidateQueries({ queryKey: ["cases", "counts"] });
      void queryClient.invalidateQueries({ queryKey: ["cases", "histogram"] });
      void queryClient.invalidateQueries({
        queryKey: ["case", variables.caseId, "timeline"],
      });
    },
  });
}

export function useCaseAlerts(caseId: string) {
  return useInfiniteQuery({
    queryKey: caseAlertsQueryKey(caseId),
    queryFn: ({ pageParam }) =>
      get<CaseAlertsResponse>(
        pagePath(`/cases/${caseId}/alerts`, pageParam),
      ),
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.pagination.nextCursor ?? undefined,
  });
}

/**
 * Every alert of a case for the close dialog's per-alert overrides: the
 * dialog needs the whole set, so pages are followed until the cursor ends.
 */
export function useAllCaseAlerts(caseId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: caseAllAlertsQueryKey(caseId),
    queryFn: () => fetchAllAlerts(caseId as string),
    enabled: enabled && caseId !== undefined,
  });
}

export function useCloseCase() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ caseId, request }: CloseCaseVariables) =>
      apiRequest<CaseDetail>("POST", `/cases/${caseId}/close`, request),
    onSuccess: (detail, variables) => {
      queryClient.setQueryData(caseQueryKey(variables.caseNumber), detail);
      mergeCaseIntoQueue(queryClient, detail);
      void queryClient.invalidateQueries({ queryKey: ["cases", "counts"] });
      void queryClient.invalidateQueries({ queryKey: ["cases", "histogram"] });
      void queryClient.invalidateQueries({
        queryKey: ["case", variables.caseId, "alerts"],
      });
      void queryClient.invalidateQueries({
        queryKey: ["case", variables.caseId, "timeline"],
      });
    },
  });
}

export function useBulkCloseCases() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ request }: BulkCloseVariables) =>
      apiRequest<BulkCloseResponse>("POST", "/cases/bulk-close", request),
    onSuccess: (response, { request, caseNumbers }) => {
      // Keep the closed rows closed at once; the GETs below replace them with
      // the server's version and closedAt, so the next refresh tick sees the
      // analyst's own change as already loaded.
      const closedIds = new Set(
        response.results
          .filter((result) => result.status === "CLOSED")
          .map((result) => result.caseId),
      );
      updateQueuePages(queryClient, (item) =>
        closedIds.has(item.id)
          ? {
              ...item,
              status: "CLOSED",
              outcome: request.outcome,
              closureReason: request.closureReason,
            }
          : item,
      );

      const refreshIds = response.results
        .filter(
          (result) =>
            result.status === "CLOSED" ||
            result.status === "VERSION_CONFLICT",
        )
        .map((result) => result.caseId);
      const refreshing = new Set(refreshIds);
      void Promise.allSettled(
        refreshIds.map(async (caseId) => {
          try {
            const detail = await get<CaseDetail>(`/cases/${caseId}`);
            mergeCaseIntoQueue(queryClient, detail);
            const caseNumber = caseNumbers[caseId];
            if (caseNumber !== undefined) {
              queryClient.setQueryData(caseQueryKey(caseNumber), detail);
            }
          } catch {
            // The local patch keeps the queue usable; refetch an open detail.
            const caseNumber = caseNumbers[caseId];
            if (caseNumber !== undefined) {
              void queryClient.invalidateQueries({
                queryKey: ["case", caseNumber],
              });
            }
          }
        }),
      );

      void queryClient.invalidateQueries({ queryKey: ["cases", "counts"] });
      void queryClient.invalidateQueries({ queryKey: ["cases", "histogram"] });
      for (const { id } of request.cases) {
        void queryClient.invalidateQueries({
          queryKey: ["case", id, "alerts"],
        });
        void queryClient.invalidateQueries({
          queryKey: ["case", id, "timeline"],
        });
        const caseNumber = caseNumbers[id];
        if (caseNumber !== undefined && !refreshing.has(id)) {
          void queryClient.invalidateQueries({
            queryKey: ["case", caseNumber],
          });
        }
      }
    },
  });
}

export function useCaseTimeline(caseId: string, kind?: "ACTIVITY") {
  return useInfiniteQuery({
    queryKey: caseTimelineQueryKey(caseId, kind),
    queryFn: ({ pageParam }) => {
      const parameters = new URLSearchParams({ limit: String(PAGE_LIMIT) });
      if (kind !== undefined) {
        parameters.set("kind", kind);
      }
      if (pageParam !== null) {
        parameters.set("cursor", pageParam);
      }
      return get<CaseTimelineResponse>(
        `/cases/${caseId}/timeline?${parameters.toString()}`,
      );
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.pagination.nextCursor ?? undefined,
  });
}

/** The newest cached version of every queue row, for a submit-time read. */
export function cachedCaseVersions(
  queryClient: QueryClient,
): Map<string, number> {
  const versions = new Map<string, number>();
  const remember = (row: CaseSummary) => {
    versions.set(row.id, Math.max(versions.get(row.id) ?? 0, row.version));
  };

  const pages = queryClient.getQueriesData<InfiniteData<CaseListResponse>>({
    queryKey: casesListPrefix,
  });
  for (const [, data] of pages) {
    for (const page of data?.pages ?? []) {
      for (const row of page.data) {
        remember(row);
      }
    }
  }

  const latest = queryClient.getQueriesData<CaseListResponse>({
    queryKey: casesLatestPrefix,
  });
  for (const [, page] of latest) {
    for (const row of page?.data ?? []) {
      remember(row);
    }
  }

  return versions;
}

function mergeCaseIntoQueue(queryClient: QueryClient, detail: CaseDetail) {
  updateQueuePages(queryClient, (item) =>
    item.id === detail.id ? caseSummaryOf(detail) : item,
  );
}

function updateQueuePages(
  queryClient: QueryClient,
  update: (item: CaseSummary) => CaseSummary,
) {
  queryClient.setQueriesData<InfiniteData<CaseListResponse>>(
    { queryKey: casesListPrefix },
    (data) =>
      data === undefined
        ? data
        : {
            ...data,
            pages: data.pages.map((page) => ({
              ...page,
              data: page.data.map(update),
            })),
          },
  );
}

function caseSummaryOf(detail: CaseDetail): CaseSummary {
  return {
    id: detail.id,
    caseNumber: detail.caseNumber,
    title: detail.title,
    status: detail.status,
    severity: detail.severity,
    outcome: detail.outcome,
    closureReason: detail.closureReason,
    assignee: detail.assignee,
    firstEventAt: detail.firstEventAt,
    lastEventAt: detail.lastEventAt,
    createdAt: detail.createdAt,
    closedAt: detail.closedAt,
    version: detail.version,
  };
}

function caseAlertsQueryKey(caseId: string) {
  return ["case", caseId, "alerts"] as const;
}

function caseAllAlertsQueryKey(caseId: string | undefined) {
  return ["case", caseId, "alerts", "all"] as const;
}

async function fetchAllAlerts(caseId: string): Promise<AlertSummary[]> {
  const alerts: AlertSummary[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | null = null;

  do {
    const page: CaseAlertsResponse = await get<CaseAlertsResponse>(
      pagePath(`/cases/${caseId}/alerts`, cursor, ALL_ALERTS_PAGE_LIMIT),
    );
    alerts.push(...page.data);
    cursor = page.pagination.nextCursor;
    if (cursor !== null) {
      if (seenCursors.has(cursor)) {
        throw new Error("The alert list cursor did not advance.");
      }
      seenCursors.add(cursor);
    }
  } while (cursor !== null);

  return alerts;
}

function caseTimelineQueryKey(caseId: string, kind: "ACTIVITY" | undefined) {
  return ["case", caseId, "timeline", kind ?? "all"] as const;
}

function pagePath(
  base: string,
  cursor: string | null,
  limit = PAGE_LIMIT,
): string {
  const parameters = new URLSearchParams({ limit: String(limit) });
  if (cursor !== null) {
    parameters.set("cursor", cursor);
  }
  return `${base}?${parameters.toString()}`;
}
