import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type InfiniteData,
  type QueryClient,
} from "@tanstack/react-query";
import { apiRequest, get } from "../../../api/client";
import { casesListPrefix } from "../queries";
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
    onSuccess: async (response, { request, caseNumbers }) => {
      const closedIds = response.results
        .filter((result) => result.status === "CLOSED")
        .map((result) => result.caseId);
      markQueueCasesClosed(queryClient, closedIds, request);

      const conflicts = response.results
        .filter((result) => result.status === "VERSION_CONFLICT")
        .map((result) => result.caseId);
      const refreshes = await Promise.allSettled(
        conflicts.map(async (caseId) => ({
          caseId,
          detail: await get<CaseDetail>(`/cases/${caseId}`),
        })),
      );
      const refreshed = new Set<string>();
      for (const result of refreshes) {
        if (result.status !== "fulfilled") {
          continue;
        }
        const { caseId, detail } = result.value;
        refreshed.add(caseId);
        mergeCaseIntoQueue(queryClient, detail);
        const caseNumber = caseNumbers[caseId];
        if (caseNumber !== undefined) {
          queryClient.setQueryData(caseQueryKey(caseNumber), detail);
        }
      }

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
        if (caseNumber !== undefined && !refreshed.has(id)) {
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

/** Every cached queue row's version, for a submit-time read. */
export function cachedCaseVersions(
  queryClient: QueryClient,
): Map<string, number> {
  const versions = new Map<string, number>();
  const pages = queryClient.getQueriesData<InfiniteData<CaseListResponse>>({
    queryKey: casesListPrefix,
  });
  for (const [, data] of pages) {
    for (const page of data?.pages ?? []) {
      for (const row of page.data) {
        versions.set(row.id, row.version);
      }
    }
  }
  return versions;
}

function mergeCaseIntoQueue(queryClient: QueryClient, detail: CaseDetail) {
  updateQueuePages(queryClient, (item) =>
    item.id === detail.id ? caseSummaryOf(detail) : item,
  );
}

function markQueueCasesClosed(
  queryClient: QueryClient,
  caseIds: string[],
  request: BulkCloseRequest,
) {
  const closed = new Set(caseIds);
  updateQueuePages(queryClient, (item) =>
    closed.has(item.id)
      ? {
          ...item,
          status: "CLOSED",
          outcome: request.outcome,
          closureReason: request.closureReason,
        }
      : item,
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
  let cursor: string | null = null;

  do {
    const page: CaseAlertsResponse = await get<CaseAlertsResponse>(
      pagePath(`/cases/${caseId}/alerts`, cursor, ALL_ALERTS_PAGE_LIMIT),
    );
    alerts.push(...page.data);
    cursor = page.pagination.nextCursor;
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
