import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { apiRequest, get } from "../../../api/client";
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
const ALL_ALERTS_LIMIT = 100;

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
      // The queue's snapshot rule keeps the visible rows: only the counts and
      // the chart refresh here, and the next refresh tick finds row changes.
      void queryClient.invalidateQueries({ queryKey: ["cases", "counts"] });
      void queryClient.invalidateQueries({ queryKey: ["cases", "histogram"] });
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
 * Every alert of a case for the close dialog's per-alert overrides. The
 * dialog needs the whole set, so pages are followed until the end, capped at
 * the contract's 100-case override limit.
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
      // The queue's snapshot rule keeps the visible rows: only the counts and
      // the chart refresh here, and the next refresh tick finds row changes.
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
    onSuccess: (_response, { request, caseNumbers }) => {
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
        if (caseNumber !== undefined) {
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

function caseAlertsQueryKey(caseId: string) {
  return ["case", caseId, "alerts"] as const;
}

function caseAllAlertsQueryKey(caseId: string | undefined) {
  return ["case", caseId, "alerts", "all"] as const;
}

async function fetchAllAlerts(caseId: string): Promise<AlertSummary[]> {
  const alerts: AlertSummary[] = [];
  let cursor: string | null = null;

  while (alerts.length < ALL_ALERTS_LIMIT) {
    const page: CaseAlertsResponse = await get<CaseAlertsResponse>(
      pagePath(`/cases/${caseId}/alerts`, cursor),
    );
    alerts.push(...page.data);
    cursor = page.pagination.nextCursor;
    if (cursor === null) {
      break;
    }
  }

  return alerts.slice(0, ALL_ALERTS_LIMIT);
}

function caseTimelineQueryKey(caseId: string, kind: "ACTIVITY" | undefined) {
  return ["case", caseId, "timeline", kind ?? "all"] as const;
}

function pagePath(base: string, cursor: string | null): string {
  const parameters = new URLSearchParams({ limit: String(PAGE_LIMIT) });
  if (cursor !== null) {
    parameters.set("cursor", cursor);
  }
  return `${base}?${parameters.toString()}`;
}
