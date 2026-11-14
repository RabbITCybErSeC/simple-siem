import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { apiRequest, get } from "../../../api/client";
import type {
  AssignRequest,
  CaseAlertsResponse,
  CaseDetail,
  CaseTimelineResponse,
} from "./types";

const PAGE_LIMIT = 50;

export interface AssignCaseVariables {
  caseId: string;
  caseNumber: number;
  request: AssignRequest;
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
