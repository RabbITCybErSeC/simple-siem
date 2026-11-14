import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { ApiError, get } from "../../api/client";
import type {
  CaseCounts,
  CaseHistogram,
  CaseListResponse,
  CaseQueueState,
  CaseSummary,
} from "./types";
import { countsParams, histogramParams, listParams } from "./urlState";

const CASES_PATH = "/cases";

export function useCaseList(state: CaseQueueState) {
  const queryClient = useQueryClient();
  const parameters = listParams(state).toString();
  // A cursor can expire between Load more clicks; the contract says the
  // client then restarts from the first page (contract A6). Reset once per
  // failing cursor: a second failure must surface instead of looping.
  const attemptedCursor = useRef<string | null>(null);
  const resetFailure = useRef<string | null>(null);

  const query = useInfiniteQuery({
    queryKey: listQueryKey(parameters),
    queryFn: async ({ pageParam }) => {
      attemptedCursor.current = pageParam;
      const page = await get<CaseListResponse>(
        casePagePath(parameters, pageParam),
      );
      if (pageParam !== null) {
        resetFailure.current = null;
      }
      return page;
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) =>
      lastPage.pagination.nextCursor ?? undefined,
  });

  useEffect(() => {
    const cursor = attemptedCursor.current;
    if (cursor === null || !isCursorError(query.error)) {
      return;
    }
    const failure = `${parameters}|${cursor}`;
    if (resetFailure.current === failure) {
      return;
    }
    resetFailure.current = failure;
    void queryClient.resetQueries({
      queryKey: listQueryKey(parameters),
      exact: true,
    });
  }, [query.error, queryClient, parameters]);

  return query;
}

export function useCaseCounts(state: CaseQueueState) {
  const parameters = countsParams(state).toString();

  return useQuery({
    queryKey: ["cases", "counts", parameters],
    queryFn: () => get<CaseCounts>(`${CASES_PATH}/counts?${parameters}`),
  });
}

export function useCaseHistogram(state: CaseQueueState) {
  const parameters = histogramParams(state).toString();

  return useQuery({
    queryKey: ["cases", "histogram", parameters],
    queryFn: () => get<CaseHistogram>(`${CASES_PATH}/histogram?${parameters}`),
  });
}

/** The first page as the server has it now, without touching the visible rows. */
export function fetchLatestFirstPage(
  queryClient: QueryClient,
  state: CaseQueueState,
): Promise<CaseListResponse> {
  const parameters = listParams(state).toString();

  return queryClient.fetchQuery({
    queryKey: ["cases", "latest", parameters],
    queryFn: () => get<CaseListResponse>(`${CASES_PATH}?${parameters}`),
    staleTime: 0,
  });
}

/** Counts rows whose case id is new or whose version moved forward. */
export function countNewOrUpdated(
  snapshot: CaseSummary[],
  latest: CaseSummary[],
): number {
  const versions = new Map(snapshot.map((item) => [item.id, item.version]));

  return latest.filter((item) => {
    const version = versions.get(item.id);
    return version === undefined || item.version > version;
  }).length;
}

function listQueryKey(parameters: string) {
  return ["cases", "list", parameters] as const;
}

function casePagePath(parameters: string, cursor: string | null): string {
  if (cursor === null) {
    return `${CASES_PATH}?${parameters}`;
  }
  const search = new URLSearchParams(parameters);
  search.set("cursor", cursor);
  return `${CASES_PATH}?${search.toString()}`;
}

function isCursorError(error: Error | null): boolean {
  return (
    error instanceof ApiError &&
    error.status === 400 &&
    error.code === "VALIDATION_ERROR"
  );
}
