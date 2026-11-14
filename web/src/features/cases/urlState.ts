import { z } from "zod";
import { isTimeExpression, resolveRange } from "./timeRange";
import type {
  CaseDetailState,
  CaseQueueState,
  CaseTab,
  RefreshInterval,
} from "./types";

export const defaultCaseQueueState: CaseQueueState = {
  tab: "open",
  scope: "mine",
  range: { from: "now-24h", to: "now" },
  field: "lastEventAt",
  sort: "lastEventAt:desc",
  refresh: "off",
};

export const defaultCaseDetailState: CaseDetailState = {
  view: "overview",
  layout: "split",
};

const tabSchema = z
  .enum(["open", "in_progress", "closed", "all"])
  .catch(defaultCaseQueueState.tab);
const scopeSchema = z
  .enum(["mine", "unassigned", "all"])
  .catch(defaultCaseQueueState.scope);
const fromSchema = timeExpressionSchema(defaultCaseQueueState.range.from);
const toSchema = timeExpressionSchema(defaultCaseQueueState.range.to);
const fieldSchema = z
  .enum(["lastEventAt", "firstEventAt", "createdAt", "closedAt"])
  .catch(defaultCaseQueueState.field);
const sortSchema = z
  .enum(["lastEventAt:desc", "createdAt:asc"])
  .catch(defaultCaseQueueState.sort);
const refreshSchema = z
  .enum(["off", "10s", "30s", "1m", "5m"])
  .catch(defaultCaseQueueState.refresh);
const viewSchema = z
  .enum(["overview", "alerts", "timeline", "activity"])
  .catch(defaultCaseDetailState.view);
const layoutSchema = z
  .enum(["split", "full"])
  .catch(defaultCaseDetailState.layout);

const tabStatuses: Record<CaseTab, string | undefined> = {
  open: "OPEN",
  in_progress: "IN_PROGRESS",
  closed: "CLOSED",
  all: undefined,
};

export function parseCaseQueueState(params: URLSearchParams): CaseQueueState {
  const range = {
    from: fromSchema.parse(params.get("from")),
    to: toSchema.parse(params.get("to")),
  };

  return {
    tab: tabSchema.parse(params.get("tab")),
    scope: scopeSchema.parse(params.get("scope")),
    // Both ends fall back together: a URL whose end is not after its start
    // would otherwise ask the API for a reversed range.
    range:
      resolveRange(range, new Date()) === undefined
        ? defaultCaseQueueState.range
        : range,
    field: fieldSchema.parse(params.get("field")),
    sort: sortSchema.parse(params.get("sort")),
    refresh: refreshSchema.parse(params.get("refresh")),
  };
}

export function parseCaseDetailState(
  params: URLSearchParams,
): CaseDetailState {
  return {
    view: viewSchema.parse(params.get("view")),
    layout: layoutSchema.parse(params.get("layout")),
  };
}

export function parseCaseNumber(value: string | undefined): number | undefined {
  if (value === undefined || !/^[1-9]\d*$/.test(value)) {
    return undefined;
  }
  return Number(value);
}

export function caseQueuePath(queue: CaseQueueState): string {
  return `/cases${caseQueueSearch(queue)}`;
}

export function caseDetailPath(
  caseNumber: number,
  queue: CaseQueueState,
  detail: CaseDetailState,
): string {
  const detailParameters = new URLSearchParams();
  if (detail.view !== defaultCaseDetailState.view) {
    detailParameters.set("view", detail.view);
  }
  if (detail.layout !== defaultCaseDetailState.layout) {
    detailParameters.set("layout", detail.layout);
  }

  const detailSearch = detailParameters.toString();
  const queueSearch = caseQueueSearch(queue);
  if (detailSearch === "") {
    return `/cases/${caseNumber}${queueSearch}`;
  }
  const separator = queueSearch === "" ? "?" : "&";
  return `/cases/${caseNumber}${queueSearch}${separator}${detailSearch}`;
}

export function caseQueueSearch(state: CaseQueueState): string {
  const parameters = new URLSearchParams();

  if (state.tab !== defaultCaseQueueState.tab) {
    parameters.set("tab", state.tab);
  }
  if (state.scope !== defaultCaseQueueState.scope) {
    parameters.set("scope", state.scope);
  }
  if (state.range.from !== defaultCaseQueueState.range.from) {
    parameters.set("from", state.range.from);
  }
  if (state.range.to !== defaultCaseQueueState.range.to) {
    parameters.set("to", state.range.to);
  }
  if (state.field !== defaultCaseQueueState.field) {
    parameters.set("field", state.field);
  }
  if (state.sort !== defaultCaseQueueState.sort) {
    parameters.set("sort", state.sort);
  }
  if (state.refresh !== defaultCaseQueueState.refresh) {
    parameters.set("refresh", state.refresh);
  }

  // A colon is legal in a query string and keeps sort and ISO values readable.
  const query = parameters.toString().replaceAll("%3A", ":");
  return query === "" ? "" : `?${query}`;
}

export function listParams(state: CaseQueueState): URLSearchParams {
  const parameters = new URLSearchParams();
  addStatus(parameters, state.tab);
  parameters.set("scope", state.scope);
  parameters.set("sort", state.sort);
  parameters.set("limit", "50");
  if (usesTimeRange(state.tab)) {
    addTimeRange(parameters, state);
  }
  return parameters;
}

export function countsParams(state: CaseQueueState): URLSearchParams {
  const parameters = new URLSearchParams();
  addStatus(parameters, state.tab);
  // The server applies the range to CLOSED and ALL only, so counts always send
  // it and keep one query shape for every tab.
  addTimeRange(parameters, state);
  return parameters;
}

export function histogramParams(state: CaseQueueState): URLSearchParams {
  const parameters = new URLSearchParams();
  addStatus(parameters, state.tab);
  parameters.set("scope", state.scope);
  addTimeRange(parameters, state);
  parameters.set("interval", "auto");
  parameters.set("splitBy", "severity");
  return parameters;
}

export const refreshMilliseconds: Record<
  Exclude<RefreshInterval, "off">,
  number
> = {
  "10s": 10_000,
  "30s": 30_000,
  "1m": 60_000,
  "5m": 300_000,
};

function timeExpressionSchema(fallback: string) {
  return z.string().refine(isTimeExpression).catch(fallback);
}

function addStatus(parameters: URLSearchParams, tab: CaseTab) {
  const status = tabStatuses[tab];
  if (status !== undefined) {
    parameters.set("status", status);
  }
}

function addTimeRange(parameters: URLSearchParams, state: CaseQueueState) {
  parameters.set("from", state.range.from);
  parameters.set("to", state.range.to);
  parameters.set("timeField", state.field);
}

export function usesTimeRange(tab: CaseTab): boolean {
  return tab === "closed" || tab === "all";
}
