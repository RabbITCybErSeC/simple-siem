import { describe, expect, it } from "vitest";
import {
  caseDetailPath,
  caseQueuePath,
  caseQueueSearch,
  countsParams,
  defaultCaseDetailState,
  defaultCaseQueueState,
  histogramParams,
  listParams,
  parseCaseDetailState,
  parseCaseNumber,
  parseCaseQueueState,
  refreshMilliseconds,
} from "./urlState";
import type { CaseDetailState, CaseQueueState } from "./types";

function parseState(
  values: string | Record<string, string>,
): CaseQueueState {
  return parseCaseQueueState(new URLSearchParams(values));
}

describe("parseCaseQueueState", () => {
  it("returns the defaults for an empty query", () => {
    expect(parseState("")).toEqual({
      tab: "open",
      scope: "mine",
      range: { from: "now-24h", to: "now" },
      field: "lastEventAt",
      sort: "lastEventAt:desc",
      refresh: "off",
    });
  });

  it("round-trips every parameter", () => {
    const search =
      "?tab=closed&scope=all&from=2026-11-01T10:00:00Z&to=2026-11-07T10:00:00Z&field=closedAt&sort=createdAt:asc&refresh=30s";

    const state = parseState(search);

    expect(state).toEqual({
      tab: "closed",
      scope: "all",
      range: {
        from: "2026-11-01T10:00:00Z",
        to: "2026-11-07T10:00:00Z",
      },
      field: "closedAt",
      sort: "createdAt:asc",
      refresh: "30s",
    });
    expect(caseQueueSearch(state)).toBe(search);
  });

  it.each([
    ["tab", "bogus"],
    ["scope", "bogus"],
    ["from", "yesterday"],
    ["to", "now+1h"],
    ["field", "bogus"],
    ["sort", "bogus"],
    ["refresh", "bogus"],
  ])("falls back alone when %s is invalid", (name, value) => {
    expect(parseState({ [name]: value })).toEqual(defaultCaseQueueState);
  });

  it("keeps valid values around an invalid one", () => {
    expect(
      parseState({
        tab: "bogus",
        scope: "unassigned",
        from: "now-7d",
        to: "now",
        field: "closedAt",
      }),
    ).toEqual({
      ...defaultCaseQueueState,
      scope: "unassigned",
      range: { from: "now-7d", to: "now" },
      field: "closedAt",
    });
  });

  it("falls back for an ISO value with an offset", () => {
    expect(
      parseState({ from: "2026-11-07T10:00:00+02:00" }).range.from,
    ).toBe("now-24h");
  });

  it("falls back for empty values", () => {
    expect(parseState({ tab: "", scope: "" })).toEqual(
      defaultCaseQueueState,
    );
  });

  it("uses the default range when the end is not after the start", () => {
    expect(parseState({ tab: "closed", from: "now", to: "now-1h" })).toEqual(
      { ...defaultCaseQueueState, tab: "closed" },
    );
    expect(
      parseState({
        tab: "all",
        from: "2026-11-09T12:00:00Z",
        to: "2026-11-09T12:00:00Z",
      }),
    ).toEqual({ ...defaultCaseQueueState, tab: "all" });
  });

  it("uses the default range beyond representable time", () => {
    expect(
      parseState({ tab: "closed", from: "now-999999999999999h", to: "now" }),
    ).toEqual({ ...defaultCaseQueueState, tab: "closed" });
  });
});

describe("caseQueueSearch", () => {
  it("is empty for the default view", () => {
    expect(caseQueueSearch(defaultCaseQueueState)).toBe("");
    expect(caseQueueSearch(parseState(""))).toBe("");
  });

  it("omits defaults that are present in the query", () => {
    expect(
      caseQueueSearch(
        parseState(
          "?tab=open&scope=mine&from=now-24h&to=now&field=lastEventAt&sort=lastEventAt:desc&refresh=off",
        ),
      ),
    ).toBe("");
  });

  it("keeps only non-default values in a fixed order", () => {
    expect(
      caseQueueSearch({
        tab: "closed",
        scope: "all",
        range: { from: "now-7d", to: "2026-11-07T10:00:00Z" },
        field: "closedAt",
        sort: "createdAt:asc",
        refresh: "30s",
      }),
    ).toBe(
      "?tab=closed&scope=all&from=now-7d&to=2026-11-07T10:00:00Z&field=closedAt&sort=createdAt:asc&refresh=30s",
    );
  });

  it("serialises a single non-default value", () => {
    expect(
      caseQueueSearch({ ...defaultCaseQueueState, tab: "closed" }),
    ).toBe("?tab=closed");
    expect(
      caseQueueSearch({ ...defaultCaseQueueState, sort: "createdAt:asc" }),
    ).toBe("?sort=createdAt:asc");
  });
});

describe("API parameter builders", () => {
  it("maps each tab to its status and omits it for all", () => {
    expect(listParams(parseState({ tab: "open" })).get("status")).toBe(
      "OPEN",
    );
    expect(
      listParams(parseState({ tab: "in_progress" })).get("status"),
    ).toBe("IN_PROGRESS");
    expect(listParams(parseState({ tab: "closed" })).get("status")).toBe(
      "CLOSED",
    );
    expect(listParams(parseState({ tab: "all" })).has("status")).toBe(
      false,
    );
  });

  it("sends no range to the open list", () => {
    const params = listParams(parseState({}));

    expect(Object.fromEntries(params)).toEqual({
      status: "OPEN",
      scope: "mine",
      sort: "lastEventAt:desc",
      limit: "50",
    });
    expect(params.has("from")).toBe(false);
    expect(params.has("to")).toBe(false);
    expect(params.has("timeField")).toBe(false);
    expect(params.has("cursor")).toBe(false);
  });

  it("sends no range to the in progress list", () => {
    const params = listParams(parseState({ tab: "in_progress" }));

    expect(params.get("status")).toBe("IN_PROGRESS");
    expect(params.has("from")).toBe(false);
  });

  it("sends the range to the closed list", () => {
    const params = listParams(
      parseState({
        tab: "closed",
        from: "now-7d",
        to: "now",
        field: "closedAt",
        sort: "createdAt:asc",
      }),
    );

    expect(Object.fromEntries(params)).toEqual({
      status: "CLOSED",
      scope: "mine",
      sort: "createdAt:asc",
      limit: "50",
      from: "now-7d",
      to: "now",
      timeField: "closedAt",
    });
  });

  it("sends the range to the all list without a status", () => {
    const params = listParams(parseState({ tab: "all" }));

    expect(params.has("status")).toBe(false);
    expect(params.get("from")).toBe("now-24h");
    expect(params.get("to")).toBe("now");
    expect(params.get("timeField")).toBe("lastEventAt");
  });

  it("sends the status and range to counts, never scope, sort, or limit", () => {
    const params = countsParams(
      parseState({ tab: "closed", from: "now-7d", field: "closedAt" }),
    );

    expect(Object.fromEntries(params)).toEqual({
      status: "CLOSED",
      from: "now-7d",
      to: "now",
      timeField: "closedAt",
    });
  });

  it("sends the range to counts on the open tab too", () => {
    const params = countsParams(parseState({}));

    expect(Object.fromEntries(params)).toEqual({
      status: "OPEN",
      from: "now-24h",
      to: "now",
      timeField: "lastEventAt",
    });
    expect(params.has("scope")).toBe(false);
  });

  it("sends no status to counts on the all tab", () => {
    expect(countsParams(parseState({ tab: "all" })).has("status")).toBe(
      false,
    );
  });

  it("sends the full filter set to the histogram", () => {
    expect(
      Object.fromEntries(
        histogramParams(
          parseState({
            tab: "closed",
            scope: "all",
            from: "now-7d",
            to: "now",
            field: "closedAt",
          }),
        ),
      ),
    ).toEqual({
      status: "CLOSED",
      scope: "all",
      from: "now-7d",
      to: "now",
      timeField: "closedAt",
      interval: "auto",
      splitBy: "severity",
    });
  });

  it("sends the range and scope, but no status, to the all histogram", () => {
    const params = histogramParams(parseState({ tab: "all" }));

    expect(params.has("status")).toBe(false);
    expect(params.get("scope")).toBe("mine");
    expect(params.get("from")).toBe("now-24h");
    expect(params.get("to")).toBe("now");
    expect(params.get("timeField")).toBe("lastEventAt");
    expect(params.get("interval")).toBe("auto");
    expect(params.get("splitBy")).toBe("severity");
  });
});

describe("refreshMilliseconds", () => {
  it("maps every interval to milliseconds", () => {
    expect(refreshMilliseconds).toEqual({
      "10s": 10_000,
      "30s": 30_000,
      "1m": 60_000,
      "5m": 300_000,
    });
  });
});

describe("parseCaseDetailState", () => {
  it("returns the defaults for an empty query", () => {
    expect(parseCaseDetailState(new URLSearchParams(""))).toEqual({
      view: "overview",
      layout: "split",
    });
  });

  it("parses the section and the layout", () => {
    expect(
      parseCaseDetailState(new URLSearchParams("view=timeline&layout=full")),
    ).toEqual({ view: "timeline", layout: "full" });
  });

  it("falls back alone when view is invalid", () => {
    expect(
      parseCaseDetailState(new URLSearchParams("view=bogus&layout=full")),
    ).toEqual({ view: "overview", layout: "full" });
  });

  it("falls back alone when layout is invalid", () => {
    expect(
      parseCaseDetailState(new URLSearchParams("view=alerts&layout=bogus")),
    ).toEqual({ view: "alerts", layout: "split" });
  });

  it("leaves the queue state alone", () => {
    expect(parseState({ view: "timeline", layout: "full" })).toEqual(
      defaultCaseQueueState,
    );
  });
});

describe("parseCaseNumber", () => {
  it.each([
    ["1", 1],
    ["312", 312],
    ["99999", 99999],
  ])("accepts the digits %s", (value, number) => {
    expect(parseCaseNumber(value)).toBe(number);
  });

  it.each([undefined, "", "0", "007", "-1", "12a", "1.5", " 12 "])(
    "rejects %s",
    (value) => {
      expect(parseCaseNumber(value)).toBeUndefined();
    },
  );
});

describe("caseQueuePath", () => {
  it("is /cases with the queue query", () => {
    expect(caseQueuePath(defaultCaseQueueState)).toBe("/cases");
    expect(caseQueuePath({ ...defaultCaseQueueState, tab: "closed" })).toBe(
      "/cases?tab=closed",
    );
  });
});

describe("caseDetailPath", () => {
  const queue: CaseQueueState = {
    tab: "closed",
    scope: "all",
    range: { from: "2026-11-01T10:00:00Z", to: "2026-11-07T10:00:00Z" },
    field: "closedAt",
    sort: "createdAt:asc",
    refresh: "30s",
  };
  const detail: CaseDetailState = { view: "timeline", layout: "full" };

  it("is the case path with the default state", () => {
    expect(
      caseDetailPath(312, defaultCaseQueueState, defaultCaseDetailState),
    ).toBe("/cases/312");
  });

  it("appends the queue parameters, then view, then layout", () => {
    expect(caseDetailPath(312, queue, detail)).toBe(
      "/cases/312?tab=closed&scope=all&from=2026-11-01T10:00:00Z&to=2026-11-07T10:00:00Z&field=closedAt&sort=createdAt:asc&refresh=30s&view=timeline&layout=full",
    );
  });

  it("omits a default section", () => {
    expect(
      caseDetailPath(312, defaultCaseQueueState, {
        ...defaultCaseDetailState,
        layout: "full",
      }),
    ).toBe("/cases/312?layout=full");
  });

  it("round-trips the queue and detail state from the path", () => {
    const path = caseDetailPath(312, queue, detail);
    const search = path.slice(path.indexOf("?"));

    expect(parseCaseQueueState(new URLSearchParams(search))).toEqual(queue);
    expect(parseCaseDetailState(new URLSearchParams(search))).toEqual(detail);
  });
});
