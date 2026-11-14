import { describe, expect, it } from "vitest";
import {
  commonlyUsedRanges,
  formatExact,
  isTimeExpression,
  rangeLabel,
  relativeTime,
  resolveRange,
  resolveTime,
  stepRange,
} from "./timeRange";

const now = new Date("2026-11-09T12:00:00Z");

function iso(value: Date | undefined): string | undefined {
  return value?.toISOString();
}

describe("isTimeExpression", () => {
  it.each([
    "now",
    "now-15m",
    "now-4h",
    "now-7d",
    "now-2w",
    "now/d",
    "now/w",
    "2026-11-07T10:00:00Z",
    "2026-11-07T10:00:00.123Z",
  ])("accepts %s", (value) => {
    expect(isTimeExpression(value)).toBe(true);
  });

  it.each([
    "now-0h",
    "now+1h",
    "now-1y",
    "now-01h",
    "now-1",
    "now-",
    "now/m",
    "yesterday",
    "2026-11-07T10:00:00+02:00",
    "2026-11-07T10:00:00",
    "2026-11-07T10:00:00z",
    "2026-02-29T10:00:00Z",
    "",
  ])("rejects %s", (value) => {
    expect(isTimeExpression(value)).toBe(false);
  });
});

describe("resolveTime", () => {
  it.each([
    ["now", "2026-11-09T12:00:00.000Z"],
    ["now-15m", "2026-11-09T11:45:00.000Z"],
    ["now-4h", "2026-11-09T08:00:00.000Z"],
    ["now-7d", "2026-11-02T12:00:00.000Z"],
    ["now-2w", "2026-10-26T12:00:00.000Z"],
    ["now/d", "2026-11-09T00:00:00.000Z"],
    ["2026-11-07T10:00:00Z", "2026-11-07T10:00:00.000Z"],
  ])("resolves %s", (value, expected) => {
    expect(iso(resolveTime(value, now))).toBe(expected);
  });

  it("resolves now/w to Monday 00:00 UTC of this week", () => {
    const wednesday = new Date("2026-11-11T12:34:56Z");

    expect(iso(resolveTime("now/w", wednesday))).toBe(
      "2026-11-09T00:00:00.000Z",
    );
  });

  it("returns undefined for an invalid expression", () => {
    expect(resolveTime("yesterday", now)).toBeUndefined();
  });
});

describe("resolveRange", () => {
  it("resolves a relative range against now", () => {
    expect(
      resolveRange({ from: "now-24h", to: "now" }, now),
    ).toEqual({
      from: new Date("2026-11-08T12:00:00Z"),
      to: new Date("2026-11-09T12:00:00Z"),
    });
  });

  it("returns undefined when either end is invalid", () => {
    expect(
      resolveRange({ from: "yesterday", to: "now" }, now),
    ).toBeUndefined();
    expect(
      resolveRange({ from: "now-1h", to: "tomorrow" }, now),
    ).toBeUndefined();
  });

  it("returns undefined unless from is before to", () => {
    expect(resolveRange({ from: "now", to: "now" }, now)).toBeUndefined();
    expect(
      resolveRange({ from: "now", to: "now-1h" }, now),
    ).toBeUndefined();
  });
});

describe("stepRange", () => {
  it("steps back by the range length as absolute values", () => {
    expect(
      stepRange({ from: "now-24h", to: "now" }, -1, now),
    ).toEqual({
      from: "2026-11-07T12:00:00Z",
      to: "2026-11-08T12:00:00Z",
    });
  });

  it("steps forward by the range length as absolute values", () => {
    expect(
      stepRange({ from: "now-24h", to: "now" }, 1, now),
    ).toEqual({
      from: "2026-11-09T12:00:00Z",
      to: "2026-11-10T12:00:00Z",
    });
  });

  it("drops milliseconds from the absolute values", () => {
    const withMilliseconds = new Date("2026-11-09T12:00:00.789Z");

    expect(
      stepRange({ from: "now-1h", to: "now" }, -1, withMilliseconds),
    ).toEqual({
      from: "2026-11-09T10:00:00Z",
      to: "2026-11-09T11:00:00Z",
    });
  });

  it("steps an absolute range", () => {
    expect(
      stepRange(
        {
          from: "2026-11-07T10:00:00Z",
          to: "2026-11-07T14:30:00Z",
        },
        1,
        now,
      ),
    ).toEqual({
      from: "2026-11-07T14:30:00Z",
      to: "2026-11-07T19:00:00Z",
    });
  });
});

describe("rangeLabel", () => {
  it.each(commonlyUsedRanges)("labels $label", ({ label, range }) => {
    const utcAnchored = label === "Today" || label === "This week";
    expect(rangeLabel(range, "local")).toBe(
      utcAnchored ? `${label} (UTC)` : label,
    );
    expect(rangeLabel(range, "utc")).toBe(label);
  });

  it("uses the singular for one unit", () => {
    expect(rangeLabel({ from: "now-1m", to: "now" }, "utc")).toBe(
      "Last 1 minute",
    );
  });

  it("marks UTC-anchored today and this week in local time", () => {
    expect(rangeLabel({ from: "now/d", to: "now" }, "local")).toBe(
      "Today (UTC)",
    );
    expect(rangeLabel({ from: "now/w", to: "now" }, "local")).toBe(
      "This week (UTC)",
    );
    expect(rangeLabel({ from: "now/d", to: "now" }, "utc")).toBe("Today");
    expect(rangeLabel({ from: "now/w", to: "now" }, "utc")).toBe(
      "This week",
    );
  });

  it("labels absolute ranges in UTC with one marker", () => {
    expect(
      rangeLabel(
        {
          from: "2026-11-07T10:00:00Z",
          to: "2026-11-07T14:30:00Z",
        },
        "utc",
      ),
    ).toBe("Nov 7, 10:00 → Nov 7, 14:30 UTC");
  });

  it("labels absolute ranges in local time without a marker", () => {
    const label = rangeLabel(
      {
        from: "2026-11-07T10:00:00Z",
        to: "2026-11-07T14:30:00Z",
      },
      "local",
    );

    expect(label).toContain(" → ");
    expect(label).not.toContain("UTC");
  });

  it("labels relative and now ends", () => {
    expect(
      rangeLabel({ from: "now-4h", to: "now-1h" }, "local"),
    ).toBe("4 hours ago → 1 hour ago");
    expect(
      rangeLabel({ from: "now-4h", to: "now-30m" }, "utc"),
    ).toBe("4 hours ago → 30 minutes ago UTC");
    expect(
      rangeLabel({ from: "2026-11-07T10:00:00Z", to: "now" }, "local"),
    ).toBe("Nov 7, 10:00 → now");
  });
});

describe("relativeTime", () => {
  function ago(milliseconds: number): string {
    return relativeTime(
      new Date(now.getTime() - milliseconds).toISOString(),
      now,
    );
  }

  it("says just now under 45 seconds or in the future", () => {
    expect(ago(10_000)).toBe("just now");
    expect(ago(44_000)).toBe("just now");
    expect(ago(-5 * 60_000)).toBe("just now");
  });

  it("counts whole minutes under an hour", () => {
    expect(ago(5 * 60_000)).toBe("5m ago");
    expect(ago(59 * 60_000 + 59_000)).toBe("59m ago");
  });

  it("counts whole hours under a day", () => {
    expect(ago(3 * 60 * 60_000)).toBe("3h ago");
    expect(ago(23 * 60 * 60_000 + 59 * 60_000)).toBe("23h ago");
  });

  it("counts whole days", () => {
    expect(ago(2 * 24 * 60 * 60_000)).toBe("2d ago");
    expect(ago(2 * 24 * 60 * 60_000 + 23 * 60 * 60_000)).toBe("2d ago");
  });
});

describe("formatExact", () => {
  const value = "2026-11-07T10:00:00Z";

  it("formats the label form in UTC with a marker", () => {
    expect(formatExact(value, "utc")).toBe("Nov 7, 10:00 UTC");
  });

  it("formats the timestamp form in UTC with year and seconds", () => {
    expect(formatExact(value, "utc", "timestamp")).toBe(
      "Nov 7, 2026, 10:00:00 UTC",
    );
  });

  it("formats local time without a marker", () => {
    expect(formatExact(value, "local")).not.toContain("UTC");
    expect(formatExact(value, "local", "timestamp")).not.toContain("UTC");
  });
});
