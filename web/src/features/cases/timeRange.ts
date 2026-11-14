import type { TimeZoneSetting } from "../shell/types";
import type { TimeRange } from "./types";

export interface OffsetExpression {
  count: number;
  unit: TimeUnit;
}

export type TimeUnit = "m" | "h" | "d" | "w";

type ExactVariant = "label" | "timestamp";

export const UNIT_MILLISECONDS: Record<TimeUnit, number> = {
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

const UNIT_NAMES: Record<TimeUnit, { singular: string; plural: string }> = {
  m: { singular: "minute", plural: "minutes" },
  h: { singular: "hour", plural: "hours" },
  d: { singular: "day", plural: "days" },
  w: { singular: "week", plural: "weeks" },
};

const OFFSET_PATTERN = /^now-([1-9]\d*)([mhdw])$/;
const ISO_UTC_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?Z$/;
const JUST_NOW_MILLISECONDS = 45_000;

const labelFormats: Record<TimeZoneSetting, Intl.DateTimeFormat> = {
  local: createFormat("local", false),
  utc: createFormat("utc", false),
};

const timestampFormats: Record<TimeZoneSetting, Intl.DateTimeFormat> = {
  local: createFormat("local", true),
  utc: createFormat("utc", true),
};

export function isTimeExpression(value: string): boolean {
  return (
    value === "now" ||
    value === "now/d" ||
    value === "now/w" ||
    parseOffset(value) !== undefined ||
    parseIsoUtc(value) !== undefined
  );
}

export function resolveTime(value: string, now: Date): Date | undefined {
  if (value === "now") {
    return new Date(now.getTime());
  }
  if (value === "now/d") {
    return startOfUtcDay(now);
  }
  if (value === "now/w") {
    return startOfUtcWeek(now);
  }

  const offset = parseOffset(value);
  if (offset) {
    return new Date(
      now.getTime() - offset.count * UNIT_MILLISECONDS[offset.unit],
    );
  }

  return parseIsoUtc(value);
}

export function resolveRange(
  range: TimeRange,
  now: Date,
): { from: Date; to: Date } | undefined {
  const from = resolveTime(range.from, now);
  const to = resolveTime(range.to, now);
  if (
    from === undefined ||
    to === undefined ||
    from.getTime() >= to.getTime()
  ) {
    return undefined;
  }
  return { from, to };
}

export function stepRange(
  range: TimeRange,
  direction: -1 | 1,
  now: Date,
): TimeRange {
  const resolved = resolveRange(range, now);
  if (resolved === undefined) {
    // Stepping needs a valid span; an invalid range stays as the user typed it.
    return range;
  }

  const length = resolved.to.getTime() - resolved.from.getTime();
  if (direction === -1) {
    return {
      from: toSecondIso(new Date(resolved.from.getTime() - length)),
      to: toSecondIso(resolved.from),
    };
  }
  return {
    from: toSecondIso(resolved.to),
    to: toSecondIso(new Date(resolved.to.getTime() + length)),
  };
}

export function rangeLabel(
  range: TimeRange,
  timeZone: TimeZoneSetting,
): string {
  const offset = range.to === "now" ? parseOffset(range.from) : undefined;
  if (offset) {
    return `Last ${offset.count} ${unitName(offset.unit, offset.count)}`;
  }
  if (range.from === "now/d" && range.to === "now") {
    // now/d is anchored in UTC, so local labels say so.
    return timeZone === "local" ? "Today (UTC)" : "Today";
  }
  if (range.from === "now/w" && range.to === "now") {
    return timeZone === "local" ? "This week (UTC)" : "This week";
  }

  const label = `${labelEnd(range.from, timeZone)} → ${labelEnd(range.to, timeZone)}`;
  return timeZone === "utc" ? `${label} UTC` : label;
}

export function relativeTime(value: string, now: Date): string {
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) {
    return value;
  }

  const elapsed = now.getTime() - timestamp;
  if (elapsed < JUST_NOW_MILLISECONDS) {
    return "just now";
  }

  const minutes = Math.floor(elapsed / UNIT_MILLISECONDS.m);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  return `${Math.floor(hours / 24)}d ago`;
}

/** Labels stay short; timestamp cells add the year and seconds. */
export function formatExact(
  value: string,
  timeZone: TimeZoneSetting,
  variant: ExactVariant = "label",
): string {
  const formats =
    variant === "timestamp" ? timestampFormats : labelFormats;
  const formatted = formatDate(formats[timeZone], value);
  if (formatted === undefined) {
    return value;
  }
  return timeZone === "utc" ? `${formatted} UTC` : formatted;
}

export const commonlyUsedRanges: { label: string; range: TimeRange }[] = [
  { label: "Today", range: { from: "now/d", to: "now" } },
  { label: "This week", range: { from: "now/w", to: "now" } },
  { label: "Last 15 minutes", range: { from: "now-15m", to: "now" } },
  { label: "Last 1 hour", range: { from: "now-1h", to: "now" } },
  { label: "Last 4 hours", range: { from: "now-4h", to: "now" } },
  { label: "Last 24 hours", range: { from: "now-24h", to: "now" } },
  { label: "Last 7 days", range: { from: "now-7d", to: "now" } },
  { label: "Last 30 days", range: { from: "now-30d", to: "now" } },
];

function createFormat(
  timeZone: TimeZoneSetting,
  includeYearAndSeconds: boolean,
): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: includeYearAndSeconds ? "numeric" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    second: includeYearAndSeconds ? "2-digit" : undefined,
    hourCycle: "h23",
    timeZone: timeZone === "utc" ? "UTC" : undefined,
  });
}

export function parseOffset(value: string): OffsetExpression | undefined {
  const match = OFFSET_PATTERN.exec(value);
  if (!match) {
    return undefined;
  }
  return { count: Number(match[1]), unit: match[2] as TimeUnit };
}

// ISO 8601 UTC only: a Z suffix and a real calendar date, which the Date
// constructor would otherwise normalize (for example 29 February).
function parseIsoUtc(value: string): Date | undefined {
  const match = ISO_UTC_PATTERN.exec(value);
  if (!match) {
    return undefined;
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return undefined;
  }

  const [, year, month, day, hour, minute, second] = match;
  const isRealDate =
    date.getUTCFullYear() === Number(year) &&
    date.getUTCMonth() === Number(month) - 1 &&
    date.getUTCDate() === Number(day) &&
    date.getUTCHours() === Number(hour) &&
    date.getUTCMinutes() === Number(minute) &&
    date.getUTCSeconds() === Number(second);
  return isRealDate ? date : undefined;
}

function startOfUtcDay(now: Date): Date {
  return new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
  );
}

function startOfUtcWeek(now: Date): Date {
  const daysSinceMonday = (now.getUTCDay() + 6) % 7;
  return new Date(
    startOfUtcDay(now).getTime() - daysSinceMonday * UNIT_MILLISECONDS.d,
  );
}

export function toSecondIso(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function labelEnd(value: string, timeZone: TimeZoneSetting): string {
  if (value === "now") {
    return "now";
  }
  if (value === "now/d") {
    return "today";
  }
  if (value === "now/w") {
    return "this week";
  }

  const offset = parseOffset(value);
  if (offset) {
    return `${offset.count} ${unitName(offset.unit, offset.count)} ago`;
  }

  return formatDate(labelFormats[timeZone], value) ?? value;
}

function unitName(unit: TimeUnit, count: number): string {
  return count === 1
    ? UNIT_NAMES[unit].singular
    : UNIT_NAMES[unit].plural;
}

function formatDate(
  formatter: Intl.DateTimeFormat,
  value: string,
): string | undefined {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : formatter.format(date);
}
