import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "../../components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../../components/ui/select";
import {
  commonlyUsedRanges,
  isTimeExpression,
  rangeLabel,
  resolveRange,
  resolveTime,
  stepRange,
  type TimeRange,
  type TimeZoneSetting,
} from "./timeRange";
import type { TimeField } from "./urlState";

export interface TimeRangePickerProps {
  range: TimeRange;
  field: TimeField;
  timeZone: TimeZoneSetting;
  onRangeChange: (range: TimeRange) => void;
  onFieldChange: (field: TimeField) => void;
}

type RangeUnit = "m" | "h" | "d" | "w";
type EndpointMode = "absolute" | "relative" | "now";

interface EndpointDraft {
  mode: EndpointMode;
  absolute: string;
  count: string;
  unit: RangeUnit;
  /** The expression the draft came from; kept until the user edits it. */
  expression: string;
  edited: boolean;
}

interface RangeDraft {
  start: EndpointDraft;
  end: EndpointDraft;
}

const RECENT_RANGES_KEY = "simple-siem.recent-ranges";
const RECENT_RANGE_LIMIT = 5;
const RANGE_ERROR_ID = "time-range-error";
const INVALID_RANGE_MESSAGE = "The end must be after the start.";

const UNIT_OPTIONS: { value: RangeUnit; label: string }[] = [
  { value: "m", label: "minutes" },
  { value: "h", label: "hours" },
  { value: "d", label: "days" },
  { value: "w", label: "weeks" },
];

const TIME_FIELD_OPTIONS: { value: TimeField; label: string }[] = [
  { value: "lastEventAt", label: "Last event" },
  { value: "firstEventAt", label: "First event" },
  { value: "createdAt", label: "Created" },
  { value: "closedAt", label: "Closed" },
];

const MODE_LABELS: Record<EndpointMode, string> = {
  absolute: "Absolute",
  relative: "Relative",
  now: "Now",
};

const OFFSET_PATTERN = /^now-([1-9]\d*)([mhdw])$/;

export function TimeRangePicker({
  range,
  field,
  timeZone,
  onRangeChange,
  onFieldChange,
}: TimeRangePickerProps) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<RangeDraft>(() =>
    draftFromRange(range, timeZone),
  );
  const [recentRanges, setRecentRanges] =
    useState<TimeRange[]>(readRecentRanges);
  const [quick, setQuick] = useState(() => quickDraftFromRange(range));

  const editedRange: TimeRange = {
    from: endpointExpression(draft.start, timeZone),
    to: endpointExpression(draft.end, timeZone),
  };
  const editedRangeValid =
    resolveRange(editedRange, new Date()) !== undefined;
  const quickRangeValid = /^[1-9]\d*$/.test(quick.count);

  function handleOpenChange(nextOpen: boolean) {
    if (nextOpen) {
      setDraft(draftFromRange(range, timeZone));
      setRecentRanges(readRecentRanges());
      setQuick(quickDraftFromRange(range));
    }
    setOpen(nextOpen);
  }

  function applyRange(nextRange: TimeRange) {
    setRecentRanges(rememberRange(nextRange));
    setOpen(false);
    onRangeChange(nextRange);
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Popover open={open} onOpenChange={handleOpenChange}>
        <PopoverTrigger asChild>
          <Button variant="outline" size="sm">
            {rangeLabel(range, timeZone)}
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-[22rem]">
          <section
            role="group"
            aria-labelledby="quick-select-heading"
            className="space-y-2"
          >
            <h2
              id="quick-select-heading"
              className="text-xs font-medium text-muted-foreground"
            >
              Quick select
            </h2>
            <div className="flex items-center gap-2">
              <Label htmlFor="quick-count">Last</Label>
              <Input
                id="quick-count"
                type="number"
                min={1}
                className="w-16"
                value={quick.count}
                onChange={(event) =>
                  setQuick({ ...quick, count: event.target.value })
                }
              />
              <Select
                value={quick.unit}
                onValueChange={(value) =>
                  setQuick({ ...quick, unit: value as RangeUnit })
                }
              >
                <SelectTrigger size="sm" aria-label="Unit">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {UNIT_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                disabled={!quickRangeValid}
                onClick={() =>
                  applyRange({
                    from: `now-${Number(quick.count)}${quick.unit}`,
                    to: "now",
                  })
                }
              >
                Apply
              </Button>
            </div>
          </section>

          <section
            role="group"
            aria-labelledby="commonly-used-heading"
            className="space-y-2"
          >
            <h2
              id="commonly-used-heading"
              className="text-xs font-medium text-muted-foreground"
            >
              Commonly used
            </h2>
            <div className="flex flex-wrap gap-1">
              {commonlyUsedRanges.map((option) => (
                <Button
                  key={option.label}
                  variant="ghost"
                  size="sm"
                  onClick={() => applyRange(option.range)}
                >
                  {option.label}
                </Button>
              ))}
            </div>
          </section>

          {recentRanges.length > 0 && (
            <section
              role="group"
              aria-labelledby="recently-used-heading"
              className="space-y-2"
            >
              <h2
                id="recently-used-heading"
                className="text-xs font-medium text-muted-foreground"
              >
                Recently used
              </h2>
              <div className="flex flex-col items-start gap-1">
                {recentRanges.map((recent) => (
                  <Button
                    key={`${recent.from}-${recent.to}`}
                    variant="ghost"
                    size="sm"
                    className="justify-start"
                    onClick={() => applyRange(recent)}
                  >
                    {rangeLabel(recent, timeZone)}
                  </Button>
                ))}
              </div>
            </section>
          )}

          <section
            role="group"
            aria-labelledby="start-end-heading"
            className="space-y-2"
          >
            <h2
              id="start-end-heading"
              className="text-xs font-medium text-muted-foreground"
            >
              Start and end
            </h2>
            <div className="space-y-2">
              <EndpointEditor
                id="start"
                label="Start"
                draft={draft.start}
                onChange={(start) => setDraft({ ...draft, start })}
              />
              <EndpointEditor
                id="end"
                label="End"
                draft={draft.end}
                onChange={(end) => setDraft({ ...draft, end })}
              />
            </div>
            {!editedRangeValid && (
              <p id={RANGE_ERROR_ID} className="text-xs text-destructive">
                {INVALID_RANGE_MESSAGE}
              </p>
            )}
            <Button
              size="sm"
              disabled={!editedRangeValid}
              aria-describedby={
                editedRangeValid ? undefined : RANGE_ERROR_ID
              }
              onClick={() => applyRange(editedRange)}
            >
              Apply
            </Button>
          </section>
        </PopoverContent>
      </Popover>

      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="icon-sm"
          aria-label="Step back"
          onClick={() =>
            onRangeChange(stepRange(range, -1, new Date()))
          }
        >
          <ChevronLeftIcon aria-hidden="true" />
        </Button>
        <Button
          variant="outline"
          size="icon-sm"
          aria-label="Step forward"
          onClick={() => onRangeChange(stepRange(range, 1, new Date()))}
        >
          <ChevronRightIcon aria-hidden="true" />
        </Button>
      </div>

      <div className="flex items-center gap-2">
        <Label htmlFor="time-field">Time field</Label>
        <Select
          value={field}
          onValueChange={(value) => onFieldChange(value as TimeField)}
        >
          <SelectTrigger id="time-field" size="sm" className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TIME_FIELD_OPTIONS.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}

interface EndpointEditorProps {
  id: "start" | "end";
  label: string;
  draft: EndpointDraft;
  onChange: (draft: EndpointDraft) => void;
}

function EndpointEditor({
  id,
  label,
  draft,
  onChange,
}: EndpointEditorProps) {
  function edit(changes: Partial<EndpointDraft>) {
    onChange({ ...draft, ...changes, edited: true });
  }

  return (
    <fieldset className="rounded-lg border border-border p-2">
      <legend className="px-1 text-xs font-medium">{label}</legend>
      <div className="flex flex-wrap items-center gap-2">
        {(Object.keys(MODE_LABELS) as EndpointMode[]).map((mode) => (
          <label key={mode} className="flex items-center gap-1 text-xs">
            <input
              type="radio"
              name={`${id}-mode`}
              checked={draft.mode === mode}
              onChange={() => edit({ mode })}
            />
            {MODE_LABELS[mode]}
          </label>
        ))}
      </div>

      {draft.mode === "absolute" && (
        <div className="mt-2 flex items-center gap-2">
          <Label htmlFor={`${id}-absolute`} className="text-xs">
            {label} time
          </Label>
          <Input
            id={`${id}-absolute`}
            type="datetime-local"
            step={1}
            value={draft.absolute}
            onChange={(event) => edit({ absolute: event.target.value })}
          />
        </div>
      )}

      {draft.mode === "relative" && (
        <div className="mt-2 flex items-center gap-2">
          <Label htmlFor={`${id}-count`} className="text-xs">
            Count
          </Label>
          <Input
            id={`${id}-count`}
            type="number"
            min={1}
            className="w-16"
            value={draft.count}
            onChange={(event) => edit({ count: event.target.value })}
          />
          <Select
            value={draft.unit}
            onValueChange={(value) => edit({ unit: value as RangeUnit })}
          >
            <SelectTrigger size="sm" aria-label={`${label} unit`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {UNIT_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
    </fieldset>
  );
}

function draftFromRange(
  range: TimeRange,
  timeZone: TimeZoneSetting,
): RangeDraft {
  const now = new Date();
  return {
    start: draftFromExpression(range.from, timeZone, now),
    end: draftFromExpression(range.to, timeZone, now),
  };
}

function draftFromExpression(
  expression: string,
  timeZone: TimeZoneSetting,
  now: Date,
): EndpointDraft {
  const offset = parseOffset(expression);
  const draft: EndpointDraft = {
    mode: "absolute",
    absolute: expressionToInputValue(expression, timeZone, now),
    count: offset === undefined ? "1" : String(offset.count),
    unit: offset === undefined ? "h" : offset.unit,
    expression,
    edited: false,
  };

  if (expression === "now") {
    return { ...draft, mode: "now" };
  }
  if (offset !== undefined) {
    return { ...draft, mode: "relative" };
  }
  return draft;
}

function endpointExpression(
  draft: EndpointDraft,
  timeZone: TimeZoneSetting,
): string {
  if (!draft.edited) {
    return draft.expression;
  }
  if (draft.mode === "now") {
    return "now";
  }
  if (draft.mode === "relative") {
    const isValid = /^[1-9]\d*$/.test(draft.count);
    return isValid ? `now-${Number(draft.count)}${draft.unit}` : "";
  }
  return inputValueToIso(draft.absolute, timeZone);
}

function quickDraftFromRange(range: TimeRange): {
  count: string;
  unit: RangeUnit;
} {
  const offset = range.to === "now" ? parseOffset(range.from) : undefined;
  return offset === undefined
    ? { count: "24", unit: "h" }
    : { count: String(offset.count), unit: offset.unit };
}

function parseOffset(
  expression: string,
): { count: number; unit: RangeUnit } | undefined {
  const match = OFFSET_PATTERN.exec(expression);
  if (!match) {
    return undefined;
  }
  return { count: Number(match[1]), unit: match[2] as RangeUnit };
}

function expressionToInputValue(
  expression: string,
  timeZone: TimeZoneSetting,
  now: Date,
): string {
  const resolved = resolveTime(expression, now);
  return resolved === undefined ? "" : isoToInputValue(resolved, timeZone);
}

function isoToInputValue(date: Date, timeZone: TimeZoneSetting): string {
  const parts =
    timeZone === "utc"
      ? [
          date.getUTCFullYear(),
          date.getUTCMonth() + 1,
          date.getUTCDate(),
          date.getUTCHours(),
          date.getUTCMinutes(),
          date.getUTCSeconds(),
        ]
      : [
          date.getFullYear(),
          date.getMonth() + 1,
          date.getDate(),
          date.getHours(),
          date.getMinutes(),
          date.getSeconds(),
        ];

  const [year, month, day, hour, minute, second] = parts.map(pad);
  return `${year}-${month}-${day}T${hour}:${minute}:${second}`;
}

function inputValueToIso(value: string, timeZone: TimeZoneSetting): string {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value);
  if (!match) {
    return "";
  }

  const [, year, month, day, hour, minute, second = "00"] = match;
  const date =
    timeZone === "utc"
      ? new Date(
          Date.UTC(
            Number(year),
            Number(month) - 1,
            Number(day),
            Number(hour),
            Number(minute),
            Number(second),
          ),
        )
      : new Date(
          Number(year),
          Number(month) - 1,
          Number(day),
          Number(hour),
          Number(minute),
          Number(second),
        );

  return Number.isNaN(date.getTime())
    ? ""
    : date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

function readRecentRanges(): TimeRange[] {
  try {
    const stored = window.localStorage.getItem(RECENT_RANGES_KEY);
    if (stored === null) {
      return [];
    }
    const parsed: unknown = JSON.parse(stored);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter(isStoredRange).slice(0, RECENT_RANGE_LIMIT);
  } catch {
    return [];
  }
}

function rememberRange(range: TimeRange): TimeRange[] {
  const next = [
    range,
    ...readRecentRanges().filter((entry) => !sameRange(entry, range)),
  ].slice(0, RECENT_RANGE_LIMIT);
  try {
    window.localStorage.setItem(RECENT_RANGES_KEY, JSON.stringify(next));
  } catch {
    // Storage can be unavailable; the applied range still takes effect.
  }
  return next;
}

function isStoredRange(value: unknown): value is TimeRange {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const { from, to } = value as { from?: unknown; to?: unknown };
  return (
    typeof from === "string" &&
    typeof to === "string" &&
    isTimeExpression(from) &&
    isTimeExpression(to)
  );
}

function sameRange(left: TimeRange, right: TimeRange): boolean {
  return left.from === right.from && left.to === right.to;
}
