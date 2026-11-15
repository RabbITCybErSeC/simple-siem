import { useState } from "react";
import { Bar, BarChart, ReferenceArea, XAxis, YAxis } from "recharts";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "../../components/ui/chart";
import type { TimeZoneSetting } from "../shell/types";
import { SectionError } from "./detail/CaseSections";
import {
  formatExact,
  toSecondIso,
  UNIT_MILLISECONDS,
  type TimeUnit,
} from "./timeRange";
import type { TimeRange } from "./types";
import type { CaseHistogram } from "./types";

export interface TrendChartProps {
  histogram: CaseHistogram | undefined;
  timeZone: TimeZoneSetting;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
  onZoom: (range: TimeRange) => void;
}

interface BucketSeries {
  start: string;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

interface DragSelection {
  startIndex: number;
  endIndex: number;
}

// Labels only: ChartStyle skips the inline <style> without color or theme.
const chartConfig = {
  HIGH: { label: "High" },
  MEDIUM: { label: "Medium" },
  LOW: { label: "Low" },
} satisfies ChartConfig;

const severityOrder = ["HIGH", "MEDIUM", "LOW"];

const tickFormats: Record<TimeZoneSetting, Intl.DateTimeFormat> = {
  local: new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }),
  utc: new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC",
  }),
};

const dateTickFormats: Record<TimeZoneSetting, Intl.DateTimeFormat> = {
  local: new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }),
  utc: new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }),
};

export function zoomRange(
  histogram: CaseHistogram | undefined,
  fromIndex: number,
  toIndex: number,
): TimeRange | undefined {
  if (histogram === undefined || fromIndex === toIndex) {
    return undefined;
  }

  const startIndex = Math.min(fromIndex, toIndex);
  const endIndex = Math.max(fromIndex, toIndex);
  const startBucket = histogram.buckets[startIndex];
  const endBucket = histogram.buckets[endIndex];
  if (startBucket === undefined || endBucket === undefined) {
    return undefined;
  }

  const startMilliseconds = Date.parse(startBucket.start);
  const nextStart = histogram.buckets[endIndex + 1]?.start;
  const intervalMilliseconds = parseInterval(histogram.interval);
  const endMilliseconds =
    nextStart === undefined
      ? intervalMilliseconds === undefined
        ? Number.NaN
        : Date.parse(endBucket.start) + intervalMilliseconds
      : Date.parse(nextStart);

  if (
    Number.isNaN(startMilliseconds) ||
    Number.isNaN(endMilliseconds) ||
    endMilliseconds <= startMilliseconds
  ) {
    return undefined;
  }

  return {
    from: toSecondIso(new Date(startMilliseconds)),
    to: toSecondIso(new Date(endMilliseconds)),
  };
}

export function TrendChart({
  histogram,
  timeZone,
  loading,
  error,
  onRetry,
  onZoom,
}: TrendChartProps) {
  const [drag, setDrag] = useState<DragSelection | undefined>();

  const buckets = histogram?.buckets ?? [];
  const data: BucketSeries[] = buckets.map((bucket) => ({
    start: bucket.start,
    HIGH: bucket.counts.HIGH,
    MEDIUM: bucket.counts.MEDIUM,
    LOW: bucket.counts.LOW,
  }));
  const intervalMilliseconds = parseInterval(histogram?.interval);
  const hasCases = data.some(
    (bucket) => bucket.HIGH + bucket.MEDIUM + bucket.LOW > 0,
  );

  function bucketIndex(label: string | undefined): number | undefined {
    if (label === undefined) {
      return undefined;
    }
    const index = buckets.findIndex((bucket) => bucket.start === label);
    return index === -1 ? undefined : index;
  }

  function handleMouseDown(state: unknown) {
    const index = bucketIndex(activeLabel(state));
    if (index !== undefined) {
      setDrag({ startIndex: index, endIndex: index });
    }
  }

  function handleMouseMove(state: unknown) {
    if (drag === undefined) {
      return;
    }
    const index = bucketIndex(activeLabel(state));
    if (index !== undefined && index !== drag.endIndex) {
      setDrag({ ...drag, endIndex: index });
    }
  }

  function handleMouseUp(state: unknown) {
    if (drag === undefined) {
      return;
    }
    const index = bucketIndex(activeLabel(state)) ?? drag.endIndex;
    setDrag(undefined);
    const range = zoomRange(histogram, drag.startIndex, index);
    if (range !== undefined) {
      onZoom(range);
    }
  }

  const selectedFrom =
    drag === undefined
      ? undefined
      : buckets[Math.min(drag.startIndex, drag.endIndex)]?.start;
  const selectedTo =
    drag === undefined
      ? undefined
      : buckets[Math.max(drag.startIndex, drag.endIndex)]?.start;

  return (
    <figure className="space-y-2">
      <figcaption className="text-sm font-medium">
        Cases over time by severity
      </figcaption>
      <p className="text-xs text-muted-foreground">
        Drag across the bars to zoom; use the time range picker from the
        keyboard.
      </p>

      {loading ? (
        <div
          aria-busy="true"
          className="h-40 animate-pulse rounded-lg bg-muted"
        />
      ) : error ? (
        <SectionError message="Could not load the trend." onRetry={onRetry} />
      ) : !hasCases ? (
        <p className="text-sm text-muted-foreground">No cases in this range.</p>
      ) : (
        <>
          <div aria-hidden="true">
            <ChartContainer config={chartConfig} className="h-40 w-full">
              <BarChart
                data={data}
                accessibilityLayer={false}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={() => setDrag(undefined)}
              >
                <XAxis
                  dataKey="start"
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(value: string) =>
                    bucketTick(value, intervalMilliseconds, timeZone)
                  }
                />
                <YAxis allowDecimals={false} width={32} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <ChartLegend
                  content={<ChartLegendContent />}
                  itemSorter={(item) =>
                    severityOrder.indexOf(String(item.dataKey))
                  }
                />
                <Bar
                  dataKey="HIGH"
                  stackId="severity"
                  fill="var(--color-severity-high)"
                  isAnimationActive={false}
                />
                <Bar
                  dataKey="MEDIUM"
                  stackId="severity"
                  fill="var(--color-severity-medium)"
                  isAnimationActive={false}
                />
                <Bar
                  dataKey="LOW"
                  stackId="severity"
                  fill="var(--color-severity-low)"
                  isAnimationActive={false}
                />
                {selectedFrom !== undefined &&
                  selectedTo !== undefined &&
                  selectedFrom !== selectedTo && (
                    <ReferenceArea
                      x1={selectedFrom}
                      x2={selectedTo}
                      fill="var(--color-muted)"
                      fillOpacity={0.4}
                    />
                  )}
              </BarChart>
            </ChartContainer>
          </div>

          <table className="sr-only">
            <caption>Cases over time by severity</caption>
            <thead>
              <tr>
                <th scope="col">Bucket start</th>
                <th scope="col">High</th>
                <th scope="col">Medium</th>
                <th scope="col">Low</th>
              </tr>
            </thead>
            <tbody>
              {buckets.map((bucket) => (
                <tr key={bucket.start}>
                  <th scope="row">{formatExact(bucket.start, timeZone)}</th>
                  <td>{bucket.counts.HIGH}</td>
                  <td>{bucket.counts.MEDIUM}</td>
                  <td>{bucket.counts.LOW}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </figure>
  );
}

function activeLabel(state: unknown): string | undefined {
  if (
    typeof state !== "object" ||
    state === null ||
    !("activeLabel" in state)
  ) {
    return undefined;
  }
  const label = (state as { activeLabel?: unknown }).activeLabel;
  return typeof label === "string" ? label : undefined;
}

function bucketTick(
  start: string,
  intervalMilliseconds: number | undefined,
  timeZone: TimeZoneSetting,
): string {
  const date = new Date(start);
  if (Number.isNaN(date.getTime())) {
    return start;
  }

  const format =
    intervalMilliseconds !== undefined &&
    intervalMilliseconds < UNIT_MILLISECONDS.d
      ? tickFormats[timeZone]
      : dateTickFormats[timeZone];
  return format.format(date);
}

function parseInterval(interval: string | undefined): number | undefined {
  const match = interval === undefined ? null : /^(\d+)([mhdw])$/.exec(interval);
  if (!match) {
    return undefined;
  }

  return Number(match[1]) * UNIT_MILLISECONDS[match[2] as TimeUnit];
}
