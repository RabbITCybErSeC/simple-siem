import "@testing-library/jest-dom/vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TrendChart, zoomRange } from "./TrendChart";
import type { CaseHistogram } from "./types";

const BUCKET_STARTS = [
  "2026-11-09T08:00:00Z",
  "2026-11-09T09:00:00Z",
  "2026-11-09T10:00:00Z",
  "2026-11-09T11:00:00Z",
  "2026-11-09T12:00:00Z",
  "2026-11-09T13:00:00Z",
];

const HISTOGRAM: CaseHistogram = {
  interval: "1h",
  buckets: BUCKET_STARTS.map((start, index) => ({
    start,
    counts: { HIGH: index + 1, MEDIUM: index + 2, LOW: index + 3 },
  })),
};

class ResizeObserverStub {
  private readonly callback: ResizeObserverCallback;

  constructor(callback: ResizeObserverCallback) {
    this.callback = callback;
  }

  observe(target: Element) {
    this.callback(
      [
        {
          target,
          contentRect: {
            x: 0,
            y: 0,
            width: 320,
            height: 200,
            top: 0,
            left: 0,
            right: 320,
            bottom: 200,
            toJSON: () => ({}),
          },
        } as ResizeObserverEntry,
      ],
      this as unknown as ResizeObserver,
    );
  }

  unobserve() {}
  disconnect() {}
}

const BOUNDING_RECT = {
  x: 0,
  y: 0,
  width: 320,
  height: 200,
  top: 0,
  left: 0,
  right: 320,
  bottom: 200,
  toJSON: () => ({}),
};

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", ResizeObserverStub);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function flushFrame(): Promise<void> {
  await act(async () => {
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  });
}

function renderChart(histogram: CaseHistogram | undefined) {
  const onZoom = vi.fn();

  const view = render(
    <TrendChart
      histogram={histogram}
      timeZone="utc"
      loading={false}
      error={false}
      onRetry={vi.fn()}
      onZoom={onZoom}
    />,
  );

  return { ...view, onZoom };
}

describe("zoomRange", () => {
  it("spans the dragged buckets from the earlier start to the later end", () => {
    expect(zoomRange(HISTOGRAM, 2, 4)).toEqual({
      from: "2026-11-09T10:00:00Z",
      to: "2026-11-09T13:00:00Z",
    });
  });

  it("handles a drag from right to left", () => {
    expect(zoomRange(HISTOGRAM, 4, 2)).toEqual({
      from: "2026-11-09T10:00:00Z",
      to: "2026-11-09T13:00:00Z",
    });
  });

  it("uses the interval length for the last bucket", () => {
    const shorter: CaseHistogram = {
      interval: "1h",
      buckets: HISTOGRAM.buckets.slice(0, 5),
    };

    expect(zoomRange(shorter, 3, 4)).toEqual({
      from: "2026-11-09T11:00:00Z",
      to: "2026-11-09T13:00:00Z",
    });
  });

  it("returns undefined for a click on one bucket or missing data", () => {
    expect(zoomRange(HISTOGRAM, 2, 2)).toBeUndefined();
    expect(zoomRange(undefined, 0, 1)).toBeUndefined();
    expect(zoomRange(HISTOGRAM, 0, 99)).toBeUndefined();
  });
});

describe("TrendChart", () => {
  it("renders the three severity series in order with the token colours", () => {
    const { container } = renderChart(HISTOGRAM);

    const rectangles = Array.from(
      container.querySelectorAll(".recharts-bar-rectangle path"),
    );
    const fills = [
      ...new Set(rectangles.map((rectangle) => rectangle.getAttribute("fill"))),
    ];

    expect(fills).toEqual([
      "var(--color-severity-high)",
      "var(--color-severity-medium)",
      "var(--color-severity-low)",
    ]);
    const legend = container.querySelector('[data-slot="trend-legend"]');
    expect(legend).not.toBeNull();
    expect(legend?.textContent).toBe("HighMediumLow");
  });

  it("lists every bucket in a screen-reader table", () => {
    renderChart(HISTOGRAM);

    const table = screen.getByRole("table", {
      name: "Cases over time by severity",
    });
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((header) => header.textContent);

    expect(headers).toEqual(["Bucket start", "High", "Medium", "Low"]);
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(HISTOGRAM.buckets.length + 1);
    expect(
      within(rows[1]).getAllByRole("cell").map((cell) => cell.textContent),
    ).toEqual(["1", "2", "3"]);
    expect(
      within(table).getByText("Nov 9, 10:00 UTC"),
    ).toBeInTheDocument();
  });

  it("says there are no cases for empty or all-zero data", () => {
    renderChart(undefined);
    expect(screen.getByText("No cases in this range.")).toBeInTheDocument();

    cleanup();
    renderChart({
      interval: "1h",
      buckets: BUCKET_STARTS.map((start) => ({
        start,
        counts: { HIGH: 0, MEDIUM: 0, LOW: 0 },
      })),
    });
    expect(screen.getByText("No cases in this range.")).toBeInTheDocument();
  });

  it("shows a busy skeleton while loading", () => {
    const { container } = render(
      <TrendChart
        histogram={undefined}
        timeZone="utc"
        loading={true}
        error={false}
        onRetry={vi.fn()}
        onZoom={vi.fn()}
      />,
    );

    expect(container.querySelector("[aria-busy='true']")).not.toBeNull();
    expect(
      screen.queryByText("No cases in this range."),
    ).not.toBeInTheDocument();
  });

  it("zooms to the dragged buckets", async () => {
    const { container, onZoom } = renderChart(HISTOGRAM);
    const wrapper = container.querySelector(".recharts-wrapper");
    expect(wrapper).not.toBeNull();

    vi.spyOn(wrapper as HTMLElement, "getBoundingClientRect").mockReturnValue(
      BOUNDING_RECT,
    );
    fireEvent.mouseMove(wrapper!, { clientX: 157, clientY: 100 });
    await flushFrame();
    fireEvent.mouseDown(wrapper!, { clientX: 157, clientY: 100 });
    fireEvent.mouseMove(wrapper!, { clientX: 253, clientY: 100 });
    await flushFrame();
    fireEvent.mouseUp(wrapper!, { clientX: 253, clientY: 100 });

    expect(onZoom).toHaveBeenCalledWith({
      from: "2026-11-09T10:00:00Z",
      to: "2026-11-09T13:00:00Z",
    });
  });

  it("does not zoom for a click without a drag", async () => {
    const { container, onZoom } = renderChart(HISTOGRAM);
    const wrapper = container.querySelector(".recharts-wrapper");

    vi.spyOn(wrapper as HTMLElement, "getBoundingClientRect").mockReturnValue(
      BOUNDING_RECT,
    );
    fireEvent.mouseMove(wrapper!, { clientX: 157, clientY: 100 });
    await flushFrame();
    fireEvent.mouseDown(wrapper!, { clientX: 157, clientY: 100 });
    fireEvent.mouseUp(wrapper!, { clientX: 157, clientY: 100 });

    expect(onZoom).not.toHaveBeenCalled();
  });
});
