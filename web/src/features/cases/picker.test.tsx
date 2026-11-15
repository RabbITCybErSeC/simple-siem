import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TimeRangePicker } from "./TimeRangePicker";
import type { TimeRange } from "./types";

const RANGE: TimeRange = { from: "now-24h", to: "now" };

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", ResizeObserverStub);
  window.HTMLElement.prototype.scrollIntoView = vi.fn();
  window.HTMLElement.prototype.hasPointerCapture = vi.fn(() => false);
  window.HTMLElement.prototype.setPointerCapture = vi.fn();
  window.HTMLElement.prototype.releasePointerCapture = vi.fn();
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function renderPicker(range: TimeRange = RANGE) {
  const onRangeChange = vi.fn();
  const onFieldChange = vi.fn();

  render(
    <TimeRangePicker
      range={range}
      field="lastEventAt"
      timeZone="utc"
      onRangeChange={onRangeChange}
      onFieldChange={onFieldChange}
    />,
  );

  return { onRangeChange, onFieldChange };
}

function openPicker(): void {
  fireEvent.click(screen.getByRole("button", { name: "Last 24 hours" }));
}

function applyCommonlyUsed(label: string): void {
  openPicker();
  const commonlyUsed = screen.getByRole("group", {
    name: "Commonly used",
  });
  fireEvent.click(within(commonlyUsed).getByRole("button", { name: label }));
}

describe("TimeRangePicker", () => {
  it("applies a quick select range as a relative expression", () => {
    const { onRangeChange } = renderPicker();
    openPicker();

    const quickSelect = screen.getByRole("group", { name: "Quick select" });
    fireEvent.change(within(quickSelect).getByLabelText("Last"), {
      target: { value: "4" },
    });
    fireEvent.click(within(quickSelect).getByRole("button", { name: "Apply" }));

    expect(onRangeChange).toHaveBeenCalledWith({
      from: "now-4h",
      to: "now",
    });
    expect(
      screen.queryByRole("group", { name: "Quick select" }),
    ).not.toBeInTheDocument();
  });

  it("applies a commonly used range", () => {
    const { onRangeChange } = renderPicker();
    openPicker();

    fireEvent.click(
      within(screen.getByRole("group", { name: "Commonly used" })).getByRole(
        "button",
        { name: "Last 7 days" },
      ),
    );

    expect(onRangeChange).toHaveBeenCalledWith({
      from: "now-7d",
      to: "now",
    });
  });

  it("keeps the five most recent ranges, newest first, across a remount", () => {
    renderPicker();

    for (const label of [
      "Today",
      "This week",
      "Last 15 minutes",
      "Last 1 hour",
      "Last 4 hours",
      "Last 24 hours",
    ]) {
      applyCommonlyUsed(label);
    }

    openPicker();
    const recent = screen.getByRole("group", { name: "Recently used" });
    expect(
      within(recent)
        .getAllByRole("button")
        .map((button) => button.textContent),
    ).toEqual([
      "Last 24 hours",
      "Last 4 hours",
      "Last 1 hour",
      "Last 15 minutes",
      "This week",
    ]);

    cleanup();
    renderPicker();
    openPicker();
    const afterRemount = screen.getByRole("group", { name: "Recently used" });
    expect(
      within(afterRemount)
        .getAllByRole("button")
        .map((button) => button.textContent),
    ).toEqual([
      "Last 24 hours",
      "Last 4 hours",
      "Last 1 hour",
      "Last 15 minutes",
      "This week",
    ]);
  });

  it("applies ranges when storage throws and hides the recent list", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });

    const { onRangeChange } = renderPicker();
    openPicker();

    expect(
      screen.queryByRole("group", { name: "Recently used" }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Last 1 hour" }));

    expect(onRangeChange).toHaveBeenCalledWith({
      from: "now-1h",
      to: "now",
    });
  });

  it("disables Apply when the absolute end is before the start", () => {
    renderPicker();
    openPicker();

    const startAndEnd = screen.getByRole("group", {
      name: "Start and end",
    });
    const start = within(startAndEnd).getByRole("group", { name: "Start" });
    const end = within(startAndEnd).getByRole("group", { name: "End" });

    fireEvent.click(within(start).getByRole("radio", { name: "Absolute" }));
    fireEvent.click(within(end).getByRole("radio", { name: "Absolute" }));
    fireEvent.change(within(start).getByLabelText("Start time"), {
      target: { value: "2026-11-08T12:00:00" },
    });
    fireEvent.change(within(end).getByLabelText("End time"), {
      target: { value: "2026-11-08T10:00:00" },
    });

    const apply = within(startAndEnd).getByRole("button", { name: "Apply" });
    const message = within(startAndEnd).getByText(
      "The end must be after the start.",
    );

    expect(apply).toBeDisabled();
    expect(apply).toHaveAttribute("aria-describedby", message.id);
  });

  it("disables Apply for a relative range beyond representable time", () => {
    renderPicker();
    openPicker();

    const startAndEnd = screen.getByRole("group", {
      name: "Start and end",
    });
    const start = within(startAndEnd).getByRole("group", { name: "Start" });
    fireEvent.change(within(start).getByLabelText("Count"), {
      target: { value: "999999999999999" },
    });

    expect(
      within(startAndEnd).getByRole("button", { name: "Apply" }),
    ).toBeDisabled();
  });

  it("steps the range back and forward as absolute values", () => {
    vi.useFakeTimers({ now: new Date("2026-11-09T12:00:00Z") });
    const { onRangeChange } = renderPicker();

    fireEvent.click(screen.getByRole("button", { name: "Step back" }));
    expect(onRangeChange).toHaveBeenLastCalledWith({
      from: "2026-11-07T12:00:00Z",
      to: "2026-11-08T12:00:00Z",
    });

    fireEvent.click(screen.getByRole("button", { name: "Step forward" }));
    expect(onRangeChange).toHaveBeenLastCalledWith({
      from: "2026-11-09T12:00:00Z",
      to: "2026-11-10T12:00:00Z",
    });
  });

  it("offers the four time fields", () => {
    const { onFieldChange } = renderPicker();

    const trigger = screen.getByRole("combobox", { name: "Time field" });
    fireEvent.pointerDown(trigger, { button: 0, pointerType: "mouse" });

    for (const label of ["Last event", "First event", "Created", "Closed"]) {
      expect(screen.getByRole("option", { name: label })).toBeInTheDocument();
    }

    fireEvent.click(screen.getByRole("option", { name: "Closed" }));
    expect(onFieldChange).toHaveBeenCalledWith("closedAt");
  });
});
