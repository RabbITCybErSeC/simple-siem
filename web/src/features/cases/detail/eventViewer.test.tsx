import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EventViewer, flattenUdm } from "./EventViewer";
import type { TimelineEvidenceEntry } from "./types";

const AT = "2026-11-09T10:04:02Z";
const LATER_AT = "2026-11-09T10:06:00Z";

const UDM: Record<string, unknown> = {
  metadata: { event_type: "USER_LOGIN" },
  principal: {
    user: { userid: "jdoe" },
    hostname: "web-01",
    ip: ["203.0.113.9", "203.0.113.10"],
  },
};

const ENTRY: TimelineEvidenceEntry = {
  id: "tl_1",
  kind: "EVIDENCE",
  at: AT,
  alertId: "alert_9",
  sourceId: "evt-123",
  udm: UDM,
};

function entryAt(
  id: string,
  at: string,
  udm: Record<string, unknown>,
): TimelineEvidenceEntry {
  return { ...ENTRY, id, at, udm };
}

function renderViewer(
  entries: TimelineEvidenceEntry[],
  onCopy: (value: string) => Promise<boolean> = async () => true,
) {
  return render(
    <EventViewer entries={entries} timeZone="utc" onCopy={onCopy} />,
  );
}

function rowAt(container: HTMLElement, at: string): HTMLElement {
  const time = container.querySelector(`time[datetime="${at}"]`);
  const row = time?.closest("tr") ?? null;
  if (row === null) {
    throw new Error(`no evidence row with time ${at}`);
  }
  return row;
}

function showFieldsButton(row: HTMLElement): HTMLElement {
  return within(row).getByRole("button", { name: /^Show fields for / });
}

function detailRow(row: HTMLElement): HTMLElement {
  const id = showFieldsButton(row).getAttribute("aria-controls");
  if (id === null) {
    throw new Error("the button has no aria-controls");
  }
  const detail = document.getElementById(id);
  if (detail === null) {
    throw new Error(`no detail row with id ${id}`);
  }
  return detail;
}

function fieldPaths(detail: HTMLElement): string[] {
  return Array.from(detail.querySelectorAll("th[scope='row']")).map(
    (cell) => cell.textContent ?? "",
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("flattenUdm", () => {
  it("flattens nested objects and arrays to dotted paths in JSON order", () => {
    expect(
      flattenUdm({
        principal: { ip: ["203.0.113.9"], user: { userid: "jdoe" } },
        metadata: { event_type: "USER_LOGIN" },
        tags: ["phish", "urgent"],
        empty: {},
        emptyList: [],
        none: null,
        objects: [{ c: 1 }],
      }),
    ).toEqual([
      { path: "principal.ip[0]", value: "203.0.113.9" },
      { path: "principal.user.userid", value: "jdoe" },
      { path: "metadata.event_type", value: "USER_LOGIN" },
      { path: "tags[0]", value: "phish" },
      { path: "tags[1]", value: "urgent" },
      { path: "none", value: "null" },
      { path: "objects[0].c", value: "1" },
    ]);
  });
});

describe("EventViewer", () => {
  it("shows the documented columns and a dash for missing values", () => {
    const bare = entryAt("tl_2", LATER_AT, { metadata: {} });
    const { container } = renderViewer([ENTRY, bare]);

    const table = screen.getByRole("table", { name: "Evidence events" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Time", "User", "Host", "Action", "Source IP"]);

    const row = rowAt(container, AT);
    expect(within(row).getByText("jdoe")).toHaveClass("font-mono");
    expect(within(row).getByText("web-01")).toHaveClass("font-mono");
    expect(within(row).getByText("USER_LOGIN")).toHaveClass("font-mono");
    expect(within(row).getByText("203.0.113.9")).toHaveClass("font-mono");

    const time = row.querySelector(`time[datetime="${AT}"]`);
    expect(time).not.toBeNull();
    expect(time).toHaveAttribute("title");
    expect(showFieldsButton(row)).toHaveAccessibleName(/^Show fields for /);

    const missing = within(rowAt(container, LATER_AT)).getAllByRole("cell");
    expect(missing).toHaveLength(5);
    expect(missing.slice(1).map((cell) => cell.textContent)).toEqual([
      "—",
      "—",
      "—",
      "—",
    ]);
  });

  it("keeps the time, alert, and source id for an event no longer cached", () => {
    const uncached: TimelineEvidenceEntry = {
      ...ENTRY,
      id: "tl_uncached",
      at: LATER_AT,
      sourceId: "evt-uncached",
      udm: null,
    };
    const { container } = renderViewer([uncached]);
    const row = rowAt(container, LATER_AT);

    expect(
      within(row).getByText("Event no longer cached"),
    ).toBeInTheDocument();
    expect(row).toHaveTextContent("alert_9");
    expect(row).toHaveTextContent("evt-uncached");
    expect(row.querySelector(`time[datetime="${LATER_AT}"]`)).not.toBeNull();
    expect(within(row).queryAllByRole("button")).toHaveLength(0);
  });

  it("expands and collapses rows and keeps expanded entries by id", () => {
    const later = entryAt("tl_2", LATER_AT, { metadata: { event_type: "DNS" } });
    const onCopy = vi.fn(async () => true);
    const { container, rerender } = renderViewer([ENTRY], onCopy);

    const toggle = showFieldsButton(rowAt(container, AT));
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(fieldPaths(detailRow(rowAt(container, AT)))).toEqual([
      "metadata.event_type",
      "principal.user.userid",
      "principal.hostname",
      "principal.ip[0]",
      "principal.ip[1]",
    ]);

    rerender(
      <EventViewer entries={[ENTRY, later]} timeZone="utc" onCopy={onCopy} />,
    );
    expect(showFieldsButton(rowAt(container, AT))).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    expect(
      within(detailRow(rowAt(container, AT))).getByRole("rowheader", {
        name: "principal.user.userid",
      }),
    ).toBeInTheDocument();
    expect(showFieldsButton(rowAt(container, LATER_AT))).toHaveAttribute(
      "aria-expanded",
      "false",
    );

    fireEvent.click(showFieldsButton(rowAt(container, AT)));
    expect(showFieldsButton(rowAt(container, AT))).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    expect(document.querySelector('[id^="event-fields-"]')).toBeNull();
  });

  it("copies each field value with one button per field and reports it", async () => {
    const onCopy = vi.fn(async () => true);
    const { container } = renderViewer([ENTRY], onCopy);

    fireEvent.click(showFieldsButton(rowAt(container, AT)));
    const detail = detailRow(rowAt(container, AT));
    const copyButtons = within(detail).getAllByRole("button", {
      name: /^Copy /,
    });
    expect(copyButtons).toHaveLength(flattenUdm(ENTRY.udm).length);

    fireEvent.click(
      within(detail).getByRole("button", {
        name: "Copy principal.user.userid",
      }),
    );
    await waitFor(() => {
      expect(onCopy).toHaveBeenCalledWith("jdoe");
    });

    const status = screen.getByRole("status");
    await waitFor(() => {
      expect(status).toHaveTextContent("Copied");
    });

    onCopy.mockResolvedValueOnce(false);
    fireEvent.click(
      within(detail).getByRole("button", { name: "Copy metadata.event_type" }),
    );
    await waitFor(() => {
      expect(status).toHaveTextContent("Could not copy");
    });
  });

  it("shows the raw UDM JSON in a pre", () => {
    const { container } = renderViewer([ENTRY]);
    fireEvent.click(showFieldsButton(rowAt(container, AT)));

    const detail = detailRow(rowAt(container, AT));
    const raw = within(detail).getByRole("button", { name: "Raw JSON" });
    expect(raw).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(raw);
    expect(raw).toHaveAttribute("aria-expanded", "true");

    const id = raw.getAttribute("aria-controls");
    const pre = id === null ? null : document.getElementById(id);
    expect(pre?.tagName).toBe("PRE");
    expect(pre?.textContent).toBe(JSON.stringify(UDM, null, 2));
  });

  it("renders a markup value as text without creating an element", () => {
    const markup = "<img src=x onerror=alert(1)>";
    const { container } = renderViewer([
      entryAt("tl_markup", AT, { principal: { hostname: markup } }),
    ]);

    const row = rowAt(container, AT);
    expect(within(row).getByText(markup)).toBeInTheDocument();

    fireEvent.click(showFieldsButton(row));
    expect(within(detailRow(row)).getByText(markup)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
