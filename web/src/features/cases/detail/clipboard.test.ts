import { afterEach, describe, expect, it, vi } from "vitest";
import { absoluteLink, copyText } from "./clipboard";

const NOW = new Date("2026-11-09T12:00:00Z");
const ORIGIN = "https://siem.example.test";

function absolute(search: string, pathname = "/cases/312"): string {
  return absoluteLink({ origin: ORIGIN, pathname, search }, NOW);
}

describe("absoluteLink", () => {
  it("freezes the default range when both ends are absent", () => {
    expect(absolute("?view=timeline")).toBe(
      "https://siem.example.test/cases/312?view=timeline&from=2026-11-08T12:00:00Z&to=2026-11-09T12:00:00Z",
    );
  });

  it("replaces relative ends in place and keeps the other parameters", () => {
    expect(absolute("?from=now-7d&to=now&tab=closed")).toBe(
      "https://siem.example.test/cases/312?from=2026-11-02T12:00:00Z&to=2026-11-09T12:00:00Z&tab=closed",
    );
  });

  it("resolves now/d and now/w", () => {
    expect(absolute("?from=now/d&to=now")).toBe(
      "https://siem.example.test/cases/312?from=2026-11-09T00:00:00Z&to=2026-11-09T12:00:00Z",
    );
    expect(absolute("?from=now/w&to=now")).toBe(
      "https://siem.example.test/cases/312?from=2026-11-09T00:00:00Z&to=2026-11-09T12:00:00Z",
    );
  });

  it("leaves absolute ends and every other parameter untouched", () => {
    const search =
      "?tab=closed&from=2026-11-01T10:00:00Z&to=2026-11-07T10:00:00Z&sort=createdAt:asc";

    expect(absolute(search)).toBe(`${ORIGIN}/cases/312${search}`);
  });

  it("replaces one relative end and keeps an absolute one", () => {
    expect(
      absolute("?from=now-1h&to=2026-11-09T11:30:00Z"),
    ).toBe(
      "https://siem.example.test/cases/312?from=2026-11-09T11:00:00Z&to=2026-11-09T11:30:00Z",
    );
  });

  it("freezes an empty search", () => {
    expect(absolute("")).toBe(
      "https://siem.example.test/cases/312?from=2026-11-08T12:00:00Z&to=2026-11-09T12:00:00Z",
    );
  });

  it("falls back to the default range beyond representable time", () => {
    expect(absolute("?from=now-999999999999999h&to=now")).toBe(
      "https://siem.example.test/cases/312?from=2026-11-08T12:00:00Z&to=2026-11-09T12:00:00Z",
    );
  });
});

type ClipboardStub = { writeText: (text: string) => Promise<unknown> };

function setClipboard(clipboard: ClipboardStub | undefined) {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
}

describe("copyText", () => {
  afterEach(() => {
    setClipboard(undefined);
  });

  it("writes the text with the clipboard API", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    setClipboard({ writeText });

    await expect(copyText("principal.ip=10.0.0.5")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("principal.ip=10.0.0.5");
  });

  it("reports failure when the clipboard API is missing", async () => {
    setClipboard(undefined);

    await expect(copyText("hello")).resolves.toBe(false);
  });

  it("reports failure when the write rejects", async () => {
    setClipboard({
      writeText: vi.fn(() => Promise.reject(new Error("denied"))),
    });

    await expect(copyText("hello")).resolves.toBe(false);
  });
});
