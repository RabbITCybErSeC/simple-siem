import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useTimeZone, writeTimeZone } from "./timeZone";

const STORAGE_KEY = "simple-siem.time-zone";

beforeEach(() => {
  window.localStorage.clear();
  writeTimeZone("local");
});

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe("useTimeZone", () => {
  it("follows a storage change made by another tab", () => {
    const { result } = renderHook(() => useTimeZone());
    expect(result.current).toBe("local");

    act(() => {
      window.localStorage.setItem(STORAGE_KEY, "utc");
      window.dispatchEvent(new StorageEvent("storage", { key: STORAGE_KEY }));
    });

    expect(result.current).toBe("utc");
  });
});
