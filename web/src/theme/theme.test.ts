import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyTheme,
  readThemePreference,
  writeThemePreference,
} from "./theme";

const STORAGE_KEY = "simple-siem.theme";

interface FakeMediaQuery {
  setMatches(matches: boolean): void;
  listenerCount(): number;
}

function stubMediaQuery(initialMatches: boolean): FakeMediaQuery {
  let matches = initialMatches;
  const listeners = new Set<() => void>();
  const mediaQuery = {
    get matches() {
      return matches;
    },
    media: "(prefers-color-scheme: dark)",
    addEventListener: vi.fn((_event: string, listener: () => void) => {
      listeners.add(listener);
    }),
    removeEventListener: vi.fn((_event: string, listener: () => void) => {
      listeners.delete(listener);
    }),
  };

  vi.stubGlobal("matchMedia", vi.fn(() => mediaQuery));

  return {
    setMatches(nextMatches: boolean) {
      matches = nextMatches;
      for (const listener of listeners) {
        listener();
      }
    },
    listenerCount() {
      return listeners.size;
    },
  };
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.classList.remove("dark");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("readThemePreference", () => {
  it("defaults to system without a stored preference", () => {
    expect(readThemePreference()).toBe("system");
  });

  it.each(["light", "dark"] as const)("reads a stored %s preference", (preference) => {
    localStorage.setItem(STORAGE_KEY, preference);

    expect(readThemePreference()).toBe(preference);
  });

  it("falls back to system for an unknown value", () => {
    localStorage.setItem(STORAGE_KEY, "sepia");

    expect(readThemePreference()).toBe("system");
  });

  it("falls back to system when storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage denied");
    });

    expect(() => readThemePreference()).not.toThrow();
    expect(readThemePreference()).toBe("system");
  });
});

describe("writeThemePreference", () => {
  it("stores the preference", () => {
    writeThemePreference("dark");

    expect(localStorage.getItem(STORAGE_KEY)).toBe("dark");
  });

  it("ignores storage errors", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage denied");
    });

    expect(() => writeThemePreference("light")).not.toThrow();
  });
});

describe("applyTheme", () => {
  it("applies a dark preference", () => {
    applyTheme("dark");

    expect(document.documentElement).toHaveClass("dark");
  });

  it("applies a light preference", () => {
    document.documentElement.classList.add("dark");

    applyTheme("light");

    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("follows the system preference", () => {
    stubMediaQuery(true);

    applyTheme("system");

    expect(document.documentElement).toHaveClass("dark");
  });

  it("tracks media changes under system", () => {
    const media = stubMediaQuery(false);
    const cleanup = applyTheme("system");

    expect(document.documentElement).not.toHaveClass("dark");

    media.setMatches(true);
    expect(document.documentElement).toHaveClass("dark");

    media.setMatches(false);
    expect(document.documentElement).not.toHaveClass("dark");

    cleanup();
  });

  it("ignores media changes under an explicit preference", () => {
    const media = stubMediaQuery(false);
    applyTheme("dark");

    media.setMatches(true);
    media.setMatches(false);

    expect(document.documentElement).toHaveClass("dark");
    expect(media.listenerCount()).toBe(0);
  });

  it("removes the media listener on cleanup", () => {
    const media = stubMediaQuery(false);
    const cleanup = applyTheme("system");

    expect(media.listenerCount()).toBe(1);

    cleanup();
    expect(media.listenerCount()).toBe(0);

    media.setMatches(true);
    expect(document.documentElement).not.toHaveClass("dark");
  });
});
