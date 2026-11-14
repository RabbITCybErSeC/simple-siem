import "@testing-library/jest-dom/vitest";
import { QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "../../App";
import { createQueryClient } from "../auth/session";
import { shortcutFor } from "./shortcuts";

type FetchFunction = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function stubSignedIn(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input) => {
      const path = new URL(input.toString(), "http://localhost").pathname;
      if (path !== "/api/v1/me") {
        throw new Error(`unexpected request ${path}`);
      }
      return new Response(
        JSON.stringify({
          id: "user_1",
          email: "analyst@example.test",
          displayName: "Alice Analyst",
          roles: ["ANALYST"],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }),
  );
}

function renderShell(initialPath = "/cases") {
  stubSignedIn();
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  const queryClient = createQueryClient(() => undefined);

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return router;
}

function keydown(
  init: KeyboardEventInit,
  target: HTMLElement = document.body,
): KeyboardEvent {
  const event = new KeyboardEvent("keydown", {
    bubbles: true,
    cancelable: true,
    ...init,
  });
  target.dispatchEvent(event);
  return event;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
  document.documentElement.classList.remove("dark");
});

beforeEach(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  );
  Element.prototype.scrollIntoView = vi.fn();
});

describe("shortcutFor", () => {
  it("opens the palette with Ctrl+K even inside a text field", () => {
    const input = document.createElement("input");
    document.body.append(input);
    const event = keydown({ key: "k", ctrlKey: true }, input);

    expect(shortcutFor(event, false)).toBe("palette");

    input.remove();
  });

  it("opens the palette with Meta+K", () => {
    const event = keydown({ key: "K", metaKey: true });

    expect(shortcutFor(event, false)).toBe("palette");
  });

  it("opens help with a question mark outside a text field", () => {
    const event = keydown({ key: "?" });

    expect(shortcutFor(event, false)).toBe("help");
  });

  it.each(["input", "textarea", "select"])(
    "ignores a question mark inside a %s",
    (tagName) => {
      const element = document.createElement(tagName);
      document.body.append(element);
      const event = keydown({ key: "?" }, element);

      expect(shortcutFor(event, false)).toBeUndefined();

      element.remove();
    },
  );

  it("ignores a question mark inside a contenteditable element", () => {
    const element = document.createElement("div");
    element.setAttribute("contenteditable", "true");
    document.body.append(element);
    const event = keydown({ key: "?" }, element);

    expect(shortcutFor(event, false)).toBeUndefined();

    element.remove();
  });

  it("ignores a question mark while a dialog is open", () => {
    const event = keydown({ key: "?" });

    expect(shortcutFor(event, true)).toBeUndefined();
  });
});

describe("AppShell", () => {
  it("puts the skip link first", async () => {
    renderShell();
    await screen.findByRole("heading", { name: "Cases" });

    const skipLink = screen.getByRole("link", { name: "Skip to content" });
    expect(document.querySelector("a")).toBe(skipLink);
  });

  it("persists the collapsed sidebar", async () => {
    renderShell();
    const collapse = await screen.findByRole("button", {
      name: "Collapse sidebar",
    });

    fireEvent.click(collapse);

    expect(collapse).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("link", { name: "Cases" })).toHaveAttribute(
      "aria-label",
      "Cases",
    );

    cleanup();
    renderShell();

    expect(
      await screen.findByRole("button", { name: "Expand sidebar" }),
    ).toHaveAttribute("aria-expanded", "false");
  });

  it("shows the not-found page for an unknown path", async () => {
    renderShell("/nope");

    expect(
      await screen.findByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Go to Cases" }),
    ).toBeInTheDocument();
  });

  it("updates the title and focuses the heading after navigation", async () => {
    const router = renderShell("/nope");
    await screen.findByRole("heading", { name: "Page not found" });
    fireEvent.click(screen.getByRole("link", { name: "Go to Cases" }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
    const heading = await screen.findByRole("heading", { name: "Cases" });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
    await waitFor(() => {
      expect(document.title).toBe("Cases · Simple SIEM");
    });
  });
});

describe("CommandPalette and shortcuts", () => {
  async function openPalette() {
    renderShell();
    await screen.findByRole("heading", { name: "Cases" });
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    return screen.findByPlaceholderText("Type a command…");
  }

  it("opens and closes with Ctrl+K", async () => {
    await openPalette();

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });

    await waitFor(() => {
      expect(
        screen.queryByPlaceholderText("Type a command…"),
      ).not.toBeInTheDocument();
    });
  });

  it("filters commands as the user types", async () => {
    const input = await openPalette();

    fireEvent.change(input, { target: { value: "dark" } });

    expect(await screen.findByText("Theme: Dark")).toBeInTheDocument();
    expect(screen.queryByText("Go to Cases")).not.toBeInTheDocument();
  });

  it("shows No results. for an unmatched query", async () => {
    const input = await openPalette();

    fireEvent.change(input, { target: { value: "zzzz" } });

    expect(await screen.findByText("No results.")).toBeInTheDocument();
  });

  it("runs the dark theme command with Enter and closes", async () => {
    const input = await openPalette();
    fireEvent.change(input, { target: { value: "dark" } });

    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => {
      expect(
        screen.queryByPlaceholderText("Type a command…"),
      ).not.toBeInTheDocument();
    });
    expect(document.documentElement).toHaveClass("dark");
    expect(localStorage.getItem("simple-siem.theme")).toBe("dark");
  });

  it("opens the shortcuts dialog with a question mark", async () => {
    renderShell();
    await screen.findByRole("heading", { name: "Cases" });

    fireEvent.keyDown(document.body, { key: "?" });

    expect(
      await screen.findByRole("dialog", { name: "Keyboard shortcuts" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Open the command palette")).toHaveLength(2);
    expect(screen.getByText("Show keyboard shortcuts")).toBeInTheDocument();
    expect(screen.getByText("Ctrl")).toBeInTheDocument();
    expect(screen.getByText("⌘")).toBeInTheDocument();
  });
});
