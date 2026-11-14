import "@testing-library/jest-dom/vitest";
import { QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
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

function stubSignedIn(
  logout: () => Response = () => new Response(null, { status: 204 }),
): void {
  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input) => {
      const path = new URL(input.toString(), "http://localhost").pathname;
      if (path === "/api/v1/auth/logout") {
        return logout();
      }
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

function renderShell(
  initialPath = "/cases",
  logout?: () => Response,
) {
  stubSignedIn(logout);
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

  it("still toggles the palette while the palette is open", () => {
    const event = keydown({ key: "k", ctrlKey: true });

    expect(shortcutFor(event, true, false)).toBe("palette");
  });

  it("ignores Ctrl+K while the shortcuts dialog is open", () => {
    const event = keydown({ key: "k", ctrlKey: true });

    expect(shortcutFor(event, true, true)).toBeUndefined();
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

    fireEvent.change(input, { target: { value: "vvvv" } });

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

  it("lists the case list shortcuts in the dialog", async () => {
    renderShell();
    await screen.findByRole("heading", { name: "Cases" });

    fireEvent.keyDown(document.body, { key: "?" });

    const dialog = await screen.findByRole("dialog", {
      name: "Keyboard shortcuts",
    });
    expect(within(dialog).getByText("Next case")).toBeInTheDocument();
    expect(within(dialog).getByText("Previous case")).toBeInTheDocument();
    expect(within(dialog).getByText("Open case")).toBeInTheDocument();
    expect(within(dialog).getByText("Assign to me")).toBeInTheDocument();
    expect(within(dialog).getByText("Select case")).toBeInTheDocument();
    expect(within(dialog).getByText("Close case")).toBeInTheDocument();
    expect(within(dialog).getByText("Close case detail")).toBeInTheDocument();
    expect(within(dialog).getAllByText("Cases list")).toHaveLength(7);
  });

  it("does not stack the palette on the shortcuts dialog", async () => {
    renderShell();
    await screen.findByRole("heading", { name: "Cases" });
    fireEvent.keyDown(document.body, { key: "?" });
    const dialog = await screen.findByRole("dialog", {
      name: "Keyboard shortcuts",
    });

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });

    expect(
      screen.queryByPlaceholderText("Type a command…"),
    ).not.toBeInTheDocument();
    expect(dialog).toBeInTheDocument();
  });

  it("reports a failed sign out in the header and stays on Cases", async () => {
    const router = renderShell(
      "/cases",
      () =>
        new Response(
          JSON.stringify({
            error: { code: "INTERNAL_ERROR", message: "boom" },
          }),
          {
            status: 500,
            headers: { "Content-Type": "application/json" },
          },
        ),
    );
    await screen.findByRole("heading", { name: "Cases" });
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByPlaceholderText("Type a command…");
    fireEvent.change(input, { target: { value: "sign out" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Sign out failed. Try again.",
    );
    expect(router.state.location.pathname).toBe("/cases");
    expect(
      screen.getByRole("heading", { name: "Cases" }),
    ).toBeInTheDocument();
  });
});

describe("review fixes: palette focus", () => {
  it("returns focus to the palette opener for a search-only case command", async () => {
    const router = renderShell("/cases");
    const opener = await screen.findByRole("button", {
      name: /Search or run a command/,
    });
    opener.focus();
    fireEvent.click(opener);
    const input = await screen.findByPlaceholderText("Type a command…");
    fireEvent.change(input, { target: { value: "Cases: Closed" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => {
      expect(
        new URLSearchParams(router.state.location.search).get("tab"),
      ).toBe("closed");
    });
    expect(opener).toHaveFocus();
  });
});
