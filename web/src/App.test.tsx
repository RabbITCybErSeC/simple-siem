import "@testing-library/jest-dom/vitest";
import { QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "./App";
import { createQueryClient } from "./features/auth/session";

type FetchFunction = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function stubSignedIn(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input) => {
      const path = new URL(input.toString(), "http://localhost").pathname;
      if (path !== "/api/v1/me") {
        throw new Error(`unexpected request ${path}`);
      }
      return jsonResponse({
        id: "user_1",
        email: "analyst@example.test",
        displayName: "Alice Analyst",
        roles: ["ANALYST"],
      });
    }),
  );
}

function stubSignedOut(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn<FetchFunction>(async (input) => {
      const path = new URL(input.toString(), "http://localhost").pathname;
      if (path !== "/api/v1/me") {
        throw new Error(`unexpected request ${path}`);
      }
      return jsonResponse(
        {
          error: {
            code: "AUTHENTICATION_REQUIRED",
            message: "Authentication required",
          },
        },
        401,
      );
    }),
  );
}

function renderRoute(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  const queryClient = createQueryClient(() => undefined);

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return router;
}

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", ResizeObserverStub);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("routes", () => {
  it("sends the landing route to Cases", async () => {
    stubSignedIn();
    const router = renderRoute("/");

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
    expect(
      await screen.findByRole("heading", { name: "Cases" }),
    ).toBeInTheDocument();
  });

  it("shows the login screen to a signed-out visitor", async () => {
    stubSignedOut();
    renderRoute("/login");

    expect(
      await screen.findByRole("heading", {
        name: "Sign in to Simple SIEM",
      }),
    ).toBeInTheDocument();
  });
});
