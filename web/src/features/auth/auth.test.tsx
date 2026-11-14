import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import {
  createMemoryRouter,
  RouterProvider,
} from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { get } from "../../api/client";
import { LoginPage } from "./LoginPage";
import {
  createQueryClient,
  loginPath,
  RequireSession,
  safeNextPath,
  useSignOut,
} from "./session";

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

function signedOut(): Response {
  return jsonResponse(
    { error: { code: "AUTHENTICATION_REQUIRED", message: "Authentication required" } },
    401,
  );
}

function signedInUser(displayName = "Alice Analyst"): Response {
  return jsonResponse({
    id: "user_1",
    email: "analyst@example.test",
    displayName,
    roles: ["ANALYST"],
  });
}

function stubApi(routes: Record<string, () => Response>): void {
  const fetchMock = vi.fn<FetchFunction>(async (input, init) => {
    const rawUrl = typeof input === "string" ? input : input.toString();
    const path = new URL(rawUrl, "http://localhost").pathname;
    const key = `${init?.method ?? "GET"} ${path}`;
    const route = routes[key];
    if (!route) {
      throw new Error(`unexpected request ${key}`);
    }
    return route();
  });
  vi.stubGlobal("fetch", fetchMock);
}

function renderLogin(initialEntry = "/login") {
  const router = createMemoryRouter(
    [
      { path: "/login", element: <LoginPage /> },
      { path: "/cases", element: <p>Cases destination</p> },
    ],
    { initialEntries: [initialEntry] },
  );
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return { router, queryClient };
}

function renderSession(initialEntry: string) {
  const router = createMemoryRouter(
    [
      { path: "/login", element: <LoginPage /> },
      {
        element: <RequireSession />,
        children: [
          { path: "/cases", element: <p>Cases page</p> },
          { path: "/nope", element: <p>Not found page</p> },
        ],
      },
    ],
    { initialEntries: [initialEntry] },
  );
  const queryClient = createQueryClient(() => {
    queryClient.clear();
    if (router.state.location.pathname !== "/login") {
      void router.navigate(
        loginPath(
          router.state.location.pathname + router.state.location.search,
          "expired",
        ),
      );
    }
  });

  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );

  return { router, queryClient };
}

function SignOutProbe() {
  const signOut = useSignOut();

  return <button onClick={() => signOut.mutate()}>Sign out</button>;
}

function fillCredentials(email: string, password: string): void {
  fireEvent.change(screen.getByLabelText("Email"), {
    target: { value: email },
  });
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: password },
  });
}

function submitForm(): void {
  const form = document.querySelector("form");
  if (!form) {
    throw new Error("missing login form");
  }
  fireEvent.submit(form);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
  sessionStorage.clear();
});

describe("safeNextPath", () => {
  it.each([
    ["an absolute URL", "https://evil.example"],
    ["a protocol-relative URL", "//evil.example"],
    ["a backslash URL", "/\\evil.example"],
    ["a javascript scheme", "javascript:alert(1)"],
    ["the login page", "/login"],
    ["the login page with a query", "/login?next=%2Fcases"],
    ["an encoded login page", "/%6Cogin"],
    ["an encoded protocol-relative URL", "%2F%2Fevil.example"],
    ["an encoded double slash", "/%2F%2Fevil.example"],
    ["an encoded scheme after a slash", "/%6Aavascript%3Aalert(1)"],
  ])("rejects %s", (_label, next) => {
    expect(safeNextPath(next)).toBe("/cases");
  });

  it("defaults to Cases without a next value", () => {
    expect(safeNextPath(null)).toBe("/cases");
  });

  it.each(["/cases", "/cases?status=open", "/nope#details"])(
    "follows the same-origin path %s",
    (next) => {
      expect(safeNextPath(next)).toBe(next);
    },
  );
});

describe("LoginPage", () => {
  it("sends nothing and focuses the email field on an empty submit", async () => {
    const fetchMock = vi.fn<FetchFunction>(async (input) => {
      const path = new URL(input.toString(), "http://localhost").pathname;
      if (path === "/api/v1/me") {
        return signedOut();
      }
      throw new Error(`unexpected request ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    renderLogin();

    submitForm();

    await waitFor(() => expect(screen.getByLabelText("Email")).toHaveFocus());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText("Email")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(screen.getByLabelText("Password")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(screen.getByLabelText("Email")).toHaveAccessibleDescription(
      "Enter a valid email address.",
    );
    expect(screen.getByLabelText("Password")).toHaveAccessibleDescription(
      "Enter your password.",
    );
  });

  it("shows the generic message after a 401 and keeps the email", async () => {
    stubApi({
      "GET /api/v1/me": signedOut,
      "POST /api/v1/auth/login": () => signedOut(),
    });
    renderLogin("/login?next=%2Fcases");

    fillCredentials("analyst@example.test", "wrong password");
    submitForm();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Email or password is incorrect.",
    );
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.getByLabelText("Email")).toHaveValue("analyst@example.test");
  });

  it("shows the rate-limit message after a 429", async () => {
    stubApi({
      "GET /api/v1/me": signedOut,
      "POST /api/v1/auth/login": () =>
        jsonResponse(
          {
            error: {
              code: "RATE_LIMITED",
              message: "Too many attempts.",
            },
          },
          429,
        ),
    });
    renderLogin();

    fillCredentials("analyst@example.test", "correct horse battery staple");
    submitForm();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Too many attempts. Wait a minute and try again.",
    );
  });

  it("sets the user, stores no token, and follows a safe next path", async () => {
    const user = {
      id: "user_1",
      email: "analyst@example.test",
      displayName: "Alice Analyst",
      roles: ["ANALYST"],
    };
    stubApi({
      "GET /api/v1/me": signedOut,
      "POST /api/v1/auth/login": () =>
        jsonResponse({
          expiresAt: "2026-11-14T10:00:00Z",
          user,
          sessionToken: "s3cr3t-session-token",
        }),
    });
    const { router, queryClient } = renderLogin(
      "/login?next=%2Fcases%3Fstatus%3Dopen",
    );

    fillCredentials("analyst@example.test", "correct horse battery staple");
    submitForm();

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
    expect(router.state.location.search).toBe("?status=open");
    expect(queryClient.getQueryData(["me"])).toEqual(user);

    const storedValues = [
      ...Object.keys(localStorage).map((key) => localStorage.getItem(key)),
      ...Object.keys(sessionStorage).map((key) => sessionStorage.getItem(key)),
    ];
    expect(storedValues.join(" ")).not.toContain("s3cr3t-session-token");
    expect(document.cookie).not.toContain("s3cr3t-session-token");
  });
});

describe("session handling", () => {
  it("redirects a signed-out visitor with the next path and no message", async () => {
    stubApi({ "GET /api/v1/me": signedOut });
    const { router } = renderSession("/cases?scope=mine");

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/login");
    });
    expect(router.state.location.search).toBe(
      "?next=%2Fcases%3Fscope%3Dmine",
    );
    expect(
      screen.queryByText("Your session ended. Sign in again."),
    ).not.toBeInTheDocument();
  });

  it("clears the cache and explains a 401 from a later call", async () => {
    let signedIn = true;
    stubApi({
      "GET /api/v1/me": () => (signedIn ? signedInUser() : signedOut()),
      "GET /api/v1/later": () => signedOut(),
    });
    const { router, queryClient } = renderSession("/cases");
    await screen.findByText("Cases page");

    signedIn = false;
    await act(async () => {
      await queryClient
        .fetchQuery({
          queryKey: ["later"],
          queryFn: () => get("/later"),
        })
        .catch(() => undefined);
    });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/login");
    });
    expect(router.state.location.search).toContain("reason=expired");
    expect(
      await screen.findByText("Your session ended. Sign in again."),
    ).toBeInTheDocument();
    expect(queryClient.getQueryData(["me"])).toBeUndefined();
  });

  it("revalidates the session after client-side navigation", async () => {
    let signedIn = true;
    stubApi({
      "GET /api/v1/me": () => (signedIn ? signedInUser() : signedOut()),
    });
    const { router } = renderSession("/cases");
    await screen.findByText("Cases page");

    signedIn = false;
    await act(async () => {
      await router.navigate("/nope");
    });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/login");
    });
    expect(router.state.location.search).toContain("reason=expired");
    expect(
      await screen.findByText("Your session ended. Sign in again."),
    ).toBeInTheDocument();
  });

  it("offers Retry when the server is unreachable", async () => {
    let meCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<FetchFunction>(async (input) => {
        const path = new URL(input.toString(), "http://localhost").pathname;
        if (path !== "/api/v1/me") {
          throw new Error(`unexpected request ${path}`);
        }
        meCalls += 1;
        if (meCalls <= 3) {
          throw new TypeError("Failed to fetch");
        }
        return signedInUser();
      }),
    );
    renderSession("/cases");

    expect(
      await screen.findByRole(
        "heading",
        { name: "Cannot reach Simple SIEM." },
        { timeout: 6000 },
      ),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Cases page")).toBeInTheDocument();
  });

  it("reaches the login screen when sign out fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<FetchFunction>(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    const router = createMemoryRouter(
      [
        { path: "/cases", element: <SignOutProbe /> },
        { path: "/login", element: <p>Login destination</p> },
      ],
      { initialEntries: ["/cases"] },
    );
    const queryClient = createQueryClient(() => undefined);
    queryClient.setQueryData(["me"], {
      id: "user_1",
      email: "analyst@example.test",
      displayName: "Alice Analyst",
      roles: ["ANALYST"],
    });

    render(
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/login");
    });
    expect(queryClient.getQueryData(["me"])).toBeUndefined();
  });

  it("redirects from the login screen while signed in", async () => {
    stubApi({ "GET /api/v1/me": () => signedInUser() });
    const { router } = renderSession("/login?next=%2Fcases");

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
    expect(screen.getByText("Cases page")).toBeInTheDocument();
  });
});
