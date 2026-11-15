import {
  MutationCache,
  QueryCache,
  QueryClient,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { Navigate, Outlet, useLocation, useNavigate } from "react-router";
import { ApiError, get, post } from "../../api/client";
import type { LoginRequest, LoginResponse, User } from "../../api/types";
import { Button } from "../../components/ui/button";

export type CurrentUser = Pick<
  User,
  "id" | "email" | "displayName" | "roles"
>;

const CASES_PATH = "/cases";
const ME_QUERY_KEY = ["me"] as const;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export function createQueryClient(onUnauthorized: () => void): QueryClient {
  const handleError = (error: Error) => {
    if (error instanceof ApiError && error.status === 401) {
      onUnauthorized();
    }
  };

  return new QueryClient({
    queryCache: new QueryCache({
      onError: (error, query) => {
        const isFirstLoad =
          query.state.data === undefined &&
          ignoresUnauthorized(query.meta);
        if (!isFirstLoad) {
          handleError(error);
        }
      },
    }),
    mutationCache: new MutationCache({
      onError: (error, _variables, _context, mutation) => {
        if (!ignoresUnauthorized(mutation.meta)) {
          handleError(error);
        }
      },
    }),
    defaultOptions: {
      queries: {
        retry: (count, error) =>
          !(
            error instanceof ApiError &&
            error.status >= 400 &&
            error.status < 500
          ) && count < 2,
        refetchOnWindowFocus: false,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

export function useCurrentUser() {
  return useQuery({
    queryKey: ME_QUERY_KEY,
    queryFn: () => get<CurrentUser>("/me"),
    meta: { ignoreUnauthorized: true },
    staleTime: 30_000,
  });
}

export function useSignIn() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (request: LoginRequest) =>
      post<LoginResponse>("/auth/login", request),
    meta: { ignoreUnauthorized: true },
    onSuccess: (response) => {
      queryClient.setQueryData(ME_QUERY_KEY, response.user);
    },
  });
}

export function useSignOut() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const finish = () => {
    queryClient.clear();
    void navigate("/login");
  };

  return useMutation({
    mutationFn: () => post<void>("/auth/logout"),
    meta: { ignoreUnauthorized: true },
    onSuccess: finish,
    onError: (error) => {
      if (error instanceof ApiError && error.status === 401) {
        finish();
      }
    },
  });
}

export type SessionView = "loading" | "login" | "offline" | "ready";

export function sessionView(
  data: CurrentUser | undefined,
  error: Error | null,
  isPending: boolean,
): SessionView {
  if (isPending) {
    return "loading";
  }

  if (!data && error instanceof ApiError && error.status === 401) {
    return "login";
  }

  if (data) {
    return "ready";
  }

  if (error) {
    return "offline";
  }

  return "ready";
}

export function RequireSession() {
  const location = useLocation();
  const queryClient = useQueryClient();
  const previousLocationKey = useRef(location.key);
  const { data, error, isPending, refetch } = useCurrentUser();

  // Re-confirm the session after client-side navigation so a revoked session
  // is noticed without waiting for the next data call.
  useEffect(() => {
    if (previousLocationKey.current === location.key) {
      return;
    }
    previousLocationKey.current = location.key;
    void queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY });
  }, [location.key, queryClient]);

  const view = sessionView(data, error, isPending);

  if (view === "loading") {
    return (
      <main className="flex min-h-svh items-center justify-center bg-background p-6 text-foreground">
        <p aria-busy="true" className="text-muted-foreground">
          Loading…
        </p>
      </main>
    );
  }

  if (view === "login") {
    return (
      <Navigate
        to={loginPath(location.pathname + location.search)}
        replace
      />
    );
  }

  if (view === "offline") {
    return (
      <main className="flex min-h-svh items-center justify-center bg-background p-6 text-foreground">
        <section className="w-full max-w-sm rounded-xl border border-border bg-card p-8 text-card-foreground shadow-sm">
          <h1 className="text-2xl font-semibold tracking-tight">
            Cannot reach Simple SIEM.
          </h1>
          <Button className="mt-4" onClick={() => void refetch()}>
            Retry
          </Button>
        </section>
      </main>
    );
  }

  return <Outlet />;
}

function ignoresUnauthorized(
  meta: Record<string, unknown> | undefined,
): boolean {
  return meta?.ignoreUnauthorized === true;
}

function isPath(value: string): boolean {
  if (
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.startsWith("/\\")
  ) {
    return false;
  }

  const firstSegment = value.slice(1).split("/")[0];
  return !firstSegment.includes(":");
}

function decodePath(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function isLoginPath(value: string): boolean {
  try {
    const url = new URL(value, window.location.origin);
    return (
      url.origin === window.location.origin && url.pathname === "/login"
    );
  } catch {
    return false;
  }
}

export function safeNextPath(next: string | null): string {
  if (next === null || CONTROL_CHARACTERS.test(next)) {
    return CASES_PATH;
  }

  const decoded = decodePath(next);
  if (
    decoded === null ||
    !isPath(next) ||
    !isPath(decoded) ||
    isLoginPath(next) ||
    isLoginPath(decoded)
  ) {
    return CASES_PATH;
  }

  let url: URL;
  try {
    url = new URL(next, window.location.origin);
  } catch {
    return CASES_PATH;
  }
  if (url.origin !== window.location.origin || url.pathname === "/login") {
    return CASES_PATH;
  }

  return `${url.pathname}${url.search}${url.hash}`;
}

export function loginPath(next: string, reason?: "expired"): string {
  const params = new URLSearchParams({ next });
  if (reason !== undefined) {
    params.set("reason", reason);
  }
  return `/login?${params.toString()}`;
}
