// Page-wide CSP setup; must evaluate before any feature builds a Zod schema.
import "./zod-setup";
import { QueryClientProvider } from "@tanstack/react-query";
import { setNonce } from "get-nonce";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import { routes } from "./App";
import { createQueryClient, loginPath } from "./features/auth/session";
import { applyTheme, readThemePreference } from "./theme/theme";
import "./index.css";

const nonce = document.querySelector<HTMLMetaElement>(
  'meta[property="csp-nonce"]',
)?.nonce;
if (nonce) {
  setNonce(nonce);
}

applyTheme(readThemePreference());

const router = createBrowserRouter(routes);
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

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing root element");
}

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
