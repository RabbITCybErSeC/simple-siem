import type { RouteObject } from "react-router";
import { Navigate } from "react-router";
import { LoginPage } from "./features/auth/LoginPage";
import { RequireSession } from "./features/auth/session";
import { CasesPage } from "./features/cases/CasesPage";
import { AppShell, NotFoundPage } from "./features/shell/AppShell";

export const routes: RouteObject[] = [
  { path: "/login", element: <LoginPage /> },
  {
    element: <RequireSession />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <Navigate to="/cases" replace /> },
          { path: "cases", element: <CasesPage /> },
          { path: "cases/:caseNumber", element: <CasesPage /> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
];
