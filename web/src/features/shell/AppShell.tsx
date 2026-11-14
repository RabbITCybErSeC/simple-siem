import { Inbox } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { ApiError } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Kbd } from "../../components/ui/kbd";
import { useCurrentUser, useSignOut } from "../auth/session";
import { CommandPalette } from "./CommandPalette";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { shortcutFor } from "./shortcuts";
import type { NavigationItem } from "./types";

const SIDEBAR_STORAGE_KEY = "simple-siem.sidebar";
const PALETTE_HINT = /Mac|iPhone|iPad/.test(navigator.userAgent)
  ? "⌘K"
  : "Ctrl K";

const navigationItems: NavigationItem[] = [
  { label: "Cases", path: "/cases", icon: Inbox },
];

export function AppShell() {
  const location = useLocation();
  const { data: user } = useCurrentUser();
  const signOut = useSignOut();
  const [collapsed, setCollapsed] = useState(readCollapsedSidebar);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const previousLocationKey = useRef(location.key);

  useEffect(() => {
    if (previousLocationKey.current === location.key) {
      return;
    }
    previousLocationKey.current = location.key;
    mainRef.current?.querySelector<HTMLElement>("h1")?.focus();
  }, [location.key]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const shortcut = shortcutFor(
        event,
        paletteOpen || shortcutsOpen,
        shortcutsOpen,
      );

      if (shortcut === undefined) {
        return;
      }

      event.preventDefault();
      if (shortcut === "palette") {
        setPaletteOpen(!paletteOpen);
      } else {
        setShortcutsOpen(true);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [paletteOpen, shortcutsOpen]);

  const signOutFailed =
    signOut.isError &&
    !(signOut.error instanceof ApiError && signOut.error.status === 401);

  const toggleSidebar = () => {
    const next = !collapsed;
    setCollapsed(next);
    writeCollapsedSidebar(next);
  };

  return (
    <div className="min-h-svh bg-background text-foreground">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:rounded-lg focus:bg-background focus:px-3 focus:py-2 focus:text-sm focus:ring-2 focus:ring-ring"
      >
        Skip to content
      </a>
      <div className="flex min-h-svh">
        <nav
          aria-label="Main"
          className={
            collapsed
              ? "flex w-14 shrink-0 flex-col border-r border-border bg-sidebar"
              : "flex w-56 shrink-0 flex-col border-r border-border bg-sidebar"
          }
        >
          <div className="flex h-14 items-center justify-between gap-2 px-3">
            <span
              className={
                collapsed ? "sr-only" : "text-sm font-semibold tracking-tight"
              }
            >
              Simple SIEM
            </span>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-expanded={!collapsed}
              aria-controls="main-navigation"
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              onClick={toggleSidebar}
            >
              {collapsed ? "»" : "«"}
            </Button>
          </div>
          <ul id="main-navigation" className="flex flex-col gap-1 p-2">
            {navigationItems.map((item) => (
              <li key={item.path}>
                <NavLink
                  to={item.path}
                  aria-label={collapsed ? item.label : undefined}
                  className={({ isActive }) =>
                    [
                      "flex items-center gap-2 rounded-lg px-2.5 py-2 text-sm font-medium text-sidebar-foreground no-underline transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                      isActive
                        ? "bg-sidebar-accent text-sidebar-accent-foreground"
                        : "",
                      collapsed ? "justify-center" : "",
                    ].join(" ")
                  }
                >
                  <item.icon aria-hidden="true" className="size-4 shrink-0" />
                  {collapsed ? null : <span>{item.label}</span>}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-14 items-center gap-4 border-b border-border px-4">
            <Button
              type="button"
              variant="outline"
              className="w-full max-w-sm justify-start gap-2"
              aria-keyshortcuts="Control+K Meta+K"
              onClick={() => setPaletteOpen(true)}
            >
              <span className="text-foreground">
                Search or run a command…
              </span>
              <Kbd className="ml-auto">{PALETTE_HINT}</Kbd>
            </Button>
            {signOutFailed && (
              <div
                role="alert"
                className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-1 text-sm text-foreground"
              >
                Sign out failed. Try again.
              </div>
            )}
            <span className="ml-auto text-sm text-muted-foreground">
              {user?.displayName}
            </span>
          </header>
          <main
            id="main"
            ref={mainRef}
            tabIndex={-1}
            className="flex-1 p-6 outline-none"
          >
            <Outlet />
          </main>
        </div>
      </div>
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onShowShortcuts={() => setShortcutsOpen(true)}
        onSignOut={() => signOut.mutate()}
      />
      <ShortcutsDialog
        open={shortcutsOpen}
        onOpenChange={setShortcutsOpen}
      />
    </div>
  );
}

export function NotFoundPage() {
  return (
    <>
      <title>Page not found · Simple SIEM</title>
      <h1
        tabIndex={-1}
        className="text-2xl font-semibold tracking-tight outline-none"
      >
        Page not found
      </h1>
      <p className="mt-2 text-sm text-muted-foreground">
        The page you asked for does not exist.
      </p>
      <NavLink
        to="/cases"
        className="mt-4 inline-block text-sm text-primary underline-offset-4 hover:underline"
      >
        Go to Cases
      </NavLink>
    </>
  );
}

function readCollapsedSidebar(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === "collapsed";
  } catch {
    return false;
  }
}

function writeCollapsedSidebar(collapsed: boolean): void {
  try {
    window.localStorage.setItem(
      SIDEBAR_STORAGE_KEY,
      collapsed ? "collapsed" : "expanded",
    );
  } catch {
    // Storage can be unavailable; the sidebar still collapses for this page.
  }
}
