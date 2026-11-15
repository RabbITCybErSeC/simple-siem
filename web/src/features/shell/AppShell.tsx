import {
  Inbox,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
  SearchIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { ApiError } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Kbd } from "../../components/ui/kbd";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "../../components/ui/popover";
import { Separator } from "../../components/ui/separator";
import {
  applyTheme,
  readThemePreference,
  writeThemePreference,
} from "../../theme/theme";
import type { ThemePreference } from "../../theme/theme";
import { useCurrentUser, useSignOut } from "../auth/session";
import { CommandPalette } from "./CommandPalette";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { buildShellCommands, useCaseCommands } from "./commands";
import { shortcutFor } from "./shortcuts";
import { useTimeZone, writeTimeZone } from "./timeZone";
import type { NavigationItem } from "./types";

const SIDEBAR_STORAGE_KEY = "simple-siem.sidebar";
const PALETTE_HINT = /Mac|iPhone|iPad/.test(navigator.userAgent)
  ? "⌘K"
  : "Ctrl K";

const navigationItems: NavigationItem[] = [
  { label: "Cases", path: "/cases", icon: Inbox },
];

const THEME_OPTIONS: {
  commandId: string;
  label: string;
  preference: ThemePreference;
}[] = [
  { commandId: "theme-system", label: "System", preference: "system" },
  { commandId: "theme-light", label: "Light", preference: "light" },
  { commandId: "theme-dark", label: "Dark", preference: "dark" },
];

export function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const { data: user } = useCurrentUser();
  const signOut = useSignOut();
  const timeZone = useTimeZone();
  const caseCommands = useCaseCommands();
  const [theme, setTheme] = useState(readThemePreference);
  const [collapsed, setCollapsed] = useState(readCollapsedSidebar);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const previousPathname = useRef(location.pathname);

  useEffect(() => {
    if (previousPathname.current === location.pathname) {
      return;
    }
    previousPathname.current = location.pathname;
    // A page that moved focus itself (the case detail heading, a queue row
    // after Escape) keeps it; otherwise the page heading is the target.
    const active = document.activeElement;
    if (
      active instanceof HTMLElement &&
      active !== document.body &&
      mainRef.current?.contains(active)
    ) {
      return;
    }
    mainRef.current?.querySelector<HTMLElement>("h1")?.focus();
  }, [location.pathname]);

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

  const chooseTheme = (preference: ThemePreference) => {
    writeThemePreference(preference);
    applyTheme(preference);
    setTheme(preference);
  };

  const commands = buildShellCommands({
    pathname: location.pathname,
    search: location.search,
    theme,
    timeZone,
    caseCommands,
    onNavigate: (path) => {
      void navigate(path);
    },
    onThemeChange: chooseTheme,
    onTimeZoneChange: writeTimeZone,
    onShowShortcuts: () => setShortcutsOpen(true),
    onSignOut: () => signOut.mutate(),
  });

  const runAccountCommand = (commandId: string) => {
    commands.find((command) => command.id === commandId)?.run();
    setAccountOpen(false);
  };

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
              : "flex w-56 max-md:w-14 shrink-0 flex-col border-r border-border bg-sidebar"
          }
        >
          <div className="flex h-14 items-center justify-between gap-2 px-3">
            <span
              className={
                collapsed
                  ? "sr-only"
                  : "text-sm font-semibold tracking-tight max-md:sr-only"
              }
            >
              Simple SIEM
            </span>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="max-md:hidden"
              aria-expanded={!collapsed}
              aria-controls="main-navigation"
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              onClick={toggleSidebar}
            >
              {collapsed ? (
                <PanelLeftOpenIcon aria-hidden="true" />
              ) : (
                <PanelLeftCloseIcon aria-hidden="true" />
              )}
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
                      "flex items-center gap-2 rounded-lg px-2.5 py-2 text-sm font-medium text-sidebar-foreground no-underline transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground max-md:justify-center",
                      isActive
                        ? "bg-sidebar-accent text-sidebar-accent-foreground"
                        : "",
                      collapsed ? "justify-center" : "",
                    ].join(" ")
                  }
                >
                  <item.icon aria-hidden="true" className="size-4 shrink-0" />
                  {collapsed ? null : (
                    <span className="max-md:sr-only">{item.label}</span>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-14 items-center gap-2 border-b border-border px-3 sm:gap-4 sm:px-4">
            <Button
              type="button"
              variant="outline"
              className="w-full max-w-sm justify-start gap-2 max-sm:size-8 max-sm:justify-center max-sm:px-0"
              aria-keyshortcuts="Control+K Meta+K"
              onClick={() => setPaletteOpen(true)}
            >
              <SearchIcon aria-hidden="true" className="size-4 shrink-0" />
              <span className="text-foreground max-sm:sr-only">
                Search or run a command…
              </span>
              <Kbd className="ml-auto max-sm:hidden">{PALETTE_HINT}</Kbd>
            </Button>
            {signOutFailed && (
              <div
                role="alert"
                className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-1 text-sm text-foreground"
              >
                Sign out failed. Try again.
              </div>
            )}
            {user !== undefined && (
              <Popover open={accountOpen} onOpenChange={setAccountOpen}>
                <PopoverTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="ml-auto rounded-full"
                    aria-label={`Account: ${user.displayName}`}
                  >
                    <span className="flex size-7 items-center justify-center rounded-full bg-muted text-xs font-medium">
                      {initialsFor(user.displayName)}
                    </span>
                  </Button>
                </PopoverTrigger>
                <PopoverContent align="end" className="w-64 gap-0 p-0">
                  <div className="px-3 py-2">
                    <p className="text-sm font-medium">{user.displayName}</p>
                    <p className="text-xs text-muted-foreground">{user.email}</p>
                  </div>
                  <Separator />
                  <div className="px-3 py-2">
                    <p className="text-xs font-medium text-muted-foreground">
                      Theme
                    </p>
                    <div className="segmented mt-2 w-full">
                      {THEME_OPTIONS.map((option) => (
                        <button
                          key={option.commandId}
                          type="button"
                          role="radio"
                          aria-checked={theme === option.preference}
                          className="segmented-item flex-1 justify-center"
                          onClick={() => runAccountCommand(option.commandId)}
                        >
                          {option.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <Separator />
                  <div className="p-1">
                    <Button
                      type="button"
                      variant="ghost"
                      className="w-full justify-start"
                      onClick={() => runAccountCommand("sign-out")}
                    >
                      Sign out
                    </Button>
                  </div>
                </PopoverContent>
              </Popover>
            )}
          </header>
          <main
            id="main"
            ref={mainRef}
            tabIndex={-1}
            className="flex-1 p-4 outline-none sm:p-6"
          >
            <Outlet />
          </main>
        </div>
      </div>
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        commands={commands}
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

function initialsFor(displayName: string): string {
  const words = displayName.trim().split(/\s+/);
  const first = words[0] ?? "";
  const last = words.length > 1 ? words[words.length - 1] : "";
  return `${first.charAt(0)}${last.charAt(0)}`.toUpperCase();
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
