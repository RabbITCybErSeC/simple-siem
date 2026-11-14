import {
  caseQueueSearch,
  parseCaseQueueState,
  type CaseScope,
  type CaseTab,
} from "../cases/urlState";
import type { TimeZoneSetting } from "../cases/timeRange";
import type { ThemePreference } from "../../theme/theme";
import type { ShellCommand } from "./types";

export interface ShellCommandContext {
  pathname: string;
  search: string;
  theme: ThemePreference;
  timeZone: TimeZoneSetting;
  onNavigate: (path: string) => void;
  onThemeChange: (preference: ThemePreference) => void;
  onTimeZoneChange: (setting: TimeZoneSetting) => void;
  onShowShortcuts: () => void;
  onSignOut: () => void;
}

const TAB_COMMANDS: { tab: CaseTab; label: string }[] = [
  { tab: "open", label: "Cases: Open" },
  { tab: "in_progress", label: "Cases: In progress" },
  { tab: "closed", label: "Cases: Closed" },
  { tab: "all", label: "Cases: All" },
];

const SCOPE_COMMANDS: { scope: CaseScope; label: string }[] = [
  { scope: "mine", label: "Cases: Mine" },
  { scope: "unassigned", label: "Cases: Unassigned" },
  { scope: "all", label: "Cases: All assignees" },
];

const THEME_PREFERENCES: ThemePreference[] = ["system", "light", "dark"];
const TIME_ZONES: TimeZoneSetting[] = ["local", "utc"];

export function buildShellCommands(
  context: ShellCommandContext,
): ShellCommand[] {
  // The queue state lives in the URL, so a tab or scope command keeps the
  // analyst's current range, field, sort, and refresh interval.
  const queueState = parseCaseQueueState(
    new URLSearchParams(context.pathname === "/cases" ? context.search : ""),
  );

  return [
    {
      id: "go-cases",
      label: "Go to Cases",
      group: "Navigation",
      keywords: ["queue", "case"],
      movesFocus: true,
      run: () => context.onNavigate("/cases"),
    },
    ...TAB_COMMANDS.map(({ tab, label }) => ({
      id: `cases-tab-${tab}`,
      label,
      group: "Navigation" as const,
      keywords: ["case", "queue", "status", tab],
      movesFocus: true,
      run: () =>
        context.onNavigate(
          `/cases${caseQueueSearch({ ...queueState, tab })}`,
        ),
    })),
    ...SCOPE_COMMANDS.map(({ scope, label }) => ({
      id: `cases-scope-${scope}`,
      label,
      group: "Navigation" as const,
      keywords: ["case", "queue", "assignee", scope],
      movesFocus: true,
      run: () =>
        context.onNavigate(
          `/cases${caseQueueSearch({ ...queueState, scope })}`,
        ),
    })),
    ...THEME_PREFERENCES.map((preference) => ({
      id: `theme-${preference}`,
      label: withCurrent(`Theme: ${capitalize(preference)}`, preference === context.theme),
      group: "Theme" as const,
      keywords: ["appearance", "color", "colour", preference],
      movesFocus: false,
      run: () => context.onThemeChange(preference),
    })),
    ...TIME_ZONES.map((setting) => ({
      id: `time-zone-${setting}`,
      label: withCurrent(
        `Time zone: ${timeZoneLabel(setting)}`,
        setting === context.timeZone,
      ),
      group: "Time zone" as const,
      keywords: ["clock", "time", "zone", setting],
      movesFocus: false,
      run: () => context.onTimeZoneChange(setting),
    })),
    {
      id: "sign-out",
      label: "Sign out",
      group: "Account",
      keywords: ["logout", "exit"],
      movesFocus: true,
      run: context.onSignOut,
    },
    {
      id: "keyboard-shortcuts",
      label: "Keyboard shortcuts",
      group: "Help",
      keywords: ["help", "keys"],
      movesFocus: true,
      run: context.onShowShortcuts,
    },
  ];
}

function withCurrent(label: string, current: boolean): string {
  return current ? `${label} (current)` : label;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function timeZoneLabel(setting: TimeZoneSetting): string {
  return setting === "utc" ? "UTC" : "Local";
}
