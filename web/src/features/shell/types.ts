import type { LucideIcon } from "lucide-react";

export type TimeZoneSetting = "local" | "utc";

export interface ShellCommand {
  id: string;
  label: string;
  group:
    | "Navigation"
    | "Case"
    | "Theme"
    | "Time zone"
    | "Account"
    | "Help";
  keywords: string[];
  movesFocus: boolean;
  run: () => void;
}

export interface Shortcut {
  keys: string[];
  description: string;
  /** Where the shortcut applies; omitted means anywhere in the console. */
  scope?: string;
}

export interface NavigationItem {
  label: string;
  path: string;
  icon: LucideIcon;
}
