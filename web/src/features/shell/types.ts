import type { LucideIcon } from "lucide-react";

export interface ShellCommand {
  id: string;
  label: string;
  group: "Navigation" | "Theme" | "Account" | "Help";
  keywords: string[];
  run: () => void;
}

export interface Shortcut {
  keys: string[];
  description: string;
}

export interface NavigationItem {
  label: string;
  path: string;
  icon: LucideIcon;
}
