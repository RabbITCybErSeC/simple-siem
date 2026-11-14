import { useState } from "react";
import { useNavigate } from "react-router";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "../../components/ui/command";
import {
  applyTheme,
  readThemePreference,
  writeThemePreference,
} from "../../theme/theme";
import type { ThemePreference } from "../../theme/theme";
import { useSignOut } from "../auth/session";
import type { ShellCommand } from "./types";

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onShowShortcuts: () => void;
}

const GROUP_ORDER: ShellCommand["group"][] = [
  "Navigation",
  "Theme",
  "Account",
  "Help",
];

export function CommandPalette({
  open,
  onOpenChange,
  onShowShortcuts,
}: CommandPaletteProps) {
  const navigate = useNavigate();
  const signOut = useSignOut();
  const [theme, setTheme] = useState(readThemePreference);

  const chooseTheme = (preference: ThemePreference) => {
    writeThemePreference(preference);
    applyTheme(preference);
    setTheme(preference);
  };

  const commands: ShellCommand[] = [
    {
      id: "go-cases",
      label: "Go to Cases",
      group: "Navigation",
      keywords: ["queue", "case"],
      run: () => {
        void navigate("/cases");
      },
    },
    ...themeCommands(theme, chooseTheme),
    {
      id: "sign-out",
      label: "Sign out",
      group: "Account",
      keywords: ["logout", "exit"],
      run: () => signOut.mutate(),
    },
    {
      id: "keyboard-shortcuts",
      label: "Keyboard shortcuts",
      group: "Help",
      keywords: ["help", "keys"],
      run: onShowShortcuts,
    },
  ];

  const runCommand = (command: ShellCommand) => {
    onOpenChange(false);
    command.run();
  };

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Command palette"
      description="Search for and run a console command."
    >
      <Command>
        <CommandInput placeholder="Type a command…" />
        <CommandList>
          <CommandEmpty>No results.</CommandEmpty>
          {GROUP_ORDER.map((group) => {
            const groupCommands = commands.filter(
              (command) => command.group === group,
            );
            if (groupCommands.length === 0) {
              return null;
            }

            return (
              <CommandGroup key={group} heading={group}>
                {groupCommands.map((command) => (
                  <CommandItem
                    key={command.id}
                    value={command.label}
                    keywords={command.keywords}
                    onSelect={() => runCommand(command)}
                  >
                    {command.label}
                  </CommandItem>
                ))}
              </CommandGroup>
            );
          })}
        </CommandList>
      </Command>
    </CommandDialog>
  );
}

function themeCommands(
  current: ThemePreference,
  chooseTheme: (preference: ThemePreference) => void,
): ShellCommand[] {
  const preferences: ThemePreference[] = ["system", "light", "dark"];

  return preferences.map((preference) => ({
    id: `theme-${preference}`,
    label:
      preference === current
        ? `Theme: ${capitalize(preference)} (current)`
        : `Theme: ${capitalize(preference)}`,
    group: "Theme",
    keywords: ["appearance", "color", "colour", preference],
    run: () => chooseTheme(preference),
  }));
}

function capitalize(value: ThemePreference): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
