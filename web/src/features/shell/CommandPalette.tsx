import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "../../components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "../../components/ui/dialog";
import {
  applyTheme,
  readThemePreference,
  writeThemePreference,
} from "../../theme/theme";
import type { ThemePreference } from "../../theme/theme";
import type { ShellCommand } from "./types";

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onShowShortcuts: () => void;
  onSignOut: () => void;
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
  onSignOut,
}: CommandPaletteProps) {
  const navigate = useNavigate();
  const [theme, setTheme] = useState(readThemePreference);
  const opener = useRef<HTMLElement | null>(null);
  const commandMovesFocus = useRef(false);

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
      movesFocus: true,
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
      movesFocus: true,
      run: onSignOut,
    },
    {
      id: "keyboard-shortcuts",
      label: "Keyboard shortcuts",
      group: "Help",
      keywords: ["help", "keys"],
      movesFocus: true,
      run: onShowShortcuts,
    },
  ];

  const runCommand = (command: ShellCommand) => {
    commandMovesFocus.current = command.movesFocus;
    onOpenChange(false);
    command.run();
  };

  const handleOpenAutoFocus = () => {
    const active = document.activeElement;
    opener.current = active instanceof HTMLElement ? active : null;
  };

  const handleCloseAutoFocus = (event: Event) => {
    event.preventDefault();

    const target = opener.current;
    opener.current = null;
    if (!commandMovesFocus.current) {
      target?.focus();
    }
    commandMovesFocus.current = false;
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogHeader className="sr-only">
        <DialogTitle>Command palette</DialogTitle>
        <DialogDescription>
          Search for and run a console command.
        </DialogDescription>
      </DialogHeader>
      <DialogContent
        className="top-1/3 translate-y-0 overflow-hidden rounded-xl! p-0"
        showCloseButton={false}
        onOpenAutoFocus={handleOpenAutoFocus}
        onCloseAutoFocus={handleCloseAutoFocus}
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
      </DialogContent>
    </Dialog>
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
    movesFocus: false,
    run: () => chooseTheme(preference),
  }));
}

function capitalize(value: ThemePreference): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
