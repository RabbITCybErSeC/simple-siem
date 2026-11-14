import { useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
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
import { buildShellCommands, useCaseCommands } from "./commands";
import { useTimeZone, writeTimeZone } from "./timeZone";
import type { ShellCommand } from "./types";

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onShowShortcuts: () => void;
  onSignOut: () => void;
}

const GROUP_ORDER: ShellCommand["group"][] = [
  "Navigation",
  "Case",
  "Theme",
  "Time zone",
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
  const location = useLocation();
  const timeZone = useTimeZone();
  const caseCommands = useCaseCommands();
  const [theme, setTheme] = useState(readThemePreference);
  const opener = useRef<HTMLElement | null>(null);
  const commandMovesFocus = useRef(false);

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
    onShowShortcuts,
    onSignOut,
  });

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
