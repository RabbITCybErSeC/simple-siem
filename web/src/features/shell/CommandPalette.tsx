import { useLayoutEffect, useRef } from "react";
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
import type { ShellCommand } from "./types";

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  commands: ShellCommand[];
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
  commands,
}: CommandPaletteProps) {
  const opener = useRef<HTMLElement | null>(null);
  const pendingCommand = useRef<ShellCommand | undefined>(undefined);

  const runCommand = (command: ShellCommand) => {
    if (!command.movesFocus) {
      // Clipboard writes need the user gesture, so run these commands now.
      command.run();
      onOpenChange(false);
      return;
    }
    pendingCommand.current = command;
    onOpenChange(false);
  };

  // A command waiting for the close animation must not be lost when the
  // palette reopens before that animation finishes. A layout effect runs at
  // the open commit, before a command selected right after the first open
  // could be mistaken for one from a reopen.
  useLayoutEffect(() => {
    if (!open) {
      return;
    }
    const command = pendingCommand.current;
    if (command === undefined) {
      return;
    }
    pendingCommand.current = undefined;
    command.run();
  }, [open]);

  const handleOpenAutoFocus = () => {
    const active = document.activeElement;
    opener.current = active instanceof HTMLElement ? active : null;
  };

  const handleCloseAutoFocus = (event: Event) => {
    event.preventDefault();

    const command = pendingCommand.current;
    const target = opener.current;
    pendingCommand.current = undefined;
    opener.current = null;

    if (command === undefined) {
      target?.focus();
      return;
    }

    // The dialog's focus trap is gone once it has closed, so a command that
    // moves focus can run now without the trap pulling focus back.
    command.run();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="top-[20%] translate-y-0 overflow-hidden p-0 max-sm:w-[calc(100%-2rem)]"
        showCloseButton={false}
        onOpenAutoFocus={handleOpenAutoFocus}
        onCloseAutoFocus={handleCloseAutoFocus}
      >
        <DialogHeader className="sr-only">
          <DialogTitle>Command palette</DialogTitle>
          <DialogDescription>
            Search for and run a console command.
          </DialogDescription>
        </DialogHeader>
        <Command>
          <CommandInput placeholder="Type a command…" />
          <CommandList className="max-h-80">
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
