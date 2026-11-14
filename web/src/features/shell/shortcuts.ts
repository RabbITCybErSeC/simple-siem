import type { Shortcut } from "./types";

export const shellShortcuts: Shortcut[] = [
  { keys: ["Ctrl", "K"], description: "Open the command palette" },
  { keys: ["⌘", "K"], description: "Open the command palette" },
  { keys: ["?"], description: "Show keyboard shortcuts" },
  { keys: ["j"], description: "Next case", scope: "Cases list" },
  { keys: ["k"], description: "Previous case", scope: "Cases list" },
];

export function shortcutFor(
  event: KeyboardEvent,
  dialogOpen: boolean,
  shortcutsOpen = false,
): "palette" | "help" | undefined {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    return shortcutsOpen ? undefined : "palette";
  }

  if (
    event.key === "?" &&
    !dialogOpen &&
    !isTextEntryTarget(event.target)
  ) {
    return "help";
  }

  return undefined;
}

function isTextEntryTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  const tagName = target.tagName.toLowerCase();
  return (
    tagName === "input" ||
    tagName === "textarea" ||
    tagName === "select" ||
    target.isContentEditable ||
    target.closest('[contenteditable]:not([contenteditable="false"])') !== null
  );
}
