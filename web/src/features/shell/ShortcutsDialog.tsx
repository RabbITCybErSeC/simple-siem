import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "../../components/ui/dialog";
import { Kbd, KbdGroup } from "../../components/ui/kbd";
import { shellShortcuts } from "./shortcuts";

export interface ShortcutsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ShortcutsDialog({
  open,
  onOpenChange,
}: ShortcutsDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Every shortcut available in the console.
          </DialogDescription>
        </DialogHeader>
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-border">
              <th scope="col" className="px-2 py-2 font-medium">
                Keys
              </th>
              <th scope="col" className="px-2 py-2 font-medium">
                Action
              </th>
              <th scope="col" className="px-2 py-2 font-medium">
                Where
              </th>
            </tr>
          </thead>
          <tbody>
            {shellShortcuts.map((shortcut) => (
              <tr
                key={`${shortcut.description}-${shortcut.keys.join("-")}`}
                className="border-b border-border last:border-b-0"
              >
                <td className="px-2 py-2">
                  <KbdGroup>
                    {shortcut.keys.map((key) => (
                      <Kbd key={key}>{key}</Kbd>
                    ))}
                  </KbdGroup>
                </td>
                <td className="px-2 py-2 text-muted-foreground">
                  {shortcut.description}
                </td>
                <td className="px-2 py-2 text-muted-foreground">
                  {shortcut.scope ?? "Anywhere"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DialogContent>
    </Dialog>
  );
}
