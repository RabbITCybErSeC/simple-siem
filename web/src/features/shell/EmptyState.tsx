import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Button } from "../../components/ui/button";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  onRetry?: () => void;
  tone?: "neutral" | "error";
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  onRetry,
  tone = "neutral",
}: EmptyStateProps) {
  return (
    <div
      role={tone === "error" ? "alert" : undefined}
      className="flex flex-col items-center gap-3 px-4 py-12 text-center"
    >
      <span
        className={cn(
          "flex size-10 items-center justify-center rounded-full",
          tone === "error"
            ? "bg-destructive/10 text-destructive"
            : "bg-muted text-muted-foreground",
        )}
      >
        <Icon aria-hidden="true" className="size-5" />
      </span>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description === undefined ? null : (
          <p className="max-w-sm text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {onRetry === undefined ? null : (
        <Button type="button" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      )}
      {action}
    </div>
  );
}
