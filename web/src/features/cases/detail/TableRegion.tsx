import type { ReactNode } from "react";

interface TableRegionProps {
  label: string;
  children: ReactNode;
}

export function TableRegion({ label, children }: TableRegionProps) {
  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      className="overflow-x-auto rounded-xl border outline-none focus-visible:ring-3 focus-visible:ring-ring [&>[data-slot=table-container]]:overflow-visible"
    >
      {children}
    </div>
  );
}
