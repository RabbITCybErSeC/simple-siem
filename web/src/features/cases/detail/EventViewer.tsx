import { useEffect, useRef, useState } from "react";
import { Button } from "../../../components/ui/button";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../../components/ui/table";
import type { TimeZoneSetting } from "../../shell/types";
import { TimeCell } from "../CaseTable";
import { formatExact } from "../timeRange";
import { TableRegion } from "./TableRegion";
import type { TimelineEvidenceEntry } from "./types";

export interface EventViewerProps {
  entries: TimelineEvidenceEntry[];
  timeZone: TimeZoneSetting;
  now: Date;
  onCopy: (value: string) => Promise<boolean>;
}

export interface UdmField {
  path: string;
  value: string;
}

interface SummaryColumn {
  header: string;
  path: string;
}

interface EvidenceRowsProps {
  entry: TimelineEvidenceEntry;
  timeZone: TimeZoneSetting;
  now: Date;
  expanded: boolean;
  rawOpen: boolean;
  onToggle: (id: string) => void;
  onToggleRaw: (id: string) => void;
  onCopy: (value: string) => void;
}

interface FieldTableProps {
  fields: UdmField[];
  onCopy: (value: string) => void;
}

const SUMMARY_COLUMNS: SummaryColumn[] = [
  { header: "User", path: "principal.user.userid" },
  { header: "Host", path: "principal.hostname" },
  { header: "Action", path: "metadata.event_type" },
  { header: "Source IP", path: "principal.ip[0]" },
];

const STATUS_MILLISECONDS = 2_000;

export function EventViewer({
  entries,
  timeZone,
  now,
  onCopy,
}: EventViewerProps) {
  const [expandedIds, setExpandedIds] = useState<ReadonlySet<string>>(
    () => new Set(),
  );
  const [rawIds, setRawIds] = useState<ReadonlySet<string>>(() => new Set());
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const statusTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    return () => window.clearTimeout(statusTimer.current);
  }, []);

  async function copy(value: string) {
    let copied = false;
    try {
      copied = await onCopy(value);
    } catch {
      // A rejected clipboard write is reported, not thrown.
    }

    setCopyStatus(copied ? "Copied" : "Could not copy");
    window.clearTimeout(statusTimer.current);
    statusTimer.current = window.setTimeout(
      () => setCopyStatus(null),
      STATUS_MILLISECONDS,
    );
  }

  function toggleExpanded(id: string) {
    setExpandedIds((current) => toggled(current, id));
  }

  function toggleRaw(id: string) {
    setRawIds((current) => toggled(current, id));
  }

  return (
    <div>
      <TableRegion label="Evidence events">
        <Table>
          <TableCaption>Evidence events</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              {SUMMARY_COLUMNS.map((column) => (
                <TableHead key={column.path}>{column.header}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {entries.map((entry) => (
              <EvidenceRows
                key={entry.id}
                entry={entry}
                timeZone={timeZone}
                now={now}
                expanded={expandedIds.has(entry.id)}
                rawOpen={rawIds.has(entry.id)}
                onToggle={toggleExpanded}
                onToggleRaw={toggleRaw}
                onCopy={copy}
              />
            ))}
          </TableBody>
        </Table>
      </TableRegion>
      <p role="status" className="sr-only">
        {copyStatus}
      </p>
    </div>
  );
}

function EvidenceRows({
  entry,
  timeZone,
  now,
  expanded,
  rawOpen,
  onToggle,
  onToggleRaw,
  onCopy,
}: EvidenceRowsProps) {
  if (entry.udm === null) {
    return (
      <TableRow>
        <TableCell>
          <TimeCell value={entry.at} timeZone={timeZone} now={now} />
        </TableCell>
        <TableCell
          colSpan={SUMMARY_COLUMNS.length}
          className="whitespace-normal"
        >
          <span>Event no longer cached</span>
          <span className="ml-2 font-mono text-xs text-muted-foreground">
            {`alert ${entry.alertId}, source ${entry.sourceId}`}
          </span>
        </TableCell>
      </TableRow>
    );
  }

  const detailId = `event-fields-${entry.id}`;
  const rawId = `${detailId}-raw`;
  const fields = flattenUdm(entry.udm);

  return (
    <>
      <TableRow>
        <TableCell>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="mr-2"
            aria-expanded={expanded}
            aria-controls={detailId}
            aria-label={`Show fields for ${formatExact(entry.at, timeZone, "timestamp")}`}
            onClick={() => onToggle(entry.id)}
          >
            {expanded ? "Hide" : "Show"}
          </Button>
          <TimeCell value={entry.at} timeZone={timeZone} now={now} />
        </TableCell>
        {SUMMARY_COLUMNS.map((column) => (
          <TableCell key={column.path} className="font-mono">
            {fieldValue(fields, column.path)}
          </TableCell>
        ))}
      </TableRow>
      {expanded ? (
        <TableRow id={detailId}>
          <TableCell
            colSpan={SUMMARY_COLUMNS.length + 1}
            className="bg-muted/30 p-4 whitespace-normal"
          >
            <FieldTable fields={fields} onCopy={onCopy} />
            <div className="mt-3">
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-expanded={rawOpen}
                aria-controls={rawId}
                onClick={() => onToggleRaw(entry.id)}
              >
                Raw JSON
              </Button>
              {rawOpen ? (
                <pre
                  id={rawId}
                  className="mt-2 overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs"
                >
                  {JSON.stringify(entry.udm, null, 2)}
                </pre>
              ) : null}
            </div>
          </TableCell>
        </TableRow>
      ) : null}
    </>
  );
}

function FieldTable({ fields, onCopy }: FieldTableProps) {
  return (
    <TableRegion label="Event fields">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Field</TableHead>
            <TableHead>Value</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {fields.map((field) => (
            <TableRow key={field.path}>
              <th
                scope="row"
                className="p-2 text-left align-middle font-mono text-xs font-medium whitespace-nowrap"
              >
                {field.path}
              </th>
              <TableCell className="whitespace-normal">
                <span className="font-mono break-all">{field.value}</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  className="ml-2"
                  aria-label={`Copy ${field.path}`}
                  onClick={() => onCopy(field.value)}
                >
                  Copy
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableRegion>
  );
}

export function flattenUdm(udm: Record<string, unknown>): UdmField[] {
  const fields: UdmField[] = [];
  appendFields(udm, "", fields);
  return fields;
}

function appendFields(
  value: unknown,
  path: string,
  fields: UdmField[],
): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      appendFields(item, `${path}[${index}]`, fields);
    });
    return;
  }

  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      appendFields(child, path === "" ? key : `${path}.${key}`, fields);
    }
    return;
  }

  fields.push({ path, value: String(value) });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function fieldValue(fields: UdmField[], path: string): string {
  return fields.find((field) => field.path === path)?.value ?? "—";
}

function toggled(current: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(current);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  return next;
}
