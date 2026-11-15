import { zodResolver } from "@hookform/resolvers/zod";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { ApiError } from "../../../api/client";
import { Button } from "../../../components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../../components/ui/dialog";
import type { CaseSummary } from "../types";
import type { ClosureValues } from "./CloseCaseDialog";
import {
  CLOSE_DIALOG_LAYOUT,
  ClosureFields,
  closeSchema,
} from "./CloseCaseDialog";
import { useBulkCloseCases, cachedCaseVersions } from "./queries";
import type { BulkCloseResponse, BulkCloseStatus } from "./types";

const BULK_STATUS_LABELS: Record<BulkCloseStatus, string> = {
  CLOSED: "Closed",
  VERSION_CONFLICT: "Changed since loaded",
  STATE_CONFLICT: "Already closed",
  NOT_FOUND: "Not found",
  FORBIDDEN: "No permission",
};

export interface BulkCloseDialogProps {
  cases: CaseSummary[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onClosed: (closedIds: string[]) => void;
}

export function BulkCloseDialog({
  cases,
  open,
  onOpenChange,
  onClosed,
}: BulkCloseDialogProps) {
  const bulkClose = useBulkCloseCases();
  const queryClient = useQueryClient();
  const form = useForm<ClosureValues>({
    resolver: zodResolver(closeSchema),
    defaultValues: { conclusion: "" },
    shouldFocusError: true,
  });
  const [results, setResults] = useState<BulkCloseResponse["results"] | null>(
    null,
  );
  const [submittedCases, setSubmittedCases] = useState<CaseSummary[]>([]);
  const [failure, setFailure] = useState<string | null>(null);

  const onSubmit = form.handleSubmit(async (values) => {
    setFailure(null);
    setSubmittedCases(cases);
    const versions = cachedCaseVersions(queryClient);
    try {
      const response = await bulkClose.mutateAsync({
        request: {
          cases: cases.map((item) => ({
            id: item.id,
            version: Math.max(versions.get(item.id) ?? 0, item.version),
          })),
          outcome: values.outcome,
          closureReason: values.closureReason,
          conclusion: values.conclusion,
        },
        caseNumbers: Object.fromEntries(
          cases.map((item) => [item.id, item.caseNumber]),
        ),
      });
      setResults(response.results);
      onClosed(
        response.results
          .filter((result) => result.status === "CLOSED")
          .map((result) => result.caseId),
      );
    } catch (error) {
      setFailure(bulkCloseFailure(error));
    }
  });

  const closedCount =
    results === null
      ? 0
      : results.filter((result) => result.status === "CLOSED").length;
  const notClosedCount = (results?.length ?? 0) - closedCount;
  const numberById = new Map(
    submittedCases.map((item) => [item.id, item.caseNumber]),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={CLOSE_DIALOG_LAYOUT.content}>
        <DialogHeader className="px-6 pt-6">
          <DialogTitle>Close selected cases</DialogTitle>
          <DialogDescription>
            {results === null
              ? `${cases.length} selected case${
                  cases.length === 1 ? "" : "s"
                }. Choose an outcome, a closure reason, and a conclusion.`
              : "The results for the selected cases."}
          </DialogDescription>
        </DialogHeader>

        {results === null ? (
          <form
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={onSubmit}
            noValidate
          >
            <div className={CLOSE_DIALOG_LAYOUT.body}>
              <ClosureFields form={form} idPrefix="bulk" />

              {failure === null ? null : (
                <div
                  role="alert"
                  className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-foreground"
                >
                  {failure}
                </div>
              )}
            </div>

            <DialogFooter className={CLOSE_DIALOG_LAYOUT.footer}>
              <DialogClose asChild>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </DialogClose>
              <Button type="submit" disabled={bulkClose.isPending}>
                Close selected cases
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <>
            <div className={CLOSE_DIALOG_LAYOUT.body}>
              <p role="status" className="text-sm font-medium">
                {`${closedCount} closed, ${notClosedCount} not closed`}
              </p>
              <ul
                aria-label="Bulk close results"
                className="flex max-h-64 flex-col gap-1 overflow-y-auto text-sm"
              >
                {results.map((result) => (
                  <li
                    key={result.caseId}
                    className="flex items-center justify-between gap-3"
                  >
                    <span>{`#${
                      numberById.get(result.caseId) ?? result.caseId
                    }`}</span>
                    <span>{BULK_STATUS_LABELS[result.status]}</span>
                  </li>
                ))}
              </ul>
            </div>
            <DialogFooter className={CLOSE_DIALOG_LAYOUT.footer}>
              <DialogClose asChild>
                <Button type="button">Done</Button>
              </DialogClose>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function bulkCloseFailure(error: unknown): string {
  if (error instanceof ApiError && error.code === "NETWORK_ERROR") {
    return "Cannot reach Simple SIEM. Try again.";
  }
  return "Something went wrong. Try again.";
}
