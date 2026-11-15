import { zodResolver } from "@hookform/resolvers/zod";
import { useCallback, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Controller, useForm } from "react-hook-form";
import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
import { Button } from "../../../components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../../components/ui/dialog";
import {
  Field,
  FieldError,
  FieldLegend,
  FieldSet,
} from "../../../components/ui/field";
import { Label } from "../../../components/ui/label";
import { RadioGroup, RadioGroupItem } from "../../../components/ui/radio-group";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../../components/ui/table";
import { Textarea } from "../../../components/ui/textarea";
import { OUTCOME_LABELS } from "../CaseTable";
import type { CaseOutcome } from "../types";
import { describeCaseFailure } from "./failures";
import { useAllCaseAlerts, useCloseCase } from "./queries";
import type {
  AlertSummary,
  CaseActionFailure,
  CaseDetail,
  ClosureReason,
  StoredClosureReason,
} from "./types";

export const CLOSURE_REASON_LABELS: Record<StoredClosureReason, string> = {
  FALSE_POSITIVE: "False positive",
  BENIGN_TRUE_POSITIVE: "Benign true positive",
  AUTHORIZED_ACTIVITY: "Authorized activity",
  DUPLICATE: "Duplicate",
  INSUFFICIENT_EVIDENCE: "Insufficient evidence",
  CONFIRMED_THREAT: "Confirmed threat",
  OTHER: "Other",
  MERGED: "Merged",
};

export const CLOSURE_REASON_OPTIONS: {
  value: ClosureReason;
  label: string;
}[] = (
  [
    "FALSE_POSITIVE",
    "BENIGN_TRUE_POSITIVE",
    "AUTHORIZED_ACTIVITY",
    "DUPLICATE",
    "INSUFFICIENT_EVIDENCE",
    "CONFIRMED_THREAT",
    "OTHER",
  ] as const
).map((value) => ({ value, label: CLOSURE_REASON_LABELS[value] }));

export const OUTCOME_OPTIONS: CaseOutcome[] = ["MALICIOUS", "ACCEPTED"];

export function closureReasonLabel(value: unknown): string {
  if (typeof value === "string" && value in CLOSURE_REASON_LABELS) {
    return CLOSURE_REASON_LABELS[value as StoredClosureReason];
  }
  return typeof value === "string" ? value : "unknown";
}

export const closeSchema = z.object({
  outcome: z.enum(["MALICIOUS", "ACCEPTED"], {
    error: "Choose an outcome.",
  }),
  closureReason: z.enum(
    [
      "FALSE_POSITIVE",
      "BENIGN_TRUE_POSITIVE",
      "AUTHORIZED_ACTIVITY",
      "DUPLICATE",
      "INSUFFICIENT_EVIDENCE",
      "CONFIRMED_THREAT",
      "OTHER",
    ],
    { error: "Choose a closure reason." },
  ),
  conclusion: z
    .string()
    .trim()
    .min(1, "Write a conclusion.")
    .max(10_000, "The conclusion is too long."),
});

export type ClosureValues = z.infer<typeof closeSchema>;

const SAME = "SAME";

const SELECT_CLASS_NAME =
  "h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:bg-input/30 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40";

type AlertOverride = {
  outcome: CaseOutcome | typeof SAME;
  closureReason: ClosureReason | typeof SAME;
};

export interface CloseCaseDialogProps {
  detail: CaseDetail;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onReload: () => void;
  onClosed: (detail: CaseDetail) => void;
}

export function CloseCaseDialog({
  detail,
  open,
  onOpenChange,
  onReload,
  onClosed,
}: CloseCaseDialogProps) {
  const closeCase = useCloseCase();
  const form = useForm<ClosureValues>({
    resolver: zodResolver(closeSchema),
    defaultValues: { conclusion: "" },
    shouldFocusError: true,
  });
  const [failure, setFailure] = useState<CaseActionFailure | null>(null);
  const [overrides, setOverrides] = useState<Record<string, AlertOverride>>({});
  const [opener, setOpener] = useState<HTMLElement | null>(null);
  const closedSuccessfully = useRef(false);
  const closedDetail = useRef<CaseDetail | null>(null);
  const showDispositions = detail.alertCount > 1;
  const alertsQuery = useAllCaseAlerts(detail.id, open && showDispositions);
  const alerts = useMemo(() => alertsQuery.data ?? [], [alertsQuery.data]);

  const changeOverride = (
    alertId: string,
    field: keyof AlertOverride,
    value: string,
  ) => {
    setOverrides((current) => ({
      ...current,
      [alertId]: {
        outcome: current[alertId]?.outcome ?? SAME,
        closureReason: current[alertId]?.closureReason ?? SAME,
        [field]: value as AlertOverride[typeof field],
      },
    }));
  };

  const submitClose = useCallback(
    async (values: ClosureValues) => {
      setFailure(null);
      const dispositions = buildDispositions(alerts, overrides, values);

      try {
        const closed = await closeCase.mutateAsync({
          caseId: detail.id,
          caseNumber: detail.caseNumber,
          request: {
            outcome: values.outcome,
            closureReason: values.closureReason,
            conclusion: values.conclusion,
            version: detail.version,
            ...(dispositions.length === 0
              ? {}
              : { alertDispositions: dispositions }),
          },
        });
        closedDetail.current = closed;
        closedSuccessfully.current = true;
        onOpenChange(false);
      } catch (error) {
        setFailure(describeCloseFailure(error));
      }
    },
    [alerts, closeCase, detail, onOpenChange, overrides],
  );
  const submitHandler = (event: FormEvent<HTMLFormElement>) => {
    void form.handleSubmit(submitClose)(event);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="max-h-[85vh] overflow-y-auto sm:max-w-2xl"
        onOpenAutoFocus={() => {
          const active = document.activeElement;
          setOpener(active instanceof HTMLElement ? active : null);
        }}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          if (closedSuccessfully.current) {
            closedSuccessfully.current = false;
            const closed = closedDetail.current;
            closedDetail.current = null;
            if (closed !== null) {
              onClosed(closed);
            }
          } else {
            opener?.focus();
          }
        }}
      >
        <DialogHeader>
          <DialogTitle>{`Close case #${detail.caseNumber}`}</DialogTitle>
          <DialogDescription>
            {detail.alertCount === 1 ? "1 alert." : `${detail.alertCount} alerts.`}{" "}
            Choose an outcome, a closure reason, and a conclusion.
          </DialogDescription>
        </DialogHeader>

        <form className="flex flex-col gap-4" onSubmit={submitHandler} noValidate>
          <ClosureFields form={form} idPrefix="close" />

          {showDispositions ? (
            alertsQuery.isPending ? (
              <p aria-busy="true" className="text-sm text-muted-foreground">
                Loading alerts…
              </p>
            ) : alertsQuery.isError ? (
              <p className="text-sm text-muted-foreground">
                Could not load the case alerts.
              </p>
            ) : (
              <AlertDispositions
                alerts={alerts}
                overrides={overrides}
                onChange={changeOverride}
              />
            )
          ) : null}

          {failure === null ? null : (
            <div
              role="alert"
              className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-foreground"
            >
              <p>{failure.message}</p>
              {failure.reload ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={onReload}
                >
                  Reload case
                </Button>
              ) : null}
            </div>
          )}

          <DialogFooter>
            <Button type="submit" disabled={closeCase.isPending}>
              Close case
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export interface ClosureFieldsProps {
  form: UseFormReturn<ClosureValues>;
  idPrefix: string;
}

export function ClosureFields({ form, idPrefix }: ClosureFieldsProps) {
  const { errors } = form.formState;
  const [characterCount, setCharacterCount] = useState<number | null>(null);
  const conclusion = form.register("conclusion");

  return (
    <div className="flex flex-col gap-4">
      <FieldSet>
        <FieldLegend id={`${idPrefix}-outcome-label`}>Outcome</FieldLegend>
        <Controller
          control={form.control}
          name="outcome"
          render={({ field, fieldState }) => (
            <RadioGroup
              value={field.value ?? ""}
              onValueChange={field.onChange}
              aria-labelledby={`${idPrefix}-outcome-label`}
              aria-describedby={
                fieldState.error ? `${idPrefix}-outcome-error` : undefined
              }
              aria-invalid={fieldState.error ? true : undefined}
            >
              <div className="flex flex-wrap gap-4">
                {OUTCOME_OPTIONS.map((outcome, index) => (
                  <div key={outcome} className="flex items-center gap-2">
                    <RadioGroupItem
                      ref={index === 0 ? field.ref : undefined}
                      id={`${idPrefix}-outcome-${outcome}`}
                      value={outcome}
                    />
                    <Label htmlFor={`${idPrefix}-outcome-${outcome}`}>
                      {OUTCOME_LABELS[outcome]}
                    </Label>
                  </div>
                ))}
              </div>
            </RadioGroup>
          )}
        />
        <FieldError
          id={`${idPrefix}-outcome-error`}
          errors={errors.outcome ? [errors.outcome] : []}
        />
      </FieldSet>

      <Field data-invalid={errors.closureReason !== undefined}>
        <Label htmlFor={`${idPrefix}-reason`}>Closure reason</Label>
        <Controller
          control={form.control}
          name="closureReason"
          render={({ field, fieldState }) => (
            <select
              id={`${idPrefix}-reason`}
              ref={field.ref}
              name={field.name}
              value={field.value ?? ""}
              onBlur={field.onBlur}
              onChange={(event) => field.onChange(event.target.value)}
              className={SELECT_CLASS_NAME}
              aria-invalid={fieldState.error ? true : undefined}
              aria-describedby={
                fieldState.error ? `${idPrefix}-reason-error` : undefined
              }
            >
              <option value="" disabled>
                Choose a reason
              </option>
              {CLOSURE_REASON_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          )}
        />
        <FieldError
          id={`${idPrefix}-reason-error`}
          errors={errors.closureReason ? [errors.closureReason] : []}
        />
      </Field>

      <Field data-invalid={errors.conclusion !== undefined}>
        <Label htmlFor={`${idPrefix}-conclusion`}>Conclusion</Label>
        <Textarea
          id={`${idPrefix}-conclusion`}
          aria-invalid={errors.conclusion !== undefined}
          aria-describedby={
            errors.conclusion ? `${idPrefix}-conclusion-error` : undefined
          }
          {...conclusion}
          onBlur={(event) => {
            conclusion.onBlur(event);
            setCharacterCount(event.currentTarget.value.trim().length);
          }}
          onFocus={() => setCharacterCount(null)}
        />
        <FieldError
          id={`${idPrefix}-conclusion-error`}
          errors={errors.conclusion ? [errors.conclusion] : []}
        />
        {characterCount === null ? null : (
          <p role="status" className="text-xs text-muted-foreground">
            {`${characterCount.toLocaleString("en-US")} of 10,000 characters`}
          </p>
        )}
      </Field>
    </div>
  );
}

interface AlertDispositionsProps {
  alerts: AlertSummary[];
  overrides: Record<string, AlertOverride>;
  onChange: (
    alertId: string,
    field: keyof AlertOverride,
    value: string,
  ) => void;
}

function AlertDispositions({
  alerts,
  overrides,
  onChange,
}: AlertDispositionsProps) {
  return (
    <Table>
      <TableCaption>Alert dispositions</TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>Alert</TableHead>
          <TableHead>Outcome</TableHead>
          <TableHead>Closure reason</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {alerts.map((alert) => {
          const override = overrides[alert.id];
          return (
            <TableRow key={alert.id}>
              <TableCell className="font-medium">{alert.title}</TableCell>
              <TableCell>
                <select
                  aria-label={`Outcome for ${alert.title}`}
                  value={override?.outcome ?? SAME}
                  onChange={(event) =>
                    onChange(alert.id, "outcome", event.target.value)
                  }
                  className={SELECT_CLASS_NAME}
                >
                  <option value={SAME}>Same as case</option>
                  {OUTCOME_OPTIONS.map((outcome) => (
                    <option key={outcome} value={outcome}>
                      {OUTCOME_LABELS[outcome]}
                    </option>
                  ))}
                </select>
              </TableCell>
              <TableCell>
                <select
                  aria-label={`Closure reason for ${alert.title}`}
                  value={override?.closureReason ?? SAME}
                  onChange={(event) =>
                    onChange(alert.id, "closureReason", event.target.value)
                  }
                  className={SELECT_CLASS_NAME}
                >
                  <option value={SAME}>Same as case</option>
                  {CLOSURE_REASON_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

function buildDispositions(
  alerts: AlertSummary[],
  overrides: Record<string, AlertOverride>,
  values: ClosureValues,
) {
  return alerts.flatMap((alert) => {
    const override = overrides[alert.id];
    const outcomeOverridden =
      override !== undefined && override.outcome !== SAME;
    const reasonOverridden =
      override !== undefined && override.closureReason !== SAME;
    if (!outcomeOverridden && !reasonOverridden) {
      return [];
    }
    return [
      {
        alertId: alert.id,
        outcome: outcomeOverridden
          ? (override.outcome as CaseOutcome)
          : values.outcome,
        closureReason: reasonOverridden
          ? (override.closureReason as ClosureReason)
          : values.closureReason,
      },
    ];
  });
}

function describeCloseFailure(error: unknown): CaseActionFailure {
  return describeCaseFailure(error, {
    versionConflict:
      "This case changed since you opened it. Reload it and close again.",
    stateConflict: "This case is already closed.",
    forbidden: "You do not have permission to close this case.",
  });
}
