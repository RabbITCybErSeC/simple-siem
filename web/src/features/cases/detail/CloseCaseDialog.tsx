import { zodResolver } from "@hookform/resolvers/zod";
import { memo, useCallback, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Controller, useForm } from "react-hook-form";
import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
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
import {
  Field,
  FieldError,
  FieldLegend,
  FieldSet,
} from "../../../components/ui/field";
import { Label } from "../../../components/ui/label";
import { RadioGroup, RadioGroupItem } from "../../../components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../../../components/ui/select";
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

export const CLOSE_DIALOG_LAYOUT = {
  content: "flex max-h-[calc(100svh-2rem)] flex-col gap-0 p-0 sm:max-w-xl",
  body: "min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-4",
  footer: "mx-0 mb-0 flex-row justify-end gap-2 border-t px-6 py-4",
} as const;

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

  const changeOverride = useCallback(
    (alertId: string, field: keyof AlertOverride, value: string) => {
      setOverrides((current) => ({
        ...current,
        [alertId]: {
          outcome: current[alertId]?.outcome ?? SAME,
          closureReason: current[alertId]?.closureReason ?? SAME,
          [field]: value as AlertOverride[typeof field],
        },
      }));
    },
    [],
  );

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
        className={CLOSE_DIALOG_LAYOUT.content}
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
        <DialogHeader className="px-6 pt-6">
          <DialogTitle>{`Close case #${detail.caseNumber}`}</DialogTitle>
          <DialogDescription>
            {detail.alertCount === 1 ? "1 alert." : `${detail.alertCount} alerts.`}{" "}
            Choose an outcome, a closure reason, and a conclusion.
          </DialogDescription>
        </DialogHeader>

        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={submitHandler}
          noValidate
        >
          <div className={CLOSE_DIALOG_LAYOUT.body}>
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
          </div>

          <DialogFooter className={CLOSE_DIALOG_LAYOUT.footer}>
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
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
              /* segmented's inline-flex and gap must beat RadioGroup's grid
                 and gap-2, which cn cannot merge with a custom utility. */
              className="segmented inline-flex gap-0.5"
              value={field.value ?? ""}
              onValueChange={field.onChange}
              aria-labelledby={`${idPrefix}-outcome-label`}
              aria-describedby={
                fieldState.error ? `${idPrefix}-outcome-error` : undefined
              }
              aria-invalid={fieldState.error ? true : undefined}
            >
              {OUTCOME_OPTIONS.map((outcome, index) => (
                <label key={outcome} className="segmented-item">
                  <RadioGroupItem
                    ref={index === 0 ? field.ref : undefined}
                    id={`${idPrefix}-outcome-${outcome}`}
                    className="sr-only"
                    value={outcome}
                  />
                  {OUTCOME_LABELS[outcome]}
                </label>
              ))}
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
            <Select
              name={field.name}
              value={field.value ?? ""}
              onValueChange={field.onChange}
            >
              <SelectTrigger
                id={`${idPrefix}-reason`}
                ref={field.ref}
                onBlur={field.onBlur}
                className="w-full"
                aria-invalid={fieldState.error ? true : undefined}
                aria-describedby={
                  fieldState.error ? `${idPrefix}-reason-error` : undefined
                }
              >
                <SelectValue placeholder="Choose a reason" />
              </SelectTrigger>
              <SelectContent>
                {CLOSURE_REASON_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
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

const DISPOSITIONS_LABEL_ID = "close-dispositions-label";

function AlertDispositions({
  alerts,
  overrides,
  onChange,
}: AlertDispositionsProps) {
  return (
    <div className="space-y-2">
      <p id={DISPOSITIONS_LABEL_ID} className="text-sm font-medium">
        Alert dispositions
      </p>
      <div
        aria-hidden="true"
        className="hidden py-2 text-xs font-medium text-muted-foreground sm:grid sm:grid-cols-[minmax(0,1fr)_10rem_10rem] sm:items-center"
      >
        <span>Alert</span>
        <span>Outcome</span>
        <span>Closure reason</span>
      </div>
      <ul aria-labelledby={DISPOSITIONS_LABEL_ID}>
        {alerts.map((alert) => (
          <AlertDispositionRow
            key={alert.id}
            alert={alert}
            override={overrides[alert.id]}
            onChange={onChange}
          />
        ))}
      </ul>
    </div>
  );
}

interface AlertDispositionRowProps {
  alert: AlertSummary;
  override: AlertOverride | undefined;
  onChange: (
    alertId: string,
    field: keyof AlertOverride,
    value: string,
  ) => void;
}

const AlertDispositionRow = memo(function AlertDispositionRow({
  alert,
  override,
  onChange,
}: AlertDispositionRowProps) {
  return (
    <li className="grid gap-2 border-t py-3 sm:grid-cols-[minmax(0,1fr)_10rem_10rem] sm:items-center">
      <span className="text-sm font-medium sm:truncate">{alert.title}</span>
      <div className="grid grid-cols-2 gap-2 sm:contents">
        <Select
          value={override?.outcome ?? SAME}
          onValueChange={(value) => onChange(alert.id, "outcome", value)}
        >
          <SelectTrigger
            aria-label={`Outcome for ${alert.title}`}
            className="w-full"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={SAME}>Same as case</SelectItem>
            {OUTCOME_OPTIONS.map((outcome) => (
              <SelectItem key={outcome} value={outcome}>
                {OUTCOME_LABELS[outcome]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={override?.closureReason ?? SAME}
          onValueChange={(value) =>
            onChange(alert.id, "closureReason", value)
          }
        >
          <SelectTrigger
            aria-label={`Closure reason for ${alert.title}`}
            className="w-full"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={SAME}>Same as case</SelectItem>
            {CLOSURE_REASON_OPTIONS.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </li>
  );
});

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
