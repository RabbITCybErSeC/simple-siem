import { useCallback, useEffect, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { ApiError } from "../../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { Input } from "../../../components/ui/input";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "../../../components/ui/tabs";
import type {
  CaseCommands,
  TimeZoneSetting,
} from "../../shell/types";
import { setCaseCommands } from "../../shell/commands";
import { SEVERITY_STYLES } from "../CaseTable";
import type {
  CaseDetailLayout,
  CaseDetailView,
  CaseQueueState,
} from "../types";
import { absoluteLink, copyText } from "./clipboard";
import { CloseCaseDialog } from "./CloseCaseDialog";
import {
  AlertsSection,
  Overview,
  STATUS_LABELS,
  TimelineSection,
} from "./CaseSections";
import { describeCaseFailure } from "./failures";
import { useAssignCase, useCaseDetail } from "./queries";
import type { CaseActionFailure, CaseDetail as CaseDetailData } from "./types";

export interface CaseDetailProps {
  caseNumber: number;
  view: CaseDetailView;
  layout: CaseDetailLayout;
  queueState: CaseQueueState;
  timeZone: TimeZoneSetting;
  /** A row's `e` asks for the close dialog once this detail has loaded. */
  closeRequested?: boolean;
  onCloseRequestHandled?: () => void;
  onViewChange: (view: CaseDetailView) => void;
  onLayoutChange: (layout: CaseDetailLayout) => void;
  onClose: () => void;
}

interface DetailFailure {
  message: string;
  retry: boolean;
}

export interface CaseActionAlertProps {
  failure: CaseActionFailure;
  onReload: () => void;
}

const COPY_STATUS_MILLISECONDS = 2_000;

export function describeAssignFailure(error: unknown): CaseActionFailure {
  return describeCaseFailure(error, {
    versionConflict: "This case changed since you opened it.",
    stateConflict: "This case is closed.",
    forbidden: "You do not have permission to assign this case.",
    validation: "This user cannot be assigned.",
  });
}

export function CaseActionAlert({ failure, onReload }: CaseActionAlertProps) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-foreground"
    >
      <p>{failure.message}</p>
      {failure.reload ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={onReload}
        >
          Reload case
        </Button>
      ) : null}
    </div>
  );
}

export function CaseDetail({
  caseNumber,
  view,
  layout,
  queueState,
  timeZone,
  closeRequested = false,
  onCloseRequestHandled,
  onViewChange,
  onLayoutChange,
  onClose,
}: CaseDetailProps) {
  const detailQuery = useCaseDetail(caseNumber);
  const detail = detailQuery.data;
  const { data: me } = useCurrentUser();
  const {
    mutate: assignCaseMutation,
    isPending: assignPending,
  } = useAssignCase();
  const [assignFailed, setAssignFailed] = useState<CaseActionFailure | null>(
    null,
  );
  const [closeOpen, setCloseOpen] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const fallbackInputRef = useRef<HTMLInputElement>(null);
  const copyTimer = useRef<number | undefined>(undefined);
  const [announcement, setAnnouncement] = useState<string | null>(null);
  const [fallbackLink, setFallbackLink] = useState<string | null>(null);

  const announce = useCallback((message: string) => {
    setAnnouncement(message);
    window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(
      () => setAnnouncement(null),
      COPY_STATUS_MILLISECONDS,
    );
  }, []);

  useEffect(() => {
    headingRef.current?.focus();
  }, [caseNumber]);

  useEffect(() => {
    return () => window.clearTimeout(copyTimer.current);
  }, []);

  useEffect(() => {
    if (fallbackLink !== null) {
      fallbackInputRef.current?.focus();
      fallbackInputRef.current?.select();
    }
  }, [fallbackLink]);

  const copyLink = useCallback(async () => {
    const link = absoluteLink(window.location, new Date());
    const copied = await copyText(link);
    if (!copied) {
      setFallbackLink(link);
      setAnnouncement(null);
      return;
    }

    setFallbackLink(null);
    announce("Link copied");
  }, [announce]);

  const closeCase = useCallback(
    (closed: CaseDetailData) => {
      setCloseOpen(false);
      onCloseRequestHandled?.();
      headingRef.current?.focus();
      announce(`Case #${closed.caseNumber} closed`);
    },
    [announce, onCloseRequestHandled],
  );

  const changeCloseOpen = (open: boolean) => {
    if (!open && closeRequested) {
      onCloseRequestHandled?.();
    }
    setCloseOpen(open);
  };

  const closeDialogOpen =
    closeOpen ||
    (closeRequested && detail !== undefined && detail.status !== "CLOSED");

  // A requested close that the loaded case cannot satisfy (already closed)
  // must not leak into the next case.
  useEffect(() => {
    if (closeRequested && detail?.status === "CLOSED") {
      onCloseRequestHandled?.();
    }
  }, [closeRequested, detail, onCloseRequestHandled]);

  const assignCase = useCallback(() => {
    if (detail === undefined || me === undefined) {
      return;
    }
    setAssignFailed(null);
    assignCaseMutation(
      {
        caseId: detail.id,
        caseNumber,
        request: {
          assigneeId: detail.assignee?.id === me.id ? null : me.id,
          version: detail.version,
        },
      },
      { onError: (error) => setAssignFailed(describeAssignFailure(error)) },
    );
  }, [assignCaseMutation, caseNumber, detail, me]);

  // The palette runs the same actions as the pane, so the detail stays the
  // single owner of assign, close, copy link, and the layout toggle. Row and
  // route commands register even while the case is loading or missing.
  useEffect(() => {
    const commands: CaseCommands = {
      caseNumber,
      copyLink: () => void copyLink(),
      closeDetail: onClose,
      toggleFullPage: () =>
        onLayoutChange(layout === "full" ? "split" : "full"),
    };
    if (detail !== undefined && detail.status !== "CLOSED") {
      commands.assignLabel = detail.assignee?.id === me?.id
        ? "Unassign"
        : "Assign to me";
      commands.assign = assignCase;
      commands.close = () => setCloseOpen(true);
    }
    setCaseCommands(commands);
    return () => setCaseCommands(undefined);
  }, [
    assignCase,
    caseNumber,
    copyLink,
    detail,
    layout,
    me,
    onClose,
    onLayoutChange,
  ]);

  function handleKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Escape" || overlayOpen()) {
      return;
    }
    event.preventDefault();
    onClose();
  }

  const loadFailure =
    detailQuery.isError && detailQuery.error !== null
      ? describeDetailFailure(detailQuery.error, caseNumber)
      : null;

  return (
    <section
      aria-label={`Case #${caseNumber}`}
      onKeyDown={handleKeyDown}
      className="min-w-0"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2
            ref={headingRef}
            tabIndex={-1}
            className="text-xl font-semibold tracking-tight outline-none"
          >
            #{caseNumber}
            {detail === undefined ? "" : ` ${detail.title}`}
          </h2>
          {detail === undefined ? null : (
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <Badge className={SEVERITY_STYLES[detail.severity].className}>
                {SEVERITY_STYLES[detail.severity].label}
              </Badge>
              <span>{STATUS_LABELS[detail.status]}</span>
              <span aria-hidden="true">·</span>
              <span>{detail.assignee?.displayName ?? "Unassigned"}</span>
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {detail === undefined || detail.status === "CLOSED" ? null : (
            <Button
              type="button"
              size="sm"
              disabled={assignPending || me === undefined}
              onClick={assignCase}
            >
              {detail.assignee?.id === me?.id ? "Unassign" : "Assign to me"}
            </Button>
          )}
          {detail === undefined || detail.status === "CLOSED" ? null : (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setCloseOpen(true)}
            >
              Close case
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void copyLink()}
          >
            Copy link
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            aria-label="Toggle full page"
            aria-pressed={layout === "full"}
            onClick={() =>
              onLayoutChange(layout === "full" ? "split" : "full")
            }
          >
            ⤢
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            aria-label="Close case detail"
            onClick={onClose}
          >
            ×
          </Button>
        </div>
      </div>

      <p role="status" className="sr-only">
        {announcement}
      </p>
      {assignFailed === null ? null : (
        <div className="mt-3">
          <CaseActionAlert
            failure={assignFailed}
            onReload={() => {
              setAssignFailed(null);
              void detailQuery.refetch();
            }}
          />
        </div>
      )}
      {fallbackLink === null ? null : (
        <div className="mt-3">
          <label htmlFor="case-link" className="text-xs text-muted-foreground">
            Case link
          </label>
          <Input
            id="case-link"
            ref={fallbackInputRef}
            readOnly
            value={fallbackLink}
            className="mt-1 font-mono text-xs"
            onFocus={(event) => event.currentTarget.select()}
          />
        </div>
      )}

      {loadFailure === null ? null : (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-foreground"
        >
          <p>{loadFailure.message}</p>
          {loadFailure.retry ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => void detailQuery.refetch()}
            >
              Retry
            </Button>
          ) : null}
        </div>
      )}

      {detail === undefined ? (
        loadFailure === null ? (
          <p aria-busy="true" className="mt-4 text-sm text-muted-foreground">
            Loading case…
          </p>
        ) : null
      ) : (
        <Tabs
          value={view}
          onValueChange={(value) => onViewChange(value as CaseDetailView)}
          className="mt-4"
        >
          <TabsList aria-label="Case sections">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="alerts">
              {`Alerts ${detail.alertCount}`}
            </TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>
          <TabsContent value="overview">
            <Overview
              detail={detail}
              queueState={queueState}
              timeZone={timeZone}
            />
          </TabsContent>
          <TabsContent value="alerts">
            <AlertsSection caseId={detail.id} timeZone={timeZone} />
          </TabsContent>
          <TabsContent value="timeline">
            <TimelineSection caseId={detail.id} timeZone={timeZone} />
          </TabsContent>
          <TabsContent value="activity">
            <TimelineSection
              caseId={detail.id}
              kind="ACTIVITY"
              timeZone={timeZone}
            />
          </TabsContent>
        </Tabs>
      )}

      {detail === undefined ? null : (
        <CloseCaseDialog
          key={detail.caseNumber}
          detail={detail}
          open={closeDialogOpen}
          onOpenChange={changeCloseOpen}
          onReload={() => void detailQuery.refetch()}
          onClosed={closeCase}
        />
      )}
    </section>
  );
}

function describeDetailFailure(
  error: Error,
  caseNumber: number,
): DetailFailure {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return {
        message: `Case #${caseNumber} was not found.`,
        retry: false,
      };
    }
    if (error.status === 403) {
      return {
        message: "You do not have permission to view this case.",
        retry: false,
      };
    }
    if (error.code === "NETWORK_ERROR") {
      return { message: "Cannot reach Simple SIEM. Try again.", retry: true };
    }
  }
  return { message: "Something went wrong. Try again.", retry: true };
}

function overlayOpen(): boolean {
  return (
    document.querySelector(
      '[role="dialog"], [data-radix-popper-content-wrapper]',
    ) !== null
  );
}
