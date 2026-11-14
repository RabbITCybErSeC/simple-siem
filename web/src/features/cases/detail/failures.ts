import { ApiError } from "../../../api/client";
import type { CaseActionFailure } from "./types";

export interface CaseFailureMessages {
  versionConflict: string;
  stateConflict: string;
  forbidden: string;
  validation?: string;
  generic?: string;
}

/** Shared API error mapping; each action supplies its own wording. */
export function describeCaseFailure(
  error: unknown,
  messages: CaseFailureMessages,
): CaseActionFailure {
  if (error instanceof ApiError) {
    if (error.status === 409 && error.code === "VERSION_CONFLICT") {
      return { message: messages.versionConflict, reload: true };
    }
    if (error.status === 409 && error.code === "STATE_CONFLICT") {
      return { message: messages.stateConflict, reload: false };
    }
    if (error.status === 403) {
      return { message: messages.forbidden, reload: false };
    }
    if (error.status === 400 && messages.validation !== undefined) {
      return { message: messages.validation, reload: false };
    }
    if (error.code === "NETWORK_ERROR") {
      return { message: "Cannot reach Simple SIEM. Try again.", reload: false };
    }
  }
  return {
    message: messages.generic ?? "Something went wrong. Try again.",
    reload: false,
  };
}
