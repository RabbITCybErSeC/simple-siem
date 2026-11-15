import type { ErrorCode, ErrorEnvelope } from "./types";

const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: ErrorCode | string;
  details: Record<string, unknown>;

  constructor(
    status: number,
    code: ErrorCode | string,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function isClientError(error: unknown): boolean {
  return (
    error instanceof ApiError && error.status >= 400 && error.status < 500
  );
}

export async function apiRequest<T>(
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Requested-With": "simple-siem",
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      credentials: "same-origin",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "NETWORK_ERROR", "Network request failed");
  }

  if (!response.ok) {
    const envelope = await readErrorEnvelope(response);
    if (envelope) {
      throw new ApiError(
        response.status,
        envelope.error.code,
        envelope.error.message,
        envelope.error.details ?? {},
      );
    }
    throw new ApiError(
      response.status,
      "INTERNAL_ERROR",
      "Unexpected response from the server",
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  if (text === "") {
    return undefined as T;
  }

  return JSON.parse(text) as T;
}

export const get = <T>(path: string) => apiRequest<T>("GET", path);
export const post = <T>(path: string, body?: unknown) =>
  apiRequest<T>("POST", path, body);

async function readErrorEnvelope(
  response: Response,
): Promise<ErrorEnvelope | undefined> {
  try {
    const parsed: unknown = JSON.parse(await response.text());
    return isErrorEnvelope(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const error = (value as { error?: unknown }).error;
  if (typeof error !== "object" || error === null) {
    return false;
  }

  const { code, message } = error as { code?: unknown; message?: unknown };
  return typeof code === "string" && typeof message === "string";
}
