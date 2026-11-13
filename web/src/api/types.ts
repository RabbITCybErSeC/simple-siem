/** `NETWORK_ERROR` is client-only: the API never sends it. */
export type ErrorCode =
  | "AUTHENTICATION_REQUIRED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "VALIDATION_ERROR"
  | "VERSION_CONFLICT"
  | "STATE_CONFLICT"
  | "RATE_LIMITED"
  | "INTERNAL_ERROR"
  | "NETWORK_ERROR";

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

export interface Pagination {
  page: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
}

export interface ListResponse<T> {
  data: T[];
  pagination: Pagination;
}

export type Role =
  | "ADMIN"
  | "SECURITY_ENGINEER"
  | "ANALYST"
  | "READ_ONLY"
  | "SERVICE";

export type UserStatus = "ACTIVE" | "DISABLED" | "INVITED";

export interface User {
  id: string;
  email: string;
  displayName: string;
  status: UserStatus;
  roles: Role[];
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

/** Browser logins receive the session cookie, so there is no token in the body. */
export interface LoginResponse {
  expiresAt: string;
  user: Pick<User, "id" | "email" | "displayName" | "roles">;
}
