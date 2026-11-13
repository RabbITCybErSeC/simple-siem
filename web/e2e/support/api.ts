// shortcut: network fixtures for /auth and /me, use the real backend when simple-siem-8jx is on main.
import type { Page, Request, Route } from "@playwright/test";

type Role = "ANALYST";

type User = {
  id: string;
  email: string;
  displayName: string;
  status: "ACTIVE";
  roles: Role[];
  createdAt: string;
  updatedAt: string;
  version: number;
};

type LoginRequest = {
  email: string;
  password: string;
};

type ErrorEnvelope = {
  error: {
    code: string;
    message: string;
    details: Record<string, never>;
  };
};

const KNOWN_EMAIL = "analyst@example.test";
const KNOWN_PASSWORD = "correct horse battery staple";

const KNOWN_USER: User = {
  id: "user_1",
  email: KNOWN_EMAIL,
  displayName: "Alice Analyst",
  status: "ACTIVE",
  roles: ["ANALYST"],
  createdAt: "2026-05-11T10:00:00Z",
  updatedAt: "2026-05-11T10:00:00Z",
  version: 1,
};

function errorEnvelope(code: string, message: string): ErrorEnvelope {
  return { error: { code, message, details: {} } };
}

const AUTHENTICATION_REQUIRED = errorEnvelope(
  "AUTHENTICATION_REQUIRED",
  "Authentication required",
);

function parseLoginRequest(body: string | null): LoginRequest | null {
  if (body === null) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null) {
      return null;
    }
    const { email, password } = parsed as Record<string, unknown>;
    if (typeof email !== "string" || typeof password !== "string") {
      return null;
    }
    return { email, password };
  } catch {
    return null;
  }
}

export class FixtureApi {
  private readonly page: Page;
  private signedIn = false;
  private expired = false;
  private loginRateLimited = false;

  readonly requests: string[] = [];
  readonly violations: string[] = [];

  constructor(page: Page) {
    this.page = page;
  }

  async install(): Promise<void> {
    await this.page.route("**/api/v1/**", (route) => this.handle(route));
  }

  signIn(): void {
    this.signedIn = true;
  }

  expireSession(): void {
    this.expired = true;
  }

  rateLimitLogin(): void {
    this.loginRateLimited = true;
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname;
    this.requests.push(`${method} ${path}`);
    this.recordContractViolations(request, method, path);

    if (this.expired) {
      this.expired = false;
      this.signedIn = false;
      await this.respondJson(route, 401, AUTHENTICATION_REQUIRED);
      return;
    }

    if (method === "POST" && path === "/api/v1/auth/login") {
      await this.login(route);
      return;
    }
    if (method === "POST" && path === "/api/v1/auth/logout") {
      this.signedIn = false;
      await route.fulfill({ status: 204 });
      return;
    }
    if (method === "GET" && path === "/api/v1/me") {
      if (this.signedIn) {
        await this.respondJson(route, 200, KNOWN_USER);
      } else {
        await this.respondJson(route, 401, AUTHENTICATION_REQUIRED);
      }
      return;
    }

    this.violations.push(`${method} ${path}: no fixture for this route`);
    await this.respondJson(
      route,
      404,
      errorEnvelope("NOT_FOUND", "Not found"),
    );
  }

  private recordContractViolations(
    request: Request,
    method: string,
    path: string,
  ): void {
    const headers = request.headers();
    if (headers["x-requested-with"] !== "simple-siem") {
      this.violations.push(`${method} ${path}: missing x-requested-with header`);
    }
    if (headers["authorization"] !== undefined) {
      this.violations.push(
        `${method} ${path}: unexpected authorization header`,
      );
    }
    if (
      request.postData() !== null &&
      !(headers["content-type"] ?? "").startsWith("application/json")
    ) {
      this.violations.push(
        `${method} ${path}: content-type must be application/json`,
      );
    }
  }

  private async login(route: Route): Promise<void> {
    if (this.loginRateLimited) {
      await this.respondJson(
        route,
        429,
        errorEnvelope(
          "RATE_LIMITED",
          "Too many attempts. Wait a minute and try again.",
        ),
      );
      return;
    }

    const credentials = parseLoginRequest(route.request().postData());
    if (
      credentials !== null &&
      credentials.email === KNOWN_EMAIL &&
      credentials.password === KNOWN_PASSWORD
    ) {
      this.signedIn = true;
      await this.respondJson(route, 200, {
        expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
        user: {
          id: KNOWN_USER.id,
          email: KNOWN_USER.email,
          displayName: KNOWN_USER.displayName,
          roles: KNOWN_USER.roles,
        },
      });
      return;
    }

    await this.respondJson(route, 401, AUTHENTICATION_REQUIRED);
  }

  private async respondJson(
    route: Route,
    status: number,
    body: object,
  ): Promise<void> {
    await route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  }
}
