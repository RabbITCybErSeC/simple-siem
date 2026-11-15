// shortcut: network fixtures for /cases, use the real case API when case-core and case-close are on main; the fake route and its fake-case self-tests are removed together.
import type { Page, Request, Route } from "@playwright/test";
import type { ErrorEnvelope } from "../../src/api/types.ts";
import type {
  CaseAssignee,
  CaseSummary,
} from "../../src/features/cases/types.ts";
import type { CloseFailure } from "./cases.ts";
import { CaseFixtureRoutes } from "./cases.ts";

function errorEnvelope(code: string, message: string): ErrorEnvelope {
  return { error: { code, message } };
}

// Every /api/v1 request passes through here so the client's half of the
// contract is checked; routes that exist on the server are let through.
export class FixtureApi {
  private readonly page: Page;
  private meRequest: Promise<CaseAssignee | null> | null = null;

  readonly violations: string[] = [];
  readonly cases: CaseFixtureRoutes;

  constructor(page: Page) {
    this.page = page;
    this.cases = new CaseFixtureRoutes(this.violations);
  }

  async currentUser(): Promise<CaseAssignee> {
    await this.ensureMe();
    return this.cases.currentUser();
  }

  failNextClose(code: CloseFailure): void {
    this.cases.failNextClose(code);
  }

  bumpVersion(caseId: string): void {
    this.cases.bumpVersion(caseId);
  }

  async install(): Promise<void> {
    await this.page.route("**/api/v1/**", (route) => this.handle(route));
  }

  addCase(partial: Partial<CaseSummary>): CaseSummary {
    return this.cases.addCase(partial);
  }

  updateCase(id: string, partial: Partial<CaseSummary>): CaseSummary {
    return this.cases.updateCase(id, partial);
  }

  setNow(date: Date): void {
    this.cases.setNow(date);
  }

  caseRequests(): string[] {
    return this.cases.caseRequests();
  }

  // The first /cases request learns the signed-in user from the real /me
  // route, so the seeded user_1 is the analyst the page is signed in as.
  private async ensureMe(): Promise<void> {
    this.meRequest ??= this.fetchMe();
    const me = await this.meRequest;
    if (me !== null) {
      this.cases.setMe(me);
    }
  }

  private async fetchMe(): Promise<CaseAssignee | null> {
    const response = await this.page.request.get("/api/v1/me", {
      headers: { "X-Requested-With": "simple-siem" },
    });
    if (!response.ok()) {
      return null;
    }
    const user = (await response.json()) as {
      id?: unknown;
      displayName?: unknown;
    };
    if (typeof user.id !== "string" || typeof user.displayName !== "string") {
      return null;
    }
    return { id: user.id, displayName: user.displayName };
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname;
    this.recordContractViolations(request, method, path);

    if (path === "/api/v1/me" || path.startsWith("/api/v1/auth/")) {
      await route.continue();
      return;
    }
    if (path === "/api/v1/cases" || path.startsWith("/api/v1/cases/")) {
      const cookieHeader = (await request.headerValue("cookie")) ?? "";
      if (!cookieHeader.includes("simple_siem_session=")) {
        await this.respondJson(
          route,
          401,
          errorEnvelope("AUTHENTICATION_REQUIRED", "Authentication required"),
        );
        return;
      }
      await this.ensureMe();
      const url = new URL(request.url());
      await this.cases.handle(route, path, url.searchParams);
      return;
    }

    this.violations.push(`${method} ${path}: no fixture or real route`);
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
