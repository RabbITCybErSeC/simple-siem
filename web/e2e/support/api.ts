// shortcut: network fixtures for /cases, use the real case API when case-core and case-close are on main.
import type { Page, Request, Route } from "@playwright/test";
import type { ErrorEnvelope } from "../../src/api/types.ts";
import type { CaseSummary } from "../../src/features/cases/types.ts";
import { CaseFixtureRoutes } from "./cases.ts";

function errorEnvelope(code: string, message: string): ErrorEnvelope {
  return { error: { code, message } };
}

// Every /api/v1 request passes through here so the client's half of the
// contract is checked; routes that exist on the server are let through.
export class FixtureApi {
  private readonly page: Page;

  readonly violations: string[] = [];
  readonly cases = new CaseFixtureRoutes(this.violations);

  constructor(page: Page) {
    this.page = page;
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
