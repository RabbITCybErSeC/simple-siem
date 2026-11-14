import { expect, test as base } from "@playwright/test";
import type { ConsoleMessage, Page } from "@playwright/test";
import { FixtureApi } from "./api.ts";

// Must match SIMPLE_SIEM_PUBLIC_URL=http://127.0.0.1:8090 in the Makefile
// e2e target; make cannot import this file.
export const APP_ORIGIN = "http://127.0.0.1:8090";

export const BROWSER_HEADERS = {
  "X-Requested-With": "simple-siem",
  Origin: APP_ORIGIN,
};

const TEST_PASSWORD = "correct horse battery staple";

export const TEST_USERS = {
  admin: {
    email: "admin@example.test",
    displayName: "Ada Admin",
    password: TEST_PASSWORD,
  },
  analyst: {
    email: "analyst@example.test",
    displayName: "Alice Analyst",
    password: TEST_PASSWORD,
  },
} as const;

export type TestRole = keyof typeof TEST_USERS;

// Signs in through the real API. The request context shares the page's cookie
// jar, so the browser keeps the HttpOnly session cookie.
export async function signIn(
  page: Page,
  role: TestRole = "analyst",
): Promise<void> {
  const user = TEST_USERS[role];
  const response = await page.request.post("/api/v1/auth/login", {
    headers: BROWSER_HEADERS,
    data: { email: user.email, password: user.password },
  });
  expect(response.status(), `sign in as ${user.email}`).toBe(200);
}

export const BASE_CONTENT_SECURITY_POLICY =
  "default-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";

const STYLE_NONCE_SUFFIX = /^; style-src 'self' 'nonce-[A-Za-z0-9_-]{22}'$/;
const FAILED_RESOURCE_MESSAGE = "Failed to load resource";

function isExpectedApiResourceFailure(message: ConsoleMessage): boolean {
  if (!message.text().startsWith(FAILED_RESOURCE_MESSAGE)) {
    return false;
  }
  const { url } = message.location();
  if (url === "") {
    return false;
  }
  try {
    return new URL(url, "http://127.0.0.1").pathname.startsWith("/api/v1/");
  } catch {
    return false;
  }
}

type Fixtures = {
  api: FixtureApi;
  browserGuard: void;
};

export const test = base.extend<Fixtures>({
  api: [
    async ({ page }, use) => {
      const api = new FixtureApi(page);
      await api.install();
      await use(api);
      expect(api.violations, "API fixture contract").toEqual([]);
    },
    { auto: true },
  ],
  browserGuard: [
    async ({ page }, use) => {
      const browserMessages: string[] = [];
      const documentPolicies: string[] = [];

      page.on("console", (message) => {
        if (message.type() !== "error" && message.type() !== "warning") {
          return;
        }
        if (isExpectedApiResourceFailure(message)) {
          return;
        }
        browserMessages.push(`${message.type()}: ${message.text()}`);
      });
      page.on("pageerror", (error) => {
        browserMessages.push(`pageerror: ${error.message}`);
      });
      page.on("response", (response) => {
        if (response.request().resourceType() === "document") {
          documentPolicies.push(
            response.headers()["content-security-policy"] ?? "",
          );
        }
      });

      await use();

      // A test that only uses page.request loads no document, so there is no
      // policy to check.
      if (documentPolicies.length > 0) {
        const firstDocumentPolicy = documentPolicies[0] ?? "";
        const policyRemainder = firstDocumentPolicy.slice(
          BASE_CONTENT_SECURITY_POLICY.length,
        );
        expect(
          firstDocumentPolicy.startsWith(BASE_CONTENT_SECURITY_POLICY),
          `first document Content-Security-Policy: ${firstDocumentPolicy}`,
        ).toBe(true);
        expect(
          STYLE_NONCE_SUFFIX.test(policyRemainder),
          `first document Content-Security-Policy style suffix: ${policyRemainder}`,
        ).toBe(true);
      }
      expect(browserMessages, "browser console").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
