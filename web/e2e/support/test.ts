import { expect, test as base } from "@playwright/test";
import type { ConsoleMessage } from "@playwright/test";
import { FixtureApi } from "./api.ts";

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
      expect(browserMessages, "browser console").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
