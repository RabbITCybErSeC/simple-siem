import { defineConfig, devices } from "@playwright/test";
import { APP_ORIGIN } from "./e2e/support/test.ts";

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.e2e.ts",
  forbidOnly: true,
  retries: 0,
  workers: 1,
  outputDir: "test-results",
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
  ],
  use: {
    baseURL: APP_ORIGIN,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "setup",
      testMatch: "**/support/users.setup.ts",
    },
    {
      name: "chromium",
      testMatch: "**/*.e2e.ts",
      dependencies: ["setup"],
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // Expects the empty database make e2e recreates before each run; admin
  // create supplies the only user the browser tests start with.
  webServer: {
    command:
      "sh -c '../bin/simple-siem migrate && ../bin/simple-siem admin create --email admin@example.test --display-name \"Ada Admin\" --password-file e2e/support/test-password.txt && exec ../bin/simple-siem serve'",
    url: "http://127.0.0.1:8090/readyz",
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  },
});
