import { defineConfig, devices } from "@playwright/test";

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
    baseURL: "http://127.0.0.1:8090",
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
  webServer: {
    command:
      "sh -c '../bin/simple-siem migrate && ../bin/simple-siem admin create --email analyst@example.test --display-name \"Alice Analyst\" --password-file e2e/support/test-password.txt && exec ../bin/simple-siem serve'",
    url: "http://127.0.0.1:8090/readyz",
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  },
});
