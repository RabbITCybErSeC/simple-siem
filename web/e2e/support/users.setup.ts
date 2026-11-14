import { expect, test as setup } from "@playwright/test";
import { BROWSER_HEADERS, TEST_USERS } from "./test.ts";

// Creates the analyst through the same admin routes the console uses, then
// sets the password with the public reset route so the analyst can sign in.
setup("creates the analyst through the admin API", async ({ request }) => {
  const adminLogin = await request.post("/api/v1/auth/login", {
    headers: BROWSER_HEADERS,
    data: {
      email: TEST_USERS.admin.email,
      password: TEST_USERS.admin.password,
    },
  });
  expect(adminLogin.status(), "admin sign in").toBe(200);

  const created = await request.post("/api/v1/users", {
    headers: BROWSER_HEADERS,
    data: {
      email: TEST_USERS.analyst.email,
      displayName: TEST_USERS.analyst.displayName,
      roles: ["ANALYST"],
    },
  });
  expect(created.status(), "create analyst").toBe(201);
  const { id } = (await created.json()) as { id: string };
  expect(id).not.toBe("");

  const reset = await request.post(`/api/v1/users/${id}/password-reset`, {
    headers: BROWSER_HEADERS,
  });
  expect(reset.status(), "create reset token").toBe(201);
  const { resetToken } = (await reset.json()) as { resetToken: string };

  const used = await request.post("/api/v1/auth/password-reset", {
    headers: BROWSER_HEADERS,
    data: { token: resetToken, password: TEST_USERS.analyst.password },
  });
  expect(used.status(), "use reset token").toBe(204);
});
