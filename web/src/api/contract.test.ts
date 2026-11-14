import { describe, expect, it } from "vitest";
import errorContract from "./contract/error.json";
import loginContract from "./contract/login.json";
import meContract from "./contract/me.json";
import type { ErrorEnvelope, LoginResponse, User } from "./types";

// JSON imports widen string literals, so Role and UserStatus values cannot be
// checked against their unions here; the Go handler owns those values. The
// mapped shape still fails the build on a missing or renamed field.
type JsonShape<T> = T extends string
  ? string
  : T extends number
    ? number
    : T extends boolean
      ? boolean
      : T extends readonly (infer Item)[]
        ? JsonShape<Item>[]
        : T extends object
          ? { [Key in keyof T]: JsonShape<T[Key]> }
          : T;

const login = loginContract satisfies JsonShape<LoginResponse>;
const user = meContract satisfies JsonShape<User>;
const error = errorContract satisfies JsonShape<ErrorEnvelope>;

function expectKeys(value: object, keys: string[]): void {
  expect(Object.keys(value).sort()).toEqual([...keys].sort());
}

describe("API contract files", () => {
  it("login.json has exactly the LoginResponse keys", () => {
    expectKeys(login, ["expiresAt", "user"]);
    expectKeys(login.user, ["id", "email", "displayName", "roles"]);
  });

  it("me.json has exactly the User keys", () => {
    expectKeys(user, [
      "id",
      "email",
      "displayName",
      "status",
      "onCall",
      "roles",
      "createdAt",
      "updatedAt",
      "version",
    ]);
  });

  it("error.json has exactly the ErrorEnvelope keys", () => {
    expectKeys(error, ["error"]);
    expectKeys(error.error, ["code", "message"]);
  });
});
