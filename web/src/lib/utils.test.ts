import { describe, expect, it } from "vitest";

import { cn } from "./utils";

describe("cn", () => {
  it("keeps the last conflicting utility", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");
    expect(cn("px-2 py-1", "p-3")).toBe("p-3");
  });

  it("drops falsy values", () => {
    expect(cn("text-sm", false, undefined, "font-medium")).toBe(
      "text-sm font-medium",
    );
  });

  it("supports conditional objects", () => {
    expect(cn({ hidden: false, flex: true })).toBe("flex");
  });
});
