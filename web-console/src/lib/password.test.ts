import { describe, expect, it } from "vitest";
import { PASSWORD_CHECKS, passwordMeetsPolicy } from "./password";

describe("password policy", () => {
  it("rejects short or simple passwords", () => {
    expect(passwordMeetsPolicy("short")).toBe(false);
    expect(passwordMeetsPolicy("alllowercase1!")).toBe(false);
    expect(passwordMeetsPolicy("ALLUPPERCASE1!")).toBe(false);
    expect(passwordMeetsPolicy("NoDigits!!")).toBe(false);
    expect(passwordMeetsPolicy("NoSpecials1")).toBe(false);
  });

  it("accepts a password that hits every rule", () => {
    expect(passwordMeetsPolicy("GoodPass1!")).toBe(true);
    expect(PASSWORD_CHECKS.every((c) => c.test("GoodPass1!"))).toBe(true);
  });
});
