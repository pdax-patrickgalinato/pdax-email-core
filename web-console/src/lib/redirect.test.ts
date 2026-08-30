import { describe, expect, it } from "vitest";
import { safeNext } from "./redirect";

describe("safeNext", () => {
  it("allows same-origin relative console paths", () => {
    expect(safeNext("/queue")).toBe("/queue");
    expect(safeNext("/mail/abc%201")).toBe("/mail/abc%201");
  });

  it("rejects open redirects and login/api loops", () => {
    expect(safeNext("//evil.example")).toBe("/overview");
    expect(safeNext("https://evil.example")).toBe("/overview");
    expect(safeNext("/login?next=/overview")).toBe("/overview");
    expect(safeNext("/api/auth/me")).toBe("/overview");
    expect(safeNext(null)).toBe("/overview");
    expect(safeNext("")).toBe("/overview");
  });
});
