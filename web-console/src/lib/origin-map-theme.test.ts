import { afterEach, describe, expect, it } from "vitest";
import "../app.css";

function token(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim().toLowerCase();
}

describe("origin map theme tokens", () => {
  afterEach(() => {
    document.documentElement.removeAttribute("data-theme");
  });

  it("paints land distinct from water in dark mode", () => {
    document.documentElement.setAttribute("data-theme", "dark");
    const land = token("--origin-land");
    const water = token("--origin-water");
    expect(land).toBe("#334155");
    expect(water).toBe("#0b1220");
    expect(land).not.toBe(water);
    expect(land).not.toBe(token("--page-accent"));
    expect(land).not.toBe(token("--surface"));
  });

  it("paints land distinct from water in light mode", () => {
    document.documentElement.setAttribute("data-theme", "light");
    const land = token("--origin-land");
    const water = token("--origin-water");
    expect(land).toBe("#b7c4d4");
    expect(water).toBe("#dce6f0");
    expect(land).not.toBe(water);
  });
});
