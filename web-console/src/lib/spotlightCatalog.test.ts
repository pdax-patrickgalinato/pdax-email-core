import { describe, expect, it } from "vitest";
import { matchCatalog, scoreCatalogItem, CONSOLE_CATALOG } from "./spotlightCatalog";

describe("spotlight catalog", () => {
  it("finds Settings from a short query", () => {
    const hits = matchCatalog("settings", { admin: true });
    expect(hits[0].id).toBe("settings-gateway");
    expect(hits.some((h) => h.id === "settings-users")).toBe(true);
  });

  it("opens Users & SSO from sso or jumpcloud", () => {
    expect(matchCatalog("sso", { admin: true })[0].id).toBe("settings-users");
    expect(matchCatalog("jumpcloud", { admin: true })[0].id).toBe("settings-users");
  });

  it("finds the organization blocklist", () => {
    expect(matchCatalog("blocklist", { admin: true })[0].id).toBe("settings-organization");
  });

  it("scores dark appearance for a theme toggle", () => {
    const dark = CONSOLE_CATALOG.find((i) => i.id === "theme-dark")!;
    expect(scoreCatalogItem(dark, "dark")).toBeGreaterThan(50);
    expect(matchCatalog("dark mode", { admin: false })[0].action).toEqual({ kind: "theme", mode: "dark" });
  });

  it("hides admin destinations from viewers", () => {
    const hits = matchCatalog("settings", { admin: false });
    expect(hits.every((h) => !h.admin)).toBe(true);
    expect(hits.some((h) => h.group === "Settings")).toBe(false);
  });

  it("suggests pages and appearance when the query is empty", () => {
    const hits = matchCatalog("", { admin: true });
    expect(hits.some((h) => h.id === "page-overview")).toBe(true);
    expect(hits.some((h) => h.id === "theme-dark")).toBe(true);
  });
});
