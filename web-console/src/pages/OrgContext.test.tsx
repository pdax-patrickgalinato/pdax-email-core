import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import OrgContext from "./OrgContext";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { viewerUser } from "../test/fixtures";

describe("Organization settings", () => {
  it("shows context notes and blocklist for admins", () => {
    resetEngine();
    renderWithConsole(<OrgContext />, { route: "/settings/organization" });
    expect(screen.getByRole("heading", { name: "Facts the AI should keep using" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Always quarantine" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Always deliver" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Organization" })).toHaveAttribute("aria-current", "page");
  });

  it("sends viewers back to overview", () => {
    resetEngine();
    window.__SEG_CURRENT_USER__ = viewerUser;
    renderWithConsole(<OrgContext />, { user: viewerUser, route: "/settings/organization" });
    expect(screen.queryByRole("heading", { name: "Facts the AI should keep using" })).not.toBeInTheDocument();
  });
});
