import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import UserManagement from "./UserManagement";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { viewerUser } from "../test/fixtures";

describe("UserManagement", () => {
  it("shows JumpCloud SSO and local accounts for admins", () => {
    resetEngine();
    renderWithConsole(<UserManagement />, { route: "/settings/users" });
    expect(screen.getByRole("heading", { name: "JumpCloud SSO" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "User provisioning" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Create user" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Users & SSO" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Open profile" })).toHaveAttribute("href", "/profile");
  });

  it("sends viewers back to overview", () => {
    resetEngine();
    window.__SEG_CURRENT_USER__ = viewerUser;
    renderWithConsole(<UserManagement />, { user: viewerUser, route: "/settings/users" });
    expect(screen.queryByRole("heading", { name: "JumpCloud SSO" })).not.toBeInTheDocument();
  });
});
