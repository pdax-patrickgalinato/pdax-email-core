import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import Profile from "./Profile";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { viewerUser } from "../test/fixtures";

describe("Profile", () => {
  it("shows security settings and audit trail for the signed-in user", () => {
    resetEngine();
    renderWithConsole(<Profile />, { route: "/profile" });
    expect(screen.getByRole("heading", { name: "Signed in as admin" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Password" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Multi-factor authentication" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Your activity" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add passkey" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Search your activity…")).toBeInTheDocument();
  });

  it("is available to viewers", () => {
    resetEngine();
    window.__SEG_CURRENT_USER__ = viewerUser;
    renderWithConsole(<Profile />, { user: viewerUser, route: "/profile" });
    expect(screen.getByRole("heading", { name: "Signed in as viewer" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Multi-factor authentication" })).toBeInTheDocument();
  });
});
