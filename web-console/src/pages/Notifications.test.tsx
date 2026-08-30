import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import Notifications from "./Notifications";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { viewerUser } from "../test/fixtures";

describe("Notifications settings", () => {
  it("shows Slack and email channels for admins", () => {
    resetEngine();
    renderWithConsole(<Notifications />, { route: "/settings/notifications" });
    expect(screen.getByRole("heading", { name: "Slack" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Email" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Notifications" })).toHaveAttribute("aria-current", "page");
  });

  it("sends viewers back to overview", () => {
    resetEngine();
    window.__SEG_CURRENT_USER__ = viewerUser;
    renderWithConsole(<Notifications />, { user: viewerUser, route: "/settings/notifications" });
    expect(screen.queryByRole("heading", { name: "Slack" })).not.toBeInTheDocument();
  });
});
