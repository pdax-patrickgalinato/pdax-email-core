import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import Layout from "./Layout";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { viewerUser } from "../test/fixtures";

function Shell() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/overview" element={<p>overview-page</p>} />
        <Route path="/settings" element={<p>settings-page</p>} />
        <Route path="/settings/users" element={<p>users-page</p>} />
        <Route path="/mail/:id" element={<p>mail-page</p>} />
      </Route>
    </Routes>
  );
}

describe("Spotlight", () => {
  it("sits at the top of the console and never shows generated SQL", async () => {
    resetEngine();
    renderWithConsole(<Shell />, { route: "/overview" });
    const box = screen.getByRole("combobox", { name: /search mail and console/i });
    expect(box).toBeInTheDocument();
    await userEvent.click(box);
    await userEvent.type(box, "invoice");
    expect(screen.queryByText(/SELECT\s+queue_id/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/AI → SQL/)).not.toBeInTheDocument();
  });

  it("opens Settings from a catalog hit", async () => {
    resetEngine();
    const user = userEvent.setup();
    renderWithConsole(<Shell />, { route: "/overview" });
    const box = screen.getByRole("combobox", { name: /search mail and console/i });
    await user.click(box);
    await user.type(box, "settings");
    await user.click(screen.getByRole("option", { name: /gateway enforcement/i }));
    expect(screen.getByText("settings-page")).toBeInTheDocument();
  });

  it("toggles dark appearance from the results", async () => {
    resetEngine();
    document.documentElement.removeAttribute("data-theme");
    const user = userEvent.setup();
    renderWithConsole(<Shell />, { route: "/overview" });
    const box = screen.getByRole("combobox", { name: /search mail and console/i });
    await user.click(box);
    await user.type(box, "dark");
    await user.click(screen.getByRole("option", { name: /dark appearance/i }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("hides admin settings from viewers", async () => {
    resetEngine();
    const user = userEvent.setup();
    renderWithConsole(<Shell />, { route: "/overview", user: viewerUser });
    const box = screen.getByRole("combobox", { name: /search mail and console/i });
    await user.click(box);
    await user.type(box, "settings");
    expect(screen.queryByRole("option", { name: /gateway enforcement/i })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: /search mail for/i })).toBeInTheDocument();
  });
});
