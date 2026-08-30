import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import Layout from "./Layout";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";

describe("Layout", () => {
  it("shows Overview without the gateway-before-Workspace subtitle", () => {
    resetEngine();
    renderWithConsole(<Layout />, { route: "/overview" });
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /search mail and console/i })).toBeInTheDocument();
    expect(screen.queryByText(/Live view of mail arriving at the gateway/)).not.toBeInTheDocument();
    expect(screen.queryByText(/before Google Workspace/)).not.toBeInTheDocument();
  });
});
