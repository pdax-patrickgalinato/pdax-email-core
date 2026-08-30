import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import Analyze from "./Analyze";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { viewerUser } from "../test/fixtures";

describe("Analyze", () => {
  it("lets analysts upload an EML", () => {
    resetEngine();
    renderWithConsole(<Analyze />);
    expect(screen.getByRole("button", { name: "Upload EML file" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Analyze" })).toBeDisabled();
  });

  it("blocks viewers", () => {
    resetEngine();
    window.__SEG_CURRENT_USER__ = viewerUser;
    renderWithConsole(<Analyze />, { user: viewerUser });
    expect(screen.getByText(/Deep analysis requires Admin or Analyst/)).toBeInTheDocument();
  });
});
