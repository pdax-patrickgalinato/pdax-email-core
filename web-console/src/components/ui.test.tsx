import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AddrCell, Chip, ScoreCell } from "./ui";
import { sampleEmail } from "../test/fixtures";
import { resetEngine } from "../test/engine";

describe("Chip", () => {
  it("shows Assessing while the LLM is pending", () => {
    resetEngine();
    const email = sampleEmail({ aiSummary: "", aiProvider: "", sourceKind: "gmail", verdict: "MALICIOUS" });
    render(<Chip email={email} />);
    expect(screen.getByText("Assessing")).toBeInTheDocument();
  });

  it("shows Checking while static workers are running", () => {
    resetEngine();
    const email = sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "static",
    });
    render(<Chip email={email} />);
    expect(screen.getByText("Checking")).toBeInTheDocument();
  });

  it("renders the verdict label for a finished copy", () => {
    resetEngine();
    render(<Chip email={sampleEmail({ verdict: "SUSPICIOUS" })} />);
    expect(screen.getByText("Suspicious")).toBeInTheDocument();
  });
});

describe("ScoreCell", () => {
  it("hides the score while assessment is pending", () => {
    resetEngine();
    const email = sampleEmail({ aiSummary: "", aiProvider: "", sourceKind: "gmail", score: 91 });
    render(<ScoreCell email={email} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("shows the numeric score when final", () => {
    resetEngine();
    render(<ScoreCell email={sampleEmail({ score: 12 })} />);
    expect(screen.getByText("12")).toBeInTheDocument();
  });
});

describe("AddrCell", () => {
  it("shows an extra recipient count", () => {
    render(<AddrCell addr="bob@pdax.ph" name="Bob" extraCount={2} />);
    expect(screen.getByText("bob@pdax.ph")).toBeInTheDocument();
    expect(screen.getByText("+2")).toBeInTheDocument();
    expect(screen.getByText("Bob")).toBeInTheDocument();
  });

  it("renders an em dash when empty", () => {
    const { container } = render(<AddrCell />);
    expect(container.querySelector(".addr-muted")).toHaveTextContent("—");
  });
});
