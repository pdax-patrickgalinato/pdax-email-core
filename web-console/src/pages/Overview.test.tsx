import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import Overview from "./Overview";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { sampleEmail } from "../test/fixtures";
import { state } from "../lib/dashboard";

describe("Overview", () => {
  it("renders live feed rows", () => {
    resetEngine();
    const row = sampleEmail({ subject: "Q3 invoice", reasons: ["spf_pass"] });
    state.feed = [row];
    renderWithConsole(<Overview />, { route: "/overview" });
    expect(screen.getByRole("heading", { name: "Live feed" })).toBeInTheDocument();
    expect(screen.getByText("Q3 invoice")).toBeInTheDocument();
    expect(screen.getByText("Total")).toBeInTheDocument();
    expect(screen.getByText("Assessed")).toBeInTheDocument();
    expect(screen.getByText("Inboxes monitored")).toBeInTheDocument();
    expect(screen.queryByText(/last 24h/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SELECT\s+queue_id/i)).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/ask: emails without thread/i)).not.toBeInTheDocument();
  });

  it("shows all-time mailbox and assessment tiles from unclipped stats", () => {
    resetEngine();
    state.feed = [sampleEmail({ subject: "One of 500" })];
    state.feedStats = {
      total: 2487,
      pending: 10,
      inconclusive: 2,
      clean: 2000,
      low: 40,
      suspicious: 20,
      malicious: 15,
      assessed: 2075,
      threadAssessed: 90,
      mailboxes: 42,
      inboxesMonitored: 42,
      inboxesPolling: 17,
      inboxesConfigured: 3,
      inboxesDiscovered: 14,
      aiPendingTotal: 10,
      aiTimedOutTotal: 2,
      hourly: [],
      feedLimit: 500,
    };
    renderWithConsole(<Overview />, { route: "/overview" });
    expect(screen.getByText("2,487")).toBeInTheDocument();
    expect(screen.getByText("2,075")).toBeInTheDocument();
    expect(screen.getByText("90 with thread AI")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("all-time · 17 currently polling")).toBeInTheDocument();
  });

  it("shows a loading empty state before the first feed response", () => {
    resetEngine();
    renderWithConsole(<Overview />, { route: "/overview" });
    expect(screen.getByText("Loading mail…")).toBeInTheDocument();
  });

  it("still renders when a copy has a non-array reasons field", () => {
    resetEngine();
    state.feed = [sampleEmail({ subject: "Malformed reasons", reasons: "spf_pass" as unknown as string[] })];
    renderWithConsole(<Overview />, { route: "/overview" });
    expect(screen.getByText("Malformed reasons")).toBeInTheDocument();
  });
});
