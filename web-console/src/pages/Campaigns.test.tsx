import { describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import Campaigns from "./Campaigns";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { jsonResponse } from "../test/fixtures";
import { state } from "../lib/dashboard";

const HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const cluster = {
  id: "cam-a1b2c3d4e5f6",
  kind: "hash",
  pattern: "hash:" + HASH,
  members: 4,
  senders: 2,
  flagged: 3,
  mailboxes: 2,
  ai_title: "Payroll password reset",
  attack_class: "credential_theft",
  subjects: ["Reset your payroll password"],
  insight: {
    lure: "Fake payroll portal",
    patterns: [
      "Primary pivot (Shared payload): " + HASH,
      "Spray across two internal mailboxes.",
    ],
    shared_iocs: { hashes: [HASH], urls: ["https://pay.example/login"] },
  },
};

describe("Campaigns", () => {
  it("does not show the clustering pivot hash or cam id", async () => {
    resetEngine();
    state.campaigns = [cluster];
    state.campaignSelected = cluster.id;
    const prev = vi.mocked(fetch).getMockImplementation();
    vi.mocked(fetch).mockImplementation((input, init) => {
      if (String(input).includes("/api/campaigns")) {
        return Promise.resolve(jsonResponse({ campaigns: [cluster] }));
      }
      return prev ? prev(input as RequestInfo, init) : Promise.resolve(jsonResponse({}));
    });
    renderWithConsole(<Campaigns />, { route: "/campaigns" });
    expect((await screen.findAllByText("Payroll password reset")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Shared payload").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Credential theft").length).toBeGreaterThan(0);
    expect(screen.queryByRole("columnheader", { name: "Pivot" })).not.toBeInTheDocument();
    expect(screen.queryByText(/cam-a1b2c3d4e5f6/)).not.toBeInTheDocument();
    expect(screen.queryByText(new RegExp(HASH))).not.toBeInTheDocument();
    expect(screen.queryByText(/^hash:/)).not.toBeInTheDocument();
    expect(screen.getByText("Fake payroll portal")).toBeInTheDocument();
    expect(screen.getByText("Spray across two internal mailboxes.")).toBeInTheDocument();
    expect(screen.queryByText(/Primary pivot/i)).not.toBeInTheDocument();
    expect(screen.getByText(/https:\/\/pay\.example\/login/)).toBeInTheDocument();
  });
});
