import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import Workers from "./Workers";
import { renderWithConsole } from "../test/render";
import { resetEngine } from "../test/engine";
import { state } from "../lib/dashboard";

describe("Workers", () => {
  it("shows the campaign queue counter on a dedicated tile", () => {
    resetEngine();
    state.workers = {
      receiver: { reachable: true, users: 3, source: "probe" },
      ops: { gmail_fetch: true, coverage: { polling: 3 }, config: {} },
      events: [],
      queues: {
        campaign: { waiting: 17, running: 1 },
        profile: { waiting: 2, running: 0 },
        sender_risk: { waiting: 1, running: 0 },
        static: { waiting: 0, running: 0 },
        content_ai: { waiting: 0, running: 0 },
        retry: { waiting: 0, running: 0 },
      },
      processes: {
        campaign: {
          source: "probe",
          reachable: true,
          campaign: { alive: true, last_finished_at: 1, last_stats: { campaigns: 4 } },
        },
      },
    };
    renderWithConsole(<Workers />, { route: "/workers" });
    expect(screen.getByText("Campaign queue")).toBeInTheDocument();
    expect(screen.getAllByText("17").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Campaign clustering").length).toBeGreaterThan(0);
    expect(screen.getByText("in queue · 1 processing")).toBeInTheDocument();
    expect(screen.getByText("17 waiting · 1 processing")).toBeInTheDocument();
    expect(screen.getByText("Follow-up")).toBeInTheDocument();
    expect(screen.getByText("profile · sender risk")).toBeInTheDocument();
  });
});
