import { describe, expect, it } from "vitest";
import { fleetReachable, pickWorkerSlot } from "./workers-status";

describe("pickWorkerSlot", () => {
  it("treats a down receiver as unreachable when no process probes exist", () => {
    const data = { receiver: { reachable: false }, api: {}, processes: {} };
    const poll = pickWorkerSlot(data, "poll");
    expect(poll.reachable).toBe(false);
    expect(fleetReachable(data)).toBe(false);
  });

  it("uses ILB process probes even when the all-in-one receiver is down", () => {
    const data = {
      receiver: { reachable: false, error: "connection refused" },
      api: { profile: { alive: false, enabled: false } },
      processes: {
        gmail_poll: {
          source: "probe",
          reachable: true,
          gmail_poll: { alive: true, last_finished_at: 1, last_stats: { mailboxes: 4 } },
        },
        profile: {
          source: "probe",
          reachable: true,
          profile: { alive: true, enabled: true, cycles: 2 },
        },
      },
    };
    const poll = pickWorkerSlot(data, "poll");
    expect(poll.reachable).toBe(true);
    expect(poll.slot.alive).toBe(true);
    expect(poll.host).toBe("Worker process");
    const profile = pickWorkerSlot(data, "profile");
    expect(profile.reachable).toBe(true);
    expect(profile.slot.enabled).toBe(true);
    expect(fleetReachable(data)).toBe(true);
  });

  it("treats the combined sender process as both profile ingest and risk AI", () => {
    const data = {
      receiver: { reachable: false },
      api: {},
      processes: {
        sender: {
          source: "probe",
          reachable: true,
          profile: { alive: true, enabled: true, cycles: 3 },
          sender_risk: { alive: true, enabled: true, cycles: 1 },
        },
      },
    };
    expect(pickWorkerSlot(data, "profile").reachable).toBe(true);
    expect(pickWorkerSlot(data, "sender_risk").slot.cycles).toBe(1);
  });

  it("uses the campaign process probe for the clustering tile", () => {
    const data = {
      receiver: { reachable: false },
      api: {},
      processes: {
        campaign: {
          source: "probe",
          reachable: true,
          campaign: { alive: true, last_stats: { campaigns: 9 } },
        },
      },
    };
    const campaign = pickWorkerSlot(data, "campaign");
    expect(campaign.reachable).toBe(true);
    expect(campaign.slot.last_stats.campaigns).toBe(9);
  });
});
