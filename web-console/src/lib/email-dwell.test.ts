import { describe, expect, it } from "vitest";
import { emailViewBody, startDwellClock } from "./email-dwell";

describe("emailViewBody", () => {
  it("prefers queueId and includes subject/from", () => {
    expect(
      emailViewBody(
        { id: "msg-1", queueId: "gmail-abc", subject: "Q3 invoice", fromAddr: "alice@example.com" },
        "open",
      ),
    ).toEqual({
      queue_id: "gmail-abc",
      event: "open",
      subject: "Q3 invoice",
      from_addr: "alice@example.com",
    });
  });

  it("records dwell on leave", () => {
    const body = emailViewBody({ id: "gmail-abc", subject: "Hi" }, "leave", 1250);
    expect(body?.event).toBe("leave");
    expect(body?.dwell_ms).toBe(1250);
    expect(body?.queue_id).toBe("gmail-abc");
  });

  it("returns null without an id", () => {
    expect(emailViewBody({ subject: "x" }, "open")).toBeNull();
  });
});

describe("startDwellClock", () => {
  it("counts only running time", () => {
    let t = 1_000;
    const clock = startDwellClock(() => t);
    t = 1_400;
    clock.pause();
    t = 9_000;
    expect(clock.visibleMs()).toBe(400);
    clock.resume();
    t = 9_200;
    expect(clock.visibleMs()).toBe(600);
  });
});
