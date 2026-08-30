import { describe, expect, it } from "vitest";
import { mailMatchesIntent, parseSearchIntent, searchIntentActive } from "./searchIntent";

describe("parseSearchIntent", () => {
  it("understands a natural request for mail without thread assessment", () => {
    const intent = parseSearchIntent("i want to see all the emails without thread assessment yet");
    expect(intent.threadAssessment).toBe("missing");
    expect(intent.labels).toContain("No thread assessment");
    expect(intent.text).toBe("");
    expect(searchIntentActive(intent)).toBe(true);
  });

  it("matches nearby phrasings for missing thread AI", () => {
    expect(parseSearchIntent("show messages with no thread ai").threadAssessment).toBe("missing");
    expect(parseSearchIntent("pending thread assessment").threadAssessment).toBe("missing");
    expect(parseSearchIntent("awaiting thread assessment").threadAssessment).toBe("missing");
    expect(parseSearchIntent("thread assessment not done").threadAssessment).toBe("missing");
  });

  it("finds threads that already have an assessment", () => {
    const intent = parseSearchIntent("emails with thread assessment done");
    expect(intent.threadAssessment).toBe("present");
  });

  it("treats pending assessment without 'thread' as content AI", () => {
    const intent = parseSearchIntent("show pending ai assessments");
    expect(intent.contentAssessment).toBe("missing");
    expect(intent.threadAssessment).toBeUndefined();
  });

  it("parses verdict and from filters together", () => {
    const intent = parseSearchIntent("malicious mail from finance@pdax.ph");
    expect(intent.verdicts).toContain("MALICIOUS");
    expect(intent.from).toBe("finance@pdax.ph");
    expect(intent.text).toBe("");
  });

  it("leaves leftover words as a text search", () => {
    const intent = parseSearchIntent("invoice from vendor");
    expect(intent.from).toBe("vendor");
    expect(intent.text).toBe("invoice");
  });

  it("does not treat 'to see' as a recipient", () => {
    const intent = parseSearchIntent("i want to see malicious emails");
    expect(intent.to).toBeUndefined();
    expect(intent.verdicts).toContain("MALICIOUS");
  });
});

describe("mailMatchesIntent", () => {
  const base = {
    fromAddr: "a@pdax.ph",
    subject: "Quarterly invoice",
    verdict: "CLEAN",
    threadAssessed: false,
    contentPending: false,
  };

  it("keeps unassessed threads and drops assessed ones", () => {
    const intent = parseSearchIntent("emails without thread assessment yet");
    expect(mailMatchesIntent({ ...base, threadAssessed: false }, intent)).toBe(true);
    expect(mailMatchesIntent({ ...base, threadAssessed: true, threadVerdict: "CLEAN" }, intent)).toBe(false);
  });

  it("matches malicious even when the leftover phrase is empty", () => {
    const intent = parseSearchIntent("show me all malicious emails");
    expect(mailMatchesIntent({ ...base, verdict: "MALICIOUS" }, intent)).toBe(true);
    expect(mailMatchesIntent({ ...base, verdict: "CLEAN" }, intent)).toBe(false);
  });
});
