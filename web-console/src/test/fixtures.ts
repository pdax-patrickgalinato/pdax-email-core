import type { AuthUser, Email } from "../types";

export const adminUser: AuthUser = { id: "u-admin", username: "admin", role: "admin" };
export const analystUser: AuthUser = { id: "u-analyst", username: "analyst", role: "analyst" };
export const viewerUser: AuthUser = { id: "u-viewer", username: "viewer", role: "viewer" };

export function sampleEmail(partial: Partial<Email> = {}): Email {
  return {
    id: "msg-1",
    ts: Date.now() - 60 * 60 * 1000,
    fromAddr: "alice@example.com",
    fromName: "Alice",
    toAddr: "bob@pdax.ph",
    toName: "Bob",
    toAddrs: ["bob@pdax.ph"],
    subject: "Q3 invoice",
    mailbox: "bob@pdax.ph",
    verdict: "CLEAN",
    score: 8,
    status: "delivered",
    sourceKind: "gmail",
    reasons: [],
    stages: {},
    aiProvider: "gemini",
    aiModel: "google/gemini-2.5-flash",
    aiSummary: "Looks like a normal invoice.",
    ...partial,
  };
}

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    statusText: status === 200 ? "OK" : "Error",
    headers: { "Content-Type": "application/json" },
  });
}
