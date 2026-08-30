import type { Page } from "@playwright/test";

export type MockUser = {
  id: string;
  username: string;
  role: "admin" | "analyst" | "viewer";
};

export const adminUser: MockUser = { id: "u-admin", username: "admin", role: "admin" };
export const viewerUser: MockUser = { id: "u-viewer", username: "viewer", role: "viewer" };

export function sampleEmail(partial: Record<string, unknown> = {}) {
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
    reasons: ["spf_pass"],
    stages: { origin_ip: { country: "US" } },
    aiProvider: "gemini",
    aiModel: "google/gemini-2.5-flash",
    aiSummary: "Looks like a normal invoice.",
    threadKey: "t-invoice",
    ...partial,
  };
}

type MockOpts = {
  user?: MockUser | null;
  needsSetup?: boolean;
  feed?: Record<string, unknown>[];
  loginFail?: boolean;
};

export async function mockApi(page: Page, opts: MockOpts = {}) {
  const user = opts.user === undefined ? adminUser : opts.user;
  const feed = opts.feed ?? [sampleEmail()];
  await page.route("**/api/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    const method = req.method();

    const json = (data: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(data),
      });

    if (path === "/api/org" && method === "GET") {
      return json({ display_name: "PDAX", context_notes: [] });
    }
    if (path === "/api/setup/status") {
      return json({ needs_setup: !!opts.needsSetup });
    }
    if (path === "/api/auth/login" && method === "POST") {
      if (opts.loginFail) return json({ detail: "Invalid credentials" }, 401);
      return json({ ok: true });
    }
    if (path === "/api/auth/logout" && method === "POST") {
      return json({ ok: true });
    }
    if (path === "/api/auth/me") {
      if (!user) return json({ detail: "unauthenticated" }, 401);
      return json(user);
    }
    if (path.indexOf("/api/feed/item/") === 0) {
      const id = decodeURIComponent(path.slice("/api/feed/item/".length));
      const hit = feed.filter((e) => e.id === id || e.queueId === id);
      if (!hit.length) return json({ detail: "entry not found" }, 404);
      return json({ id, entries: hit });
    }
    if (path === "/api/feed/search" && method === "POST") {
      let q = "";
      try {
        q = String((JSON.parse(req.postData() || "{}") || {}).q || "").trim();
      } catch {
        q = "";
      }
      const hit = q
        ? feed.filter((e) => String(e.subject || "").toLowerCase().indexOf(q.toLowerCase()) !== -1)
        : feed;
      return json({
        entries: hit,
        labels: q ? [q] : [],
        source: "fallback",
        total: hit.length,
      });
    }
    if (path === "/api/feed") {
      return json({ entries: feed, llmConfigured: true, llmAssessTimeoutSeconds: 120 });
    }
    if (path === "/api/audit/me") {
      const name = user && user.username ? user.username : "admin";
      return json({
        entries: [
          {
            ts: Date.now(),
            type: "good",
            title: "Signed in",
            detail: name + " from console",
            actor: name,
            action: "login",
            kind: "activity",
            tag: "Activity",
          },
        ],
      });
    }
    if (path === "/api/audit") {
      return json({
        entries: [
          {
            ts: Date.now(),
            type: "warning",
            title: "Signed in",
            detail: "admin from console",
            actor: "admin",
            action: "login",
          },
        ],
      });
    }
    if (path === "/api/sender-profiles") return json({ senders: [], min_n: 5 });
    if (path === "/api/workers") {
      return json({
        api: { process: "api", reachable: true, profile: { alive: true } },
        receiver: { reachable: true, users: 3, source: "heartbeat", gmail_poll: {}, inconclusive_retry: {} },
        ops: { gmail_users: 3, gmail_fetch: true, config: {}, spool: {}, coverage: { polling: 3 } },
        events: [],
        queues: {
          campaign: { waiting: 0, running: 0 },
          static: { waiting: 0, running: 0 },
          content_ai: { waiting: 0, running: 0 },
        },
      });
    }
    if (path === "/api/campaigns") return json({ campaigns: [] });
    if (path === "/api/policy") return json({ categories: [{ key: "urls", label: "URLs", enabled: true }] });
    if (path === "/api/enforcement") return json({ mode: "shadow" });
    if (path === "/api/ingest") return json({ gmail_fetch: true });
    if (path === "/api/auth/passkeys") return json({ passkeys: [] });
    if (path === "/api/users") return json([user].filter(Boolean));
    if (path === "/api/lists") return json({ allowlist: [], blocklist: [] });
    if (path === "/api/feedback/indicators") return json({ indicators: [], updated_at: "" });
    if (path === "/api/slack-config") return json({ enabled: false, threshold: "SUSPICIOUS", webhook_url_masked: "" });
    if (path === "/api/notify-config") {
      return json({
        enabled: false,
        smtp_host: "",
        smtp_port: 587,
        smtp_user: "",
        from_addr: "",
        threshold: "SUSPICIOUS",
        smtp_pass_set: false,
      });
    }
    if (path === "/api/sso-config") {
      return json({
        enabled: false,
        live: false,
        provider: "jumpcloud",
        issuer: "https://oauth.id.jumpcloud.com",
        authorization_endpoint: "https://oauth.id.jumpcloud.com/oauth2/v1/authorize",
        token_endpoint: "https://oauth.id.jumpcloud.com/oauth2/v1/token",
        userinfo_endpoint: "https://oauth.id.jumpcloud.com/oauth2/v1/userinfo",
        client_id: "",
        client_secret_set: false,
        client_secret_masked: "",
        redirect_uri: "/oauth2/idpresponse",
        discovery_url: "https://oauth.id.jumpcloud.com/.well-known/openid-configuration",
        allowed_domains: "pdax.ph",
        default_role: "viewer",
      });
    }
    if (path === "/api/activity/email-view" && method === "POST") {
      return json({ ok: true });
    }
    return json({ detail: "unmocked " + path }, 404);
  });
}
