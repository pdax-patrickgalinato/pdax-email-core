import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { jsonResponse } from "./fixtures";

afterEach(() => {
  cleanup();
});

class ChartStub {
  static register() {}
  destroy() {}
  update() {}
}

Object.defineProperty(window, "Chart", {
  configurable: true,
  writable: true,
  value: ChartStub,
});

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo) => {
      const url = String(input);
      if (url.includes("/api/auth/me")) {
        return Promise.resolve(jsonResponse({ id: "u-admin", username: "admin", role: "admin" }));
      }
      if (url.includes("/api/auth/passkeys")) {
        return Promise.resolve(jsonResponse({ passkeys: [] }));
      }
      if (url.includes("/api/feed/item/")) {
        return Promise.resolve(jsonResponse({ detail: "entry not found" }, 404));
      }
      if (url.includes("/api/feed/search")) {
        return Promise.resolve(jsonResponse({ entries: [], labels: [], source: "fallback", total: 0 }));
      }
      if (url.includes("/api/feed")) return Promise.resolve(jsonResponse({ entries: [], llmConfigured: true }));
      if (url.includes("/api/audit")) return Promise.resolve(jsonResponse({ entries: [] }));
      if (url.includes("/api/sender-profiles")) return Promise.resolve(jsonResponse({ senders: [] }));
      if (url.includes("/api/workers")) {
        return Promise.resolve(jsonResponse({ api: {}, receiver: { reachable: true }, events: [] }));
      }
      if (url.includes("/api/campaigns")) return Promise.resolve(jsonResponse({ campaigns: [] }));
      if (url.includes("/api/org")) return Promise.resolve(jsonResponse({ display_name: "PDAX", context_notes: [] }));
      if (url.includes("/api/lists")) return Promise.resolve(jsonResponse({ allowlist: [], blocklist: [] }));
      if (url.includes("/api/ingest")) return Promise.resolve(jsonResponse({ gmail_fetch: true }));
      if (url.includes("/api/slack-config")) {
        return Promise.resolve(jsonResponse({ enabled: false, threshold: "SUSPICIOUS", webhook_url_masked: "" }));
      }
      if (url.includes("/api/notify-config")) {
        return Promise.resolve(
          jsonResponse({
            enabled: false,
            smtp_host: "",
            smtp_port: 587,
            smtp_user: "",
            from_addr: "",
            threshold: "SUSPICIOUS",
            smtp_pass_set: false,
          }),
        );
      }
      if (url.includes("/api/policy")) return Promise.resolve(jsonResponse({ categories: [] }));
      if (url.includes("/api/setup/status")) return Promise.resolve(jsonResponse({ needs_setup: false }));
      return Promise.resolve(jsonResponse({}));
    })
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});
