import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Login from "./Login";
import { jsonResponse } from "../test/fixtures";

describe("Login", () => {
  it("posts credentials and follows a safe next path", async () => {
    const user = userEvent.setup();
    const loc = { href: "http://localhost/login?next=/queue", search: "?next=/queue", hostname: "localhost" };
    vi.stubGlobal("location", loc);
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo) => {
        const url = String(input);
        if (url.includes("/api/org")) return Promise.resolve(jsonResponse({ display_name: "PDAX" }));
        if (url.includes("/api/setup/status")) return Promise.resolve(jsonResponse({ needs_setup: false }));
        if (url.includes("/api/auth/login")) return Promise.resolve(jsonResponse({ ok: true }));
        return Promise.resolve(jsonResponse({}));
      })
    );

    render(<Login />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText(/PDAX Secure Email Gateway Service/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "password1");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(loc.href).toBe("/queue");
    expect(vi.mocked(fetch).mock.calls.some((c) => String(c[0]).includes("/api/auth/login"))).toBe(true);
  });

  it("shows the first-admin setup copy when no accounts exist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo) => {
        const url = String(input);
        if (url.includes("/api/setup/status")) return Promise.resolve(jsonResponse({ needs_setup: true }));
        return Promise.resolve(jsonResponse({}));
      })
    );
    render(<Login />);
    expect(await screen.findByRole("heading", { name: "Create the first admin account" })).toBeInTheDocument();
  });

  it("starts a passkey challenge after a valid password", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo) => {
        const url = String(input);
        if (url.includes("/api/setup/status")) return Promise.resolve(jsonResponse({ needs_setup: false }));
        if (url.includes("/api/auth/login")) {
          return Promise.resolve(jsonResponse({
            mfa: "webauthn",
            login_token: "pending-token",
            mode: "assert",
            options: { challenge: "YQ", rpId: "localhost", allowCredentials: [] },
          }));
        }
        return Promise.resolve(jsonResponse({}));
      })
    );
    render(<Login />);
    await screen.findByRole("heading", { name: "Sign in" });
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "password1");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Verify with passkey" })).toBeInTheDocument();
  });

  it("shows an error when credentials are rejected", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo) => {
        const url = String(input);
        if (url.includes("/api/setup/status")) return Promise.resolve(jsonResponse({ needs_setup: false }));
        if (url.includes("/api/auth/login")) {
          return Promise.resolve(jsonResponse({ detail: "Invalid credentials" }, 401));
        }
        return Promise.resolve(jsonResponse({}));
      })
    );
    render(<Login />);
    await screen.findByRole("heading", { name: "Sign in" });
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrongpass");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid credentials")).toBeInTheDocument();
  });
});
