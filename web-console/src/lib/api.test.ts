import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";
import { jsonResponse } from "../test/fixtures";

describe("api", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("parses JSON on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(jsonResponse({ ok: true })))
    );
    await expect(api<{ ok: boolean }>("/api/ping")).resolves.toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledWith(
      "/api/ping",
      expect.objectContaining({ credentials: "same-origin" })
    );
  });

  it("sets JSON content-type when sending a body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(jsonResponse({})))
    );
    await api("/api/users", { method: "POST", body: JSON.stringify({ username: "a" }) });
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("does not force JSON content-type on FormData", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(jsonResponse({})))
    );
    const body = new FormData();
    body.append("file", new Blob(["x"]), "mail.eml");
    await api("/api/analyze", { method: "POST", body });
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>)["Content-Type"]).toBeUndefined();
  });

  it("surfaces FastAPI detail strings", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(jsonResponse({ detail: "Invalid credentials" }, 401)))
    );
    await expect(api("/api/auth/login")).rejects.toThrow("Invalid credentials");
  });

  it("joins validation error arrays", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          jsonResponse({ detail: [{ msg: "username required" }, { msg: "password too short" }] }, 422)
        )
      )
    );
    await expect(api("/api/users")).rejects.toThrow("username required; password too short");
  });
});
