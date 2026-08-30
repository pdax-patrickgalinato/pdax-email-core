import { useEffect, useState, type FormEvent } from "react";
import { safeNext } from "../lib/redirect";
import { errorMessage } from "../lib/errors";
import { credentialToJson, decodePublicKeyOptions } from "../lib/webauthn";
import "./Login.css";

type OrgPayload = { display_name?: string };
type SetupStatus = { needs_setup?: boolean };
type MfaPayload = {
  mfa?: string;
  login_token?: string;
  mode?: "assert" | "enroll";
  options?: Record<string, unknown>;
};

function goNext() {
  const params = new URLSearchParams(window.location.search);
  window.location.href = safeNext(params.get("next"));
}

export default function Login() {
  const [brand, setBrand] = useState("Secure Email Gateway Service (SEGS)");
  const [needsSetup, setNeedsSetup] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [mfa, setMfa] = useState<MfaPayload | null>(null);

  useEffect(() => {
    document.body.classList.add("login-route");
    fetch("/api/org", { credentials: "same-origin" })
      .then((r) => r.json() as Promise<OrgPayload>)
      .then((org) => {
        if (org.display_name) {
          setBrand(org.display_name + " Secure Email Gateway Service (SEGS)");
        }
      })
      .catch(() => {});
    fetch("/api/setup/status", { credentials: "same-origin" })
      .then((r) => r.json() as Promise<SetupStatus>)
      .then((d) => {
        if (d.needs_setup) setNeedsSetup(true);
      })
      .catch(() => {});
    return () => document.body.classList.remove("login-route");
  }, []);

  function parseBody(r: Response, body: unknown) {
    if (!r.ok) {
      const detail =
        body && typeof body === "object" && "detail" in body
          ? (body as { detail?: unknown }).detail
          : undefined;
      throw new Error(
        (typeof detail === "string" && detail) || r.statusText || "Sign-in failed",
      );
    }
    return body;
  }

  async function completeWebauthn(payload: MfaPayload) {
    if (!window.PublicKeyCredential) {
      throw new Error("Passkeys need HTTPS or localhost");
    }
    if (!payload.options || !payload.login_token) {
      throw new Error("Passkey challenge missing — try signing in again");
    }
    const opts = decodePublicKeyOptions(payload.options);
    const cred =
      payload.mode === "enroll"
        ? await navigator.credentials.create({ publicKey: opts })
        : await navigator.credentials.get({ publicKey: opts });
    if (!cred) throw new Error("Passkey was cancelled");
    const r = await fetch("/api/auth/login/webauthn", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        login_token: payload.login_token,
        credential: credentialToJson(cred as PublicKeyCredential),
        name: "Login passkey",
      }),
    });
    const isJson = (r.headers.get("content-type") || "").includes("application/json");
    const body = isJson ? await r.json().catch(() => ({})) : await r.text();
    parseBody(r, body);
    goNext();
  }

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setBusy(true);
    fetch(needsSetup ? "/api/setup" : "/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    })
      .then(async (r) => {
        const isJson = (r.headers.get("content-type") || "").includes("application/json");
        const body = isJson ? await r.json().catch(() => ({})) : await r.text();
        return parseBody(r, body);
      })
      .then((body) => {
        const payload = body as MfaPayload;
        if (!needsSetup && payload && payload.mfa === "webauthn") {
          setMfa(payload);
          return completeWebauthn(payload);
        }
        goNext();
        return undefined;
      })
      .catch((err: unknown) => {
        setError(errorMessage(err));
        setBusy(false);
      });
  }

  const mfaCopy =
    mfa?.mode === "enroll"
      ? "Create a passkey to finish signing in. This is required on every login."
      : "Confirm with your passkey to finish signing in.";

  return (
    <div className="login-page">
      <div className="wrap">
        <div className="brand-lockup">
          <div className="brand-mark">
            <img src="/logo.png" alt="SEGS logo" width="40" height="40" />
          </div>
          <div>
            <div className="brand-name">{brand}</div>
            <div className="brand-sub">Gateway console</div>
          </div>
        </div>
        <form className="card" onSubmit={onSubmit}>
          <h1>
            {mfa
              ? "Verify with passkey"
              : needsSetup
                ? "Create the first admin account"
                : "Sign in"}
          </h1>
          <p className="sub">
            {mfa
              ? mfaCopy
              : needsSetup
                ? "No accounts exist yet — this one-time setup creates the first Admin."
                : "Password, then a passkey, every time you sign in."}
          </p>
          {mfa ? (
            <button type="button" disabled={busy} onClick={() => completeWebauthn(mfa).catch((err) => {
              setError(errorMessage(err));
              setBusy(false);
            })}>
              {mfa.mode === "enroll" ? "Create passkey" : "Use passkey"}
            </button>
          ) : (
            <>
              <label htmlFor="username">Username</label>
              <input
                id="username"
                name="username"
                autoComplete="username"
                required
                value={username}
                onChange={(ev) => setUsername(ev.target.value)}
              />
              <label htmlFor="password">Password</label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                minLength={8}
                value={password}
                onChange={(ev) => setPassword(ev.target.value)}
              />
              <button type="submit" disabled={busy}>
                {needsSetup ? "Create admin account" : "Sign in"}
              </button>
            </>
          )}
          {error ? <div className="error">{error}</div> : null}
        </form>
        <div className="footnote">Access is role-gated — Admin, Analyst, or Viewer.</div>
      </div>
    </div>
  );
}
