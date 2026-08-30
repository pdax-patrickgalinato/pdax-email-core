import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import { ConsoleProvider } from "../context/ConsoleContext";
import Layout from "../components/Layout";
import { ErrorBoundary } from "../components/ErrorBoundary";
import type { AuthUser, Org } from "../types";

export default function ConsoleLayout() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [org, setOrg] = useState<Org | null>(null);
  const [authError, setAuthError] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/me", { credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error("unauthenticated");
        return r.json() as Promise<AuthUser>;
      })
      .then((u) => {
        if (cancelled) return;
        window.__SEG_CURRENT_USER__ = u;
        setUser(u);
      })
      .catch(() => {
        if (cancelled) return;
        const here = window.location.pathname || "/";
        if (here.indexOf("/login") === 0) {
          setAuthError("unauthenticated");
          return;
        }
        window.location.href = "/login?next=" + encodeURIComponent(here);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!user) {
    return (
      <div className="console-boot">
        <p>{authError ? "Redirecting to sign in…" : "Loading console…"}</p>
      </div>
    );
  }

  return (
    <ConsoleProvider
      user={user}
      setUser={setUser as Dispatch<SetStateAction<AuthUser | null>>}
      org={org}
      setOrg={setOrg}
    >
      <ErrorBoundary>
        <Layout />
      </ErrorBoundary>
    </ConsoleProvider>
  );
}
