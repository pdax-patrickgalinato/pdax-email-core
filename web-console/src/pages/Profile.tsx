import { useEffect, useState } from "react";
import { ICON, TYPE_LABEL, fmtDateTime, refreshCurrentUser, registerPasskey, ui } from "../lib/dashboard";
import { api } from "../lib/api";
import { errorMessage } from "../lib/errors";
import { PASSWORD_CHECKS, passwordMeetsPolicy } from "../lib/password";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState, HtmlBlock } from "../components/ui";
import type { AuditEntry, AuthUser, Passkey } from "../types";

export default function Profile() {
  const { user, setUser } = useConsole();
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [passkeyErr, setPasskeyErr] = useState("");
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditQ, setAuditQ] = useState("");
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwErr, setPwErr] = useState("");
  const [pwBusy, setPwBusy] = useState(false);

  useEffect(() => {
    api<{ passkeys?: Passkey[] }>("/api/auth/passkeys")
      .then((b) => setPasskeys((b && b.passkeys) || []))
      .catch(() => {});
    api<{ entries?: AuditEntry[] }>("/api/audit/me")
      .then((b) => setAudit((b && b.entries) || []))
      .catch(() => {});
  }, []);

  const allPass = passwordMeetsPolicy(newPw);
  const match = Boolean(newPw && confirmPw === newPw);
  const canSubmitPw = Boolean(currentPw) && allPass && match && !pwBusy;

  let trail = audit;
  if (auditQ) {
    const q = auditQ.toLowerCase();
    trail = trail.filter((e) =>
      (e.title + " " + e.detail + " " + (e.actor || "") + " " + (e.action || "")).toLowerCase().includes(q)
    );
  }
  trail = trail.slice(0, 200);

  async function reloadPasskeys() {
    const b = await api<{ passkeys?: Passkey[] }>("/api/auth/passkeys");
    setPasskeys((b && b.passkeys) || []);
    const me = await refreshCurrentUser();
    setUser(me as AuthUser);
  }

  return (
    <section className="page active">
      <div className="settings-section">
        <div className="settings-section-label">Account</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Signed in as {user.username}</h2>
              <div className="card-sub">Your role, password, and passkeys apply only to this account.</div>
            </div>
            <span className="user-role">{user.role}</span>
          </div>
          <div className="profile-facts">
            <div className="profile-fact">
              <span className="profile-fact-label">Username</span>
              <span className="profile-fact-value">{user.username}</span>
            </div>
            <div className="profile-fact">
              <span className="profile-fact-label">Role</span>
              <span className="profile-fact-value">{user.role}</span>
            </div>
            <div className="profile-fact">
              <span className="profile-fact-label">Passkeys</span>
              <span className="profile-fact-value">{passkeys.length}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Security</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Password</h2>
              <div className="card-sub">
                Changing your password signs out other sessions. This session stays signed in.
              </div>
            </div>
          </div>
          <form
            className="pw-modal-fields"
            style={{ maxWidth: "420px", marginTop: 0 }}
            autoComplete="off"
            onSubmit={async (ev) => {
              ev.preventDefault();
              if (!canSubmitPw) return;
              setPwBusy(true);
              setPwErr("");
              try {
                await api("/api/auth/password", {
                  method: "POST",
                  body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
                });
                setCurrentPw("");
                setNewPw("");
                setConfirmPw("");
                if (ui.onToast) ui.onToast(ICON.good, "Password updated");
              } catch (err) {
                setPwErr(errorMessage(err));
              } finally {
                setPwBusy(false);
              }
            }}
          >
            <label>
              Current password
              <input
                type="password"
                autoComplete="current-password"
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
              />
            </label>
            <label>
              New password
              <input
                type="password"
                autoComplete="new-password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
              />
            </label>
            <label>
              Confirm new password
              <input
                type="password"
                autoComplete="new-password"
                value={confirmPw}
                onChange={(e) => {
                  setConfirmPw(e.target.value);
                  if (e.target.value && e.target.value !== newPw) setPwErr("Passwords do not match.");
                  else setPwErr("");
                }}
              />
            </label>
            <ul id="pwChecklist">
              {PASSWORD_CHECKS.map((c) => (
                <li key={c.id} className={"pwck-item" + (c.test(newPw) ? " pass" : "")}>
                  {c.label}
                </li>
              ))}
            </ul>
            {pwErr ? <div className="users-error show">{pwErr}</div> : null}
            <div>
              <button type="submit" className="btn btn-primary" disabled={!canSubmitPw}>
                {pwBusy ? "Saving…" : "Update password"}
              </button>
            </div>
          </form>
        </div>

        <div className="card">
          <div className="card-head">
            <div>
              <h2>Multi-factor authentication</h2>
              <div className="card-sub">
                A passkey is required every time you sign in, and again to view original email content.
                AI assessment stays available without unlocking.
              </div>
            </div>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => {
                setPasskeyErr("");
                registerPasskey("Passkey")
                  .then(() => {
                    if (ui.onToast) ui.onToast(ICON.good, "Passkey added");
                    return reloadPasskeys();
                  })
                  .catch((err) => setPasskeyErr(errorMessage(err)));
              }}
            >
              Add passkey
            </button>
          </div>
          {passkeys.map((k) => (
            <div key={k.id} className="passkey-row">
              <span>
                {k.name || "Passkey"} · added {fmtDateTime(Math.round((k.created_at || 0) * 1000))}
              </span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={async () => {
                  const last = passkeys.length <= 1;
                  if (
                    last &&
                    !window.confirm("This is your last passkey. You will be asked to register a new one the next time you sign in.")
                  ) {
                    return;
                  }
                  try {
                    await api("/api/auth/passkeys/" + encodeURIComponent(k.id), { method: "DELETE" });
                    if (ui.onToast) ui.onToast(ICON.good, "Passkey removed");
                    await reloadPasskeys();
                  } catch (err) {
                    setPasskeyErr(errorMessage(err));
                  }
                }}
              >
                Remove
              </button>
            </div>
          ))}
          {!passkeys.length ? (
            <EmptyState>No passkeys yet. Add one here, or when you first open an original email.</EmptyState>
          ) : null}
          {passkeyErr ? <div className="users-error show">{passkeyErr}</div> : null}
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Audit trail</div>
        <div className="card card-primary" style={{ padding: "6px 20px" }}>
          <div className="card-head" style={{ padding: "12px 0 8px" }}>
            <div>
              <h2>Your activity</h2>
              <div className="card-sub">Sign-ins, password and passkey changes, and actions you took in this console.</div>
            </div>
          </div>
          <div className="toolbar" style={{ padding: "0 0 12px" }}>
            <input
              className="search-input"
              type="search"
              placeholder="Search your activity…"
              value={auditQ}
              onChange={(e) => setAuditQ(e.target.value)}
            />
          </div>
          <div className="log-list">
            {!trail.length ? (
              <EmptyState>No matching activity for your account yet.</EmptyState>
            ) : (
              trail.map((e, i) => {
                let iconKey = e.type === "accent" ? "wazuh" : e.type || "warning";
                if (!ICON[iconKey]) iconKey = "warning";
                const tag = e.tag || TYPE_LABEL[e.type || ""] || "Activity";
                return (
                  <div key={i} className="log-entry">
                    <div className="log-time">{fmtDateTime(e.ts)}</div>
                    <div className={"log-icon t-" + e.type}>
                      <HtmlBlock tag="span" html={ICON[iconKey]} />
                    </div>
                    <div className="log-body">
                      <div className="log-title">{e.title}</div>
                      <div className="log-detail">{e.detail}</div>
                    </div>
                    <div className={"log-tag" + (e.kind === "activity" ? " activity" : "")}>{tag}</div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
