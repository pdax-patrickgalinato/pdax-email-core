import { useEffect, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { ICON, fmtDateTime, isAdmin, ui } from "../lib/dashboard";
import { api } from "../lib/api";
import { errorMessage } from "../lib/errors";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState } from "../components/ui";
import SettingsNav from "../components/SettingsNav";
import type { AuthUser, Role, SsoConfig } from "../types";

const EMPTY_SSO: SsoConfig = {
  enabled: false,
  live: false,
  provider: "jumpcloud",
  issuer: "https://oauth.id.jumpcloud.com",
  authorization_endpoint: "https://oauth.id.jumpcloud.com/oauth2/v1/authorize",
  token_endpoint: "https://oauth.id.jumpcloud.com/oauth2/v1/token",
  userinfo_endpoint: "https://oauth.id.jumpcloud.com/oauth2/v1/userinfo",
  client_id: "",
  client_secret: "",
  client_secret_set: false,
  client_secret_masked: "",
  redirect_uri: "/oauth2/idpresponse",
  discovery_url: "https://oauth.id.jumpcloud.com/.well-known/openid-configuration",
  allowed_domains: "pdax.ph",
  default_role: "viewer",
};

export default function UserManagement() {
  const { user } = useConsole();
  const admin = isAdmin();
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [userErr, setUserErr] = useState("");
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "viewer" as Role });
  const [sso, setSso] = useState<SsoConfig>(EMPTY_SSO);
  const [ssoMsg, setSsoMsg] = useState("");

  useEffect(() => {
    if (!admin) return;
    api<AuthUser[]>("/api/users")
      .then(setUsers)
      .catch((e) => setUserErr(errorMessage(e)));
    api<SsoConfig>("/api/sso-config")
      .then((cfg) => setSso({ ...EMPTY_SSO, ...cfg, client_secret: "" }))
      .catch(() => {});
  }, [admin]);

  if (!admin) return <Navigate to="/overview" replace />;

  const ssoBadge = sso.live ? "Live at ALB" : sso.enabled ? "Saved" : "Off";

  return (
    <section className="page active">
      <SettingsNav />

      <div className="settings-section">
        <div className="settings-section-label">Single sign-on</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>JumpCloud SSO</h2>
              <div className="card-sub">
                Store the OIDC application JumpCloud will use to gate this console. Live enforcement still needs{" "}
                <code>SEG_SSO_PROVIDER=alb_oidc</code> and the ALB authenticate-OIDC action.
              </div>
            </div>
            <span
              className="enforce-badge"
              style={{
                background: sso.live ? "var(--status-good)" : sso.enabled ? "var(--accent)" : "var(--status-neutral)",
                color: sso.live || sso.enabled ? "#fff" : "var(--ink)",
              }}
            >
              {ssoBadge}
            </span>
          </div>
          <form
            className="sso-form"
            autoComplete="off"
            onSubmit={async (ev) => {
              ev.preventDefault();
              setSsoMsg("");
              try {
                const saved = await api<SsoConfig>("/api/sso-config", {
                  method: "PUT",
                  body: JSON.stringify({
                    enabled: sso.enabled,
                    issuer: sso.issuer,
                    authorization_endpoint: sso.authorization_endpoint,
                    token_endpoint: sso.token_endpoint,
                    userinfo_endpoint: sso.userinfo_endpoint,
                    client_id: sso.client_id,
                    client_secret: sso.client_secret,
                    allowed_domains: sso.allowed_domains,
                    default_role: sso.default_role,
                  }),
                });
                setSso({ ...EMPTY_SSO, ...saved, client_secret: "" });
                setSsoMsg("Saved.");
                if (ui.onToast) ui.onToast(ICON.good, "JumpCloud SSO settings saved");
              } catch (err) {
                setSsoMsg(errorMessage(err));
              }
            }}
          >
            <label>
              Issuer
              <input
                className="search-input"
                type="url"
                required
                value={sso.issuer}
                onChange={(e) => setSso({ ...sso, issuer: e.target.value })}
              />
            </label>
            <label>
              Client ID
              <input
                className="search-input"
                autoComplete="off"
                value={sso.client_id}
                onChange={(e) => setSso({ ...sso, client_id: e.target.value })}
              />
            </label>
            <label>
              Client secret
              <input
                className="search-input"
                type="password"
                autoComplete="new-password"
                placeholder={sso.client_secret_set ? "Leave blank to keep the stored secret" : "From the JumpCloud OIDC app"}
                value={sso.client_secret}
                onChange={(e) => setSso({ ...sso, client_secret: e.target.value })}
              />
              <span className="sso-hint">
                {sso.client_secret_masked ? "Stored secret " + sso.client_secret_masked : "Not stored yet"}
              </span>
            </label>
            <label>
              Allowed email domains
              <input
                className="search-input"
                value={sso.allowed_domains}
                onChange={(e) => setSso({ ...sso, allowed_domains: e.target.value })}
              />
              <span className="sso-hint">Comma-separated. JumpCloud users should match these domains.</span>
            </label>
            <label>
              Default SEGS role
              <select
                className="search-input"
                value={sso.default_role}
                onChange={(e) => setSso({ ...sso, default_role: e.target.value as Role })}
              >
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
              <span className="sso-hint">Used when SSO accounts are provisioned into this console.</span>
            </label>
            <label>
              Redirect URI
              <input className="search-input" readOnly value={sso.redirect_uri} />
              <span className="sso-hint">Paste this into JumpCloud as the OIDC redirect URI.</span>
            </label>
            <label>
              Discovery URL
              <input className="search-input" readOnly value={sso.discovery_url} />
            </label>
            <div className="sso-actions">
              <label className="sso-enable">
                <input
                  type="checkbox"
                  checked={!!sso.enabled}
                  onChange={(e) => setSso({ ...sso, enabled: e.target.checked })}
                />
                Mark JumpCloud SSO as configured
              </label>
              <button type="submit" className="btn btn-sm btn-primary">
                Save SSO
              </button>
            </div>
            {ssoMsg ? <div className={"users-error show" + (ssoMsg === "Saved." ? " sso-ok" : "")}>{ssoMsg}</div> : null}
          </form>
          <ol className="sso-steps">
            <li>In JumpCloud, add a Custom OIDC application named SEGS Dashboard.</li>
            <li>Set the redirect URI to the value above and assign the SOC group.</li>
            <li>Paste the client ID and secret here, then save.</li>
            <li>
              To enforce at the edge, set <code>SEG_SSO_PROVIDER=alb_oidc</code> and attach authenticate-OIDC on the
              public ALB listener.
            </li>
          </ol>
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">SCIM 2.0</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>User provisioning</h2>
              <div className="card-sub">
                JumpCloud (and any RFC 7644 client) provisions accounts at this SCIM 2.0 base URL with
                the infra secret <code>SEG_SCIM_BEARER_TOKEN</code>. Groups map to admin, analyst, and
                viewer.
              </div>
            </div>
          </div>
          <ul className="sso-steps">
            <li>
              Base URL: <code>{typeof window !== "undefined" ? window.location.origin : ""}/scim/v2</code>
            </li>
            <li>
              Users: <code>/scim/v2/Users</code>
            </li>
            <li>
              Groups (RBAC roles): <code>/scim/v2/Groups</code>
            </li>
          </ul>
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Users &amp; access</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Your profile</h2>
              <div className="card-sub">
                Password, multi-factor passkeys, and your personal audit trail are on your profile — not this admin page.
              </div>
            </div>
            <Link to="/profile" className="btn btn-sm btn-primary">
              Open profile
            </Link>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <div>
              <h2>Create user</h2>
              <div className="card-sub">Local RBAC accounts (admin / analyst / viewer). JumpCloud can also create these through SCIM.</div>
            </div>
          </div>
          <form
            className="users-form"
            autoComplete="off"
            onSubmit={async (ev) => {
              ev.preventDefault();
              setUserErr("");
              try {
                const u = await api<AuthUser>("/api/users", { method: "POST", body: JSON.stringify(newUser) });
                if (ui.onToast) ui.onToast(ICON.good, "Created " + u.username + " (" + u.role + ")");
                setNewUser({ username: "", password: "", role: "viewer" });
                setUsers(await api<AuthUser[]>("/api/users"));
              } catch (err) {
                setUserErr(errorMessage(err));
              }
            }}
          >
            <label>
              Username
              <input
                required
                minLength={1}
                maxLength={64}
                autoComplete="off"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                required
                minLength={8}
                maxLength={256}
                autoComplete="new-password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              />
            </label>
            <label>
              Role
              <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value as Role })}>
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </label>
            <button type="submit" className="btn btn-primary">
              Add user
            </button>
          </form>
          {userErr ? <div className="users-error show">{userErr}</div> : null}
        </div>

        <div className="card card-primary" style={{ padding: 0 }}>
          <div className="card-head" style={{ padding: "18px 20px 0" }}>
            <div>
              <h2>Accounts</h2>
              <div className="card-sub">Setting a new password revokes that user&apos;s active sessions</div>
            </div>
            <button type="button" className="btn btn-sm" onClick={() => api<AuthUser[]>("/api/users").then(setUsers)}>
              Refresh
            </button>
          </div>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th style={{ width: "110px" }}>Role</th>
                  <th style={{ width: "100px" }}>Status</th>
                  <th style={{ width: "160px" }}>Created</th>
                  <th style={{ width: "220px" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.username}</td>
                    <td>{u.role}</td>
                    <td>
                      {u.disabled ? <span className="chip v-malicious">Disabled</span> : <span className="chip v-clean">Active</span>}
                    </td>
                    <td className="cell-time">{u.created_at ? fmtDateTime(Math.round(u.created_at * 1000)) : "—"}</td>
                    <td>
                      <div className="users-actions">
                        <button type="button" className="btn btn-sm" onClick={() => ui.onOpenPassword && ui.onOpenPassword(u.id, u.username)}>
                          Set password
                        </button>
                        {u.username === (user && user.username) ? (
                          <span className="analyze-meta">You</span>
                        ) : (
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={async () => {
                              if (!window.confirm("Delete user “" + u.username + "”? Their sessions will end immediately.")) return;
                              await api("/api/users/" + encodeURIComponent(u.id), { method: "DELETE" });
                              if (ui.onToast) ui.onToast(ICON.good, "Deleted " + u.username);
                              setUsers(await api<AuthUser[]>("/api/users"));
                            }}
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!users.length ? <EmptyState>No users found.</EmptyState> : null}
        </div>
      </div>
    </section>
  );
}
