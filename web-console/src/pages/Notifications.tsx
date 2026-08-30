import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { ICON, isAdmin, ui } from "../lib/dashboard";
import { api } from "../lib/api";
import { errorMessage } from "../lib/errors";
import SettingsNav from "../components/SettingsNav";
import type { NotifyConfig, SlackConfig } from "../types";

const EMPTY_SLACK: SlackConfig = {
  enabled: false,
  threshold: "SUSPICIOUS",
  webhook_url: "",
  webhook_url_masked: "",
};

const EMPTY_NOTIFY: NotifyConfig = {
  enabled: false,
  smtp_host: "",
  smtp_port: 587,
  smtp_user: "",
  from_addr: "",
  threshold: "SUSPICIOUS",
  password_set: false,
};

function StatusBadge({ on }: { on: boolean }) {
  return (
    <span
      className="enforce-badge"
      style={{
        background: on ? "var(--status-good)" : "var(--status-neutral)",
        color: on ? "#fff" : "var(--ink)",
      }}
    >
      {on ? "Enabled" : "Disabled"}
    </span>
  );
}

export default function Notifications() {
  const admin = isAdmin();
  const [slack, setSlack] = useState<SlackConfig>(EMPTY_SLACK);
  const [slackMsg, setSlackMsg] = useState("");
  const [notify, setNotify] = useState<NotifyConfig>(EMPTY_NOTIFY);
  const [notifyMsg, setNotifyMsg] = useState("");

  useEffect(() => {
    if (!admin) return;
    api<SlackConfig>("/api/slack-config")
      .then((cfg) => setSlack((s) => ({ ...s, ...cfg, webhook_url: "" })))
      .catch(() => {});
    api<NotifyConfig>("/api/notify-config").then(setNotify).catch(() => {});
  }, [admin]);

  if (!admin) return <Navigate to="/overview" replace />;

  return (
    <section className="page active">
      <SettingsNav />

      <div className="settings-section">
        <div className="settings-section-label">Analyst alerts</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Slack</h2>
              <div className="card-sub">
                Send a Block Kit notification to a Slack webhook when suspicious or malicious mail is detected.
              </div>
            </div>
            <StatusBadge on={!!slack.enabled} />
          </div>
          <form
            style={{ display: "flex", flexDirection: "column", gap: "12px", maxWidth: "520px" }}
            autoComplete="off"
            onSubmit={async (ev) => {
              ev.preventDefault();
              setSlackMsg("");
              try {
                await api("/api/slack-config", {
                  method: "PUT",
                  body: JSON.stringify({
                    enabled: slack.enabled,
                    webhook_url: slack.webhook_url,
                    threshold: slack.threshold,
                  }),
                });
                setSlackMsg("Saved.");
                setSlack((s) => ({ ...s, webhook_url: "" }));
                const cfg = await api<SlackConfig>("/api/slack-config");
                setSlack((s) => ({ ...s, ...cfg, webhook_url: "" }));
                if (ui.onToast) ui.onToast(ICON.good, "Slack config saved");
              } catch (err) {
                setSlackMsg(errorMessage(err));
              }
            }}
          >
            <label style={{ fontSize: "13px", fontWeight: 500 }}>
              Webhook URL
              <input
                className="search-input"
                style={{ width: "100%", marginTop: "4px" }}
                type="url"
                placeholder="https://hooks.slack.com/services/…"
                autoComplete="off"
                value={slack.webhook_url}
                onChange={(e) => setSlack({ ...slack, webhook_url: e.target.value })}
              />
              <span style={{ fontSize: "11.5px", color: "var(--ink-muted)", marginTop: "2px", display: "block" }}>
                {slack.webhook_url_masked ? "Current: " + slack.webhook_url_masked : ""}
              </span>
            </label>
            <label style={{ fontSize: "13px", fontWeight: 500 }}>
              Alert threshold
              <select
                className="search-input"
                style={{ width: "180px", marginTop: "4px" }}
                value={slack.threshold}
                onChange={(e) => setSlack({ ...slack, threshold: e.target.value })}
              >
                <option value="SUSPICIOUS">Suspicious &amp; above</option>
                <option value="MALICIOUS">Malicious only</option>
              </select>
            </label>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", cursor: "pointer" }}>
                <input type="checkbox" checked={!!slack.enabled} onChange={(e) => setSlack({ ...slack, enabled: e.target.checked })} />
                Enable Slack alerts
              </label>
              <button type="submit" className="btn btn-sm">
                Save
              </button>
            </div>
            <div style={{ fontSize: "12.5px", color: "var(--status-good)", minHeight: "18px" }}>{slackMsg}</div>
          </form>
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Recipient notices</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Email</h2>
              <div className="card-sub">Send an email to the original recipient when their message is quarantined or blocked.</div>
            </div>
            <StatusBadge on={!!notify.enabled} />
          </div>
          <form
            style={{ display: "flex", flexDirection: "column", gap: "12px", maxWidth: "520px" }}
            autoComplete="off"
            onSubmit={async (ev) => {
              ev.preventDefault();
              setNotifyMsg("");
              try {
                await api("/api/notify-config", {
                  method: "PUT",
                  body: JSON.stringify({
                    enabled: notify.enabled,
                    smtp_host: notify.smtp_host,
                    smtp_port: parseInt(String(notify.smtp_port), 10) || 587,
                    smtp_user: notify.smtp_user,
                    from_addr: notify.from_addr,
                    threshold: notify.threshold,
                  }),
                });
                setNotifyMsg("Saved.");
                if (ui.onToast) ui.onToast(ICON.good, "Notification config saved");
              } catch (err) {
                setNotifyMsg(errorMessage(err));
              }
            }}
          >
            <div style={{ display: "grid", gridTemplateColumns: "1fr 100px", gap: "10px" }}>
              <label style={{ fontSize: "13px", fontWeight: 500 }}>
                SMTP host
                <input
                  className="search-input"
                  style={{ width: "100%", marginTop: "4px" }}
                  value={notify.smtp_host || ""}
                  onChange={(e) => setNotify({ ...notify, smtp_host: e.target.value })}
                />
              </label>
              <label style={{ fontSize: "13px", fontWeight: 500 }}>
                Port
                <input
                  className="search-input"
                  style={{ width: "100%", marginTop: "4px" }}
                  type="number"
                  min={1}
                  max={65535}
                  value={notify.smtp_port || 587}
                  onChange={(e) => setNotify({ ...notify, smtp_port: e.target.value })}
                />
              </label>
            </div>
            <label style={{ fontSize: "13px", fontWeight: 500 }}>
              SMTP username
              <input
                className="search-input"
                style={{ width: "100%", marginTop: "4px" }}
                value={notify.smtp_user || ""}
                onChange={(e) => setNotify({ ...notify, smtp_user: e.target.value })}
              />
            </label>
            <label style={{ fontSize: "13px", fontWeight: 500 }}>
              From address
              <input
                className="search-input"
                style={{ width: "100%", marginTop: "4px" }}
                type="email"
                value={notify.from_addr || ""}
                onChange={(e) => setNotify({ ...notify, from_addr: e.target.value })}
              />
            </label>
            <div
              style={{
                fontSize: "12px",
                color: "var(--ink-muted)",
                padding: "8px 10px",
                borderRadius: "var(--radius-sm)",
                background: "var(--surface-2)",
                border: "1px solid var(--border)",
              }}
            >
              SMTP password is set via the <code>SEGS_NOTIFY_SMTP_PASS</code> environment variable and is never stored in the UI.
              <span style={{ marginLeft: "6px", fontWeight: 600 }}>
                {notify.smtp_pass_set ? "✓ Password set" : "✗ Password not set"}
              </span>
            </div>
            <label style={{ fontSize: "13px", fontWeight: 500 }}>
              Alert threshold
              <select
                className="search-input"
                style={{ width: "180px", marginTop: "4px" }}
                value={notify.threshold || "SUSPICIOUS"}
                onChange={(e) => setNotify({ ...notify, threshold: e.target.value })}
              >
                <option value="SUSPICIOUS">Suspicious &amp; above</option>
                <option value="MALICIOUS">Malicious only</option>
              </select>
            </label>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", cursor: "pointer" }}>
                <input type="checkbox" checked={!!notify.enabled} onChange={(e) => setNotify({ ...notify, enabled: e.target.checked })} />
                Enable recipient email notices
              </label>
              <button type="submit" className="btn btn-sm">
                Save
              </button>
            </div>
            <div style={{ fontSize: "12.5px", color: "var(--status-good)", minHeight: "18px" }}>{notifyMsg}</div>
          </form>
        </div>
      </div>
    </section>
  );
}
