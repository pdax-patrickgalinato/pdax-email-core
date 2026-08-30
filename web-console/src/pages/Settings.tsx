import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import {
  ENFORCE_BADGE_CLS,
  ENFORCE_LABELS,
  ICON,
  POLICY,
  fmtDateTime,
  isAdmin,
  setPolicyCategory,
  ui,
} from "../lib/dashboard";
import { api } from "../lib/api";
import { errorMessage } from "../lib/errors";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState } from "../components/ui";
import SettingsNav from "../components/SettingsNav";
import type {
  Enforcement,
  Indicator,
  IngestConfig,
} from "../types";

export default function Settings() {
  const { bump } = useConsole();
  const admin = isAdmin();
  const [enforce, setEnforce] = useState<Enforcement>({ mode: "shadow" });
  const [policyBusy, setPolicyBusy] = useState("");
  const [pack, setPack] = useState<{ indicators: Indicator[]; updated_at: string }>({ indicators: [], updated_at: "" });
  const [ingest, setIngest] = useState<IngestConfig>({ gmail_fetch: true });
  const [ingestBusy, setIngestBusy] = useState(false);

  useEffect(() => {
    if (!admin) return;
    api<Enforcement>("/api/enforcement").then(setEnforce).catch(() => {});
    api<IngestConfig>("/api/ingest").then(setIngest).catch(() => {});
    api<{ indicators: Indicator[]; updated_at: string }>("/api/feedback/indicators")
      .then(setPack)
      .catch(() => {});
  }, [admin]);

  if (!admin) return <Navigate to="/overview" replace />;

  return (
    <section className="page active">
      <SettingsNav />
      <div className="settings-section">
        <div className="settings-section-label">Gateway Controls</div>
        <div className="card enforce-card is-admin">
          <div className="enforce-header">
            <div>
              <h2 style={{ fontSize: "16px", fontWeight: 600, letterSpacing: "-0.02em" }}>Gateway enforcement</h2>
              <div className="card-sub">Gmail integration is read-only. Detection always runs; holding or rejecting mail is disabled.</div>
            </div>
            <span className={"enforce-badge " + (ENFORCE_BADGE_CLS[enforce.mode] || "mode-shadow")}>
              {ENFORCE_LABELS[enforce.mode] || enforce.mode}
            </span>
          </div>
          <div style={{ marginBottom: "12px" }}>
            <div className="enforce-seg" role="group" aria-label="Select enforcement mode">
              {["shadow", "quarantine", "reject"].map((mode) => (
                <button
                  key={mode}
                  type="button"
                  className={"mode-" + mode}
                  aria-pressed={enforce.mode === mode}
                  disabled={mode !== "shadow"}
                  title={mode !== "shadow" ? "Disabled — this deployment never holds mail" : undefined}
                  onClick={() => {
                    if (mode !== "shadow") {
                      if (ui.onToast) ui.onToast(ICON.warning, "Monitor-only: this deployment never quarantines or rejects mail");
                    }
                  }}
                >
                  {ENFORCE_LABELS[mode]}
                </button>
              ))}
            </div>
          </div>
          <div className="enforce-meta">
            {enforce.updated_by && enforce.updated_at
              ? "Last changed by " + enforce.updated_by + " on " + new Date(enforce.updated_at).toLocaleString()
              : "Default: detection and monitoring only. No mail is blocked."}
          </div>
          <div style={{ marginTop: "14px", paddingTop: "14px", borderTop: "1px solid var(--border)" }}>
            <p style={{ fontSize: "12.5px", color: "var(--ink-secondary)", lineHeight: 1.6, margin: 0 }}>
              <strong>Monitor only (shadow)</strong> — every email is scored and shown here. Inbox mail is never held, labelled, or rejected.
              <br />
              <strong>Quarantine / Reject</strong> — not available on this Gmail read-only deployment.
            </p>
          </div>
        </div>

        <div className="card">
          <div className="enforce-header">
            <div>
              <h2 style={{ fontSize: "16px", fontWeight: 600, letterSpacing: "-0.02em" }}>Email fetching</h2>
              <div className="card-sub">
                Pause Gmail inbox polling while you work the assessment pipeline against emails already in the system. Static checks and AI keep running.
              </div>
            </div>
            <button
              className="pt-switch"
              role="switch"
              aria-checked={ingest.gmail_fetch ? "true" : "false"}
              aria-label="Email fetching"
              disabled={ingestBusy}
              onClick={async () => {
                const next = !ingest.gmail_fetch;
                setIngestBusy(true);
                try {
                  const snap = await api<IngestConfig>("/api/ingest", {
                    method: "PUT",
                    body: JSON.stringify({ gmail_fetch: next }),
                  });
                  setIngest(snap);
                  if (ui.onToast) {
                    ui.onToast(
                      ICON.good,
                      snap.gmail_fetch
                        ? "Gmail fetch resumed"
                        : "Gmail fetch paused — pipeline still assesses existing mail"
                    );
                  }
                } catch (err) {
                  if (ui.onToast) ui.onToast(ICON.warning, errorMessage(err));
                } finally {
                  setIngestBusy(false);
                }
              }}
            />
          </div>
          <div className="enforce-meta">
            {ingest.gmail_fetch
              ? "Fetching is on — new inbox mail is ingested on each poll cycle."
              : "Fetching is paused — no new Gmail emails. Existing mail continues through assessment."}
            {ingest.updated_by && ingest.updated_at
              ? " Last changed by " + ingest.updated_by + " on " + fmtDateTime(ingest.updated_at) + "."
              : ""}
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <div>
              <h2>Protection policy</h2>
              <div className="card-sub">Category toggles — enable or disable entire detection families. Changes take effect on the next email processed.</div>
            </div>
          </div>
          <div className="policy-grid">
            {!(POLICY.categories || []).length ? (
              <EmptyState>Loading policy state…</EmptyState>
            ) : (
              (POLICY.categories as { key: string; label: string; enabled: boolean }[]).map((c) => (
                <div key={c.key} className={"policy-tile" + (c.enabled ? "" : " pt-off")}>
                  <span className="pt-dot" />
                  <span className="pt-label">{c.label}</span>
                  <button
                    className="pt-switch"
                    role="switch"
                    aria-checked={c.enabled ? "true" : "false"}
                    aria-label={c.label}
                    disabled={policyBusy === c.key}
                    onClick={() => {
                      setPolicyBusy(c.key);
                      setPolicyCategory(c.key, !c.enabled)
                        .then(() => bump())
                        .finally(() => setPolicyBusy(""));
                    }}
                  />
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Training</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Good-mail training pack</h2>
              <div className="card-sub">
                Analyst “not malicious” labels extract sender addresses, domains, and URL hosts into a portable indicator database. Export the pack and import it on another environment to reuse the training.
              </div>
            </div>
          </div>
          <p style={{ fontSize: "12.5px", color: "var(--ink-secondary)", margin: "0 0 12px" }}>
            {(pack.indicators || []).length
              ? pack.indicators.length +
                " indicator" +
                (pack.indicators.length === 1 ? "" : "s") +
                (pack.updated_at ? " · updated " + pack.updated_at : "") +
                ". Export this pack and import it on another environment to reuse the training."
              : "Empty pack — open a message and click “Mark as not malicious”."}
          </p>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "12px" }}>
            <button
              type="button"
              className="btn btn-sm"
              onClick={async () => {
                const exported = await api("/api/feedback/export");
                const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = "good_indicators.json";
                a.click();
                URL.revokeObjectURL(a.href);
                if (ui.onToast) ui.onToast(ICON.download, "Downloaded good_indicators.json");
              }}
            >
              Export pack
            </button>
            <label className="btn btn-sm" style={{ cursor: "pointer", margin: 0 }}>
              Import pack
              <input
                type="file"
                accept="application/json,.json"
                hidden
                onChange={async (ev) => {
                  const file = ev.target.files && ev.target.files[0];
                  ev.target.value = "";
                  if (!file) return;
                  const text = await file.text();
                  let parsed;
                  try {
                    parsed = JSON.parse(text);
                  } catch (err) {
                    if (ui.onToast) ui.onToast(ICON.warning, "Not valid JSON");
                    return;
                  }
                  const imported = await api<{ indicators?: Indicator[] }>("/api/feedback/import", {
                    method: "POST",
                    body: JSON.stringify({ pack: parsed }),
                  });
                  if (ui.onToast) ui.onToast(ICON.good, "Imported " + (imported.indicators || []).length + " indicators");
                  setPack(await api<{ indicators: Indicator[]; updated_at: string }>("/api/feedback/indicators"));
                }}
              />
            </label>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="data-table" style={{ minWidth: "480px" }}>
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Value</th>
                  <th>Confirmations</th>
                </tr>
              </thead>
              <tbody>
                {(pack.indicators || []).map((row) => (
                  <tr key={row.kind + row.value}>
                    <td>{row.kind}</td>
                    <td style={{ fontFamily: "monospace", fontSize: "13px" }}>{row.value}</td>
                    <td>{row.confirmations || 1}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!(pack.indicators || []).length ? (
            <EmptyState>No trained indicators yet. Open a message and click “Mark as not malicious”.</EmptyState>
          ) : null}
        </div>
      </div>
    </section>
  );
}
