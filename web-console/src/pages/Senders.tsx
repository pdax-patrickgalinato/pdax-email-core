import { useEffect } from "react";
import {
  filteredSenderProfiles,
  freqValues,
  networkRoleLabel,
  renderSenderAssessment,
  riskChip,
  selectSenderProfile,
  senderAssessmentOf,
  senderCopies,
  senderLaneHtml,
  senderMixBarHtml,
  state,
  fmtNum,
} from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState, HtmlBlock, StatTile } from "../components/ui";

export default function Senders() {
  const { senderProfiles, tick, bump } = useConsole();
  const all = senderProfiles || [];
  const counts: Record<string, number> = { CLEAN: 0, SUSPICIOUS: 0, MALICIOUS: 0 };
  all.forEach((p) => {
    counts[senderAssessmentOf(p)] += 1;
  });

  useEffect(() => {
    state.activePage = "senders";
    renderSenderAssessment();
  }, [tick, all.length, state.senderAssessFilter]);

  const items = filteredSenderProfiles();

  return (
    <section className="page active">
      <div className="stat-grid">
        {[
          { filter: "all", label: "Senders", value: all.length, icon: "eye", accentVar: "var(--accent)", sub: all.length ? "typical behavior, not worst email" : "No sender history yet" },
          { filter: "CLEAN", label: "Clean", value: counts.CLEAN, icon: "good", accentVar: "var(--status-good)", sub: "mostly clean emails" },
          { filter: "SUSPICIOUS", label: "Suspicious", value: counts.SUSPICIOUS, icon: "serious", accentVar: "var(--status-serious)", sub: "hostile emails are a real share of volume" },
          { filter: "MALICIOUS", label: "Malicious", value: counts.MALICIOUS, icon: "critical", accentVar: "var(--status-critical)", sub: "majority malicious, or ≥3 emails at ≥20%" },
        ].map((t) => (
          <StatTile
            key={t.filter}
            {...t}
            active={state.senderAssessFilter === t.filter}
            onClick={() => {
              state.senderAssessFilter = state.senderAssessFilter === t.filter ? "all" : t.filter;
              bump();
            }}
          />
        ))}
      </div>
      <div className="charts-row">
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Sender assessment</h2>
              <div className="card-sub">Typical email mix plus send/receive volume, counterparties, and AI identity risk</div>
            </div>
            <div className="card-sub" id="senderAssessMixLabel" />
          </div>
          <div className="chart-box doughnut">
            <canvas id="senderAssessChart" aria-label="Sender assessment mix" />
          </div>
          <div className="chart-legend-row" id="senderAssessLegend" />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Volume vs hostility</h2>
              <div className="card-sub">Each point is a From address. Color is typical behavior; height is the share of SUSPICIOUS + MALICIOUS emails</div>
            </div>
            <div className="card-sub" id="senderHostilityLabel" />
          </div>
          <div className="chart-box">
            <canvas id="senderHostilityChart" aria-label="Sender volume versus hostility" />
          </div>
        </div>
      </div>
      <div className="toolbar">
        <input
          className="search-input"
          type="search"
          placeholder="Search a From address…"
          autoComplete="off"
          defaultValue={state.senderProfileQuery}
          onChange={(e) => {
            state.senderProfileQuery = e.target.value;
            bump();
          }}
        />
        <button
          className={"btn btn-sm" + (state.senderProfileReadyOnly ? " btn-primary" : "")}
          type="button"
          onClick={() => {
            state.senderProfileReadyOnly = !state.senderProfileReadyOnly;
            bump();
          }}
        >
          Ready only (n≥5)
        </button>
      </div>
      <div className="senders-layout">
        <div className="card card-primary" style={{ padding: 0 }}>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Sender</th>
                  <th style={{ width: "108px" }}>AI risk</th>
                  <th style={{ width: "120px" }}>Mix</th>
                  <th style={{ width: "64px" }}>Sent</th>
                  <th style={{ width: "64px" }}>Recv</th>
                  <th style={{ width: "110px" }}>Usual</th>
                  <th>Countries</th>
                  <th>ASN</th>
                  <th style={{ width: "72px" }}>VPN</th>
                  <th style={{ width: "100px" }}>Baseline</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => {
                  const n = senderCopies(p);
                  const ready = !!(p.ready || (Number(p.n) || 0) >= (state.senderProfileMinN || 5));
                  const sent = Number(p.sent_count) || n;
                  const recv = Number(p.received_count) || 0;
                  return (
                    <tr
                      key={p.sender}
                      className={p.sender === state.senderProfileSelected ? "is-selected" : ""}
                      onClick={() => {
                        selectSenderProfile(p.sender);
                        bump();
                      }}
                    >
                      <td className="cell-from">
                        <span className="addr-email">{p.sender}</span>
                        {senderLaneHtml(p) ? <HtmlBlock className="addr" html={senderLaneHtml(p)} /> : null}
                      </td>
                      <td>
                        <HtmlBlock tag="span" html={riskChip(p.ai_risk)} />
                      </td>
                      <td>
                        <HtmlBlock html={senderMixBarHtml(p)} />
                      </td>
                      <td className="cell-score">{fmtNum(sent)}</td>
                      <td className="cell-score">{fmtNum(recv)}</td>
                      <td>{networkRoleLabel(p.majority_role)}</td>
                      <td>{freqValues(p.countries, 3).join(", ") || "—"}</td>
                      <td>{freqValues(p.asns, 2).join(", ") || "—"}</td>
                      <td>{Math.round((Number(p.vpn_rate) || 0) * 100)}%</td>
                      <td>
                        <span className={ready ? "baseline-ready" : "baseline-learning"}>
                          {ready ? "Ready" : "Learning " + fmtNum(Number(p.n) || 0) + "/" + fmtNum(state.senderProfileMinN || 5)}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {!items.length ? (
            <EmptyState>{all.length ? "No senders match this filter." : "No sender history yet."}</EmptyState>
          ) : null}
        </div>
        <aside className="card card-primary sender-profile-detail" id="senderProfileDetail" aria-label="Sender baseline">
          <EmptyState>Select a sender to see what they typically send and receive, who they talk to, and where from.</EmptyState>
        </aside>
      </div>
    </section>
  );
}
