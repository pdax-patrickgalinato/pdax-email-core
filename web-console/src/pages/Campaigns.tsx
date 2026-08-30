import {
  campaignAttackLabel,
  campaignKindLabel,
  campaignQueueId,
  campaignTitle,
  filteredCampaigns,
  findEmail,
  fmtNum,
  openDetailPage,
  state,
} from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState, StatTile } from "../components/ui";
import type { Campaign } from "../types";

function mixBar(mix: Record<string, number> | undefined) {
  const clean = Number(mix?.CLEAN || mix?.clean || 0);
  const susp = Number(mix?.SUSPICIOUS || mix?.suspicious || 0);
  const mal = Number(mix?.MALICIOUS || mix?.malicious || 0);
  const total = clean + susp + mal;
  if (!total) return null;
  return (
    <div className="sender-mix" aria-hidden="true">
      {mal ? <span className="v-malicious" style={{ width: `${(mal / total) * 100}%` }} /> : null}
      {susp ? <span className="v-suspicious" style={{ width: `${(susp / total) * 100}%` }} /> : null}
      {clean ? <span className="v-clean" style={{ width: `${(clean / total) * 100}%` }} /> : null}
    </div>
  );
}

function iocLines(insight: Campaign["insight"]) {
  const iocs = insight?.shared_iocs;
  if (!iocs) return [];
  const rows: { label: string; values: string[] }[] = [
    { label: "Landing URLs", values: iocs.urls || [] },
    { label: "Hosts", values: iocs.hosts || [] },
    { label: "Domains", values: iocs.domains || [] },
    { label: "IPs", values: iocs.ips || [] },
  ];
  return rows.filter((r) => r.values.length);
}

function visiblePatterns(patterns: string[]) {
  return patterns.filter((p) => {
    const t = String(p || "");
    if (/^Primary pivot\b/i.test(t)) return false;
    if (/shared attachment hash/i.test(t)) return false;
    if (/\bhash:[a-f0-9]/i.test(t)) return false;
    if (/\bcam-[a-f0-9]{8,}/i.test(t)) return false;
    return true;
  });
}

function fpClass(risk: string | undefined) {
  if (risk === "low") return "is-fp-low";
  if (risk === "high") return "is-fp-high";
  return "";
}

function CampaignDetail({ selected }: { selected: Campaign }) {
  const insight = selected.insight || {};
  const attack = campaignAttackLabel(selected.attack_class);
  const patterns = visiblePatterns(insight.patterns || []);
  const tactics = insight.tactics || [];
  const actions = insight.analyst_actions || [];
  const briefs = insight.member_briefs || [];
  const iocs = iocLines(insight);
  const analyzed = Number(insight.analyzed || 0);
  const senders = selected.sender_list || [];
  const boxes = selected.mailbox_list || [];
  const dests = selected.dests || [];
  const subjects = selected.subjects || [];

  return (
    <>
      <h2>{campaignTitle(selected)}</h2>
      <div className="card-sub">
        {campaignKindLabel(selected.kind)} — reference only, does not change the score
      </div>
      <div className="campaign-badges">
        {attack ? <span className="campaign-badge is-attack">{attack}</span> : null}
        {selected.confidence ? (
          <span className="campaign-badge">{String(selected.confidence)} confidence</span>
        ) : null}
        {insight.false_positive_risk ? (
          <span className={"campaign-badge " + fpClass(insight.false_positive_risk)}>
            FP risk {insight.false_positive_risk}
          </span>
        ) : null}
        {analyzed ? (
          <span className="campaign-badge">
            {fmtNum(analyzed)} email{analyzed === 1 ? "" : "s"} with AI assessment
          </span>
        ) : (
          <span className="campaign-badge">Waiting on per-email AI</span>
        )}
        {selected.ai_provider && selected.ai_provider !== "heuristic" ? (
          <span className="campaign-badge">Campaign model {selected.ai_model || selected.ai_provider}</span>
        ) : selected.ai_provider === "heuristic" ? (
          <span className="campaign-badge">Synthesized from member assessments</span>
        ) : null}
      </div>
      <div className="sender-vol">
        <div className="sender-vol-nums">
          <div>
            <span className="sender-vol-n">{fmtNum(Number(selected.members) || 0)}</span> emails
          </div>
          <div>
            <span className="sender-vol-n">{fmtNum(Number(selected.senders) || 0)}</span> senders
          </div>
          <div>
            <span className="sender-vol-n">{fmtNum(Number(selected.flagged) || 0)}</span> flagged
          </div>
          <div>
            <span className="sender-vol-n">{fmtNum(Number(selected.mailboxes) || 0)}</span> mailboxes
          </div>
        </div>
        {mixBar(insight.threat_mix)}
      </div>
      {selected.ai_summary ? <p className="campaign-narrative">{selected.ai_summary}</p> : null}
      {insight.lure ? (
        <p className="campaign-lure">
          <strong>Shared lure. </strong>
          {insight.lure}
        </p>
      ) : null}
      {insight.why_clustered ? (
        <>
          <h3>Why these emails cluster</h3>
          <p className="campaign-narrative">{insight.why_clustered}</p>
        </>
      ) : null}
      {insight.false_positive_note ? (
        <>
          <h3>False-positive risk</h3>
          <p className="campaign-narrative">{insight.false_positive_note}</p>
        </>
      ) : null}
      {patterns.length ? (
        <>
          <h3>Phishing patterns</h3>
          <ul className="campaign-insight-list">
            {patterns.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </>
      ) : null}
      {tactics.length ? (
        <>
          <h3>Tactics</h3>
          <ul className="campaign-insight-list">
            {tactics.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </>
      ) : null}
      {insight.targeting ? (
        <>
          <h3>Targeting</h3>
          <p className="campaign-narrative">{insight.targeting}</p>
        </>
      ) : null}
      {insight.infrastructure || iocs.length ? (
        <>
          <h3>Shared infrastructure</h3>
          {insight.infrastructure ? <p className="campaign-narrative">{insight.infrastructure}</p> : null}
          {iocs.map((row) => (
            <p key={row.label} className="campaign-ioc">
              <strong>{row.label}: </strong>
              {row.values.join(" · ")}
            </p>
          ))}
        </>
      ) : null}
      {actions.length ? (
        <>
          <h3>Analyst actions</h3>
          <ol className="campaign-insight-list">
            {actions.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ol>
        </>
      ) : null}
      {briefs.length ? (
        <>
          <h3>Member AI assessments</h3>
          {briefs.map((b) => {
            const qid = String(b.queue_id || "");
            return (
              <div key={qid || b.subject} className="campaign-member-ai">
                <strong>{b.verdict || "UNSCORED"}</strong>
                {b.intent ? ` · ${b.intent.replace(/_/g, " ")}` : ""}
                {b.subject ? ` — ${b.subject}` : ""}
                <div className="addr">
                  {b.from || "unknown sender"}
                  {b.mailbox ? ` → ${b.mailbox}` : ""}
                </div>
                {b.summary ? <div style={{ marginTop: 4 }}>{b.summary}</div> : null}
              </div>
            );
          })}
        </>
      ) : null}
      {subjects.length ? (
        <>
          <h3>Subjects</h3>
          <ul className="sender-peer-list">
            {subjects.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </>
      ) : null}
      {senders.length ? (
        <>
          <h3>Senders</h3>
          <ul className="sender-peer-list">
            {senders.map((s) => (
              <li key={s}>
                <span className="addr-email">{s}</span>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {boxes.length ? (
        <>
          <h3>Mailboxes</h3>
          <ul className="sender-peer-list">
            {boxes.map((s) => (
              <li key={s}>
                <span className="addr-email">{s}</span>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <h3>Member emails</h3>
      {dests.length ? (
        <div className="sender-chip-list">
          {dests.map((d) => {
            const qid = campaignQueueId(d);
            return findEmail(qid) ? (
              <button key={qid} type="button" className="wk-qid" onClick={() => openDetailPage(qid)}>
                {qid}
              </button>
            ) : (
              <span key={qid} className="sender-chip">
                {qid}
              </span>
            );
          })}
        </div>
      ) : (
        <div className="card-sub">No stored dests on this cluster.</div>
      )}
      <div className="card-sub" style={{ marginTop: "12px" }}>
        Open a member email to read the full per-message assessment. Campaign insight is synthesized from those
        assessments and does not change a verdict.
      </div>
    </>
  );
}

export default function Campaigns() {
  const { campaigns, bump } = useConsole();
  const all = campaigns || [];
  const flaggedN = all.filter((c) => Number(c.flagged) > 0).length;
  const emails = all.reduce((n, c) => n + (Number(c.members) || 0), 0);
  const senders = all.reduce((n, c) => n + (Number(c.senders) || 0), 0);
  const withInsight = all.filter((c) => String(c.ai_summary || "").trim()).length;
  const items = filteredCampaigns();
  const selected = all.find((c) => c.id === state.campaignSelected);

  return (
    <section className="page active">
      <div className="stat-grid">
        <StatTile label="Clusters" value={all.length} sub="shared URL, hash, or template" accentVar="var(--accent)" />
        <StatTile label="With flagged emails" value={flaggedN} sub="SUSPICIOUS or MALICIOUS members" accentVar="var(--status-serious)" />
        <StatTile
          label="With campaign insight"
          value={withInsight}
          sub={fmtNum(emails) + " member emails · " + fmtNum(senders) + " senders"}
          accentVar="var(--status-good)"
        />
      </div>
      <div className="toolbar">
        <input
          className="search-input"
          type="search"
          placeholder="Search lure, sender, or class…"
          autoComplete="off"
          defaultValue={state.campaignQuery}
          onChange={(e) => {
            state.campaignQuery = e.target.value;
            bump();
          }}
        />
        <button
          className={"btn btn-sm" + (state.campaignFlaggedOnly ? " btn-primary" : "")}
          type="button"
          onClick={() => {
            state.campaignFlaggedOnly = !state.campaignFlaggedOnly;
            bump();
          }}
        >
          Flagged emails only
        </button>
      </div>
      <div className="senders-layout">
        <div className="card card-primary" style={{ padding: 0 }}>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Cluster</th>
                  <th style={{ width: "140px" }}>Class</th>
                  <th style={{ width: "72px" }}>Emails</th>
                  <th style={{ width: "72px" }}>Senders</th>
                  <th style={{ width: "80px" }}>Flagged</th>
                </tr>
              </thead>
              <tbody>
                {items.map((c) => (
                  <tr
                    key={c.id}
                    className={c.id === state.campaignSelected ? "is-selected" : ""}
                    onClick={() => {
                      state.campaignSelected = c.id;
                      bump();
                    }}
                  >
                    <td>
                      <span className="addr-email">{campaignTitle(c)}</span>
                      <div className="addr">{campaignKindLabel(c.kind)}</div>
                    </td>
                    <td>{campaignAttackLabel(c.attack_class) || "—"}</td>
                    <td className="cell-score">{fmtNum(Number(c.members) || 0)}</td>
                    <td className="cell-score">{fmtNum(Number(c.senders) || 0)}</td>
                    <td className="cell-score">{fmtNum(Number(c.flagged) || 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!items.length ? (
            <EmptyState>
              {all.length ? "No clusters match this filter." : "No campaign clusters yet."}
            </EmptyState>
          ) : null}
        </div>
        <aside className="card card-primary sender-profile-detail" aria-label="Campaign cluster">
          {!selected ? (
            <EmptyState>
              Select a cluster to read the campaign narrative, shared lure, and patterns synthesized from member AI
              assessments.
            </EmptyState>
          ) : (
            <CampaignDetail selected={selected} />
          )}
        </aside>
      </div>
    </section>
  );
}
