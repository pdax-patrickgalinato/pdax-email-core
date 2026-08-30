import {
  escapeHtml,
  fmtAgo,
  fmtNum,
  openDetailPage,
  queueRunning,
  queuesRows,
  queueWaiting,
  retryableEmails,
  workerKv,
  workerLabel,
  workerTileHtml,
} from "../lib/dashboard";
import { fleetReachable, pickWorkerSlot } from "../lib/workers-status";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState, HtmlBlock, StatTile } from "../components/ui";

export default function Workers() {
  const { workers } = useConsole();
  const data = workers;
  const retryN = retryableEmails().length;

  if (!data) {
    return (
      <section className="page active">
        <EmptyState>Loading worker status…</EmptyState>
      </section>
    );
  }

  const rec = (data.receiver || {}) as Record<string, any>;
  const recOk = fleetReachable(data);
  const ops = (data.ops || {}) as Record<string, any>;
  const cfg = (ops.config || {}) as Record<string, any>;
  const queues = (data.queues || {}) as Record<string, any>;
  const staticWait = queueWaiting(queues, "static");
  const staticRun = queueRunning(queues, "static");
  const aiWait = queueWaiting(queues, "content_ai");
  const aiRun = queueRunning(queues, "content_ai");
  const campaignWait = queueWaiting(queues, "campaign");
  const campaignRun = queueRunning(queues, "campaign");
  const followWait = queueWaiting(queues, "profile") + queueWaiting(queues, "sender_risk");
  const timedWait = queueWaiting(queues, "retry");
  const poll = pickWorkerSlot(data, "poll");
  const staticW = pickWorkerSlot(data, "static");
  const llm = pickWorkerSlot(data, "llm");
  const thread = pickWorkerSlot(data, "thread_ai");
  const campaign = pickWorkerSlot(data, "campaign");
  const profile = pickWorkerSlot(data, "profile");
  const risk = pickWorkerSlot(data, "sender_risk");
  const retry = pickWorkerSlot(data, "retry");
  const pollSlot: Record<string, any> = { ...(poll.slot || {}), fetch_paused: ops.gmail_fetch === false };
  const llmSlot = llm.slot;
  const retrySlot = retry.slot;
  const staticSlot = staticW.slot;
  const threadSlot = thread.slot;
  const queued: string[] = ((retrySlot.last_queued as string[]) || []).slice(0, 8);
  const events = data.events || [];
  const mailboxN =
    Number((ops.coverage || {}).polling) ||
    Number(rec.users) ||
    Number((pollSlot.last_stats || {}).mailboxes) ||
    ops.gmail_users ||
    0;

  const tilesHtml =
    workerTileHtml(
      "Gmail poll",
      poll.reachable ? mailboxN + " mailboxes" : poll.host,
      pollSlot,
      "poll",
      poll.reachable,
      queues
    ) +
    workerTileHtml("Static checks", staticW.host, staticSlot, "static", staticW.reachable, queues) +
    workerTileHtml("AI assessment", llm.host, llmSlot, "llm", llm.reachable, queues) +
    workerTileHtml("Thread AI", thread.host, threadSlot, "thread_ai", thread.reachable, queues) +
    workerTileHtml("Campaign clustering", campaign.host, campaign.slot, "campaign", campaign.reachable, queues) +
    workerTileHtml("Sender profiles", profile.host, profile.slot, "profile", profile.reachable, queues) +
    workerTileHtml("Sender risk AI", risk.host, risk.slot, "sender_risk", risk.reachable, queues) +
    workerTileHtml("LLM auto-retry", retry.host, retrySlot, "retry", retry.reachable, queues);

  const qBits = queued.length
    ? queued
        .map(
          (id) =>
            "<button type='button' class='wk-qid' data-qid='" + escapeHtml(id) + "'>" + escapeHtml(id) + "</button>"
        )
        .join(" · ")
    : "None this cycle";

  const alerts = Array.isArray(queues.alerts) ? queues.alerts : [];
  const pipe = (queues.pipeline || {}) as Record<string, number>;
  const deadN = Number(pipe.dead_letter || 0);
  const errN = Number(pipe.error || 0);

  return (
    <section className="page active">
      <div className="stat-grid">
        <StatTile
          label="Receiver"
          value={recOk ? "Up" : "Down"}
          sub={
            ops.gmail_fetch === false
              ? "Fetch paused · assessing emails already in"
              : recOk
                ? fmtNum(mailboxN) +
                  " mailboxes · " +
                  (rec.source === "heartbeat" ? "via data volume" : "HTTP health")
                : "Unreachable"
          }
          accentVar={recOk ? "var(--status-good)" : "var(--status-warning)"}
        />
        <StatTile
          label="Static queue"
          value={staticWait.toLocaleString()}
          sub={staticRun ? fmtNum(staticRun) + " processing" : "none processing"}
          accentVar="var(--accent)"
        />
        <StatTile
          label="AI queue"
          value={aiWait.toLocaleString()}
          sub={aiRun ? fmtNum(aiRun) + " processing" : retryN ? fmtNum(retryN) + " timed out" : "none processing"}
          accentVar="var(--status-serious)"
        />
        <StatTile
          label="Campaign queue"
          value={campaignWait.toLocaleString()}
          sub={campaignRun ? fmtNum(campaignRun) + " processing" : "clustering follow-up"}
          accentVar="var(--status-good)"
        />
        <StatTile
          label="Follow-up"
          value={followWait.toLocaleString()}
          sub="profile · sender risk"
          accentVar="var(--status-good)"
        />
        <StatTile
          label="Timed out"
          value={timedWait.toLocaleString()}
          sub={retryN ? fmtNum(retryN) + " auto-retry" : "waiting on retry worker"}
          accentVar="var(--status-warning)"
        />
      </div>
      {alerts.length > 0 && (
        <div className="card" style={{ marginBottom: "1rem" }}>
          <div className="card-head">
            <h2>Alerts</h2>
            <div className="card-sub">
              {deadN || errN
                ? `${fmtNum(deadN)} dead letter · ${fmtNum(errN)} error`
                : "Pipeline and Gmail poll"}
            </div>
          </div>
          <ul className="wk-alerts">
            {alerts.map((a: { code?: string; summary?: string }) => (
              <li key={a.code || a.summary}>{a.summary}</li>
            ))}
          </ul>
        </div>
      )}
      <div className="worker-grid worker-grid-lg" dangerouslySetInnerHTML={{ __html: tilesHtml }} />
      <div className="charts-row">
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Job queues</h2>
              <div className="card-sub">Same waiting/processing counts as the worker tiles above</div>
            </div>
          </div>
          <div
            onClick={(ev) => {
              const btn = (ev.target as HTMLElement).closest(".wk-qid");
              if (btn) openDetailPage(btn.getAttribute("data-qid"));
            }}
          >
            <HtmlBlock
              html={workerKv(
                queuesRows(queues).concat([
                  ["Last auto-retry batch", qBits],
                  ["Wait window", (cfg.llm_timeout_seconds || 120) + "s then auto-retry"],
                ])
              )}
            />
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Recent activity</h2>
              <div className="card-sub">Last cycles from the API and worker processes</div>
            </div>
          </div>
          <ol className="worker-events worker-events-tall">
            {events.length ? (
              events.slice(0, 20).map((e, i) => {
                const when = e.ts ? fmtAgo(Number(e.ts) * 1000) : "";
                const who = (e.process === "gmail_receiver" ? "receiver" : e.process || "api") + " · " + workerLabel(e.worker);
                return (
                  <li key={i} className={e.ok === false ? "is-bad" : ""}>
                    <span className="we-meta">
                      {when} · {who}
                    </span>
                    {e.summary || ""}
                  </li>
                );
              })
            ) : (
              <li>No notable worker activity yet this process lifetime.</li>
            )}
          </ol>
        </div>
      </div>
    </section>
  );
}
