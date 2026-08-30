import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  OVERVIEW_FILTER_LABEL,
  actionTakenLabel,
  displayVerdict,
  feedMatchesSearch,
  FEED_PAGE_SIZE,
  feedOverview,
  feedPageWindow,
  groupAsThreads,
  isAiPending,
  isAiTimedOut,
  loadFeed,
  openDetailPage,
  overviewTableFeed,
  pageFeedThreads,
  renderChart,
  renderOriginMap,
  renderThreatMix,
  resetFeedPage,
  state,
  verdictIsFinal,
  VERDICTS,
  fmtTime,
  fmtNum,
} from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import {
  CategoryChips,
  EmptyState,
  FromCell,
  ScoreCell,
  StatTile,
  ThreadChip,
  ToCell,
} from "../components/ui";

export default function Overview() {
  const { feed, tick, bump } = useConsole();
  const navigate = useNavigate();
  const mixRef = useRef<HTMLDivElement>(null);
  const volRef = useRef<HTMLDivElement>(null);
  const shownIds = useRef<string[]>([]);

  useEffect(() => {
    state.activePage = "overview";
    try {
      renderThreatMix();
    } catch (err) {
      console.warn("threat mix failed", err);
    }
    try {
      renderChart();
    } catch (err) {
      console.warn("volume chart failed", err);
    }
    try {
      renderOriginMap();
    } catch (err) {
      console.warn("origin map failed", err);
    }
  }, [tick, feed]);

  const ov = feedOverview();
  const rawCounts = ov.counts || {};
  const counts = {
    CLEAN: Number(rawCounts.CLEAN) || 0,
    LOW: Number(rawCounts.LOW) || 0,
    SUSPICIOUS: Number(rawCounts.SUSPICIOUS) || 0,
    MALICIOUS: Number(rawCounts.MALICIOUS) || 0,
  };
  const pendingN = ov.pendingN;
  const inconclusiveN = ov.inconclusiveN;
  const total = ov.total;
  const decided = total - pendingN - inconclusiveN;
  const waitBits = [];
  if (pendingN) waitBits.push(fmtNum(pendingN) + " awaiting AI");
  if (inconclusiveN) waitBits.push(fmtNum(inconclusiveN) + " inconclusive");

  const inboxN = Number(ov.inboxesMonitored) || 0;
  const inboxPolling = Number(ov.inboxesPolling) || 0;
  const inboxConfigured = Number(ov.inboxesConfigured) || 0;
  const inboxDiscovered = Number(ov.inboxesDiscovered) || 0;
  const assessedN = Number(ov.assessed) || 0;
  const threadAssessedN = Number(ov.threadAssessed) || 0;
  const inboxSub = inboxPolling
    ? "all-time · " + fmtNum(inboxPolling) + " currently polling"
    : inboxDiscovered
      ? "all-time · " + fmtNum(inboxConfigured) + " seed · " + fmtNum(inboxDiscovered) + " added as mail arrived"
      : inboxConfigured
        ? "all-time · " + fmtNum(inboxConfigured) + " configured"
        : "all-time distinct mailboxes";
  const assessedSub = threadAssessedN
    ? fmtNum(threadAssessedN) + " with thread AI"
    : "content AI completed";

  const tiles = [
    {
      filter: "all",
      label: "Total",
      value: total,
      icon: "eye",
      accentVar: "var(--accent)",
      sub: waitBits.length
        ? waitBits.join(" · ")
        : decided
          ? Math.round(((counts.CLEAN + counts.LOW) / decided) * 100) + "% passed clean"
          : "No mail yet",
    },
    {
      filter: "safe",
      label: "Safe",
      value: counts.CLEAN + counts.LOW,
      icon: "good",
      accentVar: "var(--status-good)",
      sub: fmtNum(counts.CLEAN) + " clean · " + fmtNum(counts.LOW) + " low",
    },
    {
      filter: "suspicious",
      label: "Suspicious",
      value: counts.SUSPICIOUS,
      icon: "serious",
      accentVar: "var(--status-serious)",
      sub: "flagged for review",
    },
    {
      filter: "malicious",
      label: "Malicious",
      value: counts.MALICIOUS,
      icon: "critical",
      accentVar: "var(--status-critical)",
      sub: "high-confidence detections",
    },
  ];

  const q = (state.feedSearch || "").trim();

  const tableFeed = overviewTableFeed();
  const matched = q ? tableFeed.filter(feedMatchesSearch) : tableFeed;
  const threadsAll = groupAsThreads(matched, tableFeed);
  const paged = pageFeedThreads(threadsAll);
  const threads = paged.items;

  const empty = q
    ? state.searchPending
      ? "Searching mail…"
      : 'No messages match “' + q + "”."
    : state.originCountry
      ? "No messages from that origin."
      : state.overviewFilter === "all"
        ? (state.feedError
          ? "Could not load mail from the API (" + state.feedError + "). Retrying…"
          : (!feed.length && !state.feedLoaded ? "Loading mail…" : "Waiting for the first message…"))
        : "No messages match this filter.";

  const timedN = ov.aiTimedOutTotal;
  const pendingBanner = ov.aiPendingTotal;
  const keys = threadsAll.map((g) => g.key);
  const prev = shownIds.current;
  shownIds.current = keys;

  return (
    <section className="page active">
      <div className="stat-grid overview-stats">
        {tiles.map((t) => (
          <StatTile
            key={t.filter}
            {...t}
            active={state.overviewFilter === t.filter}
            onClick={() => {
              state.overviewFilter = state.overviewFilter === t.filter ? "all" : t.filter;
              if (state.overviewFilter === "all") state.filteredFeed = null;
              resetFeedPage();
              loadFeed().then(() => bump());
            }}
          />
        ))}
        <StatTile
          key="assessed"
          label="Assessed"
          value={assessedN}
          icon="scan"
          accentVar="var(--accent)"
          sub={assessedSub}
        />
        <StatTile
          key="inboxes"
          label="Inboxes monitored"
          value={inboxN}
          icon="inbox"
          accentVar="var(--accent)"
          sub={inboxSub}
          onClick={() => navigate("/workers")}
        />
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Threat mix</h2>
              <div className="card-sub">All assessed mail by verdict</div>
            </div>
            <div className="card-sub" id="mixTotalLabel" ref={mixRef} />
          </div>
          <div className="chart-box doughnut">
            <canvas id="mixChart" aria-label="Verdict distribution" />
          </div>
          <div className="chart-legend-row" id="mixLegend" />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Mail volume</h2>
              <div className="card-sub">All mail, by day</div>
            </div>
            <div className="card-sub" id="chartTotalLabel" ref={volRef} />
          </div>
          <div className="chart-box">
            <canvas id="volumeChart" aria-label="Mail volume chart" />
          </div>
        </div>
      </div>

      <div className="card origin-map-card">
        <div className="card-head">
          <div>
            <h2>Origin of mail</h2>
            <div className="card-sub">
              Sending MTA locations — click a pin or country to filter the feed
            </div>
          </div>
          <div className="card-sub" id="originMapLabel" />
        </div>
        <div className="origin-map-layout">
          <div className="origin-globe-wrap">
            <div id="originMap" className="origin-jvm" role="img" aria-label="World map of originating mail locations" />
          </div>
          <div className="origin-map-list" id="originMapList" />
        </div>
      </div>

      {pendingBanner || timedN ? (
        <div className="ai-queue-banner" onClick={() => navigate("/workers")}>
          {pendingBanner ? <span className="analyze-spinner" aria-hidden="true" /> : null}
          <span>
            {[
              pendingBanner ? fmtNum(pendingBanner) + " message" + (pendingBanner === 1 ? "" : "s") + " waiting on AI" : null,
              timedN ? fmtNum(timedN) + " retrying automatically" : null,
            ]
              .filter(Boolean)
              .join(". ")}
          </span>
        </div>
      ) : null}

      <div className="card card-primary" style={{ padding: 0 }}>
        <div className="card-head" style={{ padding: "18px 20px 0" }}>
          <div>
            <h2>Live feed</h2>
            <div className="card-sub">
              Messages in the same conversation are grouped — click a row to read the whole thread
              {state.overviewFilter !== "all"
                ? " · " + fmtNum(paged.total) + " conversation" + (paged.total === 1 ? "" : "s") + " · newest first"
                : ov.truncated
                  ? " · showing latest " + fmtNum(ov.feedLimit || feed.length) + " of " + fmtNum(ov.total) + " · newest first"
                  : " · newest first"}
            </div>
          </div>
          <div>
            {state.overviewFilter !== "all" ? (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  state.overviewFilter = "all";
                  state.filteredFeed = null;
                  resetFeedPage();
                  loadFeed().then(() => bump());
                }}
              >
                Filtered: {OVERVIEW_FILTER_LABEL[state.overviewFilter]} ✕
              </button>
            ) : null}{" "}
            {state.originCountry ? (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  state.originCountry = "";
                  resetFeedPage();
                  loadFeed().then(() => bump());
                }}
              >
                Origin: {state.originCountry} ✕
              </button>
            ) : null}
          </div>
        </div>
        {q ? (
          <div className="toolbar" style={{ padding: "4px 20px 12px" }}>
            <span className="card-sub">
              Spotlight mail results{Array.isArray(state.searchHits) ? " · " + fmtNum(state.searchHits.length) : ""}
            </span>
          </div>
        ) : null}
        <div className="feed-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "78px" }}>Time</th>
                <th style={{ width: "64px" }}>Verdict</th>
                <th>From</th>
                <th>To</th>
                <th>Subject</th>
                <th style={{ width: "56px" }}>Score</th>
                <th style={{ width: "110px" }}>Action taken</th>
              </tr>
            </thead>
            <tbody>
              {!threads.length ? (
                <tr>
                  <td colSpan={7}>
                    <EmptyState>{empty}</EmptyState>
                  </td>
                </tr>
              ) : (
                threads.map((g) => {
                  const e = g.latest;
                  const display = g.worst;
                  const isNew = prev.indexOf(g.key) === -1;
                  const tAss = (g.messages || []).reduce((best: typeof display | null, m: typeof display) => {
                    if (!(m && (m.threadSummary || m.threadVerdict))) return best;
                    if (!best || m.ts > best.ts) return m;
                    return best;
                  }, null);
                  const rowVerdict =
                    display.hardOverride || !(tAss && tAss.threadVerdict)
                      ? displayVerdict(display)
                      : tAss.threadVerdict;
                  const vinfo = VERDICTS[rowVerdict] || VERDICTS[displayVerdict(display)] || VERDICTS.PENDING;
                  const actionLabel = actionTakenLabel(display);
                  return (
                    <tr
                      key={g.key}
                      className={"row-stripe " + vinfo.cls + (isNew ? " row-enter" : "")}
                      style={{ cursor: "pointer" }}
                      onClick={() => openDetailPage(display.id)}
                    >
                      <td className="cell-time">{fmtTime(e.ts)}</td>
                      <td>
                        <ThreadChip group={g} display={display} />
                      </td>
                      <td className="cell-from">
                        <FromCell email={e} />
                      </td>
                      <td className="cell-to">
                        <ToCell email={e} />
                      </td>
                      <td className="cell-subject">
                        <div className="cell-content-min">
                          <div className="cell-subject-text">{g.subject}</div>
                          {g.messages.length > 1 ? (
                            <span className="thread-count" title={fmtNum(g.messages.length) + " messages in this thread"}>
                              {fmtNum(g.messages.length)}
                            </span>
                          ) : null}
                          {g.messages.some(isAiPending) && displayVerdict(display) !== "PENDING" && !isAiTimedOut(display) ? (
                            <span className="ai-pending">
                              <span className="analyze-spinner" aria-hidden="true" />
                              Assessing
                            </span>
                          ) : null}
                          {verdictIsFinal(display) ? <CategoryChips reasons={display.reasons} /> : null}
                        </div>
                      </td>
                      <td className="cell-score">
                        <ScoreCell email={display} />
                      </td>
                      <td>{actionLabel}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {paged.total ? (
          <div className="feed-pager">
            <div className="card-sub">
              {paged.pages > 1
                ? "Showing " +
                  fmtNum(paged.from) +
                  "–" +
                  fmtNum(paged.to) +
                  " of " +
                  fmtNum(paged.total) +
                  " conversations · " +
                  fmtNum(FEED_PAGE_SIZE) +
                  " per page"
                : fmtNum(paged.total) +
                  " conversation" +
                  (paged.total === 1 ? "" : "s")}
            </div>
            {paged.pages > 1 ? (
              <div className="feed-pager-nav">
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={paged.page <= 1}
                  onClick={() => {
                    state.feedPage = paged.page - 1;
                    bump();
                  }}
                >
                  Previous
                </button>
                {feedPageWindow(paged.page, paged.pages).map((n, i) =>
                  n === 0 ? (
                    <span key={"e" + i} className="feed-pager-ellipsis">
                      …
                    </span>
                  ) : (
                    <button
                      key={n}
                      type="button"
                      className={"btn btn-sm" + (n === paged.page ? " btn-primary" : "")}
                      aria-current={n === paged.page ? "page" : undefined}
                      onClick={() => {
                        state.feedPage = n;
                        bump();
                      }}
                    >
                      {fmtNum(n)}
                    </button>
                  ),
                )}
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={paged.page >= paged.pages}
                  onClick={() => {
                    state.feedPage = paged.page + 1;
                    bump();
                  }}
                >
                  Next
                </button>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
