import {
  ICON,
  VERDICTS,
  canAct,
  confirmRelease,
  displayVerdict,
  downloadEml,
  fmtDateTime,
  fmtExpires,
  fmtNum,
  groupAsThreads,
  heldEmails,
  openDetailPage,
  state,
  threadAssessmentOf,
  verdictIsFinal,
} from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import {
  CategoryChips,
  EmptyState,
  FromCell,
  HtmlBlock,
  ScoreCell,
  ThreadChip,
} from "../components/ui";

const TABS: [string, string][] = [
  ["all", "All"],
  ["blocked", "Blocked"],
  ["quarantined", "Quarantined"],
  ["released", "Released"],
];

export default function Quarantine() {
  const { bump } = useConsole();
  const all = heldEmails();
  const counts: Record<string, number> = { all: all.length, blocked: 0, quarantined: 0, released: 0 };
  all.forEach((e) => {
    if (e.status === "released") counts.released += 1;
    else if (!verdictIsFinal(e)) return;
    else if (e.verdict === "MALICIOUS") counts.blocked += 1;
    else counts.quarantined += 1;
  });

  let filtered = all.filter((e) => {
    if (state.qFilter === "blocked") return verdictIsFinal(e) && e.verdict === "MALICIOUS" && e.status !== "released";
    if (state.qFilter === "quarantined") return verdictIsFinal(e) && e.verdict === "SUSPICIOUS" && e.status !== "released";
    if (state.qFilter === "released") return e.status === "released";
    return true;
  });
  if (state.qSearch) {
    const q = state.qSearch.toLowerCase();
    filtered = filtered.filter(
      (e) => (e.fromAddr || "").toLowerCase().indexOf(q) !== -1 || (e.subject || "").toLowerCase().indexOf(q) !== -1
    );
  }
  const threads = groupAsThreads(filtered);
  const actor = canAct();

  return (
    <section className="page active">
      <div className="tabs">
        {TABS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={"tab" + (state.qFilter === id ? " active" : "")}
            onClick={() => {
              state.qFilter = id;
              bump();
            }}
          >
            {label} <span className="tab-count">{fmtNum(counts[id])}</span>
          </button>
        ))}
      </div>
      <div className="toolbar">
        <input
          className="search-input"
          type="search"
          placeholder="Search by sender, domain, or subject…"
          defaultValue={state.qSearch}
          onChange={(e) => {
            state.qSearch = e.target.value;
            bump();
          }}
        />
      </div>
      <div className="card card-primary" style={{ padding: 0 }}>
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "130px" }}>Received</th>
                <th style={{ width: "64px" }}>Verdict</th>
                <th>From</th>
                <th>Subject</th>
                <th style={{ width: "56px" }}>Score</th>
                <th style={{ width: "100px" }}>Expires</th>
                <th style={{ width: "220px" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {threads.map((g) => {
                const e = g.latest;
                const display = g.worst;
                const tAss = threadAssessmentOf(g.messages);
                const rowVerdict =
                  display.hardOverride || !(tAss && tAss.threadVerdict)
                    ? displayVerdict(display)
                    : tAss.threadVerdict;
                const vinfo = VERDICTS[rowVerdict] || VERDICTS[displayVerdict(display)] || VERDICTS.PENDING;
                const released = display.status === "released";
                const isSpool = display.sourceKind === "spool";
                const canRelease =
                  actor &&
                  isSpool &&
                  !released &&
                  verdictIsFinal(display) &&
                  (display.verdict === "SUSPICIOUS" || display.verdict === "MALICIOUS");
                const canDl = actor && (isSpool || display.sourceKind === "gmail");
                return (
                  <tr
                    key={g.key}
                    className={"row-stripe " + vinfo.cls}
                    style={{ cursor: "pointer" }}
                    onClick={() => openDetailPage(display.id)}
                  >
                    <td className="cell-time">{fmtDateTime(e.ts)}</td>
                    <td>
                      {released ? (
                        <span className="chip a-released">
                          <HtmlBlock tag="span" html={ICON.release} />
                          Released
                        </span>
                      ) : (
                        <ThreadChip group={g} display={display} />
                      )}
                    </td>
                    <td className="cell-from">
                      <FromCell email={e} />
                    </td>
                    <td className="cell-subject">
                      <div className="cell-content-min">
                        <div className="cell-subject-text">{g.subject}</div>
                        {g.messages.length > 1 ? (
                          <span className="thread-count" title={fmtNum(g.messages.length) + " messages in this thread"}>
                            {fmtNum(g.messages.length)}
                          </span>
                        ) : null}
                        {verdictIsFinal(display) ? <CategoryChips reasons={display.reasons} /> : null}
                      </div>
                    </td>
                    <td className="cell-score">
                      <ScoreCell email={display} />
                    </td>
                    <td className="cell-time">{released ? "—" : fmtExpires(display.expiresAt)}</td>
                    <td style={{ whiteSpace: "nowrap" }} onClick={(ev) => ev.stopPropagation()}>
                      <button type="button" className="btn btn-sm" onClick={() => openDetailPage(display.id)}>
                        <HtmlBlock tag="span" html={ICON.eye} /> View
                      </button>{" "}
                      {canDl ? (
                        <button type="button" className="btn btn-sm" onClick={() => downloadEml(display.id)}>
                          <HtmlBlock tag="span" html={ICON.download} /> Download
                        </button>
                      ) : null}{" "}
                      {canRelease ? (
                        <button type="button" className="btn btn-sm btn-primary" onClick={() => confirmRelease(display.id)}>
                          <HtmlBlock tag="span" html={ICON.release} /> Release
                        </button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!threads.length ? (
          <EmptyState>
            Nothing is held. This deployment scores mail only — inbox messages are never quarantined.
          </EmptyState>
        ) : null}
      </div>
    </section>
  );
}
