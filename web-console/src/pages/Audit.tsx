import { ICON, TYPE_LABEL, fmtDateTime, state } from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import { EmptyState, HtmlBlock } from "../components/ui";

export default function Audit() {
  const { audit, bump } = useConsole();
  let items = audit.slice();
  if (state.auditWazuhOnly) items = items.filter((e) => e.wazuh);
  if (state.auditSearch) {
    const q = state.auditSearch.toLowerCase();
    items = items.filter((e) =>
      (e.title + " " + e.detail + " " + (e.actor || "") + " " + (e.action || "")).toLowerCase().includes(q)
    );
  }
  items = items.slice(0, 200);

  return (
    <section className="page active">
      <div className="toolbar">
        <input
          className="search-input"
          type="search"
          placeholder="Search audit log…"
          defaultValue={state.auditSearch}
          onChange={(e) => {
            state.auditSearch = e.target.value;
            bump();
          }}
        />
        <button
          type="button"
          className={"btn btn-sm" + (state.auditWazuhOnly ? " btn-primary" : "")}
          onClick={() => {
            state.auditWazuhOnly = !state.auditWazuhOnly;
            bump();
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M13 2L3 14h7l-1 8 11-14h-7l1-6z" />
          </svg>
          Wazuh alerts only
        </button>
      </div>
      <div className="card card-primary" style={{ padding: "6px 20px" }}>
        <div className="log-list">
          {!items.length ? (
            <EmptyState>
              No matching audit events yet — sign-ins, user admin, quarantine actions, and gateway shadow decisions appear
              here.
            </EmptyState>
          ) : (
            items.map((e, i) => {
              let iconKey = e.type === "accent" ? "wazuh" : e.type || "warning";
              if (!ICON[iconKey]) iconKey = "warning";
              const tag = e.wazuh ? "Wazuh" : e.tag || TYPE_LABEL[e.type || ""] || "Event";
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
                  <div className={"log-tag" + (e.wazuh ? " wazuh" : "") + (e.kind === "activity" ? " activity" : "")}>
                    {tag}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </section>
  );
}
