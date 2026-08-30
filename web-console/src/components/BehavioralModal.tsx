import { useConsole } from "../context/ConsoleContext";

const VERDICT_CLASS: Record<string, string> = {
  MALICIOUS: "v-malicious",
  SUSPICIOUS: "v-suspicious",
  LOW: "v-low",
  CLEAN: "v-clean",
};

export default function BehavioralModal() {
  const { behavioral, setBehavioral } = useConsole();
  if (!behavioral) return null;
  const emails = behavioral.emails || [];
  return (
    <div
      className="modal-overlay show"
      onClick={(ev) => {
        if (ev.target === ev.currentTarget) setBehavioral(null);
      }}
    >
      <div className="modal" style={{ width: "min(580px,100%)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px" }}>
          <div>
            <h3>{behavioral.title}</h3>
            <p style={{ marginTop: "4px", fontSize: "12.5px" }}>{behavioral.sub}</p>
          </div>
          <button className="btn btn-sm" type="button" style={{ flexShrink: 0 }} onClick={() => setBehavioral(null)}>
            ✕
          </button>
        </div>
        <div style={{ marginTop: "14px", maxHeight: "380px", overflowY: "auto" }}>
          {!emails.length ? (
            <p style={{ color: "var(--ink-muted)", fontSize: "12px" }}>No prior flagged email records available.</p>
          ) : (
            emails.map((e, i) => {
              const dateStr = e.seen_at ? new Date(e.seen_at * 1000).toLocaleString() : "unknown date";
              const verdict = e.verdict || "UNKNOWN";
              const vClass = VERDICT_CLASS[verdict] || "";
              return (
                <div key={i} className="beh-email-row">
                  <span className={"chip " + vClass} style={{ flexShrink: 0, fontSize: "10px", marginTop: "2px" }}>
                    {verdict}
                  </span>
                  <div className="beh-email-detail">
                    <span className="beh-email-from">{e.sender || "(unknown sender)"}</span>
                    <span className="beh-email-id">{(e.message_id || "—").slice(0, 72)}</span>
                    <span className="beh-email-date">{dateStr}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
