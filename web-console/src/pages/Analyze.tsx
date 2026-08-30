import { useState } from "react";
import { canAct, runAnalyze, setAnalyzeFile } from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";

export default function Analyze() {
  useConsole();
  const allowed = canAct();
  const [fileName, setFileName] = useState("");
  const [drag, setDrag] = useState(false);

  function takeFile(file: File | null | undefined) {
    if (!file) {
      setAnalyzeFile(null);
      setFileName("");
      return;
    }
    if (!/\.eml$/i.test(file.name)) return;
    setAnalyzeFile(file);
    setFileName(file.name);
  }

  return (
    <section className="page active">
      <div className="card card-primary" id="analyzePanel">
        <div className="card-head">
          <div>
            <h2>Deep EML analysis</h2>
            <div className="card-sub">Upload a raw .eml — deep investigation (advisory) plus gateway SEGS preview</div>
          </div>
        </div>
        {!allowed ? (
          <div className="analyze-denied">
            Deep analysis requires Admin or Analyst role. Viewers can use Overview and Quarantine.
          </div>
        ) : (
          <div>
            <div
              className={"dropzone" + (drag ? " dragover" : "")}
              tabIndex={0}
              role="button"
              aria-label="Upload EML file"
              onClick={() => document.getElementById("analyzeFileInput")?.click()}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  document.getElementById("analyzeFileInput")?.click();
                }
              }}
              onDragEnter={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragOver={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragLeave={(e) => {
                e.preventDefault();
                setDrag(false);
              }}
              onDrop={(e) => {
                e.preventDefault();
                setDrag(false);
                const f = e.dataTransfer.files && e.dataTransfer.files[0];
                takeFile(f || undefined);
              }}
            >
              <div className="dz-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                  <path d="M17 8l-5-5-5 5" />
                  <path d="M12 3v12" />
                </svg>
              </div>
              <div className="dz-title">Drop an .eml here, or click to browse</div>
              <div className="dz-sub">Max 15 MB · LLM call typically 15–80 seconds</div>
              <div className="dz-file">{fileName}</div>
              <input
                type="file"
                id="analyzeFileInput"
                accept=".eml,.EML,message/rfc822"
                className="visually-hidden"
                onChange={(e) => takeFile(e.target.files && e.target.files[0] ? e.target.files[0] : null)}
              />
            </div>
            <div className="analyze-actions">
              <button type="button" className="btn btn-primary" id="analyzeBtn" disabled={!fileName} onClick={() => runAnalyze()}>
                Analyze
              </button>
              <span className="analyze-status" id="analyzeStatus">
                <span className="analyze-spinner" aria-hidden="true" />
                <span id="analyzeStatusText">Working…</span>
              </span>
            </div>
            <div className="analyze-error" id="analyzeError" />
          </div>
        )}
      </div>

      <div className="analyze-results" id="analyzeResults">
        <div className="card">
          <div className="card-head">
            <div>
              <h2 id="analyzeResultTitle">Report</h2>
              <div className="card-sub" id="analyzeResultSub" />
            </div>
            <div className="analyze-meta" id="analyzeElapsed" />
          </div>
          <div className="analyze-decision" id="analyzeDecisionPanel" aria-label="Gateway vs LLM decision" />
          <div className="analyze-guide" id="analyzeGuide" />
          <div className="analyze-chips" id="analyzeChips" hidden />
          <div className="scoreboard" id="analyzeScoreboard" aria-label="Analysis scoreboard" />
          <div className="disagree-banner" id="analyzeDisagree" />
          <p className="analyze-meta" id="analyzeWarning" style={{ marginTop: "10px", color: "var(--status-serious)", display: "none" }} />
        </div>
        <div className="card" id="analyzeBehavioral" style={{ display: "none" }}>
          <div className="card-head">
            <div>
              <h2>Behavioral Correlation</h2>
              <div className="card-sub">6-month pattern analysis · Reference only — not scored</div>
            </div>
          </div>
          <div id="behavioralRules" />
        </div>
        <div className="card" id="analyzeCampaigns" style={{ display: "none" }}>
          <div className="card-head">
            <div>
              <h2>Campaign patterns</h2>
              <div className="card-sub">AI campaign insight from clustered member assessments · Reference only — not scored</div>
            </div>
          </div>
          <div id="campaignRules" />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Summary</h2>
              <div className="card-sub" id="analyzeSummarySub">
                From the LLM content analysis
              </div>
            </div>
          </div>
          <p id="analyzeSummary" style={{ fontSize: "13px", color: "var(--ink-secondary)", margin: 0 }} />
          <div id="analyzeBodyStructure" />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>SEGS reasons</h2>
              <div className="card-sub">Rule hits that drove the gateway score — check these when LLM and SEGS disagree</div>
            </div>
          </div>
          <ul className="finding-list" id="analyzePipeReasons" />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Investigation findings</h2>
              <div className="card-sub">Narrative findings from the deep agent (advisory)</div>
            </div>
          </div>
          <ol className="finding-list" id="analyzeFindings" style={{ paddingLeft: "18px" }} />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Recommended actions</h2>
              <div className="card-sub">What analysts / recipients should do</div>
            </div>
          </div>
          <ol className="finding-list" id="analyzeActions" style={{ paddingLeft: "18px" }} />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Indicators</h2>
              <div className="card-sub">Threat signals called out by the LLM agent</div>
            </div>
          </div>
          <ul className="finding-list" id="analyzeIndicators" />
        </div>
        <div className="card" id="analyzeEmailContentCard" style={{ display: "none" }}>
          <div className="card-head">
            <div>
              <h2>Email content</h2>
              <div className="card-sub">Rendered as in a mail client (scripts blocked)</div>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              id="analyzeToggleEml"
              onClick={(ev) => {
                const el = document.getElementById("analyzeEmailContent");
                const hide = el && el.style.display !== "none";
                if (el) el.style.display = hide ? "none" : "";
                ev.currentTarget.textContent = hide ? "Expand" : "Collapse";
              }}
            >
              Collapse
            </button>
          </div>
          <div id="analyzeEmailContent" />
        </div>
        <div className="card analyze-flow-card">
          <div className="card-head">
            <div>
              <h2>How this mail was assessed</h2>
              <div className="card-sub">Static detectors first, then a content-level read of this email, then the conversation</div>
            </div>
          </div>
          <div id="analyzeFlow" />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Full Markdown report</h2>
              <div className="card-sub">Escaped text — advisory only</div>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              id="analyzeToggleMd"
              onClick={(ev) => {
                const pre = document.getElementById("analyzeMarkdown");
                const hide = pre && pre.style.display !== "none";
                if (pre) pre.style.display = hide ? "none" : "block";
                ev.currentTarget.textContent = hide ? "Expand" : "Collapse";
              }}
            >
              Collapse
            </button>
          </div>
          <pre className="report-pre" id="analyzeMarkdown" />
        </div>
      </div>
    </section>
  );
}
