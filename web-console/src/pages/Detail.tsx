import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  buildPreviewBodyHtml,
  buildPreviewFootHtml,
  buildThreadSidebarHtml,
  buildThreadStripHtml,
  confirmKeepBlocked,
  confirmRelease,
  copyReport,
  displayVerdict,
  downloadEml,
  escapeHtml,
  findEmail,
  fmtDateTime,
  loadEmailContent,
  loadFeedItem,
  markEmailBenign,
  mountAssessmentFlow,
  openDetailPage,
  reevaluateEntry,
  renderDetailOriginMap,
  state,
  unmarkEmailBenign,
} from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import { emailViewBody, reportEmailView, startDwellClock } from "../lib/email-dwell";

export default function Detail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { tick } = useConsole();
  const decoded = decodeURIComponent(id || "");
  const email = findEmail(decoded);
  const [lookup, setLookup] = useState<"pending" | "missing">("pending");
  const analysisRef = useRef<HTMLElement | null>(null);
  const threadRef = useRef<HTMLElement | null>(null);
  const flowRef = useRef<HTMLElement | null>(null);
  const mailRef = useRef<HTMLDivElement | null>(null);
  const footRef = useRef<HTMLDivElement | null>(null);
  const loadedId = useRef("");
  const sig = email
    ? [email.id, displayVerdict(email), email.score, email.aiSummary, email.threadSummary, email.threadVerdict, email.analystLabel, email.status].join("|")
    : "";

  useEffect(() => {
    if (state.activePage !== "detail") state.detailReturnPage = state.activePage || "overview";
    state.activePage = "detail";
    state.detailId = decoded;
  }, [decoded]);

  useEffect(() => {
    let cancelled = false;
    setLookup("pending");
    loadFeedItem(decoded).then((ok) => {
      if (cancelled) return;
      if (findEmail(decoded) || ok) return;
      setLookup("missing");
    });
    return () => {
      cancelled = true;
    };
  }, [decoded]);

  useEffect(() => {
    const e = findEmail(decoded);
    const opened = emailViewBody(e, "open");
    if (!opened) return;
    reportEmailView(opened);
    const clock = startDwellClock();
    let flushed = false;
    function flush() {
      if (flushed) return;
      clock.pause();
      const ms = clock.visibleMs();
      flushed = true;
      if (ms < 1000) return;
      reportEmailView(emailViewBody(e, "leave", ms));
    }
    function onVis() {
      if (document.visibilityState === "hidden") clock.pause();
      else clock.resume();
    }
    document.addEventListener("visibilitychange", onVis);
    window.addEventListener("pagehide", flush);
    return () => {
      document.removeEventListener("visibilitychange", onVis);
      window.removeEventListener("pagehide", flush);
      flush();
    };
  }, [decoded, email ? email.queueId || email.id : ""]);

  useEffect(() => {
    const e = findEmail(decoded);
    if (!e) return;
    if (threadRef.current) threadRef.current.innerHTML = buildThreadSidebarHtml(e);
    if (analysisRef.current) analysisRef.current.innerHTML = buildPreviewBodyHtml(e);
    if (flowRef.current) mountAssessmentFlow(flowRef.current, e, true);
    renderDetailOriginMap(e);
    if (footRef.current) {
      footRef.current.innerHTML = buildPreviewFootHtml(e);
      const actions: Record<string, () => void> = {
        copy: () => copyReport(e.id),
        download: () => downloadEml(e.id),
        reevaluate: () => reevaluateEntry(e.id),
        release: () => confirmRelease(e.id),
        keepblocked: () => confirmKeepBlocked(e.id),
        benign: () => markEmailBenign(e.id),
        unbenign: () => unmarkEmailBenign(e.id),
      };
      Array.prototype.forEach.call(footRef.current.querySelectorAll("[data-fw-action]"), (btn: Element) => {
        (btn as HTMLElement).onclick = () => {
          const fn = actions[btn.getAttribute("data-fw-action") || ""];
          if (fn) fn();
        };
      });
    }
  }, [sig, decoded]);

  useEffect(() => {
    const e = findEmail(decoded);
    const root = mailRef.current;
    if (!e || !root) return;
    if (loadedId.current === e.id && root.childNodes.length) return;
    loadedId.current = e.id;
    root.innerHTML = buildThreadStripHtml(e);
    Array.prototype.forEach.call(root.querySelectorAll("[data-thread-id]"), (btn: Element) => {
      (btn as HTMLElement).onclick = (ev: MouseEvent) => {
        ev.preventDefault();
        const tid = btn.getAttribute("data-thread-id");
        if (tid && tid !== decoded) openDetailPage(tid);
      };
    });
    if (e.queueId) {
      const slot = document.createElement("div");
      slot.className = "email-viewer-slot";
      root.appendChild(slot);
      loadEmailContent(slot, e);
      return;
    }
    const rows: string[] = [];
    function hrow(label: string, value?: string, extraCls?: string) {
      if (!value) return;
      rows.push(
        '<div class="email-viewer-hrow' +
          (extraCls || "") +
          '"><span class="email-viewer-label">' +
          label +
          '</span><span class="email-viewer-value">' +
          escapeHtml(value) +
          "</span></div>"
      );
    }
    hrow("From", e.fromName ? e.fromName + " <" + e.fromAddr + ">" : e.fromAddr);
    hrow("To", e.toAddr || e.mailbox || "");
    hrow("Subject", e.subject, " email-viewer-subject");
    hrow("Date", fmtDateTime(e.ts));
    const viewer = document.createElement("div");
    viewer.className = "email-viewer";
    viewer.innerHTML =
      '<div class="email-viewer-headers">' +
      rows.join("") +
      '</div><div class="email-viewer-body email-viewer-empty">Raw message is not retained for this sample. Use Analyze to open the EML.</div>';
    root.appendChild(viewer);
  }, [decoded, email ? email.id : ""]);

  if (!email) {
    return (
      <section className="page active">
        <div className="detail-toolbar">
          <button type="button" className="btn btn-sm" onClick={() => navigate("/" + (state.detailReturnPage || "overview"))}>
            ← Back
          </button>
        </div>
        <div className="empty-state">
          {lookup === "missing" && tick > 0
            ? "Message not found."
            : "Loading this message…"}
        </div>
      </section>
    );
  }

  return (
    <section className="page active">
      <div className="detail-toolbar">
        <button type="button" className="btn btn-sm" onClick={() => navigate("/" + (state.detailReturnPage || "overview"))}>
          ← Back
        </button>
      </div>
      <div className="detail-stack">
        <div className="detail-split">
          <div className="card card-primary detail-card detail-mail">
            <div className="detail-body" ref={mailRef} />
            <div className="detail-foot" ref={footRef} />
          </div>
          <div className="detail-side">
            <aside className="card card-primary detail-thread" ref={threadRef} aria-label="Thread assessment" />
            <aside className="card card-primary detail-analysis" ref={analysisRef} aria-label="AI analysis" />
          </div>
        </div>
        <div className="card origin-map-card" id="detailOriginCard">
          <div className="card-head">
            <div>
              <h2>Origin of mail</h2>
              <div className="card-sub">Sending MTA location, ISP, and VPN/ESP classification for this thread</div>
            </div>
            <div className="card-sub" id="detailOriginMapLabel" />
          </div>
          <div className="origin-map-layout">
            <div className="origin-globe-wrap">
              <div
                id="detailOriginMap"
                className="origin-jvm"
                role="img"
                aria-label="World map of this email's originating location"
              />
            </div>
            <div className="origin-map-side">
              <dl className="origin-intel" id="detailOriginIntel" />
              <div className="origin-map-list" id="detailOriginMapList" />
            </div>
          </div>
        </div>
        <section className="card card-primary detail-flow" ref={flowRef} aria-label="How this mail was assessed" />
      </div>
    </section>
  );
}
