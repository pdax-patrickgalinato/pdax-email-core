// @ts-nocheck
import jsVectorMap from "jsvectormap";
import "jsvectormap/dist/maps/world.js";
import { fleetReachable, pickWorkerSlot } from "./workers-status";
import { mailMatchesIntent, parseSearchIntent, searchIntentActive } from "./searchIntent";

if (typeof window !== "undefined") {
  window.jsVectorMap = jsVectorMap;
}

/** React owns routing, tables, forms, and live refresh. This module keeps
 *  scoring helpers plus Chart.js / map / assessment-breakdown painters. */
export const ui: any = {
  onData: null,
  onToast: null,
  onConfirm: null,
  onNavigate: null,
  onOpenPassword: null,
  onOpenBehavioral: null
};


  /* ============================== ICONS ============================== */
  var ICON: any = {
    good: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="9"/></svg>',
    serious: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L14.7 3.86a2 2 0 00-3.4 0z"/></svg>',
    critical: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
    wazuh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 11-14h-7l1-6z"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v13m0 0l-4-4m4 4l4-4"/><path d="M4 19h16"/></svg>',
    release: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4L19 7"/></svg>',
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>',
    close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>',
    minimize: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14"/></svg>',
    maximize: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="1.5"/></svg>',
    restore: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="12" height="12" rx="1.5"/><path d="M5 15V6a1 1 0 011-1h9"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></svg>',
    inbox: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/></svg>',
    scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7V5a1 1 0 011-1h2M4 17v2a1 1 0 001 1h2M20 7V5a1 1 0 00-1-1h-2M20 17v2a1 1 0 01-1 1h-2"/><circle cx="12" cy="12" r="3"/></svg>'
  };

  /* ============================== VERDICT MODEL ============================== */
  // Mirrors app/models.py Verdict + the status palette from the dataviz skill.
  var VERDICTS: any = {
    CLEAN:      { key: "clean",      label: "Clean",      cls: "v-clean",      icon: "good",     action: "Delivered" },
    LOW:        { key: "low",        label: "Low",         cls: "v-low",        icon: "warning",  action: "Delivered" },
    SUSPICIOUS: { key: "suspicious", label: "Suspicious",  cls: "v-suspicious", icon: "serious",  action: "Quarantined" },
    MALICIOUS:  { key: "malicious",  label: "Malicious",   cls: "v-malicious",  icon: "critical", action: "Blocked" },
    PENDING:      { key: "pending",      label: "Assessing",     cls: "v-pending",      icon: "warning",  action: "Assessing" },
    INCONCLUSIVE: { key: "inconclusive", label: "Inconclusive",  cls: "v-inconclusive", icon: "warning",  action: "Retrying" }
  };
  var STAGE_ORDER = ["headers", "origin_ip", "sender", "urls", "deception", "attachments", "content_ai", "intel", "fanout"];
  var STAGE_WEIGHTS = { headers: 20, sender: 15, urls: 20, deception: 20, attachments: 15, content_ai: 15, intel: 20 };
  var FLOW_SIGNALS = [
    { id: "headers", label: "Headers", hint: "SPF / DKIM / DMARC" },
    { id: "origin_ip", label: "Origin IP", hint: "Geo / ISP / VPN" },
    { id: "sender", label: "Sender", hint: "Identity / lookalike" },
    { id: "urls", label: "URLs", hint: "Links & beacons" },
    { id: "deception", label: "Deception", hint: "Trusted-channel abuse" },
    { id: "attachments", label: "Files", hint: "Malware / blocking" },
    { id: "intel", label: "Intel", hint: "External indicators" },
    { id: "fanout", label: "Fan-out", hint: "Same mail, other inboxes" }
  ];
  var STAGE_BLURB = {
    headers: "Authentication and envelope identity. SPF, DKIM, and DMARC say whether the sending server is allowed to use this domain. Return-Path, Reply-To, Date, and display-name checks catch bounce hijacks and visible-name tricks. This stage does not read the body.",
    origin_ip: "The public sending MTA taken from the Received chain: city and country, ISP and ASN, VPN or hosting, and whether the hop looks like consumer broadband or a cloud proxy.",
    sender: "Who the From address claims to be. Lookalikes of protected domains, VIP and brand impersonation, consumer-freemail personas, and newly registered sender domains.",
    urls: "Every link and tracking pixel in the email. Lookalike hosts, clickable text that names one domain while href goes elsewhere, redirect chains, shorteners, OAuth state leaks, IP literals, and risky TLDs.",
    deception: "Trusted-channel abuse: the platform really sent the mail (Apple, Google, Microsoft, and similar), but the lure is a foreign brand, a scarcity reward, or a freemail Reply-To.",
    attachments: "File types this organization blocks, Office macros, HTML credential-harvest forms, and packed or high-entropy payloads.",
    intel: "Known-bad indicators, this sender’s usual infrastructure versus this email, first-time requests to this recipient, and campaign clusters that share a URL, hash, or template.",
    fanout: "Whether the same send also landed in other scanned inboxes, and extra envelope To/Cc recipients on this email."
  };
  var HEADER_CHECKS = [
    { key: "spf", label: "SPF", hint: "Sender authorization", match: ["spf_fail", "spf_softfail"] },
    { key: "dkim", label: "DKIM", hint: "Signature", match: ["dkim_fail"] },
    { key: "dmarc", label: "DMARC", hint: "From alignment", match: ["dmarc_fail"] },
    { key: "return_path", label: "Return-Path", hint: "Bounce domain", match: ["return_path_mismatch"] },
    { key: "reply_to", label: "Reply-To", hint: "Reply hijack", match: ["reply_to_divergent", "reply_to_freemail"] },
    { key: "message_id", label: "Message-ID", hint: "Required header", match: ["missing_message_id"] },
    { key: "date", label: "Date", hint: "Clock / delay", match: ["date_anomaly_future", "date_anomaly_stale", "received_hop_delay"] },
    { key: "x_mailer", label: "X-Mailer", hint: "Client / bulk tool", match: ["suspicious_x_mailer"] },
    { key: "display_name", label: "Display name", hint: "Visible identity", match: ["display_name_domain_impersonation", "display_name_email_mismatch", "display_name_is_email"] }
  ];
  var SENDER_CHECKS = [
    { key: "lookalike", label: "Lookalike", hint: "Protected-domain twin", match: ["lookalike_of", "sender_lookalike_domain"] },
    { key: "vip", label: "VIP name", hint: "Executive impersonation", match: ["vip_name_spoof", "bec_vip_impersonation"] },
    { key: "brand", label: "Brand", hint: "Display-name brand", match: ["brand_impersonation_display_name"] },
    { key: "freemail", label: "Freemail", hint: "Consumer vs corporate", match: ["freemail_corporate_persona"] },
    { key: "age", label: "Domain age", hint: "Newly registered", match: ["domain_age_low"] }
  ];
  var DECEPTION_CHECKS = [
    { key: "testflight", label: "TestFlight", hint: "Trusted-channel abuse", match: ["service_abuse_testflight_brand_lure"] },
    { key: "structure", label: "Structure", hint: "Composed deception", match: ["deception_structure_service_abuse"] },
    { key: "channel", label: "Channel", hint: "Platform vs brand", match: ["trusted_channel_brand_mismatch", "trusted_channel_reply_to_freemail"] },
    { key: "scarcity", label: "Scarcity", hint: "Reward / urgency lure", match: ["lure_scarcity_reward"] }
  ];
  var FILE_CHECKS = [
    { key: "banned", label: "Banned type", hint: "Blocked attachment", match: ["banned_attachment", "banned_attachment_type"] },
    { key: "macro", label: "Macros", hint: "Office / VBA", match: ["macro_capable_doc", "oletools_vba_macro_detected", "oletools_autoexec_or_shell"] },
    { key: "html", label: "HTML form", hint: "Credential page", match: ["html_attachment_credential_form"] },
    { key: "entropy", label: "Entropy", hint: "Packed / obfuscated", match: ["forensics_high_entropy_content"] }
  ];
  var URL_CHECKS = [
    { key: "lookalike", label: "Lookalike URL", hint: "Twin of protected domain", match: ["url_lookalike", "url_lookalike_domain"] },
    { key: "mismatch", label: "Anchor vs href", hint: "Visible text lies", match: ["anchor_href_mismatch"] },
    { key: "redirect", label: "Embedded redirect", hint: "Hidden destination", match: ["url_embedded_redirect", "url_redirect_unrelated_domain", "url_redirect_to_page_file", "url_redirect_to_ip"] },
    { key: "shortener", label: "Shortener", hint: "Hidden landing", match: ["url_link_shortener"] },
    { key: "beacon", label: "Beacon", hint: "Tracking pixel", match: ["tracking_beacon_detected", "url_tracking_beacon"] },
    { key: "oauth", label: "OAuth state", hint: "Email in state param", match: ["url_oauth_state_email_exposure"] },
    { key: "ip", label: "IP URL", hint: "Literal host", match: ["url_ip_literal"] },
    { key: "tld", label: "Risky TLD", hint: "Abuse-prone suffix", match: ["url_risky_tld"] }
  ];
  var INTEL_CHECKS = [
    { key: "domain", label: "Domain intel", hint: "Known-bad domain", match: ["intel_domain", "threat_intel_hit", "vt_domain_suspicious"] },
    { key: "url", label: "URL intel", hint: "Known-bad URL", match: ["intel_url", "vt_url_submitted"] },
    { key: "hash", label: "Hash intel", hint: "Known-bad file", match: ["intel_hash"] },
    { key: "ip", label: "IP intel", hint: "Known-bad address", match: ["intel_ip"] },
    { key: "behavior", label: "Behavioral", hint: "Campaign correlation", match: ["behavioral_sender_ip_drift", "behavioral_ip_many_senders", "behavioral_ip_shortener", "behavioral_shared_shortener"] },
    { key: "campaign", label: "Campaign cluster", hint: "Shared URL / hash / template", match: ["campaign_hash", "campaign_url_path", "campaign_url_host", "campaign_content", "campaign_subject", "campaign_fanout", "campaign_mixed"] },
    { key: "profile", label: "Sender profile", hint: "Usual vs this email", match: ["profile_vpn_new", "profile_hosting_new", "profile_country_new", "profile_asn_new", "profile_auth_regression", "profile_mailbox_new", "profile_hour_unusual", "profile_peer_new"] },
    { key: "request", label: "First request", hint: "New ask for this recipient", match: ["first_request_class_from_sender", "first_request_class_for_recipient", "first_trusted_sender_to_mailbox"] }
  ];
  var ORIGIN_INFO_FLAG = /^(origin_ip:|origin_hostname:|origin_x_ip:|origin_ip_geo:|origin_ip_isp:|origin_ip_hosting|origin_ip_search)/;
  var THRESHOLDS = { malicious: 70, suspicious: 45, low: 20 };   // used by verdictMargin() — real scoring now happens server-side
  var LLM_PROVIDERS = { glm: 1, gemini: 1, bedrock: 1, ollama: 1 };
  var LLM_MODEL_NAMES = {
    "deepseek-ai/deepseek-r1-0528-maas": "DeepSeek R1",
    "deepseek-ai/deepseek-v3.1-maas": "DeepSeek V3.1",
    "deepseek-ai/deepseek-v3.2-maas": "DeepSeek V3.2",
    "zai-org/glm-5.2-maas": "GLM 5.2",
    "zai-org/glm-5-maas": "GLM 5",
    "zai-org/glm-4.7-maas": "GLM 4.7",
    "moonshotai/kimi-k3-maas": "Kimi K3",
    "moonshotai/kimi-k2-thinking-maas": "Kimi K2 Thinking",
    "google/gemini-2.5-flash": "Gemini 2.5 Flash",
    "google/gemini-2.5-pro": "Gemini 2.5 Pro",
    "google/gemini-3.5-flash": "Gemini 3.5 Flash"
  };

  function contentAiFacts(e) {
    var s = (e && e.stages && e.stages.content_ai) || {};
    return {
      provider: (e && e.aiProvider) || s.provider || "",
      model: (e && e.aiModel) || s.modelId || "",
      summary: (e && e.aiSummary) || s.summary || ""
    };
  }

  function isLlmAssessment(e) {
    var f = contentAiFacts(e);
    return !!LLM_PROVIDERS[String(f.provider).toLowerCase()] && !!String(f.summary).trim();
  }

  var LLM_WAIT_MS = 120000;

  function isAiTimedOut(e) {
    if (!e) return false;
    if (isLlmAssessment(e)) return false;
    if (e.sourceKind !== "gmail" && e.sourceKind !== "spool") return false;
    if (e.aiTimedOut) return true;
    var start = Number(e.aiQueuedAt) || 0;
    if (!start || !state.llmConfigured) return false;
    var limit = Number(state.llmAssessTimeoutMs) || LLM_WAIT_MS;
    return Date.now() - start >= limit;
  }

  function isAiPending(e) {
    if (!e) return false;
    if (isLlmAssessment(e) || isAiTimedOut(e)) return false;
    if (typeof e.aiPending === "boolean") return !!e.aiPending && !e.aiTimedOut;
    if (!state.llmConfigured) return false;
    if (e.sourceKind === "sample") return false;
    return !isLlmAssessment(e) && (e.sourceKind === "gmail" || e.sourceKind === "spool");
  }

  function needsAiRetry(e) {
    return !!(e && e.queueId && state.llmConfigured && isAiTimedOut(e) &&
      (e.sourceKind === "gmail" || e.sourceKind === "spool"));
  }

  function verdictIsFinal(e) {
    if (!e) return true;
    if (e.hardOverride) return true;
    if (isAiTimedOut(e)) return true;
    return !isAiPending(e);
  }

  function displayVerdict(e?: any): any {
    if (!e) return "CLEAN";
    if (e.hardOverride) return e.verdict || "CLEAN";
    if (isAiPending(e)) return "PENDING";
    if (isAiTimedOut(e)) return "INCONCLUSIVE";
    return e.verdict || "CLEAN";
  }

  function chipForEmail(e, opts) {
    var shown = displayVerdict(e);
    if (shown === "PENDING" && !(opts && opts.quiet)) {
      return '<span class="chip v-pending"><span class="analyze-spinner" aria-hidden="true"></span>' +
        escapeHtml(pendingChipLabel(e)) + "</span>";
    }
    return chip(shown);
  }

  function scoreCell(e) {
    var shown = displayVerdict(e);
    if (shown === "PENDING" || shown === "INCONCLUSIVE") return "—";
    return e.score != null ? fmtNum(e.score) : "—";
  }

  function pendingEmails(): any[] {
    return state.feed.filter(isAiPending).sort(function (a, b) { return a.ts - b.ts; });
  }

  function retryableEmails(): any[] {
    return state.feed.filter(needsAiRetry).sort(function (a, b) { return a.ts - b.ts; });
  }

  function queueEmails(): any[] {
    return state.feed.filter(function (e) { return isAiPending(e) || isAiTimedOut(e); })
      .sort(function (a, b) { return a.ts - b.ts; });
  }

  function _countsFromEmails(emails: any[]) {
    var counts = { CLEAN: 0, LOW: 0, SUSPICIOUS: 0, MALICIOUS: 0 };
    var pendingN = 0;
    var inconclusiveN = 0;
    (emails || []).forEach(function (e) {
      var shown = displayVerdict(e);
      if (shown === "PENDING") { pendingN++; return; }
      if (shown === "INCONCLUSIVE") { inconclusiveN++; return; }
      counts[e.verdict] = (counts[e.verdict] || 0) + 1;
    });
    return {
      total: (emails || []).length,
      pendingN: pendingN,
      inconclusiveN: inconclusiveN,
      counts: counts,
      hourly: null,
      assessed: (counts.CLEAN || 0) + (counts.LOW || 0) + (counts.SUSPICIOUS || 0) + (counts.MALICIOUS || 0),
      threadAssessed: 0,
      aiPendingTotal: pendingN,
      aiTimedOutTotal: inconclusiveN,
      feedLimit: 0,
      truncated: false,
      inboxesMonitored: 0,
      inboxesPolling: 0,
      inboxesConfigured: 0,
      inboxesDiscovered: 0
    };
  }

  function feedOverview() {
    var derived = _countsFromEmails(state.feed);
    derived.aiPendingTotal = pendingEmails().length;
    derived.aiTimedOutTotal = state.feed.filter(isAiTimedOut).length;
    var s = state.feedStats;
    if (!s || typeof s.total !== "number" || (s.total === 0 && derived.total > 0)) {
      return derived;
    }
    return {
      total: s.total || 0,
      pendingN: s.pending || 0,
      inconclusiveN: s.inconclusive || 0,
      counts: {
        CLEAN: s.clean || 0,
        LOW: s.low || 0,
        SUSPICIOUS: s.suspicious || 0,
        MALICIOUS: s.malicious || 0
      },
      hourly: Array.isArray(s.hourly) ? s.hourly : null,
      assessed: s.assessed || 0,
      threadAssessed: s.threadAssessed || 0,
      aiPendingTotal: s.aiPendingTotal != null ? s.aiPendingTotal : (s.pending || 0),
      aiTimedOutTotal: s.aiTimedOutTotal || 0,
      feedLimit: s.feedLimit || 0,
      truncated: !!(s.feedLimit && s.total > s.feedLimit),
      inboxesMonitored: s.inboxesMonitored || s.mailboxes || 0,
      inboxesPolling: s.inboxesPolling || 0,
      inboxesConfigured: s.inboxesConfigured || 0,
      inboxesDiscovered: s.inboxesDiscovered || 0
    };
  }

  function aiPendingBadgeHtml() {
    return '<span class="ai-pending"><span class="analyze-spinner" aria-hidden="true"></span>Assessing</span>';
  }

  function aiQueueStatusHtml(e) {
    return '<span class="ai-pending' + (isAiTimedOut(e) ? " ai-timed-out" : "") + '">' +
      escapeHtml(pipelineStatusLabel(e)) + "</span>";
  }

  var PIPELINE_STATUS_LABEL = {
    queued: "Queued",
    static: "Static checks",
    ai: "Content AI",
    timed_out: "Retrying automatically",
    error: "Assessment error",
    dead_letter: "Needs review",
    complete: "Complete"
  };

  function pipelineStatusOf(e) {
    if (!e) return "";
    if (isAiTimedOut(e)) return "timed_out";
    return String(e.pipelineStatus || "").trim();
  }

  function pipelineStatusLabel(e) {
    var key = pipelineStatusOf(e);
    if (PIPELINE_STATUS_LABEL[key]) return PIPELINE_STATUS_LABEL[key];
    if (isAiPending(e)) return "Content AI";
    return "Complete";
  }

  function pendingChipLabel(e) {
    var key = pipelineStatusOf(e);
    if (key === "queued") return "Queued";
    if (key === "static") return "Checking";
    if (key === "dead_letter") return "Needs review";
    if (key === "error") return "Error";
    if (key === "timed_out") return "Retrying";
    return "Assessing";
  }

  function formatLlmModel(modelId, provider) {
    var id = String(modelId || "").trim();
    if (id && LLM_MODEL_NAMES[id]) return LLM_MODEL_NAMES[id] + " (" + id + ")";
    if (id) return id;
    var p = String(provider || "").trim();
    if (p && p !== "heuristic" && p !== "null") return p;
    return "";
  }

  function bodyStructureFromEntry(e) {
    var s = (e && e.stages && e.stages.content_ai) || {};
    var deep = ((e && e.deepAnalysis) || {}).body_structure || {};
    return {
      isForwarded: !!(e && (e.isForwarded || s.isForwarded || deep.is_forwarded)),
      isReply: !!(e && (e.isReply || s.isReply || deep.is_reply)),
      primaryContent: (e && e.primaryContent) || s.primaryContent || deep.primary_content || "",
      quotedContent: (e && e.quotedContent) || s.quotedContent || deep.quoted_or_forwarded_content || "",
      footerContent: (e && e.footerContent) || s.footerContent || deep.footer_content || "",
      footerWorthAssessing: !!(e && (e.footerWorthAssessing || s.footerWorthAssessing || deep.footer_worth_assessing)),
      footerAssessment: (e && e.footerAssessment) || s.footerAssessment || deep.footer_assessment || ""
    };
  }

  function bodyStructureFromAnalyze(content, pipe) {
    var bs = (content && content.body_structure) || {};
    var s = (pipe && pipe.stages && pipe.stages.content_ai) || {};
    return {
      isForwarded: !!(bs.is_forwarded || (pipe && pipe.isForwarded) || s.isForwarded),
      isReply: !!(bs.is_reply || (pipe && pipe.isReply) || s.isReply),
      primaryContent: bs.primary_content || (pipe && pipe.primaryContent) || s.primaryContent || "",
      quotedContent: bs.quoted_or_forwarded_content || (pipe && pipe.quotedContent) || s.quotedContent || "",
      footerContent: bs.footer_content || (pipe && pipe.footerContent) || s.footerContent || "",
      footerWorthAssessing: !!(bs.footer_worth_assessing || (pipe && pipe.footerWorthAssessing) || s.footerWorthAssessing),
      footerAssessment: bs.footer_assessment || (pipe && pipe.footerAssessment) || s.footerAssessment || ""
    };
  }

  function bodyStructureHtml(st) {
    if (!st) return "";
    var has = st.primaryContent || st.quotedContent || st.footerContent ||
      st.isForwarded || st.isReply || st.footerAssessment || st.footerWorthAssessing;
    if (!has) return "";
    var chips = [];
    if (st.isForwarded) chips.push("Forwarded");
    else if (st.isReply) chips.push("Reply");
    else chips.push("Original message");
    chips.push(st.footerWorthAssessing ? "Footer worth assessing" : "Footer not scored");
    function part(label, text) {
      if (!text) return "";
      return '<div class="structure-part"><div class="ib-label">' + escapeHtml(label) + "</div>" +
        '<div class="structure-text">' + escapeHtml(text) + "</div></div>";
    }
    return '<div class="structure-block"><span class="ai-label">Message structure (LLM)</span>' +
      '<div class="structure-chips">' + chips.map(function (c) {
        return '<span class="structure-chip' +
          (c.indexOf("worth") >= 0 ? " warn" : "") + '">' + escapeHtml(c) + "</span>";
      }).join("") + "</div>" +
      part("Primary content", st.primaryContent) +
      part("Quoted / forwarded", st.quotedContent) +
      part("Footer", st.footerContent) +
      part("Footer assessment", st.footerAssessment) +
      "</div>";
  }

  // ---- Exact port of app/report.py's _FLAG_DESCRIPTIONS / _FLAG_PREFIX_DESCRIPTIONS ----
  var FLAG_DESC = {
    learned_benign: "An analyst previously marked mail from this sender or domain as not malicious. That is channel trust — this email is still analyzed, and a first-time payment/access request to this recipient can still score.",
    spf_fail: "Sender failed SPF authentication — the sending server isn't authorized to send for this domain.",
    spf_softfail: "Sender softfailed SPF — the sending server is only weakly authorized for this domain.",
    dkim_fail: "DKIM signature failed to verify — the message may have been altered in transit, or isn't really from the claimed domain.",
    dmarc_fail: "DMARC failed — this domain's own policy says messages like this shouldn't be trusted.",
    return_path_mismatch: "The bounce address (Return-Path) doesn't match the visible From domain — common in spoofed mail.",
    reply_to_divergent: "Replies would go to a different domain than the visible sender — a classic reply-hijack tell.",
    display_name_email_mismatch: "The display name shows one email address, but the real sending address is a different one entirely.",
    display_name_is_email: "The display name is itself formatted as an email address, matching the real sender — lower risk on its own, but unusual.",
    freemail_corporate_persona: "Sent from a free consumer email domain (Gmail, Yahoo, etc.) but the display name claims to be IT/finance/support — a common BEC shape.",
    html_attachment_credential_form: "An attached HTML file contains a login/password form — a classic offline credential-harvest page.",
    url_embedded_redirect: "A link hides another destination inside its own parameters (a redirect wrapper) — not inherently bad, but the real target matters more than the visible link.",
    url_ip_literal: "A link points straight at a raw IP address instead of a domain name — legitimate services almost never do this.",
    url_brand_keyword_offbrand: "A link's domain contains a trust word (login, secure, verify, etc.) despite not being a recognized brand domain.",
    url_deep_subdomain: "A link uses an unusually deep chain of subdomains — often used to bury the real (malicious) domain from casual view.",
    url_oauth_state_email_exposure: "A Microsoft/Google-style login link has a real email address baked into its state parameter — legitimate apps never do this; it's a sign of a templated credential-phishing or account-reconnaissance link.",
    url_redirect_unrelated_domain: "A tracking/redirect link's real destination is unrelated to both the wrapper and the sender's own domain — legitimate trackers redirect back to their own brand, not somewhere else.",
    url_redirect_to_page_file: "A redirect link's real destination is a bare .html/.php page on someone else's site — the typical shape of a dropped phishing page.",
    url_redirect_to_ip: "A redirect/tracker link's real destination is a raw IP address — no legitimate tracker's actual destination is a bare IP.",
    anchor_href_mismatch: "The clickable text of a link names one domain, but the link actually goes somewhere else.",
    service_abuse_testflight_brand_lure: "Legitimate Apple TestFlight mail inviting you to a beta app that impersonates a mega-brand — trusted-channel service abuse (auth looks clean because Apple really sent it).",
    deception_structure_service_abuse: "Composed deception structure: authentic trusted-platform channel + on-platform links + foreign brand lure.",
    trusted_channel_brand_mismatch: "Trusted transactional platform mail whose content names a foreign mega-brand the platform does not own.",
    trusted_channel_reply_to_freemail: "Trusted-platform From with Reply-To on consumer freemail — identity handoff reinforcer.",
    reply_to_freemail: "Reply-To points at a consumer freemail domain — reinforcing handoff when From is a trusted platform.",
    lure_scarcity_reward: "Scarcity and/or reward bait (limited seats, free credits) — social-engineering reinforcer.",
    content_padding_evasion: "The email body contains an unusually large block of blank/whitespace lines — a known trick to bury the real lure or dodge automated content scanning.",
    urgency_language: "The wording pressures urgent action (deadlines, threats, “immediately”) — a standard social-engineering tactic.",
    credential_request: "The wording asks you to log in, verify, or confirm your identity/credentials.",
    bec_pattern: "The wording matches a Business Email Compromise pattern (gift cards, wire transfers, “are you available”).",
    generic_greeting: "Uses a generic greeting (“Dear Customer”, etc.) instead of your actual name — common in mass-sent phishing.",
    payment_lure_subject: "The subject line uses a financial-document pretext (invoice, disbursement, statement, etc.) — one of the most common phishing lures.",
    fake_reply_prefix: "The subject looks like a reply (“Re:”) to a conversation that doesn't actually exist in this mailbox's thread history.",
    brand_impersonation: "The email's own wording claims to be a specific brand/organization in a way that doesn't fit the rest of the message.",
    unusual_request: "An AI reviewer flagged this as an unusual or out-of-context request.",
    prompt_injection_attempt: "The email body tried to instruct the AI reviewer directly (e.g. “ignore previous instructions”) — the attempt itself was treated as a red flag, not followed.",
    forwarded_thread: "The LLM judged this body as a forwarded original wrapped in a new envelope — the quoted/forwarded section may be camouflage or the lure itself.",
    forwarded_lure: "The LLM judged the forwarded/quoted original (not the wrapping note) as the hostile content.",
    malicious_footer: "The LLM judged the signature/disclaimer/unsubscribe block itself as hostile rather than ordinary boilerplate.",
    threat_intel_hit: "One of this email's domains/URLs/hashes matched a known-bad indicator in threat intelligence.",
    url_lookalike_domain: "A link's domain is a near-identical lookalike of one of the organization's protected domains.",
    banned_attachment_type: "This email has an attachment of a file type that's outright banned (executables, scripts, etc.).",
    sender_lookalike_domain: "The sender's own domain is a near-identical lookalike of one of the organization's protected domains.",
    bec_vip_impersonation: "The display name impersonates a protected VIP/executive name AND the message body matches a BEC financial-request pattern — a high-confidence combination.",
    missing_message_id: "Message-ID header is absent — legitimate mail servers always generate one; its absence is a sign of script-generated or spoofed mail.",
    missing_mime_version: "MIME-Version header is absent — most modern email clients include it; its absence is a marginal signal associated with spam and scripted senders.",
    date_anomaly_future: "The email's Date header shows a timestamp more than 2 days in the future — consistent with forged or tampered headers.",
    date_anomaly_stale: "The email's Date header is over 30 days in the past — either an unusually delayed message or a forged timestamp.",
    suspicious_x_mailer: "The X-Mailer or User-Agent header identifies a bulk/scripted mail tool (PHPMailer, libwww-perl, etc.) — commonly used to automate spam and phishing campaigns.",
    display_name_domain_impersonation: "The sender's display name contains a domain that doesn't match the actual sending domain — e.g. 'PayPal <attacker@evil.com>' — a classic phishing display-name spoof.",
    tracking_beacon_detected: "The email loads external images or resources automatically on open — consistent with a tracking pixel that confirms email delivery and may capture the reader's IP address.",
    url_ftp_scheme: "A URL in this email uses the FTP scheme — very rarely used in legitimate email; may indicate a link to a malicious file server.",
    oletools_vba_macro_detected: "A VBA macro was detected in the attachment by oletools static analysis — macros can execute arbitrary code when the document is opened.",
    oletools_autoexec_or_shell: "The attachment's VBA macro contains auto-execution triggers or shell commands (AutoExec, Shell, WScript) — high-confidence malicious macro indicator.",
    origin_ip_search: "Gemini Google Search looked up the originating IP (IP and hostname only; the message body was not sent).",
    origin_ip_vpn: "The originating IP matches a VPN, proxy, or bulletproof-hosting operator — uncommon for legitimate corporate or ESP mail.",
    origin_ip_hosting: "The originating IP sits on cloud/VPS hosting rather than a residential ISP or known email provider.",
    profile_vpn_new: "This email's originating hop looks like a VPN or proxy, but prior CLEAN/LOW mail from this sender never did.",
    profile_hosting_new: "This email originates from cloud/VPS hosting; this sender usually uses ESP or ISP infrastructure.",
    profile_country_new: "The originating country is new for this sender compared with their CLEAN/LOW history.",
    profile_asn_new: "The originating ASN is new for this sender (advisory; ESP IP rotation is expected).",
    profile_auth_regression: "SPF failed on this email although this sender usually passes SPF.",
    profile_mailbox_new: "This email was delivered to a mailbox this sender has not written to in CLEAN/LOW history.",
    profile_hour_unusual: "This email's Date hour is outside the hours this sender usually sends CLEAN/LOW mail.",
    profile_peer_new: "This sender has not written to this mailbox in scanned history — a new counterpart on the relationship graph.",
    profile_cold_start: "Not enough CLEAN/LOW history yet to know what is normal for this sender."
  };
  var FLAG_PREFIX_DESC = {
    banned_attachment: "Attachment has a banned, high-risk file type: .{value}",
    macro_capable_doc: "Attachment is a macro-capable Office document (.{value}) — can run code when opened.",
    url_lookalike: "A link's domain is a near-identical lookalike of the protected domain '{value}'.",
    url_risky_tld: "A link uses a top-level domain (.{value}) associated with high spam/abuse rates.",
    lookalike_of: "The sender's domain is a near-identical lookalike of the protected domain '{value}'.",
    vip_name_spoof: "The display name impersonates a watched VIP/executive name ('{value}') while sending from an unrelated domain.",
    brand_impersonation_display_name: "The display name claims to be from '{value}' (a known e-sign/file-share brand), but the sending domain has no relationship to that brand.",
    intel_domain: "Domain '{value}' matched a known-bad threat-intelligence indicator.",
    intel_ip: "IP '{value}' matched a known-bad threat-intelligence indicator.",
    intel_url: "URL '{value}' matched a known-bad threat-intelligence indicator.",
    intel_hash: "Attachment hash '{value}' matched a known-bad threat-intelligence indicator.",
    behavioral_sender_ip_drift: "Sender '{value}' has been observed using multiple originating IPs over the past 6 months — consistent with account compromise or infrastructure rotation.",
    behavioral_ip_many_senders: "Originating IP '{value}' has sent mail from 5 or more distinct sender addresses — consistent with a shared attack platform.",
    behavioral_ip_shortener: "Originating IP '{value}' has previously sent emails containing link-shortener URLs — consistent with a link obfuscation campaign.",
    behavioral_shared_shortener: "Link shortener '{value}' was also used by different sender addresses — strong indicator of a coordinated phishing campaign.",
    campaign_hash: "Attachment hash is shared with campaign {value}.",
    campaign_url_path: "Landing URL is shared with campaign {value}.",
    campaign_url_host: "URL host is shared with campaign {value}.",
    campaign_content: "Message template is shared with campaign {value}.",
    campaign_subject: "Subject template is shared with campaign {value}.",
    campaign_fanout: "This Message-ID is part of campaign {value}.",
    campaign_mixed: "This email shares multiple pivots with campaign {value}.",
    fanout_same_message: "This sender delivered the same message (same Message-ID) to {value} other scanned inbox(es).",
    fanout_same_content: "This sender sent near-identical content to {value} other scanned inbox(es).",
    fanout_envelope: "The envelope To/Cc lists {value} other recipient address(es) besides this mailbox.",
    origin_ip: "Oldest public Received hop — the sending MTA IP — is {value}.",
    origin_hostname: "The sending MTA presented hostname {value} on that hop.",
    origin_x_ip: "X-Originating-IP header claims client IP {value}, distinct from the sending MTA.",
    origin_ip_geo: "Geolocation for the sending MTA is {value}.",
    origin_ip_isp: "The sending MTA's ISP / network operator is {value}.",
    origin_ip_geo_mismatch: "Origin country {value} is outside the usual mail footprint for this sender (not the From ccTLD and not a typical Google/Microsoft/ESP hub).",
    url_link_shortener: "A link in this email uses the known link-shortener service '{value}' — shorteners hide the real destination.",
    ai: "AI reviewer identified a pattern not in the standard checklist: {value}",
    received_hop_delay: "An unusually long delay ({value}) between mail relay hops — may indicate routing through a compromised proxy or timestamp manipulation.",
    url_tracking_beacon: "External resource '{value}' is embedded as a tracking image/pixel that loads automatically when the email is opened.",
    vt_domain_suspicious: "Domain '{value}' has a suspicious VirusTotal reputation score or category flag.",
    vt_url_submitted: "URL '{value}' was submitted to VirusTotal for scanning — re-check later for results.",
    domain_age_low: "The sender's domain was registered only {value} day(s) ago — newly-registered domains are common phishing infrastructure."
  };
  var FLAG_DESC_EXTRA = {
    url_in_body: "A link appears in this message. Confirm the destination before you click — displayed text can disagree with the real URL."
  };
  // python -m backend.cli.build_flag_descriptions exports backend/report.py
  // dicts — prefer those so this dashboard never drifts out of sync with
  // the pipeline's own flag catalogue again. FLAG_DESC/FLAG_PREFIX_DESC
  // above stay as a fallback for the rare case the data file failed to load.
  var EXPORTED_FLAG_DESC = (window.SEG_FLAG_DESCRIPTIONS && window.SEG_FLAG_DESCRIPTIONS.exact) || {};
  var EXPORTED_FLAG_PREFIX_DESC = (window.SEG_FLAG_DESCRIPTIONS && window.SEG_FLAG_DESCRIPTIONS.prefix) || {};
  function describeFlag(flag) {
    if (flag.indexOf("policy_suppressed:") === 0) {
      var underlying = flag.slice("policy_suppressed:".length);
      var cat = categoryForFlag(underlying);
      var label = (cat && CATEGORY_LABEL[cat]) || "A disabled policy category";
      return label + " is disabled — this would have flagged: " + describeFlag(underlying);
    }
    if (EXPORTED_FLAG_DESC[flag]) return EXPORTED_FLAG_DESC[flag];
    if (FLAG_DESC[flag]) return FLAG_DESC[flag];
    if (FLAG_DESC_EXTRA[flag]) return FLAG_DESC_EXTRA[flag];
    var idx = flag.indexOf(":");
    if (idx !== -1) {
      var prefix = flag.slice(0, idx), value = flag.slice(idx + 1);
      if (EXPORTED_FLAG_PREFIX_DESC[prefix]) return EXPORTED_FLAG_PREFIX_DESC[prefix].replace("{value}", value);
      if (FLAG_PREFIX_DESC[prefix]) return FLAG_PREFIX_DESC[prefix].replace("{value}", value);
    }
    var s = flag.replace(/_/g, " ").replace(":", ": ");
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  function uniq(arr) { return arr.filter(function (v, i) { return arr.indexOf(v) === i; }).sort(); }

  var HIGHLIGHT_RULES = [
    { flag: "urgency_language", re: /\b(urgent|immediately|verify now|account (?:suspended|locked|closed)|within \d+ hours|action required|final notice|failure to)\b/gi },
    { flag: "credential_request", re: /\b(password|login|sign ?in|verify your account|confirm your identity|update your (?:payment|billing))\b/gi },
    { flag: "bec_pattern", re: /\b(gift ?card|wire transfer|change (?:bank|payment) details|urgent payment|are you available|quick task|new bank(?:ing)? (?:account|details|instructions)|update (?:vendor|supplier|payment|billing) (?:details|information|method|account)|change (?:invoice|payment) (?:details|instructions|method|information)|overseas (?:wire|transfer|payment)|approve (?:this )?(?:wire|transfer|payment)|payment method update|settle (?:the |this )?(?:payment|invoice|amount)|pay (?:this |the )?(?:invoice|amount|balance))\b/gi },
    { flag: "generic_greeting", re: /\b(dear (?:customer|user|valued member|account holder))\b/gi },
    { flag: "payment_lure_subject", re: /\b(payment[_ ]?disbursement|disbursement|remittance|payment advice|invoice|statement|payment notification|funds transfer|payment receipt|proof of payment)\b/gi, subjectOnly: true },
    { flag: "lure_scarcity_reward", re: /(?:limited\s+beta|only\s+\d[\d,]*\s+(?:participants|users|spots|testers)|up\s+to\s+\$\s*\d+|advertising\s+credits|free\s+(?:ad\s+)?credits|\$\d+\s+(?:in\s+)?(?:advertising\s+)?credits)/gi },
    { flag: "fake_reply_prefix", re: /^\s*(re|fwd?)\s*:/i, subjectOnly: true }
  ];
  var HL_SKIP_PREFIX = {
    ai: 1, policy_suppressed: 1, received_hop_delay: 1,
    behavioral_sender_ip_drift: 1, behavioral_ip_many_senders: 1,
    behavioral_ip_shortener: 1, nlu_intent: 1
  };

  function flagSeverity(flag) {
    var f = String(flag || "");
    if (/^(bec_pattern|credential_request|html_attachment|intel_|banned_attachment|oletools_|bec_vip)/.test(f)) return "critical";
    if (/^(urgency|url_lookalike|url_ip|url_redirect|anchor_href|fake_reply|vip_name|sender_lookalike|display_name)/.test(f)) return "serious";
    return "low";
  }

  function scanContextFromEmail(e) {
    var reasons = (e && e.reasons) ? e.reasons.slice() : [];
    if (e && e.stages) {
      Object.keys(e.stages).forEach(function (k) {
        var flags = e.stages[k] && e.stages[k].flags;
        if (flags && flags.length) reasons = reasons.concat(flags);
      });
    }
    return {
      reasons: uniq(reasons),
      iocs: (e && e.iocs) || {},
      subject: (e && e.subject) || ""
    };
  }

  function htmlToVisibleText(html) {
    var s = String(html || "");
    s = s.replace(/<script[\s\S]*?<\/script>/gi, " ");
    s = s.replace(/<style[\s\S]*?<\/style>/gi, " ");
    s = s.replace(/<br\s*\/?>/gi, "\n");
    s = s.replace(/<\/(p|div|tr|h[1-6]|li|blockquote|table|section)>/gi, "\n");
    s = s.replace(/<[^>]+>/g, " ");
    s = s.replace(/&nbsp;/gi, " ");
    s = s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"');
    s = s.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n");
    return s.trim();
  }

  function addHlSpan(spans, start, end, flag) {
    if (start >= end) return;
    spans.push({
      start: start,
      end: end,
      flag: flag,
      severity: flagSeverity(flag),
      why: describeFlag(flag)
    });
  }

  function findNeedleSpans(text, needle) {
    var out = [];
    if (!needle || needle.length < 3) return out;
    var lower = text.toLowerCase();
    var n = needle.toLowerCase();
    var from = 0;
    while (from < lower.length) {
      var i = lower.indexOf(n, from);
      if (i === -1) break;
      out.push({ start: i, end: i + needle.length });
      from = i + Math.max(needle.length, 1);
    }
    return out;
  }

  function collectHighlightSpans(text, scan, opts) {
    var spans = [];
    var subjectOnly = !!(opts && opts.subjectOnly);
    var i, m, re;
    for (i = 0; i < HIGHLIGHT_RULES.length; i++) {
      var rule = HIGHLIGHT_RULES[i];
      if (rule.subjectOnly && !subjectOnly) continue;
      re = new RegExp(rule.re.source, rule.re.flags.indexOf("g") >= 0 ? rule.re.flags : rule.re.flags + "g");
      while ((m = re.exec(text))) {
        addHlSpan(spans, m.index, m.index + m[0].length, rule.flag);
        if (m[0].length === 0) re.lastIndex += 1;
      }
    }
    if (!subjectOnly) {
      var pad = /(?:\n[ \t]*){12,}/g;
      while ((m = pad.exec(text))) {
        addHlSpan(spans, m.index, m.index + m[0].length, "content_padding_evasion");
      }
      var urlRe = /\bhttps?:\/\/[^\s<>"'\\)]+/gi;
      while ((m = urlRe.exec(text))) {
        var rawUrl = m[0].replace(/[.,;:]+$/, "");
        addHlSpan(spans, m.index, m.index + rawUrl.length, urlHighlightFlag(rawUrl, scan));
      }
    }
    var reasons = (scan && scan.reasons) || [];
    for (i = 0; i < reasons.length; i++) {
      var flag = reasons[i];
      var cut = flag.indexOf(":");
      if (cut === -1) continue;
      var prefix = flag.slice(0, cut);
      var value = flag.slice(cut + 1);
      if (HL_SKIP_PREFIX[prefix] || !value || value.length < 3) continue;
      var hits = findNeedleSpans(text, value);
      for (var h = 0; h < hits.length; h++) addHlSpan(spans, hits[h].start, hits[h].end, flag);
    }
    var iocs = (scan && scan.iocs) || {};
    ["urls", "domains", "ips"].forEach(function (key) {
      var items = iocs[key] || [];
      for (var u = 0; u < items.length; u++) {
        var needle = String(items[u] || "");
        if (needle.length < 4) continue;
        var found = findNeedleSpans(text, needle);
        var iocFlag = key === "urls" ? urlHighlightFlag(needle, scan)
          : (key === "ips" ? "url_ip_literal" : "url_in_body");
        for (var f = 0; f < found.length; f++) addHlSpan(spans, found[f].start, found[f].end, iocFlag);
      }
    });
    return mergeHlSpans(spans);
  }

  function urlHighlightFlag(url, scan) {
    var lower = String(url || "").toLowerCase();
    var reasons = (scan && scan.reasons) || [];
    for (var i = 0; i < reasons.length; i++) {
      var r = reasons[i];
      var c = r.indexOf(":");
      if (c === -1) {
        if (r === "url_ip_literal" && /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i.test(url)) return r;
        if (r === "anchor_href_mismatch") continue;
        continue;
      }
      var value = r.slice(c + 1).toLowerCase();
      if (value && lower.indexOf(value) !== -1) return r;
    }
    if (/https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i.test(url)) return "url_ip_literal";
    return "url_in_body";
  }

  function mergeHlSpans(spans) {
    spans.sort(function (a, b) {
      if (a.start !== b.start) return a.start - b.start;
      return (b.end - b.start) - (a.end - a.start);
    });
    var out = [];
    for (var i = 0; i < spans.length; i++) {
      var s = spans[i];
      var last = out[out.length - 1];
      if (last && s.start < last.end) continue;
      out.push(s);
    }
    return out;
  }

  function renderHighlightedText(text, spans) {
    var html = "";
    var pos = 0;
    for (var i = 0; i < spans.length; i++) {
      var s = spans[i];
      if (s.start > pos) html += escapeHtmlStr(text.slice(pos, s.start));
      var inner = s.flag === "content_padding_evasion"
        ? "blank-line padding"
        : escapeHtmlStr(text.slice(s.start, s.end));
      html += '<mark class="hl-mark hl-' + s.severity + '" tabindex="0" data-flag="' +
        escapeHtmlStr(s.flag) + '" data-why="' + escapeHtmlStr(s.why) + '">' + inner + "</mark>";
      pos = s.end;
    }
    if (pos < text.length) html += escapeHtmlStr(text.slice(pos));
    return html;
  }

  function highlightLegendHtml(spans) {
    var n = spans.length;
    var kinds = {};
    for (var i = 0; i < n; i++) kinds[spans[i].severity] = (kinds[spans[i].severity] || 0) + 1;
    if (!n) {
      return '<div class="hl-legend">No suspicious words, phrases, or links were found in this message.</div>';
    }
    return '<div class="hl-legend"><strong>' + n + "</strong> highlight" + (n === 1 ? "" : "s") +
      " · hover a mark to see why" +
      (kinds.critical ? ' <span class="hl-chip hl-critical">high risk</span>' : "") +
      (kinds.serious ? ' <span class="hl-chip hl-serious">suspicious</span>' : "") +
      (kinds.low ? ' <span class="hl-chip hl-low">watch</span>' : "") +
      "</div>";
  }

  function getHlTip() {
    var tip = document.getElementById("hl-tip-global");
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "hl-tip-global";
      tip.className = "hl-tip";
      tip.hidden = true;
      document.body.appendChild(tip);
    }
    return tip;
  }

  function bindHighlightHovers(root) {
    var tip = getHlTip();
    function hide() { tip.hidden = true; }
    function show(mark) {
      tip.textContent = mark.getAttribute("data-why") || "";
      tip.hidden = false;
      var r = mark.getBoundingClientRect();
      var tw = 300;
      tip.style.left = Math.min(Math.max(8, r.left), window.innerWidth - tw - 8) + "px";
      tip.style.top = (r.bottom + 8) + "px";
      var th = tip.offsetHeight || 0;
      if (r.bottom + 8 + th > window.innerHeight - 8) {
        tip.style.top = Math.max(8, r.top - th - 8) + "px";
      }
    }
    root.addEventListener("mouseover", function (ev) {
      var m = ev.target.closest ? ev.target.closest(".hl-mark") : null;
      if (m && root.contains(m)) show(m);
    });
    root.addEventListener("mouseout", function (ev) {
      var m = ev.target.closest ? ev.target.closest(".hl-mark") : null;
      if (!m) return;
      var next = ev.relatedTarget;
      if (next && (m === next || m.contains(next))) return;
      hide();
    });
    root.addEventListener("focusin", function (ev) {
      if (ev.target && ev.target.classList && ev.target.classList.contains("hl-mark")) show(ev.target);
    });
    root.addEventListener("focusout", hide);
  }

  function paintHighlightsView(stage, parsed, scan) {
    var bodyText = (parsed.plain && parsed.plain.trim())
      ? parsed.plain
      : htmlToVisibleText(parsed.html || "");
    var subject = (scan && scan.subject) || (parsed.headers && parsed.headers.subject) || "";
    var subSpans = subject ? collectHighlightSpans(subject, scan || {}, { subjectOnly: true }) : [];
    var bodySpans = collectHighlightSpans(bodyText, scan || {}, {});
    var all = subSpans.concat(bodySpans);
    var html = '<div class="email-viewer-highlights">';
    html += highlightLegendHtml(all);
    if (subject) {
      html += '<div class="hl-kicker">Subject</div>';
      html += '<div class="hl-subject">' + (subSpans.length ? renderHighlightedText(subject, subSpans) : escapeHtmlStr(subject)) + "</div>";
    }
    html += '<div class="hl-kicker">Message</div>';
    html += '<div class="hl-body">' +
      (bodyText
        ? renderHighlightedText(bodyText, bodySpans)
        : '<span class="email-viewer-empty">No message body found.</span>') +
      "</div></div>";
    stage.innerHTML = html;
  }

  /* ============================== TMES POLICY CATEGORIES ============================== */
  // Phase 11: live from GET/PUT /api/policy (server/routers/policy.py),
  // not the static build-time export dashboard/build_policy_data.py used to
  // produce — real backend/policy/detection/policy.yaml state, refreshed after every toggle.
  // categoryFlagMatch (app/pipeline/policy.py's CATEGORY_FLAG_MATCH) rarely
  // changes, so it's still fetched once and cached in POLICY, not re-sent
  // on every GET — this section ports only the *matching function*
  // (category_for_flag/_matches_prefix), not a second hand-written copy of
  // the category assignments themselves.
  var POLICY: any = { categories: [], categoryFlagMatch: {}, allCategories: [] };
  var CATEGORY_LABEL = {};
  function applyPolicyResponse(data) {
    POLICY.categories = data.categories || [];
    if (data.categoryFlagMatch) POLICY.categoryFlagMatch = data.categoryFlagMatch;
    if (data.allCategories) POLICY.allCategories = data.allCategories;
    CATEGORY_LABEL = {};
    POLICY.categories.forEach(function (c) { CATEGORY_LABEL[c.key] = c.label; });
  }
  function loadPolicy() {
    return fetch("/api/policy", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(applyPolicyResponse);
  }
  // Phase 13 white-labeling: brand name comes from GET /api/org
  // (backend/policy/identity/org.yaml) instead of being hardcoded — deploying this for a
  // different organization is a config edit, not a code change.
  function loadOrg() {
    return fetch("/api/org", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (org) {
        var el = document.getElementById("brandName");
        if (el && org.display_name) el.textContent = org.display_name + " Secure Email Gateway Service (SEGS)";
        return org;
      })
      .catch(function () { return null; });
  }
  function setPolicyCategory(category, enabled) {
    return fetch("/api/policy", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ category: category, enabled: enabled })
    }).then(function (r) {
      if (!r.ok) throw new Error("policy update failed (" + r.status + ")");
      return r.json();
    }).then(applyPolicyResponse);
  }

  function matchesPrefix(flag, prefix) {
    return flag === prefix || flag.indexOf(prefix + ":") === 0 || flag.indexOf(prefix + "_") === 0;
  }
  function categoryForFlag(flag) {
    for (var cat in POLICY.categoryFlagMatch) {
      var m = POLICY.categoryFlagMatch[cat];
      if (m.exact.indexOf(flag) !== -1) return cat;
      for (var i = 0; i < m.prefix.length; i++) {
        if (matchesPrefix(flag, m.prefix[i])) return cat;
      }
    }
    return null;
  }
  function categoriesForFlags(flags?: any): any[] {
    var seen = {}, out = [];
    var list = Array.isArray(flags) ? flags : (typeof flags === "string" && flags ? [flags] : []);
    list.forEach(function (f) {
      var cat = categoryForFlag(f);
      if (cat && !seen[cat]) { seen[cat] = true; out.push(cat); }
    });
    return out;
  }
  // Renders which of the 6 TMES policy categories fired on a row, echoing
  // the Email Security Module screenshot's per-category framing directly in
  // the feed/quarantine tables (e.g. a malicious row shows "Malware Scanning
  // · File Blocking" chips for the categories that actually caught it).
  function categoryChipsHtml(reasons) {
    var cats = categoriesForFlags(reasons);
    if (!cats.length) return "";
    return '<div class="cat-chip-row">' + cats.map(function (c) {
      return '<span class="cat-chip">' + escapeHtml(CATEGORY_LABEL[c] || c) + "</span>";
    }).join("") + "</div>";
  }

  // ---- Exact port of report.py's _verdict_margin ----
  function verdictMargin(verdict, score, hasOverride) {
    if (hasOverride) return "";
    var t = THRESHOLDS;
    if (verdict === "MALICIOUS") return (score - t.malicious).toFixed(1) + " points above the MALICIOUS threshold of " + t.malicious;
    if (verdict === "SUSPICIOUS") return (t.malicious - score).toFixed(1) + " points below MALICIOUS (" + t.malicious + "), " + (score - t.suspicious).toFixed(1) + " above SUSPICIOUS (" + t.suspicious + ")";
    if (verdict === "LOW") return (t.suspicious - score).toFixed(1) + " points below SUSPICIOUS (" + t.suspicious + "), " + (score - t.low).toFixed(1) + " above LOW (" + t.low + ")";
    return (t.low - score).toFixed(1) + " points below the LOW threshold of " + t.low;
  }

  /* ============================== STATE ============================== */
  var state: any = {
    feed: [],          // newest first, all verdicts — loaded from GET /api/feed
    feedStats: null,   // unclipped copy counts from Postgres (not feed.length)
    feedError: "",
    feedLoaded: false,
    llmConfigured: false,
    llmAssessTimeoutMs: 120000,
    activePage: "overview",
    qFilter: "all",
    overviewFilter: "all",   // Phase 14: set by clicking a stat tile — "all" | "safe" | "suspicious" | "malicious"
    filteredFeed: null,      // verdict-tile emails; null = use live feed
    originCountry: "",
    feedSearch: "",
    searchHits: null,
    searchLabels: [],
    searchSql: "",
    searchPending: false,
    searchError: "",
    searchSource: "",
    feedPage: 1,       // 1-based live-feed page; FEED_PAGE_SIZE rows per page
    qSearch: "",
    auditSearch: "",
    auditWazuhOnly: false,
    audit: [],          // loaded from GET /api/audit (shadow_enforcement.jsonl)
    senderProfiles: [],
    senderProfileQuery: "",
    senderProfileReadyOnly: false,
    senderProfileSelected: "",
    senderProfileDetail: null,
    senderProfileMinN: 5,
    senderAssessFilter: "all",
    workers: null,
    campaigns: [],
    campaignQuery: "",
    campaignFlaggedOnly: false,
    campaignSelected: "",
    detailId: null,
    detailReturnPage: "overview",
    pinnedFeed: []
  };

  /* ============================== REAL DATA LOADING ============================== */
  // Phase 12: state.feed from GET /api/feed; state.audit from GET /api/audit
  // (gateway shadow decisions + console activity from data/activity_audit.jsonl).
  function assessmentsJustFinished(prev, next) {
    if (!(prev || []).length) return [];
    var wasDone = {};
    (prev || []).forEach(function (e) {
      var k = String((e && (e.queueId || e.id)) || "");
      if (k) wasDone[k] = isLlmAssessment(e);
    });
    return (next || []).filter(function (e) {
      var k = String((e && (e.queueId || e.id)) || "");
      if (!k || !isLlmAssessment(e)) return false;
      return wasDone[k] === false;
    });
  }

  function hasThreadAssessment(e) {
    return !!(e && (String(e.threadSummary || "").trim() || String(e.threadVerdict || "").trim()));
  }

  function threadAssessmentsJustFinished(prev, next) {
    if (!(prev || []).length) return [];
    var prevHas = {};
    var prevSeen = {};
    (prev || []).forEach(function (e) {
      var k = threadKeyOf(e);
      if (!k) return;
      prevSeen[k] = true;
      if (hasThreadAssessment(e)) prevHas[k] = true;
    });
    var seen = {};
    var out = [];
    (next || []).forEach(function (e) {
      var k = threadKeyOf(e);
      if (!k || seen[k] || !hasThreadAssessment(e)) return;
      if (!prevSeen[k] || prevHas[k]) return;
      seen[k] = true;
      out.push(e);
    });
    return out;
  }

  function clipToastLabel(s, n) {
    s = String(s || "");
    if (s.length > n) return s.slice(0, n - 1) + "…";
    return s;
  }

  function notifyAssessmentsFinished(done) {
    if (!done || !done.length) return;
    if (done.length === 1) {
      var e = done[0];
      var shown = displayVerdict(e);
      var v = VERDICTS[shown] || VERDICTS[e.verdict] || VERDICTS.CLEAN;
      var label = clipToastLabel(e.subject || e.fromAddr || e.id || "message", 72);
      toast(ICON[v.icon] || ICON.good, "Content assessment complete — " + v.label + " · " + label);
      return;
    }
    toast(ICON.good, done.length + " content assessments complete");
  }

  function notifyThreadAssessmentsFinished(done) {
    if (!done || !done.length) return;
    if (done.length === 1) {
      var e = done[0];
      var key = threadKeyOf(e);
      var n = 0;
      var best = e;
      (state.feed || []).forEach(function (x) {
        if (threadKeyOf(x) !== key) return;
        n++;
        if (hasThreadAssessment(x) && (x.ts || 0) >= (best.ts || 0)) best = x;
      });
      if (n < 1) n = 1;
      var shown = String(best.threadVerdict || "").toUpperCase();
      var v = VERDICTS[shown];
      var label = clipToastLabel(
        stripThreadSubject(best.subject || e.subject) || e.fromAddr || e.id || "conversation",
        72
      );
      var count = n === 1 ? "1 message" : n + " messages";
      toast(
        (v && ICON[v.icon]) || ICON.good,
        "Thread assessment complete — " + (v ? v.label + " · " : "") + count + " · " + label
      );
      return;
    }
    toast(ICON.good, done.length + " thread assessments complete");
  }

  function senderProfileAssessed(p) {
    return !!(p && String(p.ai_risk || "").trim());
  }

  function senderProfileReady(p) {
    if (!p) return false;
    if (p.ready) return true;
    return Number(p.n) >= (state.senderProfileMinN || 5);
  }

  function senderProfilesJustFinished(prev, next) {
    if (!(prev || []).length) return [];
    var before = {};
    (prev || []).forEach(function (p) {
      var k = String((p && p.sender) || "").toLowerCase();
      if (k) before[k] = p;
    });
    return (next || []).filter(function (p) {
      var k = String((p && p.sender) || "").toLowerCase();
      var old = k ? before[k] : null;
      if (!old) return false;
      if (senderProfileAssessed(p) && !senderProfileAssessed(old)) return true;
      if (senderProfileReady(p) && !senderProfileReady(old) && !senderProfileAssessed(p)) return true;
      return false;
    });
  }

  function notifySenderProfilesFinished(done) {
    if (!done || !done.length) return;
    if (done.length === 1) {
      var p = done[0];
      var addr = clipToastLabel(p.sender || "sender", 48);
      var risk = String(p.ai_risk || "").toUpperCase();
      var riskInfo = SENDER_RISK[risk];
      var icon = (riskInfo && ICON[riskInfo.icon]) || ICON.good;
      var extra = riskInfo ? " · " + riskInfo.label : " · baseline ready";
      toast(icon, "Sender profile complete — " + addr + extra);
      return;
    }
    toast(ICON.good, done.length + " sender profiles complete");
  }

  function feedUrl() {
    var params = [];
    var f = (state.overviewFilter || "all");
    if (f && f !== "all") params.push("verdict=" + encodeURIComponent(f));
    if (state.originCountry) params.push("origin=" + encodeURIComponent(state.originCountry));
    return params.length ? "/api/feed?" + params.join("&") : "/api/feed";
  }

  function overviewTableFeed() {
    if ((state.feedSearch || "").trim() && Array.isArray(state.searchHits)) {
      return state.searchHits;
    }
    return state.feed;
  }

  var _searchSeq = 0;
  function runSpotlightSearch(q?: any, verdict?: any) {
    q = String(q || "").trim();
    var seq = ++_searchSeq;
    if (!q) {
      state.searchHits = null;
      state.searchLabels = [];
      state.searchSql = "";
      state.searchPending = false;
      state.searchError = "";
      state.searchSource = "";
      return Promise.resolve(null);
    }
    state.searchPending = true;
    state.searchError = "";
    var payload: any = { q: q };
    if (verdict && verdict !== "all") payload.verdict = verdict;
    return fetch("/api/feed/search", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (r) {
      return r.json().then(function (j) {
        return { ok: r.ok, j: j };
      });
    }).then(function (res) {
      if (seq !== _searchSeq) return;
      state.searchPending = false;
      if (!res.ok) {
        var d = res.j && res.j.detail;
        if (Array.isArray(d)) d = d.map(function (x) { return x.msg || JSON.stringify(x); }).join("; ");
        state.searchError = d || "Search failed";
        state.searchHits = [];
        return;
      }
      state.searchHits = res.j.entries || [];
      state.searchLabels = res.j.labels || [];
      state.searchSql = "";
      state.searchSource = res.j.source || "";
      state.searchError = "";
    }).catch(function (err) {
      if (seq !== _searchSeq) return;
      state.searchPending = false;
      state.searchError = (err && err.message) || "Search failed";
      state.searchHits = [];
    });
  }

  function loadFeed() {
    var prev = state.feed.slice();
    var prevSenders = (state.senderProfiles || []).slice();
    var page = state.activePage || "overview";
    var pollFeed = page === "overview" || page === "quarantine" || page === "queue";
    var extraReqs = [];
    var feedP = Promise.resolve();
    if (pollFeed) {
      feedP = fetch(feedUrl(), { credentials: "same-origin" }).then(function (r) {
        if (!r.ok) throw new Error("feed " + r.status);
        return r.json();
      }).then(function (body) {
        if (!body || !Array.isArray(body.entries)) throw new Error("feed shape");
        var next = body.entries;
        var finished = assessmentsJustFinished(prev, next);
        var finishedThreads = threadAssessmentsJustFinished(prev, next);
        if (typeof body.llmConfigured === "boolean") {
          state.llmConfigured = body.llmConfigured;
        }
        if (body.llmAssessTimeoutSeconds) {
          state.llmAssessTimeoutMs = Number(body.llmAssessTimeoutSeconds) * 1000;
        }
        state.feed = mergePinnedFeed(next, state.detailId ? state.pinnedFeed : []);
        if (!state.detailId) state.pinnedFeed = [];
        state.filteredFeed = null;
        state.feedStats = body.stats && typeof body.stats.total === "number"
          ? body.stats
          : null;
        if (typeof body.aiPendingCount === "number" && state.feedStats) {
          state.feedStats.aiPendingTotal = Math.max(
            Number(state.feedStats.aiPendingTotal) || 0,
            Number(body.aiPendingCount) || 0
          );
        }
        lastUpdate = Date.now();
        state.feedError = "";
        state.feedLoaded = true;
        if (typeof ui.onData === "function") ui.onData({ finished: finished });
        else renderAll();
        notifyAssessmentsFinished(finished);
        notifyThreadAssessmentsFinished(finishedThreads);
      }).catch(function (err) {
        state.feedError = (err && err.message) || "feed failed";
        state.feedLoaded = true;
        if (typeof ui.onData === "function") ui.onData({});
      });
    }
    if (page === "audit") {
      extraReqs.push(fetch("/api/audit", { credentials: "same-origin" }).then(function (r) {
        return r.ok ? r.json() : null;
      }).catch(function () { return null; }).then(function (auditBody) {
        if (auditBody && Array.isArray(auditBody.entries)) state.audit = auditBody.entries;
      }));
    }
    if (page === "senders") {
      extraReqs.push(fetch("/api/sender-profiles", { credentials: "same-origin" }).then(function (r) {
        return r.ok ? r.json() : null;
      }).catch(function () { return null; }).then(function (sendersBody) {
        if (!sendersBody || !Array.isArray(sendersBody.senders)) return;
        var finishedProfiles = senderProfilesJustFinished(prevSenders, sendersBody.senders);
        state.senderProfiles = sendersBody.senders;
        if (sendersBody.min_n) state.senderProfileMinN = Number(sendersBody.min_n) || 5;
        notifySenderProfilesFinished(finishedProfiles);
      }));
    }
    if (page === "workers") {
      extraReqs.push(fetch("/api/workers", { credentials: "same-origin" }).then(function (r) {
        return r.ok ? r.json() : null;
      }).catch(function () { return null; }).then(function (workersBody) {
        if (workersBody) state.workers = workersBody;
      }));
    }
    if (page === "campaigns") {
      extraReqs.push(fetch("/api/campaigns?limit=200", { credentials: "same-origin" }).then(function (r) {
        return r.ok ? r.json() : null;
      }).catch(function () { return null; }).then(function (campaignsBody) {
        if (campaignsBody && Array.isArray(campaignsBody.campaigns)) {
          state.campaigns = campaignsBody.campaigns;
        }
      }));
    }
    return Promise.all([feedP].concat(extraReqs)).then(function () {
      if (extraReqs.length && typeof ui.onData === "function") ui.onData({});
    });
  }

  /* ============================== FORMATTERS ============================== */
  function fmtTime(ts) {
    var d = new Date(ts);
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function fmtDateTime(ts) {
    var d = new Date(ts);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  function fmtAgo(ts) {
    var s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 5) return "just now";
    if (s < 60) return s + "s ago";
    var m = Math.round(s / 60);
    if (m < 60) return m + "m ago";
    var h = Math.round(m / 60);
    return h + "h ago";
  }
  function fmtExpires(ts) {
    var days = Math.ceil((ts - Date.now()) / (24 * 3600 * 1000));
    if (days <= 0) return "today";
    return days + "d";
  }
  function fmtNum(n) {
    var x = Number(n);
    if (!isFinite(x)) x = 0;
    var opts = { maximumFractionDigits: 2 };
    if (Math.abs(x - Math.round(x)) < 1e-9) {
      x = Math.round(x);
      opts.maximumFractionDigits = 0;
    }
    return x.toLocaleString("en-US", opts);
  }
  var SENDER_RISK = {
    LOW:      { label: "Low risk",      cls: "v-clean",      icon: "good" },
    MEDIUM:   { label: "Medium risk",   cls: "v-low",        icon: "warning" },
    HIGH:     { label: "High risk",     cls: "v-suspicious", icon: "serious" },
    CRITICAL: { label: "Critical risk", cls: "v-malicious",  icon: "critical" }
  };
  function chip(verdict) {
    var v = VERDICTS[verdict] || VERDICTS.PENDING;
    return '<span class="chip ' + v.cls + '">' + ICON[v.icon] + v.label + "</span>";
  }
  function riskChip(risk) {
    var key = String(risk || "").toUpperCase();
    var v = SENDER_RISK[key];
    if (!v) return "<span class='addr-muted'>Pending</span>";
    return '<span class="chip ' + v.cls + '">' + ICON[v.icon] + v.label + "</span>";
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  // LLM often returns "1. Do X" while we render inside <ol> — strip to avoid 1. 1. Do X.
  function stripListPrefix(s) {
    return String(s).replace(/^\s*(?:\d+[\.\)]\s+|[-*•]\s+)/, "").trim();
  }
  // feed_builder.py falls back to the raw address for fromName when an email
  // has no display name — rendering both lines then just repeats the address.
  function addrCellHtml(addr, name, extraCount) {
    addr = String(addr || "").trim();
    name = String(name || "").trim();
    if (!addr && !name) {
      return '<div class="cell-content-min"><span class="addr-muted">—</span></div>';
    }
    var email = addr || name;
    var showName = name && name.toLowerCase() !== email.toLowerCase();
    var more = extraCount > 0 ? '<span class="addr-more">+' + fmtNum(extraCount) + "</span>" : "";
    return '<div class="cell-content-min">' +
      '<span class="addr-email">' + escapeHtml(email) + more + "</span>" +
      (showName ? '<span class="addr">' + escapeHtml(name) + "</span>" : "") +
      "</div>";
  }
  function fromCellHtml(fromName, fromAddr) {
    return addrCellHtml(fromAddr, fromName, 0);
  }
  function toCellHtml(e) {
    var extras = (e.toAddrs && e.toAddrs.length > 1) ? e.toAddrs.length - 1 : 0;
    return addrCellHtml(e.toAddr, e.toName, extras);
  }

  /* ============================== RENDER: STAT TILES ============================== */
  // Phase 14: tiles are clickable filters over the Live feed table below,
  // reusing the same active-tab pattern the Quarantine page's #qTabs already
  // established (state.overviewFilter + a small filter fn renderFeed() consults).
  function renderStats() {
    if (!document.getElementById("statGrid")) return;
    var ov = feedOverview();
    var counts = ov.counts;
    var pendingN = ov.pendingN;
    var inconclusiveN = ov.inconclusiveN;
    var total = ov.total;
    var decided = total - pendingN - inconclusiveN;
    var waitBits = [];
    if (pendingN) waitBits.push(fmtNum(pendingN) + " awaiting AI");
    if (inconclusiveN) waitBits.push(fmtNum(inconclusiveN) + " inconclusive");
    var tiles = [
      { filter: "all", label: "Total", value: total, icon: "eye", accentVar: "var(--accent)",
        sub: waitBits.length ? waitBits.join(" · ") : (decided ? Math.round((counts.CLEAN + counts.LOW) / decided * 100) + "% passed clean" : "No mail yet") },
      { filter: "safe", label: "Safe", value: counts.CLEAN + counts.LOW, icon: "good", accentVar: "var(--status-good)", sub: fmtNum(counts.CLEAN) + " clean · " + fmtNum(counts.LOW) + " low" },
      { filter: "suspicious", label: "Suspicious", value: counts.SUSPICIOUS, icon: "serious", accentVar: "var(--status-serious)", sub: "flagged for review" },
      { filter: "malicious", label: "Malicious", value: counts.MALICIOUS, icon: "critical", accentVar: "var(--status-critical)", sub: "high-confidence detections" }
    ];
    document.getElementById("statGrid").innerHTML = tiles.map(function (t) {
      var active = state.overviewFilter === t.filter;
      return '<button type="button" class="stat-tile' + (active ? " active" : "") + '" data-filter="' + t.filter + '" style="--tile-accent:' + t.accentVar + '">' +
        '<div class="stat-label">' + ICON[t.icon] + t.label + "</div>" +
        '<div class="stat-value mono">' + fmtNum(t.value) + "</div>" +
        '<div class="stat-sub">' + t.sub + "</div>" +
        "</button>";
    }).join("");
    Array.prototype.forEach.call(document.querySelectorAll("#statGrid .stat-tile"), function (btn) {
      btn.addEventListener("click", function () {
        state.overviewFilter = state.overviewFilter === btn.dataset.filter ? "all" : btn.dataset.filter;
        if (state.overviewFilter === "all") state.filteredFeed = null;
        resetFeedPage();
        loadFeed().then(function () {
          renderStats();
          renderFeed();
        });
      });
    });
    var heldCount = heldEmails().filter(function (e) { return e.status !== "released"; }).length;
    document.getElementById("navQuarantineCount").textContent = fmtNum(heldCount);
    document.getElementById("navQuarantineCount").dataset.zero = heldCount === 0;
    var pendingCount = ov.aiPendingTotal + ov.aiTimedOutTotal;
    var qn = document.getElementById("navQueueCount");
    if (qn) {
      qn.textContent = fmtNum(pendingCount);
      qn.dataset.zero = pendingCount === 0;
    }
  }

  /* ============================== RENDER: POLICY PANEL ============================== */
  // Sourced live from GET /api/policy (server/routers/policy.py) — real
  // backend/policy/detection/policy.yaml state, Admin-only toggle switches write back via
  // PUT /api/policy (see setPolicyCategory() above).
  function renderPolicyPanel() {
    var el = document.getElementById("policyGrid");
    if (!el) return;
    if (!POLICY.categories.length) {
      el.innerHTML = '<div class="empty-state">Loading policy state…</div>';
      return;
    }
    var isAdmin = window.__SEG_CURRENT_USER__ && window.__SEG_CURRENT_USER__.role === "admin";
    el.innerHTML = POLICY.categories.map(function (c) {
      return '<div class="policy-tile' + (c.enabled ? "" : " pt-off") + '">' +
        '<span class="pt-dot"></span>' +
        '<span class="pt-label">' + escapeHtml(c.label) + "</span>" +
        '<button class="pt-switch" role="switch" aria-checked="' + (c.enabled ? "true" : "false") + '" ' +
          'aria-label="' + escapeHtml(c.label) + (isAdmin ? "" : " (Admin only)") + '" ' +
          'data-key="' + c.key + '"' + (isAdmin ? "" : " disabled") + "></button>" +
        "</div>";
    }).join("");
    if (!isAdmin) return;
    Array.prototype.forEach.call(el.querySelectorAll(".pt-switch"), function (btn) {
      btn.addEventListener("click", function () {
        var key = btn.dataset.key;
        var nextEnabled = btn.getAttribute("aria-checked") !== "true";
        btn.disabled = true;
        setPolicyCategory(key, nextEnabled).then(renderPolicyPanel).catch(function (err) {
          btn.disabled = false;
          console.error(err);
        });
      });
    });
  }

  /* ============================== RENDER: CHART.JS GRAPHS ============================== */
  var mixChartInst = null;
  var volumeChartInst = null;
  var senderAssessChartInst = null;
  var senderHostilityChartInst = null;
  function chartInk() {
    return getComputedStyle(document.documentElement).getPropertyValue("--ink-muted").trim() || "#94a3b8";
  }
  function chartColors() {
    var s = getComputedStyle(document.documentElement);
    return {
      clean: s.getPropertyValue("--status-good").trim() || "#059669",
      low: s.getPropertyValue("--status-warning").trim() || "#d97706",
      suspicious: s.getPropertyValue("--status-serious").trim() || "#ea580c",
      malicious: s.getPropertyValue("--status-critical").trim() || "#dc2626",
      accent: s.getPropertyValue("--accent").trim() || "#0f766e",
      accent2: s.getPropertyValue("--accent-2").trim() || "#0369a1"
    };
  }

  function renderThreatMix() {
    if (!document.getElementById("mixLegend") && !document.getElementById("mixChart")) return;
    var ov = feedOverview();
    var counts = ov.counts;
    var pendingN = ov.pendingN;
    var inconclusiveN = ov.inconclusiveN;
    var decided = ov.total - pendingN - inconclusiveN;
    var total = ov.total;
    var order = ["CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS"];
    var legend = document.getElementById("mixLegend");
    var mixLabel = document.getElementById("mixTotalLabel");
    var extra = [];
    if (pendingN) extra.push(fmtNum(pendingN) + " assessing");
    if (inconclusiveN) extra.push(fmtNum(inconclusiveN) + " inconclusive");
    if (mixLabel) {
      mixLabel.textContent = fmtNum(total) + " messages" +
        (extra.length ? " · " + extra.join(" · ") : "");
    }
    if (!legend) return;
    legend.innerHTML = decided
      ? order.map(function (v) {
          var pct = Math.round(counts[v] / decided * 100);
          return '<div class="mix-legend-item"><span class="lg-swatch ' + VERDICTS[v].cls + '"></span>' +
            VERDICTS[v].label + ' <span class="lg-count">' + fmtNum(counts[v]) + '</span>' +
            '<span class="lg-pct">(' + pct + '%)</span></div>';
        }).join("")
      : '<div class="mix-legend-item">' + (extra.length ? extra.join(" · ") + "." : "No mail yet.") + "</div>";

    var canvas = document.getElementById("mixChart");
    if (!canvas || typeof Chart === "undefined") return;
    var cols = chartColors();
    var data = order.map(function (v) { return counts[v]; });
    var colors = [cols.clean, cols.low, cols.suspicious, cols.malicious];
    if (mixChartInst && !(mixChartInst.data && mixChartInst.data.datasets && mixChartInst.data.datasets[0])) {
      try { mixChartInst.destroy(); } catch (err) {}
      mixChartInst = null;
    }
    if (mixChartInst) {
      mixChartInst.data.datasets[0].data = data;
      mixChartInst.data.datasets[0].backgroundColor = colors;
      mixChartInst.update();
      return;
    }
    mixChartInst = new Chart(canvas, {
      type: "doughnut",
      data: {
        labels: order.map(function (v) { return VERDICTS[v].label; }),
        datasets: [{ data: data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                var n = ctx.parsed || 0;
                var ds = (ctx.dataset && ctx.dataset.data) || [];
                var sum = 0;
                for (var i = 0; i < ds.length; i++) sum += ds[i] || 0;
                var p = sum ? Math.round(n / sum * 100) : 0;
                return " " + ctx.label + ": " + fmtNum(n) + " (" + p + "%)";
              }
            }
          }
        }
      }
    });
  }

  function renderChart() {
    if (!document.getElementById("volumeChart") && !document.getElementById("chartTotalLabel")) return;
    var ov = feedOverview();
    var buckets = [];
    if (ov.hourly && ov.hourly.length) {
      ov.hourly.forEach(function (h) {
        buckets.push({
          start: h.start,
          count: h.count || 0,
          low: h.low || 0,
          suspicious: h.suspicious || 0,
          malicious: h.malicious || 0
        });
      });
    } else {
      var byDay: any = {};
      state.feed.forEach(function (e) {
        var start = Math.floor(Number(e.ts) / 86400000) * 86400000;
        var b = byDay[start] || { start: start, count: 0, low: 0, suspicious: 0, malicious: 0 };
        b.count++;
        var shown = displayVerdict(e);
        if (shown === "LOW") b.low++;
        else if (shown === "SUSPICIOUS") b.suspicious++;
        else if (shown === "MALICIOUS") b.malicious++;
        byDay[start] = b;
      });
      buckets = Object.keys(byDay).sort().map(function (k) { return byDay[k]; });
    }
    var totalN = ov.hourly ? ov.total : buckets.reduce(function (s, b) { return s + b.count; }, 0);
    var lowN = ov.hourly ? ov.counts.LOW : buckets.reduce(function (s, b) { return s + b.low; }, 0);
    var susN = ov.hourly ? ov.counts.SUSPICIOUS : buckets.reduce(function (s, b) { return s + b.suspicious; }, 0);
    var malN = ov.hourly ? ov.counts.MALICIOUS : buckets.reduce(function (s, b) { return s + b.malicious; }, 0);
    var volLabel = document.getElementById("chartTotalLabel");
    if (volLabel) {
      volLabel.textContent =
        fmtNum(totalN) + " total · " +
        fmtNum(lowN) + " low · " +
        fmtNum(susN) + " suspicious · " +
        fmtNum(malN) + " malicious";
    }

    var canvas = document.getElementById("volumeChart");
    if (!canvas || typeof Chart === "undefined") return;
    var cols = chartColors();
    var span = buckets.length ? (buckets[buckets.length - 1].start - buckets[0].start) : 0;
    var labels = buckets.map(function (b) {
      var d = new Date(b.start);
      if (span >= 36 * 3600 * 1000 || buckets.length > 24) {
        return d.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
      }
      var hh = d.getHours();
      return (hh < 10 ? "0" : "") + hh + ":00";
    });
    var totals = buckets.map(function (b) { return b.count; });
    var lowVals = buckets.map(function (b) { return b.low; });
    var suspVals = buckets.map(function (b) { return b.suspicious; });
    var malVals = buckets.map(function (b) { return b.malicious; });
    var ink = chartInk();
    var series = [
      { label: "Total", data: totals, borderColor: cols.accent2, backgroundColor: "rgba(3,105,161,0.10)", fill: true, borderWidth: 2.5 },
      { label: "Low", data: lowVals, borderColor: cols.low, backgroundColor: "transparent", fill: false, borderWidth: 2 },
      { label: "Suspicious", data: suspVals, borderColor: cols.suspicious, backgroundColor: "transparent", fill: false, borderWidth: 2 },
      { label: "Malicious", data: malVals, borderColor: cols.malicious, backgroundColor: "transparent", fill: false, borderWidth: 2 }
    ];

    if (volumeChartInst && volumeChartInst.data && volumeChartInst.data.datasets &&
        volumeChartInst.data.datasets.length === series.length) {
      volumeChartInst.data.labels = labels;
      series.forEach(function (s, i) {
        volumeChartInst.data.datasets[i].data = s.data;
        volumeChartInst.data.datasets[i].borderColor = s.borderColor;
      });
      volumeChartInst.update();
      return;
    }
    if (volumeChartInst) {
      volumeChartInst.destroy();
      volumeChartInst = null;
    }
    volumeChartInst = new Chart(canvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: series.map(function (s) {
          return {
            label: s.label,
            data: s.data,
            borderColor: s.borderColor,
            backgroundColor: s.backgroundColor,
            fill: s.fill,
            tension: 0.35,
            pointRadius: 2,
            pointHoverRadius: 5,
            borderWidth: s.borderWidth,
            pointBackgroundColor: s.borderColor
          };
        })
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            position: "bottom",
            labels: { boxWidth: 10, usePointStyle: true, color: ink, padding: 14, font: { family: "Google Sans", size: 12 } }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: ink, maxRotation: 0, autoSkip: true, maxTicksLimit: 24, font: { family: "Google Sans", size: 10 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(148,163,184,0.18)" },
            ticks: { color: ink, precision: 0, callback: function (v) { return fmtNum(v); }, font: { family: "Google Sans", size: 11 } }
          }
        }
      }
    });
  }

  /* ============================== RENDER: ORIGIN MAP ============================== */
  var COUNTRY_CENTROIDS = {
    AD: [42.5, 1.5], AE: [23.4, 53.8], AF: [33.9, 67.7], AL: [41.2, 20.2], AM: [40.1, 45],
    AR: [-38.4, -63.6], AT: [47.5, 14.6], AU: [-25.3, 133.8], AZ: [40.1, 47.6],
    BA: [43.9, 17.7], BD: [23.7, 90.4], BE: [50.5, 4.5], BG: [42.7, 25.5], BH: [26, 50.6],
    BO: [-16.3, -63.6], BR: [-14.2, -51.9], BY: [53.7, 27.9],
    CA: [56.1, -106.3], CH: [46.8, 8.2], CL: [-35.7, -71.5], CN: [35.9, 104.2],
    CO: [4.6, -74.3], CR: [9.7, -83.8], CY: [35.1, 33.4], CZ: [49.8, 15.5],
    DE: [51.2, 10.4], DK: [56.3, 9.5], DO: [18.7, -70.2], DZ: [28, 1.7],
    EC: [-1.8, -78.2], EE: [58.6, 25], EG: [26.8, 30.8], ES: [40.5, -3.7], ET: [9.1, 40.5],
    FI: [61.9, 25.7], FR: [46.2, 2.2], GB: [55.4, -3.4], GE: [42.3, 43.4], GH: [7.9, -1],
    GR: [39.1, 21.8], GT: [15.8, -90.2], HK: [22.4, 114.1], HR: [45.1, 15.2], HU: [47.2, 19.5],
    ID: [-0.8, 113.9], IE: [53.1, -8], IL: [31, 34.9], IN: [20.6, 79], IQ: [33.2, 43.7],
    IR: [32.4, 53.7], IS: [65, -19], IT: [41.9, 12.6],
    JP: [36.2, 138.3], KE: [0.02, 37.9], KR: [35.9, 127.8], KW: [29.3, 47.5], KZ: [48, 67],
    LB: [33.9, 35.9], LK: [7.9, 80.8], LT: [55.2, 23.9], LU: [49.8, 6.1], LV: [56.9, 24.6],
    MA: [31.8, -7.1], MX: [23.6, -102.6], MY: [4.2, 101.9], NG: [9.1, 8.7], NL: [52.1, 5.3],
    NO: [60.5, 8.5], NP: [28.4, 84.1], NZ: [-40.9, 174.9],
    OM: [21.5, 55.9], PA: [8.5, -80.8], PE: [-9.2, -75], PH: [12.9, 121.8], PK: [30.4, 69.3],
    PL: [51.9, 19.1], PR: [18.2, -66.6], PT: [39.4, -8.2], PY: [-23.4, -58.4],
    QA: [25.4, 51.2], RO: [45.9, 25], RS: [44, 21], RU: [61.5, 105.3],
    SA: [23.9, 45.1], SE: [60.1, 18.6], SG: [1.35, 103.8], SI: [46.2, 14.8], SK: [48.7, 19.7],
    TH: [15.9, 100.9], TR: [38.96, 35.2], TW: [23.7, 121],
    UA: [48.4, 31.2], UG: [1.4, 32.3], US: [39.8, -98.5], UY: [-32.5, -55.8], UZ: [41.4, 64.6],
    VE: [6.4, -66.6], VN: [14.1, 108.3], ZA: [-30.6, 22.9]
  };
  var originMapCtl = {
    map: null, host: null, points: [], countries: [], bound: false, fingerprint: ""
  };
  var detailOriginMapCtl = {
    map: null, host: null, points: [], countries: [], fingerprint: ""
  };

  function originStageOf(e) {
    var st = (e && e.stages && e.stages.origin_ip) || {};
    if (e && e.originCountry && !st.country) {
      return Object.assign({}, st, { country: e.originCountry });
    }
    return st;
  }
  function originIntelDlHtml(st) {
    st = st || {};
    var ip = st.ip || "";
    var loc = [st.city, st.region, st.countryName || st.country].filter(Boolean).join(", ");
    var isp = st.isp || st.org || "";
    var asName = st.asName || st.as_name || "";
    if (st.asn) isp += (isp ? " · " : "") + st.asn + (asName ? " " + asName : "");
    var net = st.networkRoleLabel || st.network_role_label || "";
    var vpn = st.vpn ? "Likely yes" : ((st.isp || st.country) ? "No indication" : "Not looked up yet");
    var sus = st.suspicion || "";
    var susReason = st.suspicionReason || st.suspicion_reason || "";
    var rows = [
      ["IP", ip + (st.hostname ? " (" + st.hostname + ")" : "")],
      ["Location", loc || "Not looked up yet"],
      ["ISP / ASN", isp || "Not looked up yet"],
      ["Network", net || "Unknown"],
      ["VPN / proxy", vpn]
    ];
    if (sus && sus !== "none") {
      rows.push(["Suspicion", sus + (susReason ? " — " + susReason : "")]);
    }
    return rows.map(function (pair) {
      return "<dt>" + escapeHtml(pair[0]) + "</dt><dd>" + escapeHtml(pair[1]) + "</dd>";
    }).join("");
  }
  function originIntelBlockHtml(st) {
    st = st || {};
    if (!st.ip) return "No originating IP on the Received chain.";
    return '<dl class="origin-intel origin-intel-inline">' + originIntelDlHtml(st) + "</dl>";
  }
  function renderDetailOriginIntel(e) {
    var el = document.getElementById("detailOriginIntel");
    if (!el) return;
    var st = originStageOf(e);
    if (!st.ip) {
      el.className = "origin-intel is-empty";
      el.innerHTML = "No originating IP on the Received chain for this email.";
      return;
    }
    el.className = "origin-intel";
    el.innerHTML = originIntelDlHtml(st);
  }
  function originCoords(st) {
    var lat = st.lat, lon = st.lon;
    if (typeof lat === "number" && typeof lon === "number" && isFinite(lat) && isFinite(lon)) {
      return [lat, lon];
    }
    var cc = String(st.country || "").toUpperCase();
    return COUNTRY_CENTROIDS[cc] ? COUNTRY_CENTROIDS[cc].slice() : null;
  }
  function originVerdictOf(e) {
    var shown = displayVerdict(e);
    return (shown === "PENDING" || shown === "INCONCLUSIVE") ? "CLEAN" : (e.verdict || "CLEAN");
  }
  function collectOriginFromEmails(emails) {
    var bySpot = {};
    var byCountry = {};
    var rank = { CLEAN: 0, LOW: 1, SUSPICIOUS: 2, MALICIOUS: 3 };
    var located = 0;
    (emails || []).forEach(function (e) {
      var st = originStageOf(e);
      var cc = String(st.country || "").toUpperCase();
      var xy = originCoords(st);
      if (!xy && !cc) return;
      located++;
      var v = originVerdictOf(e);
      if (cc) {
        var c = byCountry[cc] || (byCountry[cc] = {
          country: cc, name: st.countryName || cc, count: 0, worst: "CLEAN",
          lat: xy ? xy[0] : (COUNTRY_CENTROIDS[cc] ? COUNTRY_CENTROIDS[cc][0] : 0),
          lon: xy ? xy[1] : (COUNTRY_CENTROIDS[cc] ? COUNTRY_CENTROIDS[cc][1] : 0),
          city: st.city || "", ip: st.ip || "", isp: st.isp || "",
          networkRoleLabel: st.networkRoleLabel || st.network_role_label || "",
          vpn: !!st.vpn, ids: []
        });
        c.count++;
        if ((rank[v] || 0) > (rank[c.worst] || 0)) c.worst = v;
        if (st.countryName) c.name = st.countryName;
        if (st.city) c.city = st.city;
        if (st.ip) c.ip = st.ip;
        if (st.isp) c.isp = st.isp;
        if (st.networkRoleLabel || st.network_role_label) {
          c.networkRoleLabel = st.networkRoleLabel || st.network_role_label;
        }
        if (st.vpn) c.vpn = true;
        if (e.id && c.ids.indexOf(e.id) < 0) c.ids.push(e.id);
      }
      if (!xy) return;
      var key = xy[0].toFixed(1) + "," + xy[1].toFixed(1) + ":" + cc;
      var p = bySpot[key] || (bySpot[key] = {
        lat: xy[0], lon: xy[1], country: cc, name: st.countryName || cc,
        city: st.city || "", ip: st.ip || "", isp: st.isp || "",
        count: 0, worst: "CLEAN", ids: []
      });
      p.count++;
      if ((rank[v] || 0) > (rank[p.worst] || 0)) p.worst = v;
      if (st.city) p.city = st.city;
      if (st.ip) p.ip = st.ip;
      if (st.isp) p.isp = st.isp;
      if (e.id && p.ids.indexOf(e.id) < 0) p.ids.push(e.id);
    });
    return {
      points: Object.keys(bySpot).map(function (k) { return bySpot[k]; }),
      countries: Object.keys(byCountry).map(function (k) { return byCountry[k]; })
        .sort(function (a, b) { return b.count - a.count; }),
      located: located,
      total: (emails || []).length
    };
  }
  function collectOriginPoints() {
    var snap = state.feedStats && state.feedStats.origin;
    if (snap && Array.isArray(snap.countries)) {
      originMapCtl.points = snap.points || [];
      originMapCtl.countries = snap.countries;
      return {
        points: originMapCtl.points,
        countries: originMapCtl.countries,
        located: Number(snap.located) || 0,
        total: Number(state.feedStats.total) || 0
      };
    }
    var collected = collectOriginFromEmails(state.feed);
    originMapCtl.points = collected.points;
    originMapCtl.countries = collected.countries;
    return collected;
  }
  function originToken(name, fallback) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
  }
  function colorAlpha(hex, a) {
    hex = String(hex || "").replace("#", "").trim();
    if (hex.length === 3) hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
    if (hex.length !== 6) return "rgba(15,118,110," + a + ")";
    var n = parseInt(hex, 16);
    return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
  }
  function originThemeFingerprint() {
    var cols = chartColors();
    return [
      cols.clean, cols.low, cols.suspicious, cols.malicious, cols.accent,
      originToken("--origin-land", ""), originToken("--origin-stroke", ""),
      originToken("--origin-water", ""),
    ];
  }
  function originMapFingerprint(ctl) {
    return JSON.stringify({
      points: ctl.points,
      countries: ctl.countries,
      theme: originThemeFingerprint()
    });
  }
  function originCountryFrom(ctl, cc) {
    cc = String(cc || "").toUpperCase();
    var i;
    for (i = 0; i < ctl.countries.length; i++) {
      if (ctl.countries[i].country === cc) return ctl.countries[i];
    }
    return null;
  }
  function originCountryByCode(cc) {
    return originCountryFrom(originMapCtl, cc);
  }
  function toggleOriginFilter(cc) {
    cc = String(cc || "").toUpperCase();
    if (!cc) return;
    state.originCountry = state.originCountry === cc ? "" : cc;
    resetFeedPage();
    loadFeed().then(function () {
      if (typeof ui.onData === "function") ui.onData({ origin: state.originCountry });
      else {
        renderFeed();
        renderOriginMapList();
      }
      syncJvmSelection(originMapCtl.map, state.originCountry);
    });
  }
  function originMarkersFrom(points) {
    var cols = chartColors();
    var colorOf = { CLEAN: cols.clean, LOW: cols.low, SUSPICIOUS: cols.suspicious, MALICIOUS: cols.malicious };
    return (points || []).map(function (p) {
      var fill = colorOf[p.worst] || cols.accent;
      var r = 4 + Math.min(10, Math.sqrt(p.count) * 2.4);
      var label = p.city ? p.city + ", " + (p.name || p.country) : (p.name || p.country || "Unknown");
      return {
        name: label,
        coords: [p.lat, p.lon],
        country: p.country,
        count: p.count,
        worst: p.worst,
        style: {
          initial: { fill: fill, r: r, stroke: originToken("--surface", "#fff"), strokeWidth: 1.2, fillOpacity: 0.92 },
          hover: { fill: fill, stroke: originToken("--surface", "#fff"), cursor: "pointer" },
          selected: { fill: fill, stroke: originToken("--surface", "#fff"), strokeWidth: 2 }
        }
      };
    });
  }
  function paintOriginRegions(map, countries) {
    if (!map || !map.regions) return;
    var cols = chartColors();
    var colorOf = { CLEAN: cols.clean, LOW: cols.low, SUSPICIOUS: cols.suspicious, MALICIOUS: cols.malicious };
    var land = originToken("--origin-land", "#b7c4d4");
    var byCc = {};
    (countries || []).forEach(function (c) { byCc[c.country] = c; });
    Object.keys(map.regions).forEach(function (code) {
      var c = byCc[code];
      map.regions[code].element.setStyle("fill", c ? colorAlpha(colorOf[c.worst] || cols.accent, 0.42) : land);
    });
  }
  function syncJvmSelection(map, cc) {
    if (!map) return;
    if (cc && map.regions[cc]) map.setSelectedRegions([cc]);
    else map.clearSelectedRegions();
  }
  function syncOriginMapSelection() {
    syncJvmSelection(originMapCtl.map, state.originCountry);
  }
  function originTooltipHtml(title, count, worst, extra) {
    var html = "<strong>" + escapeHtml(title) + "</strong>";
    if (extra && extra.ip) html += "<br>" + escapeHtml(extra.ip);
    if (extra && extra.isp) html += "<br>" + escapeHtml(extra.isp);
    html += "<br>" + fmtNum(count) + " message" + (count === 1 ? "" : "s");
    if (worst && worst !== "CLEAN") html += " · worst " + escapeHtml(String(worst).toLowerCase());
    return html;
  }
  function createOriginJvm(el, cfg) {
    var Ctor = jsVectorMap || (typeof window !== "undefined" && window.jsVectorMap);
    if (!el || typeof Ctor !== "function") return null;
    var land = originToken("--origin-land", "#b7c4d4");
    var stroke = originToken("--origin-stroke", "rgba(15,23,42,0.22)");
    var accent = originToken("--accent", "#0f766e");
    try {
      return new Ctor({
        selector: el,
        map: "world",
        backgroundColor: "transparent",
        draggable: true,
        zoomButtons: true,
        zoomOnScroll: false,
        zoomAnimate: true,
        showTooltip: true,
        regionsSelectable: false,
        markersSelectable: false,
        regionStyle: {
          initial: { fill: land, fillOpacity: 1, stroke: stroke, strokeWidth: 0.6 },
          hover: { fillOpacity: 0.85, cursor: "pointer" },
          selected: { fill: accent, fillOpacity: 0.55 },
          selectedHover: { fillOpacity: 0.7 }
        },
        markerStyle: {
          initial: { r: 6, fill: accent, fillOpacity: 0.92, stroke: originToken("--surface", "#fff"), strokeWidth: 1.2 },
          hover: { cursor: "pointer" }
        },
        markers: cfg.markers || [],
        selectedRegions: cfg.selectedRegions || [],
        onRegionClick: cfg.onRegionClick,
        onMarkerClick: cfg.onMarkerClick,
        onRegionTooltipShow: cfg.onRegionTooltipShow,
        onMarkerTooltipShow: cfg.onMarkerTooltipShow
      });
    } catch (err) {
      console.warn("origin map failed to mount", err);
      return null;
    }
  }
  function focusOriginJvm(map, countries, points) {
    if (!map || typeof map.setFocus !== "function") return;
    var codes = (countries || []).map(function (c) { return c.country; })
      .filter(function (cc) { return map.regions[cc]; });
    if (codes.length) {
      map.setFocus({ regions: codes, animate: true });
      return;
    }
    if (points && points[0]) {
      map.setFocus({ coords: [points[0].lat, points[0].lon], scale: 3, animate: true });
    }
  }
  function refreshOriginJvm(ctl, el, data, handlers, opts) {
    opts = opts || {};
    if (!el) return;
    ctl.points = data.points || [];
    ctl.countries = data.countries || [];
    // React remounts #originMap when you leave Overview/Detail. The old
    // jsVectorMap instance is then attached to a detached node.
    if (ctl.map && (ctl.host !== el || !el.querySelector("svg"))) {
      try {
        if (typeof ctl.map.destroy === "function") ctl.map.destroy();
      } catch (err) {}
      ctl.map = null;
      ctl.host = null;
      ctl.fingerprint = "";
    }
    var fp = originMapFingerprint(ctl);
    if (ctl.map && fp !== ctl.fingerprint) {
      try {
        if (typeof ctl.map.destroy === "function") ctl.map.destroy();
      } catch (err) {}
      ctl.map = null;
      ctl.host = null;
    }
    if (!ctl.map) {
      ctl.map = createOriginJvm(el, {
        markers: originMarkersFrom(ctl.points),
        selectedRegions: opts.selected ? [opts.selected] : [],
        onRegionClick: handlers.onRegionClick,
        onMarkerClick: handlers.onMarkerClick,
        onRegionTooltipShow: handlers.onRegionTooltipShow,
        onMarkerTooltipShow: handlers.onMarkerTooltipShow
      });
      ctl.host = el;
      ctl.fingerprint = fp;
      if (ctl.map) {
        paintOriginRegions(ctl.map, ctl.countries);
        ctl.map.updateSize();
        if (opts.focus) focusOriginJvm(ctl.map, ctl.countries, ctl.points);
      }
      return;
    }
    syncJvmSelection(ctl.map, opts.selected || "");
    ctl.map.updateSize();
  }
  function bindOriginMap() {
    if (originMapCtl.bound) return;
    originMapCtl.bound = true;
    window.addEventListener("resize", function () {
      if (state.activePage === "overview" && originMapCtl.map) originMapCtl.map.updateSize();
      if (state.activePage === "detail" && detailOriginMapCtl.map) detailOriginMapCtl.map.updateSize();
    });
  }
  function renderOriginMapList() {
    var list = document.getElementById("originMapList");
    if (!list) return;
    if (!originMapCtl.countries.length) {
      list.innerHTML = '<div class="origin-map-empty">No originating locations yet. Locations appear after geo lookup on the sending MTA IP.</div>';
      return;
    }
    list.innerHTML = originMapCtl.countries.map(function (c) {
      var active = state.originCountry === c.country ? " is-active" : "";
      var v = VERDICTS[c.worst] || VERDICTS.CLEAN;
      return '<button type="button" class="origin-map-row' + active + '" data-origin-cc="' + escapeHtml(c.country) + '">' +
        '<span><span class="origin-map-name">' + escapeHtml(c.name || c.country) + "</span>" +
        '<div class="origin-map-meta">' + escapeHtml(c.country) +
        (c.worst && c.worst !== "CLEAN" ? " · " + v.label : "") + "</div></span>" +
        '<span class="origin-map-count">' + fmtNum(c.count) + "</span>" +
        '<span class="lg-swatch ' + v.cls + '"></span></button>';
    }).join("");
    Array.prototype.forEach.call(list.querySelectorAll("[data-origin-cc]"), function (btn) {
      btn.addEventListener("click", function () {
        toggleOriginFilter(btn.getAttribute("data-origin-cc") || "");
      });
    });
  }
  function renderOriginMap() {
    var stats = collectOriginPoints();
    var label = document.getElementById("originMapLabel");
    if (label) {
      label.textContent = stats.total
        ? fmtNum(stats.located) + " of " + fmtNum(stats.total) + " located"
        : "No mail yet";
    }
    renderOriginMapList();
    bindOriginMap();
    var el = document.getElementById("originMap");
    if (!el || state.activePage !== "overview") return;
    refreshOriginJvm(originMapCtl, el, stats, {
      onRegionClick: function (ev, code) {
        var cc = String(code || "").toUpperCase();
        if (!originCountryByCode(cc)) return;
        toggleOriginFilter(cc);
      },
      onMarkerClick: function (ev, index) {
        var p = originMapCtl.points[index];
        if (p && p.country) toggleOriginFilter(p.country);
      },
      onRegionTooltipShow: function (ev, tooltip, code) {
        var c = originCountryByCode(code);
        if (!c) return;
        tooltip.text(originTooltipHtml(c.name || c.country, c.count, c.worst), true);
      },
      onMarkerTooltipShow: function (ev, tooltip, index) {
        var p = originMapCtl.points[index];
        if (!p) return;
        var title = p.city ? p.city + ", " + (p.name || p.country) : (p.name || p.country || "Unknown");
        tooltip.text(originTooltipHtml(title, p.count, p.worst), true);
      }
    }, { selected: state.originCountry });
  }
  function openOriginMessage(ids) {
    if (!ids || !ids.length) return;
    var id = ids[ids.length - 1];
    if (id && id !== state.detailId) openDetailPage(id);
  }
  function renderDetailOriginMapList(selectedCc) {
    var list = document.getElementById("detailOriginMapList");
    if (!list) return;
    selectedCc = String(selectedCc || "").toUpperCase();
    if (!detailOriginMapCtl.countries.length) {
      list.innerHTML = '<div class="origin-map-empty">No originating location for this thread yet. Location appears after geo lookup on the sending MTA IP.</div>';
      return;
    }
    list.innerHTML = detailOriginMapCtl.countries.map(function (c) {
      var v = VERDICTS[c.worst] || VERDICTS.CLEAN;
      var active = selectedCc === c.country ? " is-active" : "";
      var meta = [c.country];
      if (c.city) meta.unshift(c.city);
      if (c.ip) meta.push(c.ip);
      if (c.isp) meta.push(c.isp);
      if (c.networkRoleLabel) meta.push(c.networkRoleLabel);
      meta.push(c.vpn ? "VPN/proxy" : "Not a VPN");
      if (c.worst && c.worst !== "CLEAN") meta.push(v.label);
      return '<button type="button" class="origin-map-row' + active + '" data-origin-cc="' + escapeHtml(c.country) + '">' +
        '<span><span class="origin-map-name">' + escapeHtml(c.name || c.country) + "</span>" +
        '<div class="origin-map-meta">' + escapeHtml(meta.join(" · ")) + "</div></span>" +
        '<span class="origin-map-count">' + fmtNum(c.count) + "</span>" +
        '<span class="lg-swatch ' + v.cls + '"></span></button>';
    }).join("");
    Array.prototype.forEach.call(list.querySelectorAll("[data-origin-cc]"), function (btn) {
      btn.addEventListener("click", function () {
        var c = originCountryFrom(detailOriginMapCtl, btn.getAttribute("data-origin-cc") || "");
        if (!c) return;
        syncJvmSelection(detailOriginMapCtl.map, c.country);
        openOriginMessage(c.ids);
      });
    });
  }
  function renderDetailOriginMap(e) {
    var emails = e ? threadSiblings(e) : [];
    if (!emails.length && e) emails = [e];
    var stats = collectOriginFromEmails(emails);
    detailOriginMapCtl.points = stats.points;
    detailOriginMapCtl.countries = stats.countries;
    var label = document.getElementById("detailOriginMapLabel");
    if (label) {
      label.textContent = stats.total
        ? fmtNum(stats.located) + " of " + fmtNum(stats.total) + " located"
        : "No origin yet";
    }
    renderDetailOriginIntel(e);
    var selected = String((originStageOf(e).country || "")).toUpperCase();
    if (!selected && stats.countries[0]) selected = stats.countries[0].country;
    renderDetailOriginMapList(selected);
    bindOriginMap();
    var el = document.getElementById("detailOriginMap");
    if (!el || state.activePage !== "detail") return;
    refreshOriginJvm(detailOriginMapCtl, el, stats, {
      onRegionClick: function (ev, code) {
        var c = originCountryFrom(detailOriginMapCtl, code);
        if (!c) return;
        syncJvmSelection(detailOriginMapCtl.map, c.country);
        openOriginMessage(c.ids);
      },
      onMarkerClick: function (ev, index) {
        var p = detailOriginMapCtl.points[index];
        if (!p) return;
        syncJvmSelection(detailOriginMapCtl.map, p.country);
        openOriginMessage(p.ids);
      },
      onRegionTooltipShow: function (ev, tooltip, code) {
        var c = originCountryFrom(detailOriginMapCtl, code);
        if (!c) return;
        tooltip.text(originTooltipHtml(c.name || c.country, c.count, c.worst, c), true);
      },
      onMarkerTooltipShow: function (ev, tooltip, index) {
        var p = detailOriginMapCtl.points[index];
        if (!p) return;
        var title = p.city ? p.city + ", " + (p.name || p.country) : (p.name || p.country || "Unknown");
        tooltip.text(originTooltipHtml(title, p.count, p.worst, p), true);
      }
    }, { focus: true, selected: selected });
  }

  /* ============================== RENDER: LIVE FEED ============================== */
  var lastRenderedFeedIds = [];
  function feedMatchesOverviewFilter(e) {
    if (state.overviewFilter === "all") return true;
    var copyV = String(displayVerdict(e) || "").toUpperCase();
    var storedV = String(e.verdict || "").toUpperCase();
    var threadV = String(e.threadVerdict || "").toUpperCase();
    if (state.overviewFilter === "safe") {
      return copyV === "CLEAN" || copyV === "LOW" || storedV === "CLEAN" || storedV === "LOW";
    }
    if (state.overviewFilter === "suspicious") {
      return copyV === "SUSPICIOUS" || storedV === "SUSPICIOUS" || threadV === "SUSPICIOUS";
    }
    if (state.overviewFilter === "malicious") {
      return copyV === "MALICIOUS" || storedV === "MALICIOUS" || threadV === "MALICIOUS";
    }
    return true;
  }
  function feedMatchesOrigin(e) {
    if (!state.originCountry) return true;
    var cc = String(e.originCountry || (e.stages && e.stages.origin_ip && e.stages.origin_ip.country) || "").toUpperCase();
    return cc === state.originCountry;
  }
  function feedMatchesSearch(e) {
    if ((state.feedSearch || "").trim() && Array.isArray(state.searchHits)) return true;
    var intent = parseSearchIntent(state.feedSearch);
    if (!searchIntentActive(intent)) return true;
    var key = threadKeyOf(e);
    var sibs = state.feed.filter(function (x) { return threadKeyOf(x) === key; });
    return mailMatchesIntent({
      fromName: e.fromName,
      fromAddr: e.fromAddr,
      toName: e.toName,
      toAddr: e.toAddr,
      toAddrs: e.toAddrs,
      subject: e.subject,
      mailbox: e.mailbox,
      verdict: displayVerdict(e),
      threadVerdict: e.threadVerdict,
      status: e.status,
      actionLabel: actionTakenLabel(e),
      contentPending: isAiPending(e),
      contentTimedOut: isAiTimedOut(e),
      threadAssessed: !!threadAssessmentOf(sibs)
    }, intent);
  }
  var OVERVIEW_FILTER_LABEL: any = { safe: "Safe", suspicious: "Suspicious", malicious: "Malicious" };
  var VERDICT_RANK = { INCONCLUSIVE: -1, CLEAN: 0, LOW: 1, SUSPICIOUS: 2, MALICIOUS: 3 };

  function threadKeyOf(e) {
    return (e && e.threadKey) || ("msg:" + (e && e.id ? e.id : ""));
  }

  function stripThreadSubject(subject) {
    return String(subject || "").replace(/^\s*((re|fw|fwd)\s*:\s*)+/i, "").trim();
  }

  function groupAsThreads(messages?: any, expandFrom?: any) {
    var keys = {};
    (messages || []).forEach(function (e) { keys[threadKeyOf(e)] = true; });
    var source = expandFrom || messages || [];
    var expanded = source.filter(function (e) { return keys[threadKeyOf(e)]; });
    var map = {};
    var order = [];
    expanded.forEach(function (e) {
      var key = threadKeyOf(e);
      if (!map[key]) {
        map[key] = { key: key, messages: [] };
        order.push(map[key]);
      }
      map[key].messages.push(e);
    });
    order.forEach(function (g) {
      g.messages.sort(function (a, b) { return a.ts - b.ts; });
      g.latest = g.messages[g.messages.length - 1];
      var finals = g.messages.filter(verdictIsFinal);
      g.worst = (finals.length ? finals : g.messages)[0];
      (finals.length ? finals : g.messages).forEach(function (m) {
        var wr = VERDICT_RANK[displayVerdict(g.worst)] || 0;
        var mr = VERDICT_RANK[displayVerdict(m)] || 0;
        if (mr > wr || (mr === wr && (m.score || 0) > (g.worst.score || 0))) g.worst = m;
      });
      g.subject = stripThreadSubject(g.messages[0].subject) || g.latest.subject;
    });
    order.sort(function (a, b) { return (b.latest.ts || 0) - (a.latest.ts || 0); });
    return order;
  }

  var FEED_PAGE_SIZE = 100;

  function pageFeedThreads(threads?: any[]) {
    var size = FEED_PAGE_SIZE;
    var list: any[] = threads || [];
    var total = list.length;
    var pages = total ? Math.max(1, Math.ceil(total / size)) : 1;
    var page = Math.max(1, parseInt(state.feedPage, 10) || 1);
    if (page > pages) page = pages;
    state.feedPage = page;
    var start = (page - 1) * size;
    var items = list.slice(start, start + size);
    return {
      items: items,
      page: page,
      pages: pages,
      total: total,
      size: size,
      from: total ? start + 1 : 0,
      to: start + items.length,
    };
  }

  function feedPageWindow(page?: any, pages?: any) {
    page = Math.max(1, page || 1);
    pages = Math.max(1, pages || 1);
    if (pages <= 7) {
      var all = [];
      for (var i = 1; i <= pages; i++) all.push(i);
      return all;
    }
    var keep: any = { 1: true };
    keep[pages] = true;
    for (var j = page - 1; j <= page + 1; j++) {
      if (j >= 1 && j <= pages) keep[j] = true;
    }
    var out = [];
    var prev = 0;
    for (var k = 1; k <= pages; k++) {
      if (!keep[k]) continue;
      if (prev && k - prev > 1) out.push(0);
      out.push(k);
      prev = k;
    }
    return out;
  }

  function resetFeedPage() {
    state.feedPage = 1;
  }

  function threadAssessmentOf(messages?: any): any {
    var best = null;
    (messages || []).forEach(function (m) {
      if (!(m && (m.threadSummary || m.threadVerdict))) return;
      if (!best || m.ts > best.ts) best = m;
    });
    return best;
  }

  function chipForThreadGroup(g, display) {
    if (display && display.hardOverride) return chipForEmail(display);
    var t = threadAssessmentOf(g && g.messages);
    if (t && t.threadVerdict) return chip(t.threadVerdict);
    return chipForEmail(display);
  }

  function threadSiblings(e) {
    var key = threadKeyOf(e);
    return state.feed.filter(function (x) { return threadKeyOf(x) === key; })
      .sort(function (a, b) { return a.ts - b.ts; });
  }

  function renderFeed() {
    var badge = document.getElementById("feedFilterBadge");
    if (!badge) return;
    var chips = [];
    if (state.overviewFilter !== "all") {
      chips.push('<button type="button" class="btn btn-sm" data-clear-filter="verdict">Filtered: ' +
        OVERVIEW_FILTER_LABEL[state.overviewFilter] + " ✕</button>");
    }
    if (state.originCountry) {
      chips.push('<button type="button" class="btn btn-sm" data-clear-filter="origin">Origin: ' +
        escapeHtml(state.originCountry) + " ✕</button>");
    }
    badge.innerHTML = chips.join(" ");
    Array.prototype.forEach.call(badge.querySelectorAll("[data-clear-filter]"), function (btn) {
      btn.addEventListener("click", function () {
        if (btn.getAttribute("data-clear-filter") === "origin") state.originCountry = "";
        else {
          state.overviewFilter = "all";
          state.filteredFeed = null;
        }
        resetFeedPage();
        loadFeed().then(function () {
          renderStats();
          renderFeed();
          renderOriginMap();
        });
      });
    });
    var q = (state.feedSearch || "").trim();
    var source = overviewTableFeed();
    var matched = q ? source.filter(feedMatchesSearch) : source;
    var threads = groupAsThreads(matched, source);
    var paged = pageFeedThreads(threads);
    threads = paged.items;
    var body = document.getElementById("feedBody");
    if (!threads.length) {
      var empty = q
        ? "No messages match “" + escapeHtml(q) + "”."
        : (state.originCountry ? "No messages from that origin."
          : (state.overviewFilter === "all" ? "Waiting for the first message…" : "No messages match this filter."));
      body.innerHTML = '<tr><td colspan="7"><div class="empty-state">' + empty + "</div></td></tr>";
      return;
    }
    body.innerHTML = threads.map(function (g) {
      var e = g.latest;
      var display = g.worst;
      var isNew = lastRenderedFeedIds.indexOf(g.key) === -1;
      var tAss = threadAssessmentOf(g.messages);
      var rowVerdict = (display.hardOverride || !(tAss && tAss.threadVerdict))
        ? displayVerdict(display)
        : tAss.threadVerdict;
      var vinfo = VERDICTS[rowVerdict] || VERDICTS[displayVerdict(display)] || VERDICTS.PENDING;
      var actionLabel = actionTakenLabel(display);
      var countBadge = g.messages.length > 1
        ? '<span class="thread-count" title="' + fmtNum(g.messages.length) + ' messages in this thread">' + fmtNum(g.messages.length) + "</span>"
        : "";
      var pendingBadge = g.messages.some(isAiPending) && displayVerdict(display) !== "PENDING" && !isAiTimedOut(display)
        ? aiPendingBadgeHtml() : "";
      var openId = display.id;
      return '<tr class="row-stripe ' + vinfo.cls + (isNew ? " row-enter" : "") + '" data-id="' + escapeHtml(openId) + '" style="cursor:pointer">' +
        '<td class="cell-time">' + fmtTime(e.ts) + "</td>" +
        "<td>" + chipForThreadGroup(g, display) + "</td>" +
        '<td class="cell-from">' + fromCellHtml(e.fromName, e.fromAddr) + "</td>" +
        '<td class="cell-to">' + toCellHtml(e) + "</td>" +
        '<td class="cell-subject"><div class="cell-content-min"><div class="cell-subject-text">' + escapeHtml(g.subject) + "</div>" + countBadge + pendingBadge + (verdictIsFinal(display) ? categoryChipsHtml(display.reasons) : "") + "</div></td>" +
        '<td class="cell-score">' + scoreCell(display) + "</td>" +
        "<td>" + escapeHtml(actionLabel) + "</td>" +
        "</tr>";
    }).join("");
    lastRenderedFeedIds = threads.map(function (g) { return g.key; });
    Array.prototype.forEach.call(body.querySelectorAll("tr[data-id]"), function (tr) {
      tr.addEventListener("click", function () { openDetailPage(tr.dataset.id); });
    });
  }

  /* ============================== RENDER: QUARANTINE ============================== */
  function heldEmails(): any[] {
    return state.feed.filter(function (e) {
      return e.sourceKind === "spool" &&
        (e.bucket === "quarantine" || e.bucket === "rejected" || e.bucket === "released");
    });
  }
  function actionTakenLabel(e) {
    if (e.status === "released") return "Released";
    if (!verdictIsFinal(e) || isAiTimedOut(e)) return pipelineStatusLabel(e);
    if (e.sourceKind === "spool" && e.bucket === "rejected") return "Blocked";
    if (e.sourceKind === "spool" && e.bucket === "quarantine") return "Quarantined";
    return "Delivered";
  }
  function renderQuarantine() {
    if (!document.getElementById("quarantineBody")) return;
    var all = heldEmails();
    var counts = { all: all.length, blocked: 0, quarantined: 0, released: 0 };
    all.forEach(function (e) {
      if (e.status === "released") counts.released++;
      else if (!verdictIsFinal(e)) return;
      else if (e.verdict === "MALICIOUS") counts.blocked++;
      else counts.quarantined++;
    });
    document.getElementById("qcAll").textContent = counts.all;
    document.getElementById("qcBlocked").textContent = counts.blocked;
    document.getElementById("qcQuarantined").textContent = counts.quarantined;
    document.getElementById("qcReleased").textContent = counts.released;

    var filtered = all.filter(function (e) {
      if (state.qFilter === "blocked") return verdictIsFinal(e) && e.verdict === "MALICIOUS" && e.status !== "released";
      if (state.qFilter === "quarantined") return verdictIsFinal(e) && e.verdict === "SUSPICIOUS" && e.status !== "released";
      if (state.qFilter === "released") return e.status === "released";
      return true;
    });
    if (state.qSearch) {
      var q = state.qSearch.toLowerCase();
      filtered = filtered.filter(function (e) {
        return (e.fromAddr || "").toLowerCase().indexOf(q) !== -1 ||
          (e.subject || "").toLowerCase().indexOf(q) !== -1;
      });
    }
    var threads = groupAsThreads(filtered);

    var body = document.getElementById("quarantineBody");
    var empty = document.getElementById("quarantineEmpty");
    if (!threads.length) {
      body.innerHTML = "";
      empty.style.display = "block";
      return;
    }
    empty.style.display = "none";
    // Just one action (View) per row now — Download/Re-evaluate/Release/
    // Keep-blocked moved exclusively into the floating window's footer
    // (populateFloatWindow()) so the row doesn't wrap onto a second line.
    var actor = canAct();
    body.innerHTML = threads.map(function (g) {
      var e = g.latest;
      var display = g.worst;
      var tAss = threadAssessmentOf(g.messages);
      var rowVerdict = (display.hardOverride || !(tAss && tAss.threadVerdict))
        ? displayVerdict(display)
        : tAss.threadVerdict;
      var vinfo = VERDICTS[rowVerdict] || VERDICTS[displayVerdict(display)] || VERDICTS.PENDING;
      var released = display.status === "released";
      var isSpool = display.sourceKind === "spool";
      var canRelease = actor && isSpool && !released && verdictIsFinal(display) && (display.verdict === "SUSPICIOUS" || display.verdict === "MALICIOUS");
      var canDl = actor && (isSpool || display.sourceKind === "gmail");
      var countBadge = g.messages.length > 1
        ? '<span class="thread-count" title="' + fmtNum(g.messages.length) + ' messages in this thread">' + fmtNum(g.messages.length) + "</span>"
        : "";
      return '<tr class="row-stripe ' + vinfo.cls + '" data-id="' + escapeHtml(display.id) + '" style="cursor:pointer">' +
        '<td class="cell-time">' + fmtDateTime(e.ts) + "</td>" +
        "<td>" + (released ? '<span class="chip a-released">' + ICON.release + "Released</span>" : chipForThreadGroup(g, display)) + "</td>" +
        '<td class="cell-from">' + fromCellHtml(e.fromName, e.fromAddr) + "</td>" +
        '<td class="cell-subject"><div class="cell-content-min"><div class="cell-subject-text">' + escapeHtml(g.subject) + "</div>" + countBadge + (verdictIsFinal(display) ? categoryChipsHtml(display.reasons) : "") + "</div></td>" +
        '<td class="cell-score">' + scoreCell(display) + "</td>" +
        '<td class="cell-time">' + (released ? "—" : fmtExpires(display.expiresAt)) + "</td>" +
        '<td style="white-space:nowrap">' +
          '<button class="btn btn-sm" data-action="view" data-id="' + escapeHtml(display.id) + '">' + ICON.eye + "View</button>" +
          (canDl ? ' <button class="btn btn-sm" data-action="download" data-id="' + escapeHtml(display.id) + '">' + ICON.download + "Download</button>" : "") +
          (canRelease ? ' <button class="btn btn-sm btn-primary" data-action="release" data-id="' + escapeHtml(display.id) + '">' + ICON.release + "Release</button>" : "") +
        "</td>" +
        "</tr>";
    }).join("");

    Array.prototype.forEach.call(body.querySelectorAll("tr[data-id]"), function (tr) {
      tr.addEventListener("click", function () { openDetailPage(tr.dataset.id); });
    });
    Array.prototype.forEach.call(body.querySelectorAll("button[data-action]"), function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var id = btn.dataset.id;
        if (btn.dataset.action === "download") { downloadEml(id); }
        else if (btn.dataset.action === "release") { confirmRelease(id); }
        else { openDetailPage(id); }
      });
    });
  }

  function renderAiQueueBanner() {
    var banner = document.getElementById("aiQueueBanner");
    if (!banner) return;
    var ov = feedOverview();
    var pendingN = ov.aiPendingTotal;
    var timedN = ov.aiTimedOutTotal;
    if (!pendingN && !timedN) {
      banner.hidden = true;
      banner.innerHTML = "";
      banner.onclick = null;
      return;
    }
    banner.hidden = false;
    var parts = [];
    if (pendingN) {
      parts.push(fmtNum(pendingN) + " message" + (pendingN === 1 ? "" : "s") + " waiting on AI");
    }
    if (timedN) {
      parts.push(fmtNum(timedN) + " retrying automatically");
    }
    banner.innerHTML = (pendingN ? '<span class="analyze-spinner" aria-hidden="true"></span>' : "") +
      "<span>" + parts.join(". ") + "</span>";
    banner.onclick = function () { setPage("workers"); };
  }

  function renderQueue() {
    renderAiQueueBanner();
    var body = document.getElementById("queueBody");
    var empty = document.getElementById("queueEmpty");
    if (!body || !empty) return;
    var rows = queueEmails();
    if (!rows.length) {
      body.innerHTML = "";
      empty.style.display = "block";
      empty.textContent = state.llmConfigured
        ? "No messages are waiting on AI."
        : "LLM is not configured — mail is scored with heuristics only.";
      return;
    }
    empty.style.display = "none";
    body.innerHTML = rows.map(function (e) {
      var timed = isAiTimedOut(e);
      return '<tr class="row-stripe ' + (timed ? "v-inconclusive" : "v-pending") + '" data-id="' + escapeHtml(e.id) + '" style="cursor:pointer">' +
        '<td class="cell-time">' + fmtDateTime(e.ts) + "</td>" +
        "<td>" + chipForEmail(e) + "</td>" +
        '<td class="cell-from">' + fromCellHtml(e.fromName, e.fromAddr) + "</td>" +
        '<td class="cell-to">' + toCellHtml(e) + "</td>" +
        '<td class="cell-subject"><div class="cell-content-min"><div class="cell-subject-text">' +
          escapeHtml(e.subject || "(no subject)") + "</div></div></td>" +
        '<td class="cell-score">' + scoreCell(e) + "</td>" +
        "<td>" + aiQueueStatusHtml(e) + "</td>" +
        "</tr>";
    }).join("");
    Array.prototype.forEach.call(body.querySelectorAll("tr[data-id]"), function (tr) {
      tr.addEventListener("click", function () { openDetailPage(tr.dataset.id); });
    });
  }

  /* ============================== RENDER: AUDIT LOG ============================== */
  var TYPE_LABEL: any = {
    good: "Delivered", warning: "Delivered", serious: "Quarantined",
    critical: "Blocked", accent: "Admin"
  };
  function renderAudit() {
    if (!document.getElementById("auditList")) return;
    var items = state.audit.slice();
    if (state.auditWazuhOnly) items = items.filter(function (e) { return e.wazuh; });
    if (state.auditSearch) {
      var q = state.auditSearch.toLowerCase();
      items = items.filter(function (e) {
        return (e.title + " " + e.detail + " " + (e.actor || "") + " " + (e.action || ""))
          .toLowerCase().indexOf(q) !== -1;
      });
    }
    items = items.slice(0, 200);
    var list = document.getElementById("auditList");
    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No matching audit events yet — sign-ins, user admin, quarantine actions, and gateway shadow decisions appear here.</div>';
      return;
    }
    list.innerHTML = items.map(function (e) {
      var iconKey = e.type === "accent" ? "wazuh" : e.type;
      if (!ICON[iconKey]) iconKey = "warning";
      var tag = e.wazuh ? "Wazuh" : (e.tag || TYPE_LABEL[e.type] || "Event");
      return '<div class="log-entry">' +
        '<div class="log-time">' + fmtDateTime(e.ts) + "</div>" +
        '<div class="log-icon t-' + escapeHtml(e.type) + '">' + ICON[iconKey] + "</div>" +
        '<div class="log-body"><div class="log-title">' + escapeHtml(e.title) + '</div><div class="log-detail">' + escapeHtml(e.detail) + "</div></div>" +
        '<div class="log-tag' + (e.wazuh ? " wazuh" : "") + (e.kind === "activity" ? " activity" : "") + '">' + escapeHtml(tag) + "</div>" +
        "</div>";
    }).join("");
  }

  function freqValues(rows, n) {
    return (rows || []).slice(0, n || 3).map(function (r) {
      return r && (r.value || (r.hour_utc != null ? r.hour_utc : ""));
    }).filter(function (v) { return v || v === 0; }).map(String);
  }
  function mixChipsHtml(rows, empty) {
    var items = (rows || []).slice(0, 8).filter(function (r) { return r && r.value; });
    if (!items.length) return "<div class='card-sub'>" + escapeHtml(empty || "None yet.") + "</div>";
    return "<div class='sender-chip-list'>" + items.map(function (r) {
      return "<span class='sender-chip'>" + escapeHtml(String(r.value).replace(/_/g, " ")) +
        " <b>" + fmtNum(Number(r.count) || 0) + "</b></span>";
    }).join("") + "</div>";
  }
  function peerListHtml(rows, empty) {
    var items = (rows || []).slice(0, 8).filter(function (r) { return r && r.value; });
    if (!items.length) return "<div class='card-sub'>" + escapeHtml(empty || "None yet.") + "</div>";
    return "<ul class='sender-peer-list'>" + items.map(function (r) {
      return "<li><span class='addr-email'>" + escapeHtml(r.value) + "</span>" +
        " <span class='sender-peer-n'>" + fmtNum(Number(r.count) || 0) + "</span></li>";
    }).join("") + "</ul>";
  }
  function hoursBarHtml(rows) {
    var byHour = {};
    var max = 0;
    (rows || []).forEach(function (r) {
      var h = r && (r.value != null && r.value !== "" ? r.value : r.hour_utc);
      h = Number(h);
      if (isNaN(h) || h < 0 || h > 23) return;
      var c = Number(r.count) || 0;
      byHour[h] = (byHour[h] || 0) + c;
      if (byHour[h] > max) max = byHour[h];
    });
    if (!max) return "<div class='card-sub'>No Date-hour history yet.</div>";
    var bars = [];
    for (var i = 0; i < 24; i++) {
      var c = byHour[i] || 0;
      var pct = c ? Math.max(8, Math.round(c / max * 100)) : 0;
      bars.push("<span title='" + (i < 10 ? "0" : "") + i + ":00 UTC × " + fmtNum(c) +
        "' style='height:" + pct + "%'" + (c ? "" : " class='is-empty'") + "></span>");
    }
    return "<div class='sender-hours'>" + bars.join("") + "</div>" +
      "<div class='sender-hours-axis'><span>00Z</span><span>12Z</span><span>23Z</span></div>";
  }
  function networkRoleLabel(role) {
    var map = {
      esp: "ESP", isp: "ISP", mobile_isp: "Mobile ISP",
      cloud_hosting: "Cloud hosting", vpn_proxy: "VPN/proxy"
    };
    return map[role] || role || "—";
  }
  function fmtUnix(ts) {
    var n = Number(ts);
    if (!n) return "—";
    return fmtDateTime(n * 1000);
  }
  function senderLaneHtml(p) {
    var lane = String((p && p.lane) || "").toLowerCase();
    if (lane === "role") return "<span class='addr-muted'>Role</span>";
    if (lane === "internal") return "<span class='addr-muted'>Internal</span>";
    return "";
  }
  function senderAssessmentOf(p) {
    var a = String((p && p.assessment) || "CLEAN").toUpperCase();
    if (a === "MALICIOUS" || a === "SUSPICIOUS") return a;
    return "CLEAN";
  }
  function senderVerdicts(p) {
    var v = (p && p.verdicts) || {};
    return {
      CLEAN: Number(v.CLEAN) || 0,
      LOW: Number(v.LOW) || 0,
      SUSPICIOUS: Number(v.SUSPICIOUS) || 0,
      MALICIOUS: Number(v.MALICIOUS) || 0
    };
  }
  function senderCopies(p) {
    var n = Number(p && p.copies);
    if (n) return n;
    var v = senderVerdicts(p);
    return v.CLEAN + v.LOW + v.SUSPICIOUS + v.MALICIOUS || Number(p && p.n) || 0;
  }
  function senderMixBarHtml(p) {
    var v = senderVerdicts(p);
    var total = v.CLEAN + v.LOW + v.SUSPICIOUS + v.MALICIOUS;
    if (!total) return "<span class='addr-muted'>—</span>";
    function seg(cls, n) {
      if (!n) return "";
      return "<span class='" + cls + "' style='width:" + (n / total * 100) + "%'></span>";
    }
    return "<div class='sender-mix' title='" +
      fmtNum(v.CLEAN + v.LOW) + " clean/low · " + fmtNum(v.SUSPICIOUS) + " suspicious · " + fmtNum(v.MALICIOUS) + " malicious'>" +
      seg("v-clean", v.CLEAN + v.LOW) +
      seg("v-suspicious", v.SUSPICIOUS) +
      seg("v-malicious", v.MALICIOUS) +
      "</div>";
  }
  function filteredSenderProfiles(): any[] {
    var q = (state.senderProfileQuery || "").trim().toLowerCase();
    var minN = state.senderProfileMinN || 5;
    var assess = state.senderAssessFilter || "all";
    return (state.senderProfiles || []).filter(function (p) {
      if (state.senderProfileReadyOnly && !(p.n >= minN || p.ready)) return false;
      if (assess !== "all" && senderAssessmentOf(p) !== assess) return false;
      if (!q) return true;
      var hay = [p.sender, p.majority_role, senderAssessmentOf(p), p.lane, p.assessment_note, p.ai_risk, p.ai_posture]
        .concat(freqValues(p.countries, 8))
        .concat(freqValues(p.asns, 8))
        .join(" ").toLowerCase();
      return hay.indexOf(q) !== -1;
    });
  }
  function renderSenderAssessment() {
    var all = state.senderProfiles || [];
    var counts = { CLEAN: 0, SUSPICIOUS: 0, MALICIOUS: 0 };
    all.forEach(function (p) { counts[senderAssessmentOf(p)]++; });
    var total = all.length;
    var grid = document.getElementById("senderAssessGrid");
    if (grid) {
      var tiles = [
        { filter: "all", label: "Senders", value: total, icon: "eye", accentVar: "var(--accent)",
          sub: total ? "typical behavior, not worst email" : "No sender history yet" },
        { filter: "CLEAN", label: "Clean", value: counts.CLEAN, icon: "good", accentVar: "var(--status-good)",
          sub: "mostly clean emails" },
        { filter: "SUSPICIOUS", label: "Suspicious", value: counts.SUSPICIOUS, icon: "serious", accentVar: "var(--status-serious)",
          sub: "hostile emails are a real share of volume" },
        { filter: "MALICIOUS", label: "Malicious", value: counts.MALICIOUS, icon: "critical", accentVar: "var(--status-critical)",
          sub: "majority malicious, or ≥3 emails at ≥20%" }
      ];
      grid.innerHTML = tiles.map(function (t) {
        var active = state.senderAssessFilter === t.filter;
        return '<button type="button" class="stat-tile' + (active ? " active" : "") + '" data-sender-filter="' + t.filter + '" style="--tile-accent:' + t.accentVar + '">' +
          '<div class="stat-label">' + ICON[t.icon] + t.label + "</div>" +
          '<div class="stat-value mono">' + fmtNum(t.value) + "</div>" +
          '<div class="stat-sub">' + t.sub + "</div></button>";
      }).join("");
      Array.prototype.forEach.call(grid.querySelectorAll("[data-sender-filter]"), function (btn) {
        btn.addEventListener("click", function () {
          var next = btn.getAttribute("data-sender-filter");
          state.senderAssessFilter = state.senderAssessFilter === next ? "all" : next;
          renderSenderAssessment();
          renderSenderProfiles();
        });
      });
    }
    var order = ["CLEAN", "SUSPICIOUS", "MALICIOUS"];
    var legend = document.getElementById("senderAssessLegend");
    var mixLabel = document.getElementById("senderAssessMixLabel");
    if (mixLabel) mixLabel.textContent = fmtNum(total) + " senders";
    if (legend) {
      legend.innerHTML = total
        ? order.map(function (v) {
            var pct = Math.round(counts[v] / total * 100);
            return '<div class="mix-legend-item"><span class="lg-swatch ' + VERDICTS[v].cls + '"></span>' +
              VERDICTS[v].label + ' <span class="lg-count">' + fmtNum(counts[v]) + '</span>' +
              '<span class="lg-pct">(' + pct + '%)</span></div>';
          }).join("")
        : '<div class="mix-legend-item">No sender history yet.</div>';
    }
    var cols = chartColors();
    var canvas = document.getElementById("senderAssessChart");
    if (canvas && typeof Chart !== "undefined") {
      var data = order.map(function (v) { return counts[v]; });
      var colors = [cols.clean, cols.suspicious, cols.malicious];
      if (senderAssessChartInst) {
        senderAssessChartInst.data.datasets[0].data = data;
        senderAssessChartInst.data.datasets[0].backgroundColor = colors;
        senderAssessChartInst.update();
      } else {
        senderAssessChartInst = new Chart(canvas, {
          type: "doughnut",
          data: {
            labels: ["Clean", "Suspicious", "Malicious"],
            datasets: [{ data: data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
              legend: { display: false },
              tooltip: {
                callbacks: {
                  label: function (ctx) {
                    var n = ctx.parsed || 0;
                    var p = total ? Math.round(n / total * 100) : 0;
                    return " " + ctx.label + ": " + fmtNum(n) + " senders (" + p + "%)";
                  }
                }
              }
            },
            onClick: function (_ev, els) {
              if (!els || !els.length) return;
              var idx = els[0].index;
              var key = order[idx];
              state.senderAssessFilter = state.senderAssessFilter === key ? "all" : key;
              renderSenderAssessment();
              renderSenderProfiles();
            }
          }
        });
      }
    }
    var scatter = document.getElementById("senderHostilityChart");
    var hostLabel = document.getElementById("senderHostilityLabel");
    if (hostLabel) {
      var hostileN = counts.SUSPICIOUS + counts.MALICIOUS;
      hostLabel.textContent = hostileN
        ? fmtNum(hostileN) + " with at least one hostile email"
        : (total ? "No hostile emails in this window" : "");
    }
    if (scatter && typeof Chart !== "undefined") {
      var grouped = { CLEAN: [], SUSPICIOUS: [], MALICIOUS: [] };
      all.forEach(function (p) {
        var emails = senderCopies(p);
        if (!emails) return;
        var rate = Math.round((Number(p.hostile_rate) || 0) * 1000) / 10;
        grouped[senderAssessmentOf(p)].push({
          x: emails,
          y: rate,
          sender: p.sender
        });
      });
      var datasets = [
        { label: "Clean", data: grouped.CLEAN, backgroundColor: cols.clean, pointRadius: 5, pointHoverRadius: 7 },
        { label: "Suspicious", data: grouped.SUSPICIOUS, backgroundColor: cols.suspicious, pointRadius: 6, pointHoverRadius: 8 },
        { label: "Malicious", data: grouped.MALICIOUS, backgroundColor: cols.malicious, pointRadius: 7, pointHoverRadius: 9 }
      ];
      if (senderHostilityChartInst) {
        senderHostilityChartInst.data.datasets = datasets;
        senderHostilityChartInst.update();
      } else {
        senderHostilityChartInst = new Chart(scatter, {
          type: "scatter",
          data: { datasets: datasets },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: {
                callbacks: {
                  label: function (ctx) {
                    var d = ctx.raw || {};
                    return " " + (d.sender || ctx.dataset.label) + " · " + d.x + " emails · " + d.y + "% hostile";
                  }
                }
              }
            },
            scales: {
              x: {
                title: { display: true, text: "Emails scored", color: chartInk() },
                ticks: { color: chartInk() },
                grid: { color: "rgba(148,163,184,0.18)" },
                beginAtZero: true
              },
              y: {
                title: { display: true, text: "Hostile emails (%)", color: chartInk() },
                ticks: { color: chartInk(), callback: function (v) { return v + "%"; } },
                grid: { color: "rgba(148,163,184,0.18)" },
                min: 0,
                max: 100
              }
            },
            onClick: function (_ev, els) {
              if (!els || !els.length) return;
              var ds = senderHostilityChartInst.data.datasets[els[0].datasetIndex];
              var pt = ds && ds.data[els[0].index];
              if (pt && pt.sender) selectSenderProfile(pt.sender);
            }
          }
        });
      }
    }
  }
  function renderSenderProfiles() {
    var body = document.getElementById("senderProfileBody");
    var empty = document.getElementById("senderProfileEmpty");
    var items = filteredSenderProfiles();
    if (body) {
      if (!items.length) {
        body.innerHTML = "";
        if (empty) {
          empty.style.display = "block";
          empty.textContent = (state.senderProfiles || []).length
            ? "No senders match this filter."
            : "No sender history yet.";
        }
      } else {
        if (empty) empty.style.display = "none";
        body.innerHTML = items.map(function (p) {
          var n = senderCopies(p);
          var ready = !!(p.ready || (Number(p.n) || 0) >= (state.senderProfileMinN || 5));
          var selected = p.sender === state.senderProfileSelected ? " is-selected" : "";
          var sent = Number(p.sent_count) || n;
          var recv = Number(p.received_count) || 0;
          return "<tr class='" + selected + "' data-sender='" + escapeHtml(p.sender) + "'>" +
            "<td class='cell-from'><span class='addr-email'>" + escapeHtml(p.sender) + "</span>" +
              (senderLaneHtml(p) ? "<div class='addr'>" + senderLaneHtml(p) + "</div>" : "") + "</td>" +
            "<td>" + riskChip(p.ai_risk) + "</td>" +
            "<td>" + senderMixBarHtml(p) + "</td>" +
            "<td class='cell-score'>" + fmtNum(sent) + "</td>" +
            "<td class='cell-score'>" + fmtNum(recv) + "</td>" +
            "<td>" + escapeHtml(networkRoleLabel(p.majority_role)) + "</td>" +
            "<td>" + escapeHtml(freqValues(p.countries, 3).join(", ") || "—") + "</td>" +
            "<td>" + escapeHtml(freqValues(p.asns, 2).join(", ") || "—") + "</td>" +
            "<td>" + Math.round((Number(p.vpn_rate) || 0) * 100) + "%</td>" +
            "<td><span class='" + (ready ? "baseline-ready" : "baseline-learning") + "'>" +
              (ready ? "Ready" : ("Learning " + fmtNum(Number(p.n) || 0) + "/" + fmtNum(state.senderProfileMinN || 5))) +
            "</span></td></tr>";
        }).join("");
        Array.prototype.forEach.call(body.querySelectorAll("tr[data-sender]"), function (row) {
          row.addEventListener("click", function () { selectSenderProfile(row.getAttribute("data-sender")); });
        });
      }
    }
    renderSenderProfileDetail();
  }
  function selectSenderProfile(addr) {
    state.senderProfileSelected = addr || "";
    state.senderProfileDetail = null;
    renderSenderProfiles();
    if (!addr) return;
    fetch("/api/sender-profiles/by-address?sender=" + encodeURIComponent(addr), { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (state.senderProfileSelected !== addr) return;
        state.senderProfileDetail = data;
        renderSenderProfileDetail();
      })
      .catch(function () {});
  }
  function renderSenderProfileDetail() {
    var el = document.getElementById("senderProfileDetail");
    if (!el) return;
    var addr = state.senderProfileSelected;
    if (!addr) {
      el.innerHTML = "<div class='empty-state'>Select a sender to see what they typically send and receive, who they talk to, and where from.</div>";
      return;
    }
    var data = state.senderProfileDetail;
    if (!data) {
      el.innerHTML = "<div class='empty-state'>Loading baseline for " + escapeHtml(addr) + "…</div>";
      return;
    }
    var prof = data.profile || {};
    var n = Number(prof.n) || 0;
    var ready = !!data.ready;
    var minN = data.min_n || state.senderProfileMinN || 5;
    var assess = senderAssessmentOf(data);
    var v = senderVerdicts(data);
    var emails = senderCopies(data);
    var usual = ready
      ? (networkRoleLabel(prof.majority_role) + " · " + (freqValues(prof.countries, 4).join(", ") || "unknown") +
        " · " + (freqValues(prof.asns, 4).join(", ") || "unknown") +
        " · " + Math.round((Number(prof.vpn_rate) || 0) * 100) + "% VPN")
      : ("Not enough CLEAN/LOW history yet (" + fmtNum(n) + "/" + fmtNum(minN) + ").");
    var obs = data.observations || [];
    var obsHtml = obs.length
      ? obs.map(function (o) {
          var bits = [networkRoleLabel(o.network_role), o.country, o.asn].filter(Boolean);
          if (o.vpn) bits.push("VPN/proxy");
          return "<div class='sender-profile-obs-row'>" +
            escapeHtml(bits.join(" · ") || "No origin intel on this email") +
            "<div class='sender-profile-obs-meta'>" + escapeHtml(fmtUnix(o.seen_at)) +
            (o.mailbox ? " · " + escapeHtml(o.mailbox) : "") +
            (o.verdict ? " · " + escapeHtml(o.verdict) : "") +
            "</div></div>";
        }).join("")
      : "<div class='empty-state'>No stored hops for this address.</div>";
    var note = String(data.assessment_note || "").trim();
    var hostile = (v.SUSPICIOUS || 0) + (v.MALICIOUS || 0);
    var sent = Number(data.sent_count);
    if (!sent) sent = emails;
    var recv = Number(data.received_count) || 0;
    var volTotal = sent + recv;
    var sentPct = volTotal ? Math.round(sent / volTotal * 100) : 100;
    var recvPct = volTotal ? 100 - sentPct : 0;
    var risk = String(data.ai_risk || "").toUpperCase();
    var factors = data.ai_factors || [];
    var factorHtml = factors.length
      ? "<ul class='sender-risk-factors'>" + factors.map(function (f) {
          var dir = String((f && f.direction) || "context");
          return "<li class='sr-" + escapeHtml(dir) + "'>" +
            "<span class='sr-dir'>" + escapeHtml(dir.replace(/_/g, " ")) + "</span> " +
            escapeHtml((f && f.detail) || "") + "</li>";
        }).join("") + "</ul>"
      : "";
    var posture = String(data.ai_posture || "").replace(/_/g, " ");
    var provider = data.ai_provider || "";
    var model = data.ai_model || "";
    var conf = data.ai_confidence || "";
    el.innerHTML =
      "<h2>" + escapeHtml(addr) + "</h2>" +
      "<div class='card-sub'>" + riskChip(risk) + " · " + chip(assess) +
        (senderLaneHtml(data) ? " · " + senderLaneHtml(data) : "") +
        (hostile ? " · " + fmtNum(hostile) + " hostile emails" : "") +
        "</div>" +
      "<div class='sender-vol'>" +
        "<div class='sender-vol-nums'>" +
          "<div><span class='sender-vol-n'>" + fmtNum(sent) + "</span> sent</div>" +
          "<div><span class='sender-vol-n'>" + fmtNum(recv) + "</span> received</div>" +
          "<div><span class='sender-vol-n'>" + fmtNum(Number(data.mailbox_targets) || 0) + "</span> mailboxes</div>" +
        "</div>" +
        "<div class='sender-mix sender-vol-bar' title='Sent vs received'>" +
          "<span class='v-sent' style='width:" + sentPct + "%'></span>" +
          "<span class='v-recv' style='width:" + recvPct + "%'></span>" +
        "</div>" +
        "<div class='card-sub'>Sent is mail this From originated. Received is mail delivered to this address when it is a mailbox we poll. External received=0 is expected.</div>" +
      "</div>" +
      "<div class='sender-habits'>" +
        "<div><h3>Typical asks (sends)</h3>" + mixChipsHtml(data.request_mix || prof.request_mix, "No classified asks yet.") + "</div>" +
        "<div><h3>Typical asks (receives)</h3>" + mixChipsHtml(data.receive_mix, "No inbound mix — expected for external senders.") + "</div>" +
        "<div><h3>Writes to</h3>" + peerListHtml(data.sent_to, "No counterparties recorded yet.") + "</div>" +
        "<div><h3>Receives from</h3>" + peerListHtml(data.received_from, "No inbound peers — expected for external senders.") + "</div>" +
      "</div>" +
      "<h3>When they send (UTC)</h3>" +
      hoursBarHtml(data.hours || prof.hours) +
      "<div class='card-sub'>" +
        Math.round((Number(data.attachment_rate) || 0) * 100) + "% of emails have attachments · " +
        Math.round((Number(data.reply_rate) || 0) * 100) + "% are replies" +
        (data.burst && data.burst.days_active
          ? " · busiest day " + fmtNum(Number(data.burst.max_day) || 0) + " emails across " + fmtNum(data.burst.days_active) + " active days"
          : "") +
      "</div>" +
      (data.ai_summary
        ? "<div class='sender-risk-narrative'><h3>AI assessment</h3><p>" + escapeHtml(data.ai_summary) + "</p>" +
          "<div class='card-sub'>" +
            (posture ? escapeHtml(posture) + " · " : "") +
            (conf ? "confidence " + escapeHtml(conf) + " · " : "") +
            "score " + fmtNum(Number(data.ai_score) || 0) +
            (provider ? " · " + escapeHtml(provider) : "") +
            (model ? " " + escapeHtml(model) : "") +
            " — advisory, not a message verdict" +
          "</div>" + factorHtml + "</div>"
        : "<div class='card-sub'>AI identity risk will appear after the sender-risk worker’s first pass.</div>") +
      (note ? "<p class='card-sub'>" + escapeHtml(note) + "</p>" : "") +
      senderMixBarHtml(data) +
      "<div class='card-sub' style='margin-top:10px;'>" +
        (ready ? fmtNum(n) + " CLEAN/LOW emails in the last 6 months" : "Learning — " + fmtNum(n) + " of " + fmtNum(minN) + " CLEAN/LOW emails") +
      "</div>" +
      "<dl class='origin-intel origin-intel-inline'>" +
        "<dt>Usual</dt><dd>" + escapeHtml(usual) + "</dd>" +
        "<dt>Auth</dt><dd>SPF " + escapeHtml((freqValues(prof.spf, 1)[0] || "—")) +
          " · DKIM " + escapeHtml((freqValues(prof.dkim, 1)[0] || "—")) + "</dd>" +
      "</dl>" +
      (data.summary ? "<p class='card-sub'>" + escapeHtml(data.summary) + "</p>" : "") +
      "<button type='button' class='btn btn-sm' id='senderProfileShowMail'>Show mail from this sender</button>" +
      "<div class='sender-profile-obs'>" + obsHtml + "</div>";
    var showMail = document.getElementById("senderProfileShowMail");
    if (showMail) {
      showMail.addEventListener("click", function () {
        state.feedSearch = addr;
        var inp = document.getElementById("feedSearch");
        if (inp) inp.value = addr;
        setPage("overview");
        renderFeed();
      });
    }
  }

  function campaignKindLabel(kind) {
    var map = {
      hash: "Shared payload",
      url_path: "Shared landing URL",
      url_host: "Shared URL host",
      content: "Shared template",
      subj: "Shared subject",
      msgid: "Fan-out",
      mixed: "Mixed pivots"
    };
    return map[kind] || kind || "cluster";
  }
  function campaignAttackLabel(cls) {
    var map = {
      credential_theft: "Credential theft",
      bec: "Business email compromise",
      malware_delivery: "Malware delivery",
      callback_scam: "Callback / vishing",
      extortion: "Extortion",
      steal_pii: "PII harvesting",
      job_scam: "Job scam",
      ransomware: "Ransomware",
      reconnaissance: "Reconnaissance",
      mixed: "Mixed classes",
      unknown: "Unclassified"
    };
    return map[cls] || cls || "";
  }
  function isCampaignInternalId(s) {
    var t = String(s || "").trim();
    if (!t) return true;
    if (/^cam-[a-f0-9]{8,}$/i.test(t)) return true;
    if (/^(hash|url_path|url_host|content|subj|msgid):/i.test(t)) return true;
    if (/^[a-f0-9]{32,}$/i.test(t)) return true;
    return false;
  }
  function campaignTitle(c) {
    c = c || {};
    var candidates = [c.ai_title, (c.subjects && c.subjects[0])];
    var i, title;
    for (i = 0; i < candidates.length; i++) {
      title = String(candidates[i] || "").replace(/\s+/g, " ").trim();
      if (title && !isCampaignInternalId(title)) {
        if (title.length > 72) title = title.slice(0, 69) + "…";
        return title;
      }
    }
    return campaignKindLabel(c.kind);
  }
  function campaignQueueId(dest) {
    var s = String(dest || "");
    var slash = s.indexOf("/");
    return slash >= 0 ? s.slice(slash + 1) : s;
  }
  function filteredCampaigns(): any[] {
    var q = (state.campaignQuery || "").trim().toLowerCase();
    return (state.campaigns || []).filter(function (c) {
      if (state.campaignFlaggedOnly && !(Number(c.flagged) > 0)) return false;
      if (!q) return true;
      var hay = [c.id, c.kind, c.pattern, campaignKindLabel(c.kind), c.ai_title, c.ai_summary, c.attack_class]
        .concat(c.subjects || [])
        .concat(c.sender_list || [])
        .join(" ").toLowerCase();
      return hay.indexOf(q) !== -1;
    });
  }
  function renderCampaigns() {
    var all = state.campaigns || [];
    var flaggedN = all.filter(function (c) { return Number(c.flagged) > 0; }).length;
    var navN = document.getElementById("navCampaignsCount");
    if (navN) {
      navN.textContent = fmtNum(all.length);
      navN.dataset.zero = all.length === 0;
    }
    var statsEl = document.getElementById("campaignStatGrid");
    if (statsEl) {
      var emails = all.reduce(function (n, c) { return n + (Number(c.members) || 0); }, 0);
      var senders = all.reduce(function (n, c) { return n + (Number(c.senders) || 0); }, 0);
      statsEl.innerHTML = [
        { label: "Clusters", value: all.length, sub: "shared URL, hash, or template", accentVar: "var(--accent)" },
        { label: "With flagged emails", value: flaggedN, sub: "SUSPICIOUS or MALICIOUS members", accentVar: "var(--status-serious)" },
        { label: "Member emails", value: emails, sub: fmtNum(senders) + " distinct senders", accentVar: "var(--status-good)" }
      ].map(function (t) {
        return '<div class="stat-tile" style="--tile-accent:' + t.accentVar + '">' +
          '<div class="stat-label">' + t.label + "</div>" +
          '<div class="stat-value mono">' + fmtNum(t.value) + "</div>" +
          '<div class="stat-sub">' + t.sub + "</div></div>";
      }).join("");
    }
    var items = filteredCampaigns();
    var body = document.getElementById("campaignBody");
    var empty = document.getElementById("campaignEmpty");
    if (body) {
      if (!items.length) {
        body.innerHTML = "";
        if (empty) {
          empty.style.display = "block";
          empty.textContent = all.length
            ? "No clusters match this filter."
            : "No clusters yet. The campaign worker needs at least two related emails.";
        }
      } else {
        if (empty) empty.style.display = "none";
        body.innerHTML = items.map(function (c) {
          var selected = c.id === state.campaignSelected ? " is-selected" : "";
          return "<tr class='" + selected + "' data-campaign='" + escapeHtml(c.id) + "'>" +
            "<td><span class='addr-email'>" + escapeHtml(campaignTitle(c)) + "</span>" +
              "<div class='addr'>" + escapeHtml(campaignKindLabel(c.kind)) + "</div></td>" +
            "<td>" + escapeHtml(campaignAttackLabel(c.attack_class) || "—") + "</td>" +
            "<td class='cell-score'>" + fmtNum(Number(c.members) || 0) + "</td>" +
            "<td class='cell-score'>" + fmtNum(Number(c.senders) || 0) + "</td>" +
            "<td class='cell-score'>" + fmtNum(Number(c.flagged) || 0) + "</td></tr>";
        }).join("");
        Array.prototype.forEach.call(body.querySelectorAll("tr[data-campaign]"), function (row) {
          row.addEventListener("click", function () {
            state.campaignSelected = row.getAttribute("data-campaign") || "";
            renderCampaigns();
          });
        });
      }
    }
    renderCampaignDetail();
  }
  function renderCampaignDetail() {
    var el = document.getElementById("campaignDetail");
    if (!el) return;
    var id = state.campaignSelected;
    if (!id) {
      el.innerHTML = "<div class='empty-state'>Select a cluster to see shared landing pages, payloads, or templates.</div>";
      return;
    }
    var c = (state.campaigns || []).filter(function (x) { return x.id === id; })[0];
    if (!c) {
      el.innerHTML = "<div class='empty-state'>Cluster " + escapeHtml(id) + " is not in the current list.</div>";
      return;
    }
    var senders = c.sender_list || [];
    var boxes = c.mailbox_list || [];
    var dests = c.dests || [];
    var subjects = c.subjects || [];
    el.innerHTML =
      "<h2>" + escapeHtml(campaignTitle(c)) + "</h2>" +
      "<div class='card-sub'>" + escapeHtml(campaignKindLabel(c.kind)) +
        " — reference only, does not change the score</div>" +
      "<div class='sender-vol'>" +
        "<div class='sender-vol-nums'>" +
          "<div><span class='sender-vol-n'>" + fmtNum(Number(c.members) || 0) + "</span> emails</div>" +
          "<div><span class='sender-vol-n'>" + fmtNum(Number(c.senders) || 0) + "</span> senders</div>" +
          "<div><span class='sender-vol-n'>" + fmtNum(Number(c.flagged) || 0) + "</span> flagged</div>" +
        "</div>" +
      "</div>" +
      "<dl class='origin-intel origin-intel-inline'>" +
        "<dt>Mailboxes</dt><dd>" + fmtNum(Number(c.mailboxes) || 0) + "</dd>" +
      "</dl>" +
      (subjects.length ? "<h3>Subjects</h3><ul class='sender-peer-list'>" +
        subjects.map(function (s) { return "<li>" + escapeHtml(s) + "</li>"; }).join("") + "</ul>" : "") +
      (senders.length ? "<h3>Senders</h3><ul class='sender-peer-list'>" +
        senders.map(function (s) { return "<li><span class='addr-email'>" + escapeHtml(s) + "</span></li>"; }).join("") + "</ul>" : "") +
      (boxes.length ? "<h3>Mailboxes</h3><ul class='sender-peer-list'>" +
        boxes.map(function (s) { return "<li><span class='addr-email'>" + escapeHtml(s) + "</span></li>"; }).join("") + "</ul>" : "") +
      "<h3>Member emails</h3>" +
      (dests.length
        ? "<div class='sender-chip-list'>" + dests.map(function (d) {
            var qid = campaignQueueId(d);
            var inFeed = !!findEmail(qid);
            return inFeed
              ? "<button type='button' class='wk-qid' data-qid='" + escapeHtml(qid) + "'>" + escapeHtml(qid) + "</button>"
              : "<span class='sender-chip'>" + escapeHtml(qid) + "</span>";
          }).join("") + "</div>"
        : "<div class='card-sub'>No stored dests on this cluster.</div>") +
      "<div class='card-sub' style='margin-top:12px;'>Open an email in the feed, or search the subject from Overview.</div>";
    Array.prototype.forEach.call(el.querySelectorAll(".wk-qid"), function (btn) {
      btn.addEventListener("click", function () { openDetailPage(btn.getAttribute("data-qid")); });
    });
  }

  /* ============================== DRAWER ============================== */
  function findEmail(id) {
    var want = String(id || "");
    if (!want) return undefined;
    var pools = [state.feed, state.filteredFeed, state.searchHits, state.pinnedFeed];
    for (var p = 0; p < pools.length; p++) {
      var list = pools[p];
      if (!Array.isArray(list)) continue;
      for (var i = 0; i < list.length; i++) {
        var e = list[i];
        if (e && (e.id === want || e.queueId === want)) return e;
      }
    }
    return undefined;
  }

  function mergePinnedFeed(primary, extra) {
    var seen = {};
    var out = [];
    (primary || []).concat(extra || []).forEach(function (e) {
      var k = String((e && (e.id || e.queueId)) || "");
      if (!k || seen[k]) return;
      seen[k] = true;
      out.push(e);
    });
    return out;
  }

  function loadFeedItem(queueId) {
    var id = String(queueId || "").trim();
    if (!id) return Promise.resolve(false);
    return fetch("/api/feed/item/" + encodeURIComponent(id), { credentials: "same-origin" })
      .then(function (r) {
        if (r.status === 404) return null;
        if (!r.ok) throw new Error("Could not load message");
        return r.json();
      })
      .then(function (body) {
        var entries = (body && body.entries) || [];
        state.pinnedFeed = entries;
        state.feed = mergePinnedFeed(state.feed, entries);
        if (typeof ui.onData === "function") ui.onData({});
        return entries.length > 0;
      })
      .catch(function () { return false; });
  }

  function iocBlockHtml(label, values, context) {
    if (!values || !values.length) return '<div class="ioc-block"><div class="ib-label">' + label + '</div><div class="ioc-empty">none observed</div></div>';
    return '<div class="ioc-block"><div class="ib-label">' + label + "</div>" +
      values.map(function (v) {
        var note = context[v];
        return '<div class="ioc-item">' + escapeHtml(v) + (note ? '<span class="ib-note">⚠ ' + escapeHtml(note) + "</span>" : "") + "</div>";
      }).join("") + "</div>";
  }

  function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
  function padStart(s, n) { s = String(s); while (s.length < n) s = " " + s; return s; }

  // Mirrors app/report.py's text_report() format exactly, for the "Copy as
  // text report" action — a SOC analyst can paste this straight into a
  // ticket the same way they would CLI output from analyze.py.
  function buildTextReport(e) {
    var lines = [];
    var bar = new Array(65).join("=");
    lines.push(bar);
    if (isAiPending(e)) {
      lines.push("  VERDICT: ASSESSING — waiting on LLM");
      lines.push("  (heuristic score withheld until the AI assessment finishes)");
    } else if (isAiTimedOut(e)) {
      lines.push("  VERDICT: INCONCLUSIVE — LLM timed out; retrying automatically");
    } else {
      var margin = e.hardOverride ? "" : "  (" + verdictMargin(e.verdict, e.score) + ")";
      lines.push("  VERDICT: " + e.verdict + "   score=" + e.score + margin);
    }
    if (e.hardOverride) lines.push("  HARD OVERRIDE: " + e.hardOverride + " — " + describeFlag(e.hardOverride));
    lines.push(bar);
    lines.push("From    : \"" + e.fromName + "\" <" + e.fromAddr + ">");
    lines.push("To      : " + (e.toAddr || e.mailbox || "—"));
    lines.push("Subject : " + e.subject);
    lines.push("Source  : " + (
      e.sourceKind === "sample" ? "file (" + e.sourceFile + ")" :
      e.sourceKind === "gmail" ? "Gmail INBOX" + (e.mailbox ? " (" + e.mailbox + ")" : "") :
      "gateway/spool/" + e.bucket + "/" + e.queueId
    ));
    lines.push("");
    var aiFacts = contentAiFacts(e);
    var aiSummary = isLlmAssessment(e) ? aiFacts.summary : "";
    var modelLabel = formatLlmModel(aiFacts.model, aiFacts.provider);
    if (e.hasStageDetail) {
      lines.push("Stages:");
      STAGE_ORDER.forEach(function (name) {
        var s = e.stages[name];
        if (!s) return;
        var flags = (s.flags && s.flags.length) ? s.flags.join(", ") : "-";
        lines.push("  [" + padStart(s.status, 8) + "] " + pad(name, 12) + " score=" + padStart(s.score.toFixed(1), 5) + "  " + flags);
        if (name === "content_ai" && isLlmAssessment(e) && s.summary) aiSummary = s.summary;
      });
    } else {
      lines.push("Stages: not available for previously-processed mail (meta.json summary only) — use Re-evaluate for a fresh, fully-detailed run.");
    }
    lines.push("");
    if (aiSummary) {
      lines.push("AI assessment" + (modelLabel ? " [" + modelLabel + "]" : "") + ": " + aiSummary);
      var st = bodyStructureFromEntry(e);
      if (st.isForwarded || st.isReply || st.primaryContent || st.footerAssessment) {
        lines.push("Message structure: " +
          (st.isForwarded ? "forwarded" : st.isReply ? "reply" : "original") +
          "; footer " + (st.footerWorthAssessing ? "worth assessing" : "not scored"));
        if (st.footerAssessment) lines.push("Footer assessment: " + st.footerAssessment);
      }
      lines.push("");
    }
    lines.push("Why this verdict:");
    if (e.reasons.length) e.reasons.forEach(function (f) { lines.push("  - " + describeFlag(f)); });
    else lines.push("  - No red flags fired on any stage.");
    lines.push("");
    lines.push("Reasons (raw tags): " + (e.reasons.length ? e.reasons.join(", ") : "none"));
    lines.push("");
    lines.push("IOCs:");
    lines.push("  (context in [brackets] is this analysis's own rule-based findings — NOT");
    lines.push("   a live threat-intel/reputation lookup; that provider is still a stub)");
    function block(label, values) {
      if (!values.length) { lines.push("  " + label + ": none observed"); return; }
      lines.push("  " + label + ":");
      values.forEach(function (v) {
        var note = e.iocs.context[v];
        lines.push("    - " + v + (note ? "   [" + note + "]" : ""));
      });
    }
    block("senders ", e.iocs.sender_emails);
    block("domains ", e.iocs.domains);
    block("ips     ", e.iocs.ips);
    block("urls    ", e.iocs.urls);
    block("hashes  ", e.iocs.hashes_sha256);
    block("auth relay senders", e.iocs.authenticated_relay_senders);
    return lines.join("\n");
  }

  function copyReport(id) {
    var e = findEmail(id);
    if (!e) return;
    var text = buildTextReport(e);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        toast(ICON.download, "Report copied — paste into a ticket or Wazuh note");
      }, function () { toast(ICON.download, "Couldn't access clipboard — see console"); console.log(text); });
    } else {
      console.log(text);
      toast(ICON.download, "Clipboard unavailable — report printed to console");
    }
  }

  function buildThreadStripHtml(e) {
    var sibs = threadSiblings(e);
    if (sibs.length < 2) return "";
    return '<div class="thread-strip">' +
      '<div class="thread-strip-head">' + sibs.length + " messages in this thread</div>" +
      sibs.map(function (m) {
        var active = m.id === e.id ? " is-active" : "";
        return '<button type="button" class="thread-msg' + active + '" data-thread-id="' + escapeHtml(m.id) + '">' +
          '<span class="thread-msg-verdict">' + chipForEmail(m) + "</span>" +
          '<span class="thread-msg-from">' + escapeHtml(m.fromName || m.fromAddr || "Unknown") + "</span>" +
          '<span class="thread-msg-time">' + fmtDateTime(m.ts) + "</span>" +
          '<span class="thread-msg-subject">' + escapeHtml(m.subject || "") + "</span>" +
          (isAiPending(m) && displayVerdict(m) !== "PENDING" ? aiPendingBadgeHtml() : "") +
        "</button>";
      }).join("") +
    "</div>";
  }

  function buildDetailMailHtml(e) {
    var strip = buildThreadStripHtml(e);
    var mail;
    if (e.queueId) {
      mail = '<div class="email-viewer-slot" id="fw-eml-' + escapeHtml(e.id) + '">' +
        '<div class="email-viewer-loading">Loading message…</div></div>';
    } else {
      var rows = "";
      function hrow(label, value, extraCls) {
        if (!value) return "";
        return '<div class="email-viewer-hrow' + (extraCls || "") + '">' +
          '<span class="email-viewer-label">' + label + '</span>' +
          '<span class="email-viewer-value">' + escapeHtml(value) + "</span></div>";
      }
      rows += hrow("From", (e.fromName ? e.fromName + " <" + e.fromAddr + ">" : e.fromAddr));
      rows += hrow("To", e.toAddr || e.mailbox || "");
      rows += hrow("Subject", e.subject, " email-viewer-subject");
      rows += hrow("Date", fmtDateTime(e.ts));
      mail = '<div class="email-viewer">' +
        '<div class="email-viewer-headers">' + rows + "</div>" +
        '<div class="email-viewer-body email-viewer-empty">Raw message is not retained for this sample. Use Analyze to open the EML.</div>' +
        "</div>";
    }
    return strip + mail;
  }

  function flowScoreTone(score) {
    var n = Number(score) || 0;
    if (n >= THRESHOLDS.malicious) return "critical";
    if (n >= THRESHOLDS.suspicious) return "serious";
    if (n >= THRESHOLDS.low) return "warning";
    return "good";
  }

  function flagStageGuess(flag) {
    var f = String(flag || "");
    if (/^(spf_|dkim_|dmarc_|return_path|reply_to|missing_message|missing_mime|date_anomaly|suspicious_x_mailer|display_name_)/.test(f)) return "headers";
    if (/^(lookalike_of|vip_name|brand_impersonation|sender_lookalike|freemail_corporate)/.test(f)) return "sender";
    if (/^(url_|anchor_|tracking_beacon)/.test(f)) return "urls";
    if (/^(service_abuse|deception_|trusted_channel|lure_scarcity)/.test(f)) return "deception";
    if (/^(banned_attachment|macro_|oletools_|html_attachment)/.test(f)) return "attachments";
    if (/^(threat_intel|intel_|behavioral_|profile_|first_request_|first_trusted_sender|first_time_sender)/.test(f)) return "intel";
    if (/^fanout_/.test(f)) return "fanout";
    if (/^origin_/.test(f)) return "origin_ip";
    if (/^(urgency_|credential_|bec_|generic_greeting|payment_lure|fake_reply|unusual_request|prompt_injection|forwarded_|malicious_footer|content_padding|nlu_intent|ai_|ai:)/.test(f)) return "content_ai";
    return "";
  }

  function flowStageOf(e, id) {
    return ((e && e.stages) || {})[id] || null;
  }

  function flowContribution(id, score) {
    var w = STAGE_WEIGHTS[id] || 0;
    var maxW = 20;
    return ((Number(score) || 0) / 100) * (w / maxW) * 100;
  }

  function flagsMatching(flags, keys) {
    return (flags || []).filter(function (f) {
      var s = String(f);
      var base = s.split(":")[0];
      return (keys || []).some(function (k) {
        return s === k || base === k || s.indexOf(k + ":") === 0 || s.indexOf(k + "_") === 0;
      });
    });
  }
  function hostFromUrl(u) {
    var s = String(u || "").replace(/&amp;/g, "&");
    var m = s.match(/^[a-z][a-z0-9+.-]*:\/\/([^\/?#]+)/i);
    if (m) return m[1].split("@").pop().split(":")[0].toLowerCase();
    return "";
  }
  function addrLabel(addr) {
    var a = String(addr || "");
    if (a.length <= 22) return a;
    var at = a.indexOf("@");
    if (at > 0) {
      var local = a.slice(0, at);
      var dom = a.slice(at + 1);
      if (local.length > 8) local = local.slice(0, 7) + "…";
      if (dom.length > 12) dom = "…" + dom.slice(-11);
      return local + "@" + dom;
    }
    return a.slice(0, 20) + "…";
  }
  function uniqueStrings(list) {
    var out = [];
    (list || []).forEach(function (v) {
      var s = String(v || "").trim();
      if (s && out.indexOf(s) < 0) out.push(s);
    });
    return out;
  }
  function unwrapClientHops(url) {
    var hops = [String(url || "")];
    var seen = {};
    var u = hops[0];
    var depth = 0;
    while (u && depth < 4) {
      var next = "";
      try {
        var parsed = new URL(u.replace(/&amp;/g, "&"));
        ["url", "redirect", "redirect_uri", "redirect_url", "u", "dest", "destination", "target", "next", "goto", "continue"].forEach(function (k) {
          if (next) return;
          var v = parsed.searchParams.get(k);
          if (v && /^https?:/i.test(v)) next = v;
        });
      } catch (err) {
        break;
      }
      if (!next || seen[next]) break;
      seen[next] = 1;
      hops.push(next);
      u = next;
      depth++;
    }
    return hops;
  }
  function iocUrlsOf(e) {
    var iocs = (e && e.iocs) || {};
    var urls = iocs.urls || iocs.Urls || [];
    return Array.isArray(urls) ? urls : [];
  }

  function buildFlowModel(e) {
    var recorded = !!(e && e.hasStageDetail && e.stages && Object.keys(e.stages).length);
    var nodes = {};
    var edges = [];
    var lanes = [];
    var leafIds = [];
    FLOW_SIGNALS.forEach(function (spec) {
      var st = flowStageOf(e, spec.id);
      var flags = (st && st.flags) || [];
      if (!recorded) {
        flags = (e.reasons || []).filter(function (r) { return flagStageGuess(r) === spec.id; });
      }
      nodes[spec.id] = {
        id: spec.id, label: spec.label, hint: spec.hint, kind: "signal",
        recorded: recorded && !!st,
        status: (st && st.status) || (flags.length ? "ok" : "skipped"),
        score: st ? Number(st.score) || 0 : 0,
        flags: flags,
        summary: (st && st.summary) || ""
      };
    });
    var fanSt = flowStageOf(e, "fanout") || {};
    var fanBoxes = fanSt.mailboxes || e.fanoutMailboxes || [];
    var fanRecipients = fanSt.recipients || e.fanoutRecipients || [];
    if (nodes.fanout) {
      nodes.fanout.hint = "Same mail, other inboxes";
      nodes.fanout.count = fanBoxes.length || Number(e.fanoutCount) || 0;
      nodes.fanout.mailboxes = fanBoxes;
      nodes.fanout.recipients = fanRecipients;
      if (fanSt.summary) nodes.fanout.summary = fanSt.summary;
      else if (fanBoxes.length) {
        nodes.fanout.summary = "Same message also delivered to " + fanBoxes.length +
          " other scanned inbox" + (fanBoxes.length === 1 ? "" : "es") + ": " + fanBoxes.join(", ");
      } else if (fanRecipients.length) {
        nodes.fanout.summary = "Envelope lists other recipients: " + fanRecipients.slice(0, 8).join(", ");
      }
    }
    var oiSt = flowStageOf(e, "origin_ip") || {};
    if (nodes.origin_ip) {
      nodes.origin_ip.ip = oiSt.ip || "";
      nodes.origin_ip.hostname = oiSt.hostname || "";
      nodes.origin_ip.org = oiSt.org || "";
      nodes.origin_ip.country = oiSt.country || "";
      nodes.origin_ip.countryName = oiSt.countryName || "";
      nodes.origin_ip.region = oiSt.region || "";
      nodes.origin_ip.city = oiSt.city || "";
      nodes.origin_ip.isp = oiSt.isp || "";
      nodes.origin_ip.asn = oiSt.asn || "";
      nodes.origin_ip.asName = oiSt.asName || "";
      nodes.origin_ip.timezone = oiSt.timezone || "";
      nodes.origin_ip.networkRole = oiSt.networkRole || "";
      nodes.origin_ip.networkRoleLabel = oiSt.networkRoleLabel || "";
      nodes.origin_ip.vpn = !!oiSt.vpn;
      nodes.origin_ip.hosting = !!oiSt.hosting;
      nodes.origin_ip.geoMismatch = !!oiSt.geoMismatch;
      nodes.origin_ip.suspicion = oiSt.suspicion || "";
      nodes.origin_ip.suspicionReason = oiSt.suspicionReason || "";
      nodes.origin_ip.searchSummary = oiSt.searchSummary || "";
      nodes.origin_ip.xOriginatingIp = oiSt.xOriginatingIp || "";
      var locHint = [oiSt.city, oiSt.country].filter(Boolean).join(", ");
      nodes.origin_ip.hint = locHint || oiSt.networkRoleLabel || "Geo / ISP / VPN";
      if (oiSt.summary) nodes.origin_ip.summary = oiSt.summary;
      else if (nodes.origin_ip.ip) {
        nodes.origin_ip.summary = nodes.origin_ip.ip +
          (locHint ? " — " + locHint : "") +
          (nodes.origin_ip.isp ? " · " + nodes.origin_ip.isp : "") +
          (nodes.origin_ip.vpn ? " · VPN/proxy" : "") +
          (nodes.origin_ip.searchSummary ? ". " + nodes.origin_ip.searchSummary : "");
      }
    }
    var intelSt = flowStageOf(e, "intel") || {};
    if (nodes.intel) {
      nodes.intel.profile = intelSt.profile || {};
      nodes.intel.profileDelta = intelSt.profileDelta || intelSt.profile_delta || [];
      nodes.intel.profileSummary = intelSt.profileSummary || intelSt.profile_summary || "";
      nodes.intel.requestClass = intelSt.requestClass || intelSt.request_class || "";
      nodes.intel.requestSummary = intelSt.requestSummary || intelSt.request_summary || "";
      nodes.intel.trustedChannel = !!(intelSt.trustedChannel || intelSt.trusted_channel);
      var thisOi = originStageOf(e);
      nodes.intel.thisCopy = {
        asn: thisOi.asn || "",
        country: thisOi.country || "",
        vpn: !!thisOi.vpn,
        networkRole: thisOi.networkRoleLabel || thisOi.networkRole || "",
        isp: thisOi.isp || ""
      };
      var behavHits = intelSt.behavioralHits || intelSt.behavioral_hits || [];
      behavHits.forEach(function (f) {
        if (String(f).indexOf("profile_") === 0 && nodes.intel.flags.indexOf(f) < 0) {
          nodes.intel.flags = nodes.intel.flags.concat([f]);
        }
        if (/^first_request_|^first_trusted_sender/.test(String(f)) && nodes.intel.flags.indexOf(f) < 0) {
          nodes.intel.flags = nodes.intel.flags.concat([f]);
        }
      });
      var campHits = intelSt.campaignHits || intelSt.campaign_hits || [];
      campHits.forEach(function (f) {
        if (String(f).indexOf("campaign_") === 0 && nodes.intel.flags.indexOf(f) < 0) {
          nodes.intel.flags = nodes.intel.flags.concat([f]);
        }
      });
    }
    var urlSt = flowStageOf(e, "urls") || {};
    if (nodes.urls) {
      nodes.urls.linkHops = Array.isArray(urlSt.linkHops) ? urlSt.linkHops : [];
      nodes.urls.linkHopCount = Number(urlSt.linkHopCount) || 0;
      if (nodes.urls.linkHopCount >= 2) {
        nodes.urls.hint = nodes.urls.linkHopCount + "-hop redirect";
      }
    }
    var cai = flowStageOf(e, "content_ai") || {};
    var aiFacts = contentAiFacts(e);
    var pending = isAiPending(e);
    var timed = isAiTimedOut(e);
    nodes.content_ai = {
      id: "content_ai", label: "LLM",
      hint: pending ? "In progress" : (timed ? "Retrying automatically" : "Advisory content review"),
      kind: "llm",
      recorded: recorded,
      pending: pending,
      retrying: timed,
      status: cai.status || (isLlmAssessment(e) ? "ok" : (pending || timed ? "pending" : "skipped")),
      score: Number(cai.score) || 0,
      flags: cai.flags || (e.reasons || []).filter(function (r) { return flagStageGuess(r) === "content_ai"; }),
      summary: (isLlmAssessment(e) ? aiFacts.summary : "") || cai.summary || "",
      provider: aiFacts.provider || cai.provider || "",
      model: aiFacts.model || cai.modelId || "",
      nluIntent: cai.nluIntent || e.threatClass || "",
      nluConfidence: cai.nluConfidence || e.threatConfidence || 0,
      scoreCapped: !!cai.scoreCapped,
      degraded: !!cai.degraded
    };
    var shown = displayVerdict(e);
    var final = shown !== "PENDING" && shown !== "INCONCLUSIVE";
    nodes.verdict = {
      id: "verdict",
      label: shown === "PENDING" ? "Assessing" : (shown === "INCONCLUSIVE" ? "Inconclusive" : (e.verdict || "CLEAN")),
      hint: final ? "Weighted decision" : (shown === "INCONCLUSIVE" ? "Retrying automatically" :
        (pipelineStatusOf(e) === "queued" ? "Waiting for static checks" :
          (pipelineStatusOf(e) === "static" ? "Static checks in progress" : "Waiting on LLM"))),
      kind: "verdict",
      recorded: true,
      pending: false,
      awaiting: !final,
      status: final ? "ok" : "pending",
      score: final ? (Number(e.score) || 0) : 0,
      flags: e.reasons || [],
      summary: shown === "INCONCLUSIVE"
        ? "The first attempt timed out. Another attempt is queued automatically."
        : (!final
        ? "Verdict and score stay hidden until the LLM finishes."
        : (e.hardOverride
          ? "Hard override: " + e.hardOverride
          : (nodes.content_ai.nluIntent && nodes.content_ai.nluIntent !== "none"
            ? "Threat class " + nodes.content_ai.nluIntent
            : ""))),
      hardOverride: e.hardOverride || ""
    };
    nodes.mail = {
      id: "mail",
      label: "This email",
      hint: (e && e.subject) ? String(e.subject).slice(0, 42) : "Message under review",
      kind: "mail",
      recorded: true,
      score: final ? (Number(e.score) || 0) : 0,
      flags: e.reasons || [],
      summary: (e && e.fromAddr ? e.fromAddr : "unknown sender") +
        (e && e.mailbox ? " → " + e.mailbox : "")
    };

    var overrideFrom = e.hardOverride ? (flagStageGuess(e.hardOverride) || "") : "";
    var claimed = {};

    function addLeaf(parent, id, spec) {
      spec = spec || {};
      nodes[id] = {
        id: id,
        label: spec.label || id,
        hint: spec.hint || "",
        kind: spec.kind || "check",
        recorded: true,
        status: spec.status || "ok",
        score: spec.score || 0,
        flags: spec.flags || [],
        summary: spec.summary || "",
        parent: parent,
        addr: spec.addr || "",
        host: spec.host || "",
        suspicious: !!spec.suspicious,
        hopIndex: spec.hopIndex,
        hopCount: spec.hopCount,
        chainKind: spec.chainKind || "",
        empty: !!spec.empty
      };
      leafIds.push(id);
      edges.push({
        from: spec.from || parent,
        to: id,
        kind: spec.edgeKind || "branch",
        weight: spec.score ? Math.max(14, spec.score) : 10
      });
      return id;
    }
    function addChecks(parent, catalog, flags) {
      var ids = [];
      (catalog || []).forEach(function (chk) {
        var hits = flagsMatching(flags, chk.match);
        hits.forEach(function (f) { claimed[f] = 1; });
        ids.push(addLeaf(parent, "chk_" + parent + "_" + chk.key, {
          label: chk.label,
          hint: hits.length ? "Finding" : "Checked — no finding",
          kind: "check",
          score: hits.length ? 36 : 0,
          flags: hits,
          summary: hits.length
            ? hits.map(describeFlag).join(" ")
            : chk.hint + " was evaluated and did not fire."
        }));
      });
      (flags || []).forEach(function (f, i) {
        if (claimed[f] || ORIGIN_INFO_FLAG.test(f) || /^origin_ip:/.test(f) || /^nlu_intent/.test(f)) return;
        if (flagStageGuess(f) && flagStageGuess(f) !== parent && parent !== "content_ai") return;
        ids.push(addLeaf(parent, "chk_" + parent + "_flag_" + i, {
          label: String(f).split(":")[0].replace(/_/g, " ").slice(0, 18),
          hint: "Finding",
          kind: "check",
          score: 32,
          flags: [f],
          summary: describeFlag(f)
        }));
        claimed[f] = 1;
      });
      return ids;
    }

    addChecks("headers", HEADER_CHECKS, nodes.headers.flags);
    if (nodes.origin_ip) {
      var oi = nodes.origin_ip;
      if (oi.ip) {
        addLeaf("origin_ip", "chk_oi_ip", {
          label: oi.ip, hint: oi.hostname || "Sending MTA", kind: "check",
          summary: oi.ip + (oi.hostname ? " (" + oi.hostname + ")" : "")
        });
      }
      var loc = [oi.city, oi.region, oi.countryName || oi.country].filter(Boolean).join(", ");
      addLeaf("origin_ip", "chk_oi_loc", {
        label: loc ? hopHostLabel(oi.city || oi.country || loc) : "No geo",
        hint: "Location", kind: "check",
        summary: loc || "Geolocation was not available for this hop."
      });
      addLeaf("origin_ip", "chk_oi_isp", {
        label: (oi.isp || oi.org || "ISP").slice(0, 18),
        hint: oi.asn || "ISP / ASN", kind: "check",
        summary: [oi.isp || oi.org, oi.asn, oi.asName].filter(Boolean).join(" · ") || "ISP was not looked up."
      });
      addLeaf("origin_ip", "chk_oi_net", {
        label: (oi.networkRoleLabel || "Unknown").slice(0, 18),
        hint: "Network role", kind: "check",
        summary: oi.networkRoleLabel || "Role was not classified."
      });
      addLeaf("origin_ip", "chk_oi_vpn", {
        label: oi.vpn ? "VPN likely" : "Not a VPN",
        hint: "VPN / proxy", kind: "check",
        score: oi.vpn ? 48 : 0,
        flags: oi.vpn ? ["origin_ip_vpn"] : [],
        summary: oi.vpn ? "This hop matches VPN/proxy infrastructure." : "No VPN/proxy indication on this hop."
      });
      if (oi.hosting) {
        addLeaf("origin_ip", "chk_oi_hosting", {
          label: "Cloud / VPS",
          hint: "Network role", kind: "empty", empty: true,
          summary: "This hop is cloud or VPS infrastructure. That is normal for many SaaS and marketing senders, not a VPN/proxy finding."
        });
      }
      (oi.flags || []).forEach(function (f, i) {
        if (ORIGIN_INFO_FLAG.test(f) || /origin_ip_vpn|origin_ip_hosting/.test(f)) return;
        addLeaf("origin_ip", "chk_oi_flag_" + i, {
          label: String(f).split(":")[0].replace(/_/g, " ").slice(0, 18),
          hint: "Finding", kind: "check", score: 32, flags: [f], summary: describeFlag(f)
        });
      });
    }
    addChecks("sender", SENDER_CHECKS, nodes.sender.flags);
    addChecks("deception", DECEPTION_CHECKS, nodes.deception.flags);
    addChecks("attachments", FILE_CHECKS, nodes.attachments.flags);
    addChecks("intel", INTEL_CHECKS, nodes.intel.flags);
    if (nodes.intel) {
      var prof = nodes.intel.profile || {};
      var nProf = Number(prof.n) || 0;
      var usualRole = prof.majority_role || ((prof.roles || [])[0] || {}).value || "";
      var usualCc = ((prof.countries || [])[0] || {}).value || "";
      addLeaf("intel", "chk_intel_usual", {
        label: nProf ? ("Usual " + (usualRole || usualCc || "pattern")).slice(0, 18) : "Usual",
        hint: "Sender baseline",
        kind: nProf >= 5 ? "check" : "empty",
        empty: nProf < 5,
        summary: nodes.intel.profileSummary ||
          ("Not enough CLEAN/LOW history yet (" + nProf + "/5).")
      });
      var thisOi = originStageOf(e);
      var thisBits = [thisOi.networkRoleLabel || thisOi.networkRole || "", thisOi.country || ""].filter(Boolean);
      addLeaf("intel", "chk_intel_this", {
        label: (thisBits.join(" ") || "This email").slice(0, 18),
        hint: "This email",
        kind: "check",
        summary: thisBits.length
          ? ("This email: " + thisBits.join(" · ") + (thisOi.vpn ? " · VPN/proxy" : ""))
          : "No originating hop to compare against the sender baseline."
      });
      if (nodes.intel.requestSummary) {
        addLeaf("intel", "chk_intel_request", {
          label: (String(nodes.intel.requestClass || "request").replace(/_/g, " ")).slice(0, 18),
          hint: nodes.intel.trustedChannel ? "Trusted channel" : "This recipient",
          kind: "check",
          score: (nodes.intel.flags || []).some(function (f) {
            return String(f).indexOf("first_request_class_from_sender") === 0;
          }) ? 36 : 0,
          flags: (nodes.intel.flags || []).filter(function (f) {
            return /^first_request_|^first_trusted_sender/.test(String(f));
          }),
          summary: nodes.intel.requestSummary
        });
      }
      (nodes.intel.profileDelta || []).forEach(function (d, i) {
        if (!d || d.code === "profile_cold_start") return;
        addLeaf("intel", "chk_intel_dev_" + i, {
          label: String(d.code || "deviation").replace(/^profile_/, "").replace(/_/g, " ").slice(0, 18),
          hint: d.score ? "Unusual" : "Advisory",
          kind: "check",
          score: d.score ? 36 : 0,
          flags: d.code ? [d.code] : [],
          summary: d.summary || describeFlag(d.code || "")
        });
      });
    }

    var hopIds = [];
    var urlChains = [];
    var seenHosts = {};
    function addHopChain(chain, ci) {
      var hosts = (chain.hosts || []).slice(0, 8);
      if (hosts.length < 2) return;
      var key = hosts.join(">");
      if (seenHosts[key]) return;
      seenHosts[key] = 1;
      var row = [];
      hosts.forEach(function (host, hi) {
        var id = "hop_" + ci + "_" + hi;
        var last = hi === hosts.length - 1;
        nodes[id] = {
          id: id, label: hopHostLabel(host),
          hint: last ? "Landing" : (chain.kind === "http" ? "Followed hop" : "Encoded hop"),
          kind: "hop", recorded: true, score: chain.suspicious && last ? 48 : 0,
          flags: [], summary: (chain.urls && chain.urls[hi]) || host,
          host: host, suspicious: !!(chain.suspicious && last),
          hopIndex: hi, hopCount: hosts.length, chainKind: chain.kind || "",
          parent: "urls"
        };
        leafIds.push(id);
        hopIds.push(id);
        row.push(id);
        var prev = hi === 0 ? "urls" : ("hop_" + ci + "_" + (hi - 1));
        edges.push({ from: prev, to: id, kind: "branch", weight: chain.suspicious ? 28 : 14 });
      });
      urlChains.push(row);
    }
    (nodes.urls.linkHops || []).slice(0, 8).forEach(function (chain, ci) { addHopChain(chain, ci); });
    if (!urlChains.length) {
      var extra = 0;
      uniqueStrings(iocUrlsOf(e)).slice(0, 12).forEach(function (u) {
        var hops = unwrapClientHops(u);
        var hosts = [];
        hops.forEach(function (h) {
          var host = hostFromUrl(h);
          if (host && hosts.indexOf(host) < 0) hosts.push(host);
        });
        if (hosts.length >= 2 && extra < 6) {
          addHopChain({ hosts: hosts, urls: hops, kind: "embedded", suspicious: hosts.length >= 3 }, 80 + extra);
          extra++;
        }
      });
    }
    if (!urlChains.length) {
      uniqueStrings(iocUrlsOf(e).map(hostFromUrl)).slice(0, 8).forEach(function (host, i) {
        if (!host) return;
        addLeaf("urls", "urlhost_" + i, {
          label: hopHostLabel(host), hint: "Surface URL", kind: "hop",
          host: host, summary: host
        });
      });
    }
    addChecks("urls", URL_CHECKS, nodes.urls.flags);

    var addrIds = [];
    uniqueStrings(fanBoxes).slice(0, 16).forEach(function (addr, i) {
      var id = addLeaf("fanout", "addr_mb_" + i, {
        label: addrLabel(addr), hint: "Scanned inbox", kind: "addr",
        addr: addr, summary: "Same send was also delivered to " + addr
      });
      addrIds.push(id);
    });
    uniqueStrings(fanRecipients).slice(0, 16).forEach(function (addr, i) {
      if (fanBoxes.indexOf(addr) >= 0) return;
      if (addrIds.length >= 16) return;
      var id = addLeaf("fanout", "addr_env_" + i, {
        label: addrLabel(addr), hint: "Envelope To/Cc", kind: "addr",
        addr: addr, summary: "Envelope lists " + addr + " as a recipient of this email."
      });
      addrIds.push(id);
    });
    if (!addrIds.length) {
      addLeaf("fanout", "addr_none", {
        label: "No other recipients", hint: "Fan-out", kind: "empty", empty: true,
        summary: "This email was not seen in other scanned inboxes, and the envelope does not list extra recipients."
      });
    }
    nodes.fanout.count = addrIds.length;

    var llmLeaves = addChecks("content_ai", [], nodes.content_ai.flags);
    if (nodes.content_ai.nluIntent && nodes.content_ai.nluIntent !== "none") {
      addLeaf("content_ai", "chk_llm_intent", {
        label: String(nodes.content_ai.nluIntent).replace(/_/g, " ").slice(0, 18),
        hint: "NLU intent", kind: "check",
        score: nodes.content_ai.score || 0,
        summary: "Model intent " + nodes.content_ai.nluIntent +
          (nodes.content_ai.nluConfidence ? " (" + Math.round(nodes.content_ai.nluConfidence * 100) + "%)" : "")
      });
    } else if (!llmLeaves.length && !nodes.content_ai.pending) {
      addLeaf("content_ai", "chk_llm_none", {
        label: isLlmAssessment(e) ? "Reviewed" : "Not used",
        hint: "Advisory", kind: "empty", empty: true,
        summary: isLlmAssessment(e)
          ? (nodes.content_ai.summary || "LLM completed with no extra content flags.")
          : "LLM did not contribute a content assessment for this email."
      });
    }

    var laneOrder = FLOW_SIGNALS.map(function (s) { return s.id; }).concat(["content_ai"]);
    laneOrder.forEach(function (id) {
      var childIds = [];
      var chains = id === "urls" ? urlChains : [];
      var chainSet = {};
      chains.forEach(function (row) { row.forEach(function (hid) { chainSet[hid] = 1; }); });
      leafIds.forEach(function (lid) {
        if (nodes[lid] && nodes[lid].parent === id && !chainSet[lid]) childIds.push(lid);
      });
      lanes.push({
        id: id,
        childIds: childIds,
        chains: chains,
        wrap: id === "fanout" ? 3 : 1
      });
      edges.push({ from: "mail", to: id, kind: "branch", weight: 8 });
      var n = nodes[id];
      var notable = n && (n.score >= 8 || (n.flags || []).some(function (f) {
        return !ORIGIN_INFO_FLAG.test(String(f)) && !/^fanout_/.test(String(f));
      }));
      if (id !== "fanout" && id !== "origin_ip" && final && notable) {
        edges.push({
          from: id, to: "verdict",
          kind: overrideFrom === id ? "override" : "score",
          weight: overrideFrom === id ? 100 : flowContribution(id, n.score)
        });
      }
      if (id === "origin_ip" && final && n && (n.vpn || n.score >= 8 ||
          (n.flags || []).some(function (f) { return /origin_ip_vpn|origin_ip_hosting|geo_mismatch/.test(f); }))) {
        edges.push({
          from: id, to: "verdict",
          kind: overrideFrom === id ? "override" : "score",
          weight: overrideFrom === id ? 100 : Math.max(12, n.score || 0)
        });
      }
    });
    if (final && nodes.content_ai && (nodes.content_ai.score >= 8 || (nodes.content_ai.flags || []).length)) {
      var hasLlmScore = edges.some(function (ed) { return ed.from === "content_ai" && ed.to === "verdict"; });
      if (!hasLlmScore) {
        edges.push({
          from: "content_ai", to: "verdict",
          kind: overrideFrom === "content_ai" ? "override" : "score",
          weight: overrideFrom === "content_ai" ? 100 : flowContribution("content_ai", nodes.content_ai.score)
        });
      }
    } else {
      edges.push({ from: "content_ai", to: "verdict", kind: "branch", weight: 6 });
    }
    edges.push({ from: "mail", to: "verdict", kind: "branch", weight: 6 });

    return {
      recorded: recorded, pending: pending, nodes: nodes, edges: edges,
      overrideFrom: overrideFrom, hopIds: hopIds, leafIds: leafIds,
      lanes: lanes, addrIds: addrIds
    };
  }

  function hopHostLabel(host) {
    var h = String(host || "");
    if (h.length <= 20) return h;
    var parts = h.split(".");
    if (parts.length >= 2) {
      var reg = parts.slice(-2).join(".");
      if (reg.length <= 20) return reg;
    }
    return h.slice(0, 18) + "…";
  }

  function hopChainsHtml(chains) {
    var list = (chains || []).filter(function (c) { return (c.hosts || []).length >= 2; }).slice(0, 4);
    if (!list.length) return "";
    return list.map(function (c) {
      var hops = (c.hosts || []).map(function (h, i) {
        var last = i === c.hosts.length - 1;
        return '<span class="hop-pill' + (c.suspicious && last ? " is-alert" : "") + '">' +
          escapeHtml(hopHostLabel(h)) + "</span>";
      }).join('<span class="hop-arrow">→</span>');
      var kind = c.kind === "http" ? "followed" : "encoded";
      return '<div class="hop-chain"><span class="hop-chain-meta">' + escapeHtml(kind) +
        " · " + (c.hop_count || c.hosts.length) + " hops</span><div class='hop-chain-pills'>" + hops + "</div></div>";
    }).join("");
  }

  function flowInspectHtml(e, model, stageId) {
    var n = model.nodes[stageId];
    if (!n) n = model.nodes.mail;
    var title = n.label;
    var bits = [];
    if (n.kind === "verdict") {
      bits.push((n.awaiting || n.pending) ? "awaiting AI" : "composite " + (Number(n.score) || 0).toFixed(1) + "/100");
    }
    else if (n.recorded) bits.push("stage score " + (Number(n.score) || 0).toFixed(1));
    else if (!model.recorded) bits.push("scores were not stored for this email");
    if (n.status && n.status !== "ok") bits.push(n.status);
    if (n.scoreCapped) bits.push("LLM score capped (uncorroborated)");
    if (n.degraded) bits.push("degraded");
    if (n.nluIntent && n.nluIntent !== "none") {
      bits.push("intent " + n.nluIntent + (n.nluConfidence ? " (" + Math.round(n.nluConfidence * 100) + "%)" : ""));
    }
    var flags = (n.flags || []).slice(0, 8);
    var flagHtml = flags.length
      ? "<ul class='flow-inspect-flags'>" + flags.map(function (f) {
          return "<li>" + escapeHtml(describeFlag(f)) + "</li>";
        }).join("") + "</ul>"
      : "<div class='flow-inspect-empty'>No red flags from this step.</div>";
    var summary = n.summary ? "<p class='flow-inspect-summary'>" + escapeHtml(n.summary) + "</p>" : "";
    if (n.id === "origin_ip") {
      var loc = [n.city, n.region, n.countryName || n.country].filter(Boolean).join(", ");
      var ispLine = n.isp || n.org || "";
      if (n.asn) ispLine += (ispLine ? " · " : "") + n.asn + (n.asName ? " " + n.asName : "");
      var oiRows = [];
      if (n.ip) oiRows.push(["IP", n.ip + (n.hostname ? " (" + n.hostname + ")" : "")]);
      if (loc) oiRows.push(["Location", loc + (n.timezone ? " · " + n.timezone : "")]);
      if (ispLine) oiRows.push(["ISP / ASN", ispLine]);
      if (n.networkRoleLabel || n.networkRole) oiRows.push(["Network", n.networkRoleLabel || n.networkRole]);
      oiRows.push(["VPN / proxy", n.vpn ? "Likely yes" : "No indication"]);
      var sus = n.suspicion && n.suspicion !== "none" ? n.suspicion : "none";
      oiRows.push(["Suspicion", sus + (n.suspicionReason ? " — " + n.suspicionReason : (sus === "none" ? " — not inherently suspicious" : ""))]);
      if (n.xOriginatingIp && n.xOriginatingIp !== n.ip) oiRows.push(["X-Originating-IP", n.xOriginatingIp]);
      if (oiRows.length) {
        summary = "<dl class='flow-inspect-dl'>" + oiRows.map(function (pair) {
          return "<dt>" + escapeHtml(pair[0]) + "</dt><dd>" + escapeHtml(pair[1]) + "</dd>";
        }).join("") + "</dl>" +
          (n.searchSummary
            ? "<p class='flow-inspect-summary'>" + escapeHtml(n.searchSummary) + "</p>"
            : "");
        var notable = (n.flags || []).filter(function (f) {
          return /^(origin_ip_vpn|origin_ip_hosting|origin_ip_search)$/.test(f)
            || /^origin_ip_geo_mismatch:/.test(f);
        });
        flagHtml = notable.length
          ? "<ul class='flow-inspect-flags'>" + notable.map(function (f) {
              return "<li>" + escapeHtml(describeFlag(f)) + "</li>";
            }).join("") + "</ul>"
          : "";
      } else if (!n.flags || !n.flags.length) {
        flagHtml = "<div class='flow-inspect-empty'>No public originating IP on the Received chain for this email.</div>";
      }
    }
    if (n.id === "intel") {
      var psum = n.profileSummary || "";
      var prof = n.profile || {};
      var nProf = Number(prof.n) || 0;
      var thisC = n.thisCopy || {};
      var usualRole = prof.majority_role || ((prof.roles || [])[0] || {}).value || "unknown";
      var usualCc = ((prof.countries || [])[0] || {}).value || "unknown";
      var usualAsn = ((prof.asns || [])[0] || {}).value || "unknown";
      var usualVpn = nProf ? (Math.round((Number(prof.vpn_rate) || 0) * 100) + "% VPN") : "unknown";
      var usualLine = nProf < 5
        ? ("Not enough CLEAN/LOW history yet (" + nProf + "/5).")
        : (usualRole + " · " + usualCc + " · " + usualAsn + " · " + usualVpn + " (" + nProf + " emails)");
      var thisBits = [thisC.networkRole, thisC.country, thisC.asn].filter(Boolean);
      if (thisC.vpn) thisBits.push("VPN/proxy");
      var thisLine = thisBits.length ? thisBits.join(" · ") : "No originating hop to compare.";
      var profRows = [
        ["Usual for this sender", usualLine],
        ["This email", thisLine]
      ];
      summary = "<dl class='flow-inspect-dl'>" + profRows.map(function (pair) {
        return "<dt>" + escapeHtml(pair[0]) + "</dt><dd>" + escapeHtml(pair[1]) + "</dd>";
      }).join("") + "</dl>" +
        (psum ? "<p class='flow-inspect-summary'>" + escapeHtml(psum) + "</p>" : "") +
        (summary || "");
    }
    if (n.id === "mail") {
      var laneCount = (model.lanes || []).length;
      var leafCount = (model.leafIds || []).length;
      summary = "<p class='flow-inspect-summary'>" + escapeHtml(n.summary || n.hint || "") + "</p>";
      flagHtml = "<div class='flow-inspect-empty'>" + laneCount + " detector branches · " + leafCount +
        " checks, hops, and recipients. Click a branch to inspect what ran.</div>";
    }
    if (n.kind === "addr") {
      summary = "<p class='flow-inspect-summary'>" + escapeHtml(n.summary || n.addr || n.label) + "</p>";
      flagHtml = "<div class='flow-inspect-empty'>" +
        (n.hint === "Scanned inbox"
          ? "This address has a scanned email of the same send."
          : "This address is listed on the envelope To/Cc of this email.") +
        "</div>";
    }
    if (n.kind === "check" || n.kind === "empty") {
      if (n.summary) summary = "<p class='flow-inspect-summary'>" + escapeHtml(n.summary) + "</p>";
      if (!n.flags || !n.flags.length) {
        flagHtml = "<div class='flow-inspect-empty'>" +
          (n.empty ? escapeHtml(n.summary || "Nothing extra to show.") : "This check ran and did not fire a red flag.") +
          "</div>";
      }
    }
    if (n.id === "fanout") {
      var listed = (n.mailboxes || []).concat(n.recipients || []).filter(function (v, i, a) {
        return v && a.indexOf(v) === i;
      }).slice(0, 12);
      if (listed.length) {
        summary += "<ul class='flow-inspect-flags'>" + listed.map(function (addr) {
          return "<li>" + escapeHtml(addr) + "</li>";
        }).join("") + "</ul>";
      } else if (!n.flags || !n.flags.length) {
        flagHtml = "<div class='flow-inspect-empty'>This email was not seen in other scanned inboxes, and the envelope does not list extra recipients.</div>";
      }
    }
    if (n.id === "urls") {
      var urlHops = n.linkHops || [];
      if (urlHops.length) summary += hopChainsHtml(urlHops);
    }
    if (n.kind === "hop") {
      bits.push("hop " + ((n.hopIndex || 0) + 1) + " of " + (n.hopCount || 1));
      if (n.suspicious) bits.push("suspicious landing");
      summary = "<p class='flow-inspect-summary'>" + escapeHtml(n.summary || n.host || n.label) + "</p>";
      if (!n.flags || !n.flags.length) {
        flagHtml = n.suspicious
          ? "<div class='flow-inspect-empty'>This hop lands on a different domain than the wrapper — typical of a redirect lure.</div>"
          : "<div class='flow-inspect-empty'>Redirect hop in the link chain. Click URLs to see the full path.</div>";
      }
    }
    var modelLine = "";
    if (n.kind === "llm") {
      var ml = formatLlmModel(n.model, n.provider);
      if (ml) modelLine = "<div class='flow-inspect-meta'>" + escapeHtml(ml) + "</div>";
      if (n.pending) {
        summary = "";
        flagHtml = "<div class='flow-inspect-empty'>The model is still running. Verdict stays hidden until it finishes.</div>";
      } else if (n.retrying) {
        summary = "";
        flagHtml = "<div class='flow-inspect-empty'>First attempt timed out. Another attempt is queued automatically.</div>";
      }
    }
    return "<div class='flow-inspect-kicker'>" + escapeHtml(n.hint || n.kind) +
      (bits.length ? " · " + escapeHtml(bits.join(" · ")) : "") + "</div>" +
      "<h3>" + escapeHtml(title) + "</h3>" + modelLine + summary + flagHtml;
  }

  function stageFindingCount(n) {
    return ((n && n.flags) || []).filter(function (f) {
      var s = String(f);
      return !ORIGIN_INFO_FLAG.test(s) && s.indexOf("origin_ip:") !== 0 && s.indexOf("fanout_") !== 0;
    }).length;
  }

  function stageLeaves(model, stageId) {
    var lane = (model.lanes || []).filter(function (l) { return l.id === stageId; })[0];
    var ids = (lane && lane.childIds) || [];
    return ids.map(function (id) { return model.nodes[id]; }).filter(Boolean);
  }

  function defaultStaticStage(model) {
    var found = "";
    FLOW_SIGNALS.forEach(function (spec) {
      if (found) return;
      var n = model.nodes[spec.id];
      if (stageFindingCount(n) || (n && n.vpn)) found = spec.id;
    });
    return found || "headers";
  }

  function abCheckHtml(leaf) {
    var hit = !leaf.empty && ((leaf.flags && leaf.flags.length) || Number(leaf.score) >= 20);
    var status = leaf.empty ? "note" : (hit ? "hit" : "clear");
    var label = status === "hit" ? "Finding" : (status === "clear" ? "Clear" : "Note");
    return '<article class="ab-check is-' + status + '">' +
      '<div class="ab-check-head"><span class="ab-check-status">' + label + "</span>" +
      '<strong class="ab-check-name">' + escapeHtml(leaf.label || "") + "</strong>" +
      (leaf.hint ? '<span class="ab-check-hint">' + escapeHtml(leaf.hint) + "</span>" : "") +
      "</div>" +
      (leaf.summary ? '<p class="ab-check-summary">' + escapeHtml(leaf.summary) + "</p>" : "") +
      "</article>";
  }

  function staticStageDetailHtml(e, model, stageId) {
    var n = model.nodes[stageId] || {};
    var recorded = !!(n.recorded);
    var html = '<div class="ab-stage-copy">' +
      '<div class="ab-kicker">' + escapeHtml(n.hint || "Static detector") + "</div>" +
      "<h3>" + escapeHtml(n.label || stageId) + "</h3>" +
      "<p>" + escapeHtml(STAGE_BLURB[stageId] || "") + "</p>" +
      '<p class="ab-stage-meta">' +
      (recorded
        ? "Stage score " + (Number(n.score) || 0).toFixed(0) +
          (STAGE_WEIGHTS[stageId] != null ? " · max weight " + STAGE_WEIGHTS[stageId] : "")
        : "Stage scores were not stored on this email — checks below are inferred from flags.") +
      "</p></div>";
    if (n.summary && stageId !== "origin_ip" && stageId !== "intel") {
      html += '<p class="ab-stage-summary">' + escapeHtml(n.summary) + "</p>";
    }
    if (stageId === "origin_ip") {
      html += '<div class="ab-facts">' + originIntelBlockHtml(n) +
        (n.searchSummary ? '<p class="ab-stage-summary">' + escapeHtml(n.searchSummary) + "</p>" : "") +
        "</div>";
    }
    if (stageId === "urls") html += hopChainsHtml(n.linkHops || []);
    var leaves = stageLeaves(model, stageId);
    if (leaves.length) html += '<div class="ab-checks">' + leaves.map(abCheckHtml).join("") + "</div>";
    return html;
  }

  function staticActHtml(e, model, stageId) {
    var pills = FLOW_SIGNALS.map(function (spec) {
      var n = model.nodes[spec.id] || {};
      var hits = stageFindingCount(n);
      var tone = n.pending ? "warning" : (hits || n.vpn ? flowScoreTone(n.score || 45) : "good");
      return '<button type="button" class="ab-stage-pill tone-' + tone +
        (spec.id === stageId ? " is-active" : "") + '" data-ab-stage-id="' + spec.id + '"' +
        ' aria-pressed="' + (spec.id === stageId ? "true" : "false") + '">' +
        '<span class="ab-stage-pill-name">' + escapeHtml(spec.label) + "</span>" +
        '<span class="ab-stage-pill-sub">' +
        (hits ? hits + (hits === 1 ? " finding" : " findings")
          : (n.recorded ? "Clear" : "Not stored")) +
        "</span></button>";
    }).join("");
    var hitStages = FLOW_SIGNALS.filter(function (spec) {
      return stageFindingCount(model.nodes[spec.id]);
    }).length;
    return '<p class="ab-act-lede">Deterministic detectors run first, before any model reads the body. ' +
      "They authenticate the sender, locate the sending MTA, inspect links and files, and correlate this email with known infrastructure. " +
      (hitStages
        ? hitStages + " of " + FLOW_SIGNALS.length + " stages raised a finding."
        : "None of the eight stages raised a red flag.") +
      "</p>" +
      '<div class="ab-stages" role="tablist" aria-label="Static check stages">' + pills + "</div>" +
      '<div class="ab-stage-detail" data-ab-stage-detail>' + staticStageDetailHtml(e, model, stageId) + "</div>";
  }

  function contentActHtml(e, model) {
    var n = model.nodes.content_ai || {};
    var modelLabel = formatLlmModel(n.model, n.provider);
    var structure = bodyStructureHtml(bodyStructureFromEntry(e));
    var status = n.pending ? "The model is still reading this email. Verdict stays hidden until it finishes."
      : (n.retrying ? "The first attempt timed out. Another attempt is queued automatically."
        : (isLlmAssessment(e) ? "The model finished a content-level read of this email."
          : "No content assessment is stored yet."));
    var intent = (n.nluIntent && n.nluIntent !== "none")
      ? String(n.nluIntent).replace(/_/g, " ") +
        (n.nluConfidence ? " (" + Math.round(n.nluConfidence * 100) + "% confidence)" : "")
      : "";
    var staticHits = [];
    FLOW_SIGNALS.forEach(function (spec) {
      ((model.nodes[spec.id] || {}).flags || []).forEach(function (f) {
        if (ORIGIN_INFO_FLAG.test(String(f))) return;
        staticHits.push({ stage: spec.label, flag: f });
      });
    });
    var leaves = stageLeaves(model, "content_ai");
    var html = '<p class="ab-act-lede">After static checks finish, the content model is given the parsed body ' +
      "(primary text versus quoted thread versus footer), the subject, and the flags already raised. " +
      "It interprets intent and lure language. It does not replace SPF/DKIM — those already ran.</p>" +
      '<div class="ab-ai-status"><div class="ab-kicker">This email</div>' +
      "<p>" + escapeHtml(status) + "</p>" +
      (modelLabel ? '<p class="ab-stage-meta">Model · ' + escapeHtml(modelLabel) + "</p>" : "") +
      (intent ? '<p class="ab-stage-meta">Threat class · ' + escapeHtml(intent) + "</p>" : "") +
      (n.scoreCapped ? '<p class="ab-stage-meta">LLM score was capped because static checks did not corroborate it.</p>' : "") +
      "</div>";
    if (n.summary && isLlmAssessment(e)) {
      html += '<blockquote class="ab-ai-summary">' + escapeHtml(n.summary) + "</blockquote>";
    }
    if (structure) html += structure;
    if (leaves.length) html += '<div class="ab-checks">' + leaves.map(abCheckHtml).join("") + "</div>";
    html += '<div class="ab-context"><div class="ab-kicker">Static evidence the model can see</div>';
    if (staticHits.length) {
      html += "<ul class='ab-context-list'>" + staticHits.slice(0, 16).map(function (row) {
        return "<li><span class='ab-context-stage'>" + escapeHtml(row.stage) + "</span> " +
          escapeHtml(describeFlag(row.flag)) + "</li>";
      }).join("") + "</ul>";
    } else {
      html += '<p class="ab-stage-summary">No static red flags were on the email when the model ran. The assessment is from wording and structure alone.</p>';
    }
    html += "</div>";
    return html;
  }

  function threadActHtml(e) {
    var sibs = (e && e.id) ? threadSiblings(e) : [];
    var tAss = threadAssessmentOf(sibs);
    var threadSummary = (e && e.threadSummary) || (tAss && tAss.threadSummary) || "";
    var threadVerdict = (e && e.threadVerdict) || (tAss && tAss.threadVerdict) || "";
    var html = '<p class="ab-act-lede">Thread AI runs after this email is assessed. It reads every unique Gmail message in the conversation for this mailbox — not just the latest turn. ' +
      "A clean first mail plus a later payment request is a different story than a one-shot phishing blast.</p>";
    if (sibs.length > 1) {
      html += '<p class="ab-stage-meta">' + sibs.length + " messages in this conversation" +
        (e.mailbox ? " · " + escapeHtml(e.mailbox) : "") + "</p>";
    } else if (!sibs.length) {
      html += '<p class="ab-stage-summary">This view is a single scan, so there is no Gmail thread to join. Thread assessment appears on live mailbox emails once sibling messages are in the feed.</p>';
      return html;
    }
    if (threadVerdict || threadSummary) {
      html += '<div class="ab-ai-status"><div class="ab-kicker">Conversation assessment</div>' +
        (threadVerdict ? "<div>" + chip(threadVerdict) + "</div>" : "") +
        (threadSummary ? '<blockquote class="ab-ai-summary">' + escapeHtml(threadSummary) + "</blockquote>" : "") +
        "</div>";
    } else {
      html += '<p class="ab-stage-summary">Thread assessment has not landed yet. It queues once every unique message in the thread has a content assessment.</p>';
    }
    html += '<ol class="ab-thread-list">';
    sibs.forEach(function (m, i) {
      var shown = displayVerdict(m);
      var current = e && m.id === e.id;
      html += '<li class="ab-thread-item' + (current ? " is-current" : "") + '">' +
        '<span class="ab-thread-idx">' + (i + 1) + "</span>" +
        '<div class="ab-thread-copy"><div class="ab-thread-from">' +
        escapeHtml(m.fromAddr || "unknown") +
        (current ? ' <span class="ab-thread-you">this email</span>' : "") +
        '</div><div class="ab-thread-sub">' + escapeHtml(m.subject || "(no subject)") +
        " · " + escapeHtml(fmtDateTime(m.ts)) + "</div></div>" +
        '<div class="ab-thread-verdict">' + chip(shown) + "</div></li>";
    });
    html += "</ol>";
    return html;
  }

  function assessmentFlowHtml(e, opts) {
    var wide = !!(opts && opts.wide);
    var model = buildFlowModel(e);
    var stageId = defaultStaticStage(model);
    var sub = isAiPending(e)
      ? "Static checks are in. Content AI is still running on this email."
      : (isAiTimedOut(e)
        ? "Static checks are in. Content AI timed out and will retry."
        : "Static detectors, then a content-level read of this email, then the conversation.");
    return '<div class="assessment-flow assessment-breakdown' + (wide ? " is-wide" : "") +
      '" data-ab-default-stage="' + stageId + '">' +
      '<div class="flow-head"><div class="flow-head-copy"><span class="df-label">How this mail was assessed</span>' +
      '<span class="flow-head-sub">' + escapeHtml(sub) + "</span></div></div>" +
      '<div class="ab-pipeline" role="tablist" aria-label="Assessment stages">' +
      '<button type="button" class="ab-tab is-active" data-ab-tab="static" aria-selected="true">' +
      '<span class="ab-tab-num">1</span><span class="ab-tab-copy"><strong>Static checks</strong>' +
      "<span>Headers, origin, links, files</span></span></button>" +
      '<span class="ab-pipe" aria-hidden="true"></span>' +
      '<button type="button" class="ab-tab" data-ab-tab="content" aria-selected="false">' +
      '<span class="ab-tab-num">2</span><span class="ab-tab-copy"><strong>Content AI</strong>' +
      "<span>This email, body and intent</span></span></button>" +
      '<span class="ab-pipe" aria-hidden="true"></span>' +
      '<button type="button" class="ab-tab" data-ab-tab="thread" aria-selected="false">' +
      '<span class="ab-tab-num">3</span><span class="ab-tab-copy"><strong>Thread AI</strong>' +
      "<span>Whole conversation</span></span></button>" +
      "</div>" +
      '<div class="ab-panel" data-ab-panel="static">' + staticActHtml(e, model, stageId) + "</div>" +
      '<div class="ab-panel" data-ab-panel="content" hidden>' + contentActHtml(e, model) + "</div>" +
      '<div class="ab-panel" data-ab-panel="thread" hidden>' + threadActHtml(e) + "</div>" +
      "</div>";
  }

  function mountAssessmentFlow(el, e, wide) {
    if (!el) return;
    el.innerHTML = assessmentFlowHtml(e, { wide: !!wide });
    bindAssessmentFlow(el, e);
  }

  function bindAssessmentFlow(root, e) {
    var host = root.querySelector(".assessment-breakdown") ||
      (root.classList && root.classList.contains("assessment-breakdown") ? root : null);
    if (!host) return;
    var model = buildFlowModel(e);
    function showAct(id) {
      Array.prototype.forEach.call(host.querySelectorAll("[data-ab-tab]"), function (t) {
        var on = t.getAttribute("data-ab-tab") === id;
        t.classList.toggle("is-active", on);
        t.setAttribute("aria-selected", on ? "true" : "false");
      });
      Array.prototype.forEach.call(host.querySelectorAll("[data-ab-panel]"), function (p) {
        p.hidden = p.getAttribute("data-ab-panel") !== id;
      });
    }
    function showStage(id) {
      Array.prototype.forEach.call(host.querySelectorAll("[data-ab-stage-id]"), function (t) {
        var on = t.getAttribute("data-ab-stage-id") === id;
        t.classList.toggle("is-active", on);
        t.setAttribute("aria-pressed", on ? "true" : "false");
      });
      var panel = host.querySelector("[data-ab-stage-detail]");
      if (panel) panel.innerHTML = staticStageDetailHtml(e, model, id);
    }
    Array.prototype.forEach.call(host.querySelectorAll("[data-ab-tab]"), function (t) {
      t.addEventListener("click", function () { showAct(t.getAttribute("data-ab-tab")); });
    });
    Array.prototype.forEach.call(host.querySelectorAll("[data-ab-stage-id]"), function (t) {
      t.addEventListener("click", function () { showStage(t.getAttribute("data-ab-stage-id")); });
    });
  }
  function threadAssessmentFields(e) {
    var summary = (e && e.threadSummary) || "";
    var verdict = (e && e.threadVerdict) || "";
    var sibs = threadSiblings(e);
    if (!summary && !verdict) {
      var tAss = threadAssessmentOf(sibs);
      if (tAss) {
        summary = tAss.threadSummary || "";
        verdict = tAss.threadVerdict || "";
      }
    }
    return { summary: summary, verdict: verdict, siblings: sibs };
  }

  function buildThreadSidebarHtml(e) {
    var t = threadAssessmentFields(e);
    var n = (t.siblings || []).length;
    var html = '<div class="detail-analysis-head"><h2>Thread assessment</h2>' +
      '<div class="card-sub">' +
      (n > 1
        ? n + " messages in this conversation — scored after each email"
        : "Whole conversation for this mailbox, not just this email") +
      "</div></div>";
    if (t.verdict) {
      html += '<div class="drawer-field"><span class="df-label">Thread verdict</span><div>' +
        chip(t.verdict) + "</div></div>";
    }
    if (t.summary) {
      html += '<div class="ai-callout thread-callout">' + escapeHtml(t.summary) + "</div>";
    } else if (n <= 1) {
      html += '<p class="ioc-empty">Only this email is in the feed so far. Thread AI runs once other messages in the conversation are assessed.</p>';
    } else {
      html += '<p class="ioc-empty">Thread AI has not finished. It queues after each unique message in the conversation has a content assessment.</p>';
    }
    return html;
  }

  function buildPreviewBodyHtml(e) {
    var aiFacts = contentAiFacts(e);
    var aiSummary = isLlmAssessment(e) ? aiFacts.summary : "";
    var modelLabel = formatLlmModel(aiFacts.model, aiFacts.provider);
    var shown = displayVerdict(e);
    var scored = shown !== "PENDING" && shown !== "INCONCLUSIVE";
    var html = "";
    html += '<div class="detail-analysis-head"><h2>AI analysis</h2>' +
      '<div class="card-sub">' + (isAiPending(e)
        ? "Heuristic stages are in. The LLM is still running."
        : (isAiTimedOut(e)
          ? "Timed out — another attempt is queued automatically."
          : "Gateway score plus required LLM assessment")) + "</div></div>";

    var marginLine = e.hardOverride
      ? '<div style="margin-top:6px;">' + '<div class="override-banner">' + ICON.critical + "<span><strong>Hard override: " + escapeHtml(e.hardOverride || "") + ".</strong> " + escapeHtml(describeFlag(e.hardOverride)) + "</span></div></div>"
      : scored
        ? '<div class="df-value" style="margin-top:4px; color:var(--ink-muted); font-size:12px;">' + escapeHtml(verdictMargin(e.verdict, e.score)) + "</div>"
        : "";
    html += '<div class="drawer-field"><span class="df-label">Verdict</span><div>' + chipForEmail(e, { quiet: true }) +
      ' <span class="mono" style="margin-left:6px;">score ' + (scored ? e.score + "/100" : "—") + "</span></div>" +
      marginLine + "</div>";
    html += '<div class="drawer-field"><span class="df-label">Action taken</span><span class="df-value">' +
      (e.status === "released" ? "Released by admin" : actionTakenLabel(e)) + "</span></div>";
    if (modelLabel) {
      html += '<div class="drawer-field"><span class="df-label">LLM model</span><span class="df-value">' +
        escapeHtml(modelLabel) + "</span></div>";
    }
    html += '<div class="drawer-field"><span class="df-label">Origin IP</span><div class="df-value">' +
      originIntelBlockHtml(originStageOf(e)) + "</div></div>";

    if (e.analystLabel === "benign") {
      html += '<div class="override-banner benign">' + ICON.good + "<span><strong>Analyst marked this as not malicious.</strong> " +
        (e.analystLabelBy ? escapeHtml(e.analystLabelBy) + " labelled it; " : "") +
        "sender and URL-host indicators were added to the good-mail training pack for future scans.</span></div>";
    }

    if (scored && e.threatClass && e.threatClass !== "none") {
      var tcLabel = String(e.threatClass).replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
      var tcConf = (typeof e.threatConfidence === "number") ? " (" + Math.round(e.threatConfidence * 100) + "% confidence)" : "";
      html += '<div class="drawer-field"><span class="df-label">Threat class (AI)</span>' +
        '<span class="df-value"><strong>' + escapeHtml(tcLabel) + "</strong>" + escapeHtml(tcConf) + "</span></div>";
    }

    if (aiSummary) {
      html += '<div class="ai-callout"><span class="ai-label">LLM content assessment</span>' +
        (modelLabel ? '<span class="ai-model">' + escapeHtml(modelLabel) + "</span>" : "") +
        escapeHtml(aiSummary) + "</div>";
      html += bodyStructureHtml(bodyStructureFromEntry(e));
    }
    if (e.deepAnalysis) {
      var d = e.deepAnalysis;
      html += '<div class="deep-callout"><span class="deep-label">Deep agent analysis</span>' +
        (d.model ? '<div class="ai-model" style="margin-bottom:6px;">' + escapeHtml(formatLlmModel(d.model)) + "</div>" : "") +
        '<div style="margin-bottom:6px;"><strong>' + escapeHtml(String(d.risk_level || "?")) +
        "</strong> · score " + escapeHtml(String(d.risk_score != null ? d.risk_score : "—")) +
        (d.landing_mismatch ? ' · <span style="color:var(--status-critical)">landing mismatch</span>' : "") +
        "</div>" +
        "<div>" + escapeHtml(d.summary || "(no summary)") + "</div>" +
        (d.investigation_findings && d.investigation_findings.length
          ? '<ol class="finding-list" style="margin-top:8px;padding-left:18px;">' +
            d.investigation_findings.map(function (ind) { return "<li>" + escapeHtml(stripListPrefix(ind)) + "</li>"; }).join("") +
            "</ol>"
          : "") +
        (d.recommended_actions && d.recommended_actions.length
          ? '<div style="margin-top:10px;font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.04em;">Recommended actions</div>' +
            '<ol class="finding-list" style="margin-top:4px;padding-left:18px;">' +
            d.recommended_actions.map(function (a) { return "<li>" + escapeHtml(stripListPrefix(a)) + "</li>"; }).join("") +
            "</ol>"
          : "") +
        (d.indicators && d.indicators.length
          ? '<ul class="finding-list" style="margin-top:8px;">' +
            d.indicators.map(function (ind) { return "<li>" + escapeHtml(String(ind)) + "</li>"; }).join("") +
            "</ul>"
          : "") +
        (d.consistency_warning
          ? '<div style="margin-top:8px;color:var(--status-serious);font-size:12px;">' +
            escapeHtml(d.consistency_warning) + "</div>"
          : "") +
        "</div>";
    } else if (isAiPending(e) || isAiTimedOut(e)) {
      /* Status lives on the verdict chip and the neural LLM node — don't repeat it. */
    } else if (e.sourceKind === "sample") {
      html += '<div class="ioc-empty" style="margin-top:8px;">Deep LLM enrichment pending or unavailable — open Analyze to run a full report on the EML.</div>';
    } else if (!aiSummary) {
      html += '<div class="ioc-empty" style="margin-top:8px;">LLM assessment pending — scoring waits on the configured model (DeepSeek R1).</div>';
    }

    html += '<div class="drawer-field"><span class="df-label">' +
      (scored ? "Why this verdict" : "Signals so far") + '</span><ul class="reason-list">' +
      (e.reasons.length ? e.reasons.map(function (r) { return "<li>" + escapeHtml(describeFlag(r)) + "</li>"; }).join("") : "<li>No red flags fired on any stage.</li>") +
      "</ul></div>";

    html += '<div class="drawer-field"><span class="df-label">Raw tags</span><span class="df-value mono" style="font-size:11.5px; color:var(--ink-muted);">' +
      (e.reasons.length ? escapeHtml(e.reasons.join(", ")) : "none") + "</span></div>";

    var drawerBehavHits = (((e.stages || {}).intel || {}).behavioralHits || []);
    if (drawerBehavHits.length) {
      var drawerMalicious = drawerBehavHits.filter(function (h) { return h.indexOf("behavioral_shared_shortener:") === 0; });
      var drawerSuspicious = drawerBehavHits.filter(function (h) { return h.indexOf("behavioral_shared_shortener:") !== 0; });
      if (drawerMalicious.length) {
        var malRows = drawerMalicious.map(function (h) {
          var p = h.split(":");
          var domain = p[1] || "", count = p[2] || "?";
          return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-top:1px solid rgba(128,128,128,.15);font-size:12px;">' +
            '<span><strong>Shortener domain:</strong> <code style="font-size:11px;background:rgba(0,0,0,.18);padding:1px 5px;border-radius:3px;">' + escapeHtml(domain) + '</code></span>' +
            '<span style="opacity:.65;font-size:11px;">\xd7' + escapeHtml(fmtNum(count)) + ' other sender' + (Number(count) === 1 ? "" : "s") + '</span>' +
            '</div>';
        }).join("");
        html += '<div class="drawer-field"><div style="padding:10px 12px;border-radius:8px;background:var(--status-critical-bg);color:var(--status-critical);">' +
          '<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:600;margin-bottom:6px;">' +
          ICON.critical + '<span>Coordinated Campaign — shared shortener across senders</span></div>' +
          malRows + '</div></div>';
      }
      if (drawerSuspicious.length) {
        var ruleLabels = {
          behavioral_sender_ip_drift: "Sender IP drift",
          behavioral_ip_many_senders: "Shared attack-platform IP",
          behavioral_ip_shortener: "IP-linked shortener abuse",
        };
        var suspRows = drawerSuspicious.map(function (h) {
          var p = h.split(":");
          var rule = p[0], ioc = p[1] || "", count = p[2] || "";
          var label = ruleLabels[rule] || rule.replace("behavioral_", "").replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
          return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-top:1px solid rgba(128,128,128,.15);font-size:12px;">' +
            '<span><strong>' + escapeHtml(label) + ':</strong> <code style="font-size:11px;background:rgba(0,0,0,.18);padding:1px 5px;border-radius:3px;">' + escapeHtml(ioc) + '</code></span>' +
            (count && !isNaN(Number(count)) ? '<span style="opacity:.65;font-size:11px;">' + fmtNum(count) + ' occurrence' + (Number(count) === 1 ? "" : "s") + '</span>' : "") +
            "</div>";
        }).join("");
        html += '<div class="drawer-field"><div style="padding:10px 12px;border-radius:8px;background:var(--status-serious-bg);color:var(--status-serious);width:100%;">' +
          '<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:600;margin-bottom:' + (drawerSuspicious.length ? "6" : "0") + 'px;">' +
          ICON.serious + '<span>Behavioral Anomaly — ' + drawerSuspicious.length + ' pattern' + (drawerSuspicious.length === 1 ? "" : "s") + ' detected</span></div>' +
          suspRows + '</div></div>';
      }
    }

    var drawerCampaigns = e.campaigns || (((e.stages || {}).intel || {}).campaignDetails) || [];
    if (drawerCampaigns.length) {
      var camRows = drawerCampaigns.map(function (c) {
        var kind = c.kind || "";
        var label = kind.replace(/_/g, " ") || "campaign";
        return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-top:1px solid rgba(128,128,128,.15);font-size:12px;">' +
          '<span><strong>' + escapeHtml(label) + ':</strong> <code style="font-size:11px;background:rgba(0,0,0,.18);padding:1px 5px;border-radius:3px;">' +
          escapeHtml(c.id || c.pattern || "") + '</code></span>' +
          '<span style="opacity:.65;font-size:11px;">' + escapeHtml(String(c.members || "?")) + ' emails</span></div>';
      }).join("");
      html += '<div class="drawer-field"><div style="padding:10px 12px;border-radius:8px;background:var(--status-serious-bg);color:var(--status-serious);width:100%;">' +
        '<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:600;margin-bottom:6px;">' +
        ICON.serious + '<span>Campaign cluster — ' + drawerCampaigns.length + ' pattern' +
        (drawerCampaigns.length === 1 ? "" : "s") + '</span></div>' +
        camRows + '</div></div>';
    }

    var iocs = e.iocs || {};
    html += '<div class="drawer-field"><span class="df-label">IOCs</span>' +
      '<div style="font-size:11px; color:var(--ink-muted); margin-bottom:8px;">Bracketed notes are this analysis\'s own rule-based findings, not a live threat-intel lookup.</div>' +
      iocBlockHtml("senders", iocs.sender_emails, iocs.context) +
      iocBlockHtml("domains", iocs.domains, iocs.context) +
      iocBlockHtml("ips", iocs.ips, iocs.context) +
      iocBlockHtml("urls", iocs.urls, iocs.context) +
      iocBlockHtml("hashes (sha256)", iocs.hashes_sha256, iocs.context) +
      iocBlockHtml("auth relay senders", iocs.authenticated_relay_senders, iocs.context) +
      "</div>";

    if (scored && e.status !== "released" && (e.verdict === "SUSPICIOUS" || e.verdict === "MALICIOUS")) {
      html += '<div class="retention-note">EML retained for admin retest until <strong>' + fmtDateTime(e.expiresAt) + "</strong> (7-day policy), then purged.</div>";
    }
    return html;
  }

  function buildPreviewFootHtml(e) {
    var canActOnThis = e.sourceKind === "spool" && canAct();
    var canDl = (e.sourceKind === "spool" || e.sourceKind === "gmail") && e.queueId && canAct();
    var canLabel = !!e.queueId && canAct();
    var labelled = e.analystLabel === "benign";
    return '<button class="btn btn-sm" data-fw-action="copy">' + ICON.download + "Copy report</button>" +
      (canDl ? '<button class="btn btn-sm" data-fw-action="download">' + ICON.download + "Download EML</button>" : "") +
      (canLabel && !labelled ? '<button class="btn btn-sm btn-primary" data-fw-action="benign">' + ICON.good + "Mark as not malicious</button>" : "") +
      (canLabel && labelled ? '<button class="btn btn-sm" data-fw-action="unbenign">Undo benign label</button>' : "") +
      (canActOnThis ? '<button class="btn btn-sm" data-fw-action="reevaluate">' + ICON.eye + "Re-evaluate</button>" : "") +
      (canActOnThis && verdictIsFinal(e) && (e.verdict === "SUSPICIOUS" || e.verdict === "MALICIOUS") && e.status !== "released"
        ? '<button class="btn btn-sm btn-primary" data-fw-action="release">' + ICON.release + "Release</button>" +
          '<button class="btn btn-sm" data-fw-action="keepblocked">' + ICON.critical + "Keep blocked</button>" : "");
  }

  /* ============================== EMAIL DETAIL PAGE ============================== */
  function b64urlToBuf(s) {
    s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function decodePublicKeyOptions(opts) {
    var o = JSON.parse(JSON.stringify(opts));
    o.challenge = b64urlToBuf(o.challenge);
    if (o.user && o.user.id) o.user.id = b64urlToBuf(o.user.id);
    (o.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    (o.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return o;
  }
  function credentialToJson(cred) {
    var r = cred.response;
    var out = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON)
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64url(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64url(r.authenticatorData);
      out.response.signature = bufToB64url(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64url(r.userHandle);
    }
    return out;
  }
  function apiErrorDetail(j, fallback) {
    var d = j && j.detail;
    if (Array.isArray(d)) d = d.map(function (x) { return x.msg || JSON.stringify(x); }).join("; ");
    return d || fallback;
  }
  function refreshCurrentUser(): any {
    return fetch("/api/auth/me", { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) throw new Error("Session expired");
      return r.json();
    }).then(function (u) {
      window.__SEG_CURRENT_USER__ = u;
      if (u && u.content_unlocked_thread && !unlockedThread.key) {
        unlockedThread.key = u.content_unlocked_thread;
      }
      return u;
    });
  }
  function registerPasskey(name?: any, unlock?: any, queueId?: any) {
    if (!window.PublicKeyCredential) {
      return Promise.reject(new Error("Passkeys need HTTPS or localhost"));
    }
    return fetch("/api/auth/passkeys/register/options", {
      method: "POST", credentials: "same-origin"
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(apiErrorDetail(j, "Could not start passkey registration"));
        return j;
      });
    }).then(function (opts) {
      return navigator.credentials.create({ publicKey: decodePublicKeyOptions(opts) });
    }).then(function (cred) {
      if (!cred) throw new Error("Passkey registration was cancelled");
      return fetch("/api/auth/passkeys/register", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential: credentialToJson(cred),
          name: name || "Passkey",
          unlock: !!unlock,
          queue_id: queueId || ""
        })
      });
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(apiErrorDetail(j, "Passkey registration failed"));
        rememberUnlockGrant(j);
        return j;
      });
    }).then(function () { return refreshCurrentUser(); });
  }
  function assertPasskey(queueId) {
    if (!window.PublicKeyCredential) {
      return Promise.reject(new Error("Passkeys need HTTPS or localhost"));
    }
    return fetch("/api/auth/passkeys/assert/options", {
      method: "POST", credentials: "same-origin"
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(apiErrorDetail(j, "Could not start passkey unlock"));
        return j;
      });
    }).then(function (opts) {
      return navigator.credentials.get({ publicKey: decodePublicKeyOptions(opts) });
    }).then(function (cred) {
      if (!cred) throw new Error("Passkey unlock was cancelled");
      return fetch("/api/auth/passkeys/assert", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: credentialToJson(cred), queue_id: queueId || "" })
      });
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(apiErrorDetail(j, "Passkey unlock failed"));
        rememberUnlockGrant(j);
        return j;
      });
    }).then(function () { return refreshCurrentUser(); });
  }
  function ensureContentUnlocked(queueId) {
    var me = window.__SEG_CURRENT_USER__ || {};
    if (!canAct()) return Promise.reject(new Error("Email content is limited to analysts and admins"));
    var e = findEmail(queueId) || (state.feed || []).filter(function (x) { return x.queueId === queueId; })[0]
      || { id: queueId, queueId: queueId, threadKey: unlockedThread.key, gmailThreadId: unlockedThread.gmailThreadId };
    if (sameUnlockedThread(e)) return Promise.resolve(true);
    if (!(me.passkey_count > 0)) {
      return registerPasskey("Passkey", true, queueId).then(function () { return true; });
    }
    return assertPasskey(queueId).then(function () { return true; });
  }
  function contentLockHtml(kind, message) {
    var btn = "";
    if (kind === "register") {
      btn = '<button type="button" class="btn btn-primary" id="contentRegisterBtn">Register a passkey</button>';
    } else if (kind === "unlock") {
      btn = '<button type="button" class="btn btn-primary" id="contentUnlockBtn">Unlock with passkey</button>';
    }
    return '<div class="content-lock">' +
      ICON.lock +
      "<h3>Email content is locked</h3>" +
      "<p>" + escapeHtml(message) + "</p>" +
      btn +
      '<div class="content-lock-error" id="contentLockError"></div></div>';
  }
  function setContentLockError(slot, msg) {
    var el = slot.querySelector("#contentLockError");
    if (el) el.textContent = msg || "";
  }
  function showContentLock(slot, e) {
    var me = window.__SEG_CURRENT_USER__ || {};
    if (!canAct()) {
      slot.innerHTML = contentLockHtml("none",
        "Original email content is available to analysts and admins. AI analysis on the right is still visible.");
      return;
    }
    if (me.passkey_count > 0) {
      slot.innerHTML = contentLockHtml("unlock",
        "Unlock this thread with your passkey. Other messages in the conversation stay unlocked until you leave it. AI analysis stays visible.");
      var unlockBtn = slot.querySelector("#contentUnlockBtn");
      if (unlockBtn) unlockBtn.addEventListener("click", function () {
        unlockBtn.disabled = true;
        setContentLockError(slot, "");
        assertPasskey(e.queueId).then(function () {
          rememberUnlockGrant(null, e);
          fetchEmlInto(slot, e);
        }).catch(function (err) {
          unlockBtn.disabled = false;
          setContentLockError(slot, err.message || String(err));
        });
      });
      return;
    }
    slot.innerHTML = contentLockHtml("register",
      "Register a passkey to unlock this thread. Other messages in the conversation stay unlocked until you leave it. AI analysis is not blocked.");
    var regBtn = slot.querySelector("#contentRegisterBtn");
    if (regBtn) regBtn.addEventListener("click", function () {
      regBtn.disabled = true;
      setContentLockError(slot, "");
      registerPasskey("Passkey", true, e.queueId).then(function () {
        rememberUnlockGrant(null, e);
        fetchEmlInto(slot, e);
        loadPasskeys();
      }).catch(function (err) {
        regBtn.disabled = false;
        setContentLockError(slot, err.message || String(err));
      });
    });
  }
  var unlockedThread = { key: null, gmailThreadId: "", bodies: {} };
  function rememberUnlockGrant(j, e) {
    var key = (j && j.thread_key) || (e && threadKeyOf(e)) || unlockedThread.key || null;
    var gid = (e && e.gmailThreadId) || unlockedThread.gmailThreadId || "";
    var keep = (unlockedThread.key && key && unlockedThread.key === key)
      || (unlockedThread.gmailThreadId && gid && String(unlockedThread.gmailThreadId) === String(gid));
    unlockedThread = {
      key: key,
      gmailThreadId: gid,
      bodies: keep ? (unlockedThread.bodies || {}) : {}
    };
  }
  function sameUnlockedThread(e) {
    if (!e) return false;
    var key = threadKeyOf(e);
    if (unlockedThread.key && unlockedThread.key === key) return true;
    if (unlockedThread.gmailThreadId && e.gmailThreadId
        && String(unlockedThread.gmailThreadId) === String(e.gmailThreadId)) return true;
    var grant = ((window.__SEG_CURRENT_USER__ || {}).content_unlocked_thread) || "";
    if (grant === "*") return true;
    if (grant && grant === key) return true;
    if (grant && e.gmailThreadId) {
      if (grant === "gmail:" + e.gmailThreadId) return true;
      if (grant.indexOf("gmail:") === 0 && grant.lastIndexOf(":" + e.gmailThreadId) === grant.length - (e.gmailThreadId.length + 1)) return true;
    }
    return false;
  }
  function lockContentGrant() {
    unlockedThread = { key: null, gmailThreadId: "", bodies: {} };
    fetch("/api/auth/passkeys/lock", { method: "POST", credentials: "same-origin" }).catch(function () {});
  }
  function fetchEmlInto(slot, e) {
    slot.innerHTML = '<div class="email-viewer-loading">Loading message…</div>';
    fetch("/api/quarantine/" + encodeURIComponent(e.queueId) + "/download?intent=view", { credentials: "same-origin" })
      .then(function (r) {
        if (r.status === 403) {
          return r.json().then(function (j) {
            var detail = (j && j.detail) || "";
            if (detail === "passkey_required") {
              if (window.__SEG_CURRENT_USER__) {
                window.__SEG_CURRENT_USER__.content_unlocked = false;
                window.__SEG_CURRENT_USER__.content_unlocked_thread = "";
              }
              unlockedThread = { key: null, gmailThreadId: "", bodies: {} };
              showContentLock(slot, e);
              throw new Error("__locked__");
            }
            throw new Error(detail || "forbidden");
          });
        }
        if (!r.ok) throw new Error("Could not load message (" + r.status + ")");
        return r.text();
      })
      .then(function (text) {
        rememberUnlockGrant(null, e);
        unlockedThread.bodies[e.queueId] = text;
        slot.innerHTML = renderEmailViewer(parseEml(text), scanContextFromEmail(e));
        bindEmailViewer(slot);
      })
      .catch(function (err) {
        if (err && err.message === "__locked__") return;
        slot.innerHTML = '<div class="email-viewer-loading">' + escapeHtml(err.message || String(err)) + "</div>";
      });
  }
  function loadEmailContent(slot, e) {
    if (!canAct()) { showContentLock(slot, e); return; }
    if (sameUnlockedThread(e)) {
      var cached = unlockedThread.bodies[e.queueId];
      if (cached) {
        slot.innerHTML = renderEmailViewer(parseEml(cached), scanContextFromEmail(e));
        bindEmailViewer(slot);
        return;
      }
      fetchEmlInto(slot, e);
      return;
    }
    showContentLock(slot, e);
  }
  function loadPasskeys() {
    var list = document.getElementById("passkeyList");
    var empty = document.getElementById("passkeyEmpty");
    if (!list) return Promise.resolve();
    return fetch("/api/auth/passkeys", { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) throw new Error("Could not load passkeys");
      return r.json();
    }).then(function (body) {
      var keys = (body && body.passkeys) || [];
      empty.style.display = keys.length ? "none" : "block";
      list.innerHTML = keys.map(function (k) {
        return '<div class="passkey-row"><span>' + escapeHtml(k.name || "Passkey") +
          " · added " + fmtDateTime(Math.round((k.created_at || 0) * 1000)) +
          '</span><button type="button" class="btn btn-sm" data-passkey-del="' +
          escapeHtml(String(k.id)) + '">Remove</button></div>';
      }).join("");
      Array.prototype.forEach.call(list.querySelectorAll("[data-passkey-del]"), function (btn) {
        btn.addEventListener("click", function () {
          fetch("/api/auth/passkeys/" + encodeURIComponent(btn.dataset.passkeyDel), {
            method: "DELETE", credentials: "same-origin"
          }).then(function (r) {
            if (!r.ok) throw new Error("Could not remove passkey");
            return refreshCurrentUser().then(loadPasskeys);
          }).catch(function (err) { toast(ICON.warning, err.message || String(err)); });
        });
      });
    }).catch(function (err) {
      empty.style.display = "none";
      list.innerHTML = '<div class="users-error show">' + escapeHtml(err.message || String(err)) + "</div>";
    });
  }
  function wirePasskeysPage() {
    var addBtn = document.getElementById("passkeyAddBtn");
    if (!addBtn) return;
    addBtn.addEventListener("click", function () {
      addBtn.disabled = true;
      var errEl = document.getElementById("passkeyError");
      if (errEl) { errEl.classList.remove("show"); errEl.textContent = ""; }
      registerPasskey("Passkey").then(function () {
        toast(ICON.good, "Passkey added. Unlock is still required to view email content.");
        return loadPasskeys();
      }).catch(function (err) {
        if (errEl) { errEl.textContent = err.message || String(err); errEl.classList.add("show"); }
        toast(ICON.warning, err.message || String(err));
      }).finally(function () { addBtn.disabled = false; });
    });
  }

  function populateDetailPage(e) {
    var body = document.getElementById("detailBody");
    var analysis = document.getElementById("detailAnalysis");
    var foot = document.getElementById("detailFoot");
    if (!body || !foot || !analysis) return;
    body.innerHTML = buildDetailMailHtml(e);
    analysis.innerHTML = buildPreviewBodyHtml(e);
    var threadSide = document.getElementById("detailThread");
    if (threadSide) threadSide.innerHTML = buildThreadSidebarHtml(e);
    mountAssessmentFlow(document.getElementById("detailFlow"), e, true);
    renderDetailOriginMap(e);
    foot.innerHTML = buildPreviewFootHtml(e);

    Array.prototype.forEach.call(body.querySelectorAll("[data-thread-id]"), function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        var id = btn.dataset.threadId;
        if (id && id !== state.detailId) openDetailPage(id);
      });
    });

    if (e.queueId) {
      var emlSlot = document.getElementById("fw-eml-" + e.id);
      if (emlSlot) loadEmailContent(emlSlot, e);
    }

    var copyBtn = foot.querySelector('[data-fw-action="copy"]');
    if (copyBtn) copyBtn.addEventListener("click", function () { copyReport(e.id); });
    var dlBtn = foot.querySelector('[data-fw-action="download"]');
    if (dlBtn) dlBtn.addEventListener("click", function () { downloadEml(e.id); });
    var reBtn = foot.querySelector('[data-fw-action="reevaluate"]');
    if (reBtn) reBtn.addEventListener("click", function () { reevaluateEntry(e.id); });
    var relBtn = foot.querySelector('[data-fw-action="release"]');
    if (relBtn) relBtn.addEventListener("click", function () { confirmRelease(e.id); });
    var kbBtn = foot.querySelector('[data-fw-action="keepblocked"]');
    if (kbBtn) kbBtn.addEventListener("click", function () { confirmKeepBlocked(e.id); });
    var benignBtn = foot.querySelector('[data-fw-action="benign"]');
    if (benignBtn) benignBtn.addEventListener("click", function () { markEmailBenign(e.id); });
    var unbenignBtn = foot.querySelector('[data-fw-action="unbenign"]');
    if (unbenignBtn) unbenignBtn.addEventListener("click", function () { unmarkEmailBenign(e.id); });
  }

  function refreshDetailPage(id) {
    if (typeof ui.onData === "function") ui.onData({ detailId: id || state.detailId });
    var e = findEmail(id || state.detailId);
    if (!e || state.activePage !== "detail") return;
    if (document.getElementById("detailBody")) populateDetailPage(e);
    var title = document.getElementById("pageTitle");
    if (title) title.textContent = e.subject || "(no subject)";
  }

  function openDetailPage(id) {
    var qid = String(id || "").trim();
    if (!qid) return;
    var e = findEmail(qid);
    if (state.activePage !== "detail") state.detailReturnPage = state.activePage;
    state.detailId = qid;
    if (typeof ui.onNavigate === "function") {
      ui.onNavigate("/mail/" + encodeURIComponent(qid));
      return;
    }
    if (!e) return;
    setPage("detail");
    populateDetailPage(e);
  }

  function closeDetailPage() {
    var returnPage = state.detailReturnPage || "overview";
    state.detailId = null;
    if (typeof ui.onNavigate === "function") {
      ui.onNavigate(pathForPage(returnPage));
      return;
    }
    setPage(returnPage);
  }

  function cancelRelease() {
    pendingAction = null;
    document.getElementById("modalOverlay").classList.remove("show");
  }
  // Click the dimmed backdrop (not the modal card itself) to dismiss.
  var __el1 = document.getElementById("modalOverlay"); if (__el1) __el1.addEventListener("click", function (ev) {
    if (ev.target === this) cancelRelease();
  });
  // Escape closes whatever is on top: modal first, then the email detail page.
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    if (document.getElementById("modalOverlay").classList.contains("show")) { cancelRelease(); return; }
    if (state.activePage === "detail") closeDetailPage();
  });

  /* ============================== ACTIONS: DOWNLOAD / RELEASE / KEEP BLOCKED ============================== */
  // All three call the real backend (server/routers/feed.py, wrapping
  // app/disposition.py's existing release_from_quarantine()/keep_blocked())
  // and only apply to spool-sourced entries (e.sourceKind === "spool",
  // e.queueId set) — demo .eml pipeline-run entries are an eval corpus,
  // not queued mail pending a triage decision, so they get no action
  // buttons at all (see renderQuarantine()/renderFeed()).
  function canAct() {
    var u = window.__SEG_CURRENT_USER__;
    return !!u && (u.role === "admin" || u.role === "analyst");
  }

  function markEmailBenign(id) {
    var e = findEmail(id);
    if (!e || !e.queueId) return;
    toast(ICON.good, "Recording benign label…");
    fetch("/api/feedback/benign", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queue_id: e.queueId })
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (err) { throw new Error(err.detail || r.status); });
      return r.json();
    }).then(function (body) {
      var n = (body.indicators || []).length;
      return loadFeed().then(function () {
        refreshDetailPage(id);
        toast(ICON.good, "Marked not malicious — " + n + " good-mail indicator" + (n === 1 ? "" : "s") + " stored");
      });
    }).catch(function (err) { toast(ICON.warning, err.message || String(err)); });
  }

  function unmarkEmailBenign(id) {
    var e = findEmail(id);
    if (!e || !e.queueId) return;
    fetch("/api/feedback/benign/" + encodeURIComponent(e.queueId), {
      method: "DELETE", credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) throw new Error("Could not remove label (" + r.status + ")");
      return loadFeed().then(function () {
        refreshDetailPage(id);
        toast(ICON.good, "Benign label removed");
      });
    }).catch(function (err) { toast(ICON.warning, err.message || String(err)); });
  }

  function reportCachedDownload(e) {
    fetch("/api/activity/email-view", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queue_id: e.queueId || e.id,
        event: "download",
        subject: e.subject || "",
        from_addr: e.fromAddr || "",
      }),
      keepalive: true,
    }).catch(function () {});
  }

  function downloadEml(id) {
    var e = findEmail(id);
    if (!e || !e.queueId) return;
    function save(text) {
      var blob = new Blob([text], { type: "message/rfc822" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = e.id + ".eml";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);
      toast(ICON.download, "Downloading " + e.id + ".eml");
    }
    if (sameUnlockedThread(e) && unlockedThread.bodies[e.queueId]) {
      save(unlockedThread.bodies[e.queueId]);
      reportCachedDownload(e);
      return;
    }
    ensureContentUnlocked(e.queueId).then(function (ok) {
      if (!ok) return;
      return fetch("/api/quarantine/" + encodeURIComponent(e.queueId) + "/download", { credentials: "same-origin" })
        .then(function (r) {
          if (!r.ok) throw new Error("Download failed (" + r.status + ")");
          return r.text();
        })
        .then(function (text) {
          rememberUnlockGrant(null, e);
          unlockedThread.bodies[e.queueId] = text;
          save(text);
        });
    }).catch(function (err) {
      toast(ICON.warning, err.message || "Passkey required to download");
    });
  }

  var pendingAction = null;   // { id, kind: "release" | "keepblocked" }
  function confirmRelease(id) {
    var e = findEmail(id);
    if (!e) return;
    pendingAction = { id: id, kind: "release" };
    if (typeof ui.onConfirm === "function") {
      ui.onConfirm({
        id: id,
        kind: "release",
        title: "Release this email?",
        body: "This moves the message out of quarantine (gateway/spool/released/) and logs the action to the audit trail. Use this only after retesting confirms it's safe.",
        detail: e.fromAddr + " — “" + e.subject + "”",
        confirmLabel: "Release"
      });
      return;
    }
    document.getElementById("modalTitle").textContent = "Release this email?";
    document.getElementById("modalBody").textContent = "This moves the message out of quarantine (gateway/spool/released/) and logs the action to the audit trail. Use this only after retesting confirms it's safe.";
    document.getElementById("modalDetail").textContent = e.fromAddr + " — “" + e.subject + "”";
    document.getElementById("modalOverlay").classList.add("show");
  }
  function reevaluateEntry(id) {
    var e = findEmail(id);
    if (!e || !e.queueId) return;
    toast(ICON.eye, "Re-evaluating " + e.id + "…");
    fetch("/api/quarantine/" + encodeURIComponent(e.queueId) + "/reevaluate", {
      method: "POST", credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) throw new Error("re-evaluate failed (" + r.status + ")");
      return r.json();
    }).then(function (body) {
      return loadFeed().then(function () {
        if (body && body.queued) {
          toast(ICON.good, e.id + " queued for re-evaluation");
        } else if (body && body.reeval) {
          toast(ICON.good, e.id + " re-evaluated: " + body.reeval.new_verdict + " (was " + body.reeval.previous_verdict + ")");
        } else {
          toast(ICON.good, e.id + " queued for re-evaluation");
        }
        refreshDetailPage(id);
      });
    }).catch(function (err) {
      toast(ICON.warning, "Re-evaluate failed — " + err.message);
    });
  }

  function confirmKeepBlocked(id) {
    var e = findEmail(id);
    if (!e) return;
    pendingAction = { id: id, kind: "keepblocked" };
    if (typeof ui.onConfirm === "function") {
      ui.onConfirm({
        id: id,
        kind: "keepblocked",
        title: "Keep this email blocked?",
        body: "This confirms the block and moves the message to gateway/spool/rejected/.",
        detail: e.fromAddr + " — “" + e.subject + "”",
        confirmLabel: "Keep blocked"
      });
      return;
    }
    document.getElementById("modalTitle").textContent = "Keep this email blocked?";
    document.getElementById("modalBody").textContent = "This confirms the block and moves the message to gateway/spool/rejected/.";
    document.getElementById("modalDetail").textContent = e.fromAddr + " — “" + e.subject + "”";
    document.getElementById("modalOverlay").classList.add("show");
  }

  function executePendingAction(kind, id) {
    var e = findEmail(id);
    if (!e || !e.queueId) return Promise.reject(new Error("missing queue id"));
    var endpoint = kind === "release" ? "release" : "keep-blocked";
    return fetch("/api/quarantine/" + encodeURIComponent(e.queueId) + "/" + endpoint, {
      method: "POST", credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) throw new Error("action failed (" + r.status + ")");
      return loadFeed();
    }).then(function () {
      toast(kind === "release" ? ICON.release : ICON.critical,
        (kind === "release" ? "Released " : "Kept blocked: ") + e.id);
    });
  }
  var __el2 = document.getElementById("modalCancel"); if (__el2) __el2.addEventListener("click", cancelRelease);
  var __el3 = document.getElementById("modalConfirm"); if (__el3) __el3.addEventListener("click", function () {
    if (!pendingAction) { document.getElementById("modalOverlay").classList.remove("show"); return; }
    var e = findEmail(pendingAction.id);
    var actedId = pendingAction.id;
    var endpoint = pendingAction.kind === "release" ? "release" : "keep-blocked";
    var btn = this;
    btn.disabled = true;
    fetch("/api/quarantine/" + encodeURIComponent(e.queueId) + "/" + endpoint, {
      method: "POST", credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) throw new Error("action failed (" + r.status + ")");
      return loadFeed();
    }).then(function () {
      toast(pendingAction.kind === "release" ? ICON.release : ICON.critical,
        (pendingAction.kind === "release" ? "Released " : "Kept blocked: ") + e.id);
      refreshDetailPage(actedId);
    }).catch(function (err) {
      toast(ICON.warning, "Action failed — " + err.message);
    }).finally(function () {
      btn.disabled = false;
      pendingAction = null;
      document.getElementById("modalOverlay").classList.remove("show");
    });
  });

  function toast(icon, msg) {
    if (typeof ui.onToast === "function") {
      ui.onToast(icon, msg);
      return;
    }
    var stack = document.getElementById("toastStack");
    if (!stack) return;
    var t = document.createElement("div");
    t.className = "toast";
    t.innerHTML = icon + "<span>" + escapeHtml(msg) + "</span>";
    stack.appendChild(t);
    setTimeout(function () {
      t.style.transition = "opacity .25s ease";
      t.style.opacity = "0";
      setTimeout(function () { t.remove(); }, 260);
    }, 3200);
  }

  /* ============================== ANALYZE (EML UPLOAD) ============================== */
  var analyzeFile = null;
  var analyzeRawEml = "";
  var analyzeTimer = null;
  var analyzeAbort = null;
  var _behavModalData = [];
  var RISK_CHIP = {
    LOW: { cls: "v-clean", label: "LOW" },
    MEDIUM: { cls: "v-low", label: "MEDIUM" },
    HIGH: { cls: "v-suspicious", label: "HIGH" },
    CRITICAL: { cls: "v-malicious", label: "CRITICAL" }
  };
  var CLASSIFICATION_CHIP = {
    Benign: { cls: "v-clean", label: "Benign" },
    Suspicious: { cls: "v-low", label: "Suspicious" },
    Spam: { cls: "v-low", label: "Spam" },
    Phishing: { cls: "v-suspicious", label: "Phishing" },
    BEC: { cls: "v-suspicious", label: "BEC" },
    Malware: { cls: "v-malicious", label: "Malware" },
    Malicious: { cls: "v-malicious", label: "Malicious" }
  };

  function resolveAnalyzeClassification(data) {
    var threat = (data.analysis && data.analysis.threat_assessment) || {};
    var content = (data.analysis && data.analysis.content_analysis) || {};
    var pb = data.playbook || {};
    var raw = threat.classification || content.category || pb.classification || pb.verdict || "";
    if (raw && typeof raw === "string") {
      raw = raw.trim();
      if (raw.indexOf(" — ") !== -1) raw = raw.split(" — ").pop().trim();
      if (CLASSIFICATION_CHIP[raw]) return raw;
      var upper = raw.toUpperCase();
      var keys = Object.keys(CLASSIFICATION_CHIP);
      for (var i = 0; i < keys.length; i++) {
        if (keys[i].toUpperCase() === upper) return keys[i];
      }
      if (upper.indexOf("PHISH") !== -1) return "Phishing";
      if (upper.indexOf("MALWARE") !== -1) return "Malware";
      if (upper.indexOf("BEC") !== -1 || upper.indexOf("BUSINESS EMAIL") !== -1) return "BEC";
      if (upper.indexOf("SPAM") !== -1) return "Spam";
      if (upper.indexOf("BENIGN") !== -1 || upper.indexOf("LEGIT") !== -1) return "Benign";
      if (upper.indexOf("SUSPICIOUS") !== -1) return "Suspicious";
      if (upper.indexOf("MALICIOUS") !== -1) return "Malicious";
    }
    var risk = String(threat.risk_level || "").toUpperCase();
    if (risk === "LOW") return "Benign";
    if (risk === "MEDIUM") return "Suspicious";
    if (risk === "HIGH" || risk === "CRITICAL") return "Malicious";
    return "Suspicious";
  }

  function setAnalyzeFile(file) {
    analyzeFile = file || null;
    analyzeRawEml = "";
    var dz = document.getElementById("analyzeDropzone");
    var label = document.getElementById("analyzeFileLabel");
    var btn = document.getElementById("analyzeBtn");
    if (analyzeFile) {
      if (dz) dz.classList.add("has-file");
      if (label) label.textContent = analyzeFile.name + " · " + (analyzeFile.size / 1024).toFixed(1) + " KB";
      if (btn) btn.disabled = !canAct();
      var reader = new FileReader();
      reader.onload = function (ev) { analyzeRawEml = ev.target.result || ""; };
      reader.readAsText(analyzeFile);
    } else {
      if (dz) dz.classList.remove("has-file");
      if (label) label.textContent = "";
      if (btn) btn.disabled = true;
    }
  }

  function syncAnalyzeRoleGate() {
    var denied = document.getElementById("analyzeDenied");
    var form = document.getElementById("analyzeForm");
    if (!canAct()) {
      denied.style.display = "block";
      form.style.display = "none";
    } else {
      denied.style.display = "none";
      form.style.display = "block";
    }
  }

  function isAdmin() {
    var u = window.__SEG_CURRENT_USER__;
    return !!u && u.role === "admin";
  }

  function syncUserChrome() {
    var u = window.__SEG_CURRENT_USER__ || {};
    document.getElementById("userChipName").textContent = u.username || "—";
    document.getElementById("userChipRole").textContent = u.role || "—";
    var navSettings = document.getElementById("navSettings");
    if (navSettings) navSettings.hidden = !isAdmin();
  }

  // ===== ENFORCEMENT MODE =====
  var _enforcePending = null;

  var ENFORCE_LABELS: any = { shadow: "Monitor only", quarantine: "Quarantine", reject: "Reject" };
  var ENFORCE_BADGE_CLS: any = { shadow: "mode-shadow", quarantine: "mode-quarantine", reject: "mode-reject" };

  function renderEnforcement(data) {
    var mode = (data && data.mode) || "shadow";
    var badge = document.getElementById("enforceBadge");
    var meta  = document.getElementById("enforceMeta");
    if (!badge) return;
    badge.textContent = ENFORCE_LABELS[mode] || mode;
    badge.className = "enforce-badge " + (ENFORCE_BADGE_CLS[mode] || "mode-shadow");
    var btns = document.querySelectorAll(".enforce-seg button[data-mode]");
    for (var i = 0; i < btns.length; i++) {
      var pressed = btns[i].dataset.mode === mode;
      btns[i].setAttribute("aria-pressed", pressed ? "true" : "false");
    }
    if (meta) {
      var by = data && data.updated_by ? data.updated_by : "";
      var at = data && data.updated_at ? data.updated_at : "";
      if (by && at) {
        try { at = new Date(at).toLocaleString(); } catch (e) {}
        meta.textContent = "Last changed by " + by + " on " + at;
      } else {
        meta.textContent = mode === "shadow" ? "Default: detection and monitoring only. No mail is blocked." : "";
      }
    }
  }

  function loadEnforcement() {
    if (!isAdmin()) return Promise.resolve();
    return fetch("/api/enforcement", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d) renderEnforcement(d); })
      .catch(function () {});
  }

  function applyEnforcement(mode) {
    return fetch("/api/enforcement", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: mode })
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
      return r.json();
    }).then(function (d) {
      renderEnforcement(d);
      toast(ICON.good, "Enforcement set to: " + (ENFORCE_LABELS[d.mode] || d.mode));
    }).catch(function (err) {
      toast(ICON.warning, "Could not change enforcement: " + (err.message || err));
    });
  }

  (function initEnforcementUI() {
    var seg = document.querySelector(".enforce-seg");
    if (!seg) return;
    seg.addEventListener("click", function (ev) {
      var btn = ev.target.closest("button[data-mode]");
      if (!btn) return;
      var newMode = btn.dataset.mode;
      if (newMode !== "shadow") {
        toast(ICON.warning, "Monitor-only: this deployment never quarantines or rejects mail");
        return;
      }
      var curMode = "shadow";
      var badges = document.getElementById("enforceBadge");
      if (badges) curMode = (badges.className.match(/mode-(\w+)/) || [])[1] || "shadow";
      if (newMode === curMode) return;
      // Warn before escalating from shadow or quarantine → a blocking mode
      var isEscalating = (curMode === "shadow" && newMode !== "shadow") ||
                         (curMode === "quarantine" && newMode === "reject");
      if (isEscalating) {
        _enforcePending = newMode;
        var modal = document.getElementById("enforceModal");
        var title = document.getElementById("enforceModalTitle");
        var body  = document.getElementById("enforceModalBody");
        var confirmBtn = document.getElementById("enforceModalConfirm");
        if (newMode === "quarantine") {
          title.textContent = "Enable quarantine mode?";
          body.textContent = "Suspicious and malicious mail will be held in spool/quarantine/ instead of delivered. Confirm you've validated detection quality in monitor-only mode first.";
          confirmBtn.className = "enforce-btn-confirm is-quarantine";
        } else {
          title.textContent = "Enable reject mode?";
          body.textContent = "Malicious mail will be hard-rejected at the gateway. This affects live delivery immediately. Only enable after thorough shadow validation.";
          confirmBtn.className = "enforce-btn-confirm";
        }
        modal.classList.add("open");
      } else {
        applyEnforcement(newMode);
      }
    });
    var __el4 = document.getElementById("enforceModalCancel"); if (__el4) __el4.addEventListener("click", function () {
      _enforcePending = null;
      document.getElementById("enforceModal").classList.remove("open");
    });
    var __el5 = document.getElementById("enforceModalConfirm"); if (__el5) __el5.addEventListener("click", function () {
      var mode = _enforcePending;
      _enforcePending = null;
      document.getElementById("enforceModal").classList.remove("open");
      if (mode) applyEnforcement(mode);
    });
    var __el6 = document.getElementById("enforceModal"); if (__el6) __el6.addEventListener("click", function (ev) {
      if (ev.target === this) { _enforcePending = null; this.classList.remove("open"); }
    });
  })();

  function showUsersError(msg) {
    var el = document.getElementById("usersError");
    if (!msg) { el.classList.remove("show"); el.textContent = ""; return; }
    el.textContent = msg;
    el.classList.add("show");
  }

  function loadUsers() {
    if (!isAdmin()) return Promise.resolve();
    showUsersError("");
    return fetch("/api/users", { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) throw new Error("Could not load users (" + r.status + ")");
      return r.json();
    }).then(function (users) {
      renderUsersTable(users || []);
    }).catch(function (err) {
      showUsersError(err.message || String(err));
      renderUsersTable([]);
    });
  }

  function renderUsersTable(users) {
    var body = document.getElementById("usersBody");
    var empty = document.getElementById("usersEmpty");
    var me = (window.__SEG_CURRENT_USER__ && window.__SEG_CURRENT_USER__.username) || "";
    if (!users.length) {
      body.innerHTML = "";
      empty.style.display = "block";
      return;
    }
    empty.style.display = "none";
    body.innerHTML = users.map(function (u) {
      var created = u.created_at ? fmtDateTime(Math.round(u.created_at * 1000)) : "—";
      var status = u.disabled ? '<span class="chip v-malicious">Disabled</span>' : '<span class="chip v-clean">Active</span>';
      var isMe = u.username === me;
      var pwBtn = '<button type="button" class="btn btn-sm" data-user-pw="' + escapeHtml(String(u.id)) +
        '" data-user-name="' + escapeHtml(u.username) + '">Set password</button>';
      var delBtn = isMe
        ? '<span class="analyze-meta">You</span>'
        : '<button type="button" class="btn btn-sm" data-user-del="' + escapeHtml(String(u.id)) +
          '" data-user-name="' + escapeHtml(u.username) + '">Delete</button>';
      return "<tr>" +
        "<td>" + escapeHtml(u.username) + "</td>" +
        "<td>" + escapeHtml(u.role) + "</td>" +
        "<td>" + status + "</td>" +
        '<td class="cell-time">' + escapeHtml(created) + "</td>" +
        '<td><div class="users-actions">' + pwBtn + delBtn + "</div></td>" +
        "</tr>";
    }).join("");
    Array.prototype.forEach.call(body.querySelectorAll('[data-user-pw]'), function (btn) {
      btn.addEventListener('click', function () {
        var id = btn.getAttribute('data-user-pw');
        var name = btn.getAttribute('data-user-name') || id;
        openPwModal(id, name);
      });
    });
    Array.prototype.forEach.call(body.querySelectorAll("[data-user-del]"), function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-user-del");
        var name = btn.getAttribute("data-user-name") || id;
        if (!window.confirm("Delete user “" + name + "”? Their sessions will end immediately.")) return;
        fetch("/api/users/" + encodeURIComponent(id), {
          method: "DELETE", credentials: "same-origin"
        }).then(function (r) {
          if (!r.ok) {
            return r.json().then(function (j) {
              throw new Error((j && j.detail) || ("Delete failed (" + r.status + ")"));
            }, function () { throw new Error("Delete failed (" + r.status + ")"); });
          }
          toast(ICON.good, "Deleted " + name);
          loadFeed();
          return loadUsers();
        }).catch(function (err) {
          showUsersError(err.message || String(err));
        });
      });
    });
  }

  function wireUsersPage() {
    var __el7 = document.getElementById("usersRefreshBtn"); if (__el7) __el7.addEventListener("click", function () { loadUsers(); });
    var __el8 = document.getElementById("usersCreateForm"); if (__el8) __el8.addEventListener("submit", function (ev) {
      ev.preventDefault();
      showUsersError("");
      var username = document.getElementById("usersNewName").value.trim();
      var password = document.getElementById("usersNewPass").value;
      var role = document.getElementById("usersNewRole").value;
      if (!username || password.length < 8) {
        showUsersError("Username required; password must be at least 8 characters.");
        return;
      }
      var btn = document.getElementById("usersCreateBtn");
      btn.disabled = true;
      fetch("/api/users", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, password: password, role: role })
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) {
            var detail = j && j.detail;
            if (Array.isArray(detail)) detail = detail.map(function (d) { return d.msg || JSON.stringify(d); }).join("; ");
            throw new Error(detail || ("Create failed (" + r.status + ")"));
          }
          return j;
        });
      }).then(function (u) {
          toast(ICON.good, "Created " + u.username + " (" + u.role + ")");
        document.getElementById("usersNewName").value = "";
        document.getElementById("usersNewPass").value = "";
        document.getElementById("usersNewRole").value = "viewer";
        loadFeed();
        return loadUsers();
      }).catch(function (err) {
        showUsersError(err.message || String(err));
      }).finally(function () { btn.disabled = false; });
    });
  }

  var __el9 = document.getElementById("logoutBtn"); if (__el9) __el9.addEventListener("click", function () {
    fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" })
      .catch(function () { /* still leave */ })
      .then(function () { window.location.href = "/login"; });
  });
  wireUsersPage();
  wirePasskeysPage();

  // ===== ALLOW / BLOCKLIST =====
  var _listsActiveTab = "allowlist";

  function loadLists() {
    if (!isAdmin()) return;
    fetch("/api/lists", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) { renderListsTable(data[_listsActiveTab] || []); })
      .catch(function () { renderListsTable([]); });
  }

  function renderListsTable(entries) {
    var tbody = document.getElementById("listsBody");
    var empty = document.getElementById("listsEmpty");
    if (!entries.length) {
      tbody.innerHTML = "";
      empty.style.display = "";
      return;
    }
    empty.style.display = "none";
    tbody.innerHTML = entries.map(function (e) {
      var t = e.address ? "address" : "domain";
      var v = e.address || e.domain || "";
      return "<tr>" +
        "<td><span class='verdict-chip verdict-low'>" + t + "</span></td>" +
        "<td style='font-family:monospace;font-size:13px;'>" + escapeHtml(v) + "</td>" +
        "<td style='color:var(--ink-muted);font-size:12px;'>" + escapeHtml(e.note || "") + "</td>" +
        "<td><button class='btn btn-sm btn-danger rm-list-btn'" +
          " data-list='" + escapeHtml(_listsActiveTab) + "'" +
          " data-val='" + escapeHtml(v) + "'>Remove</button></td>" +
        "</tr>";
    }).join("");
  }

  // Delegated click handler for Remove buttons — avoids inline onclick= which
  // is vulnerable to HTML entity decode bypass (escapeHtml maps " to &quot;
  // but the HTML parser decodes it back to " before the JS engine sees it).
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest(".rm-list-btn");
    if (!btn) return;
    var listName = btn.dataset.list;
    var value = btn.dataset.val;
    fetch("/api/lists/" + encodeURIComponent(listName) + "/" + encodeURIComponent(value), {
      method: "DELETE", credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
      toast(ICON.good, "Removed " + value + " from " + listName);
      loadLists();
    }).catch(function (err) { toast(ICON.warning, err.message || String(err)); });
  });

  document.querySelectorAll(".lists-tab-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      _listsActiveTab = btn.dataset.list;
      document.querySelectorAll(".lists-tab-btn").forEach(function (b) {
        var active = b === btn;
        b.style.background = active ? "var(--accent)" : "";
        b.style.color = active ? "#fff" : "";
      });
      loadLists();
    });
  });

  function loadFeedbackPack() {
    var tbody = document.getElementById("feedbackPackBody");
    var empty = document.getElementById("feedbackPackEmpty");
    var meta = document.getElementById("feedbackPackMeta");
    if (!tbody) return;
    fetch("/api/feedback/indicators", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        var rows = data.indicators || [];
        if (meta) {
          meta.textContent = rows.length
            ? (rows.length + " indicator" + (rows.length === 1 ? "" : "s") +
              (data.updated_at ? " · updated " + data.updated_at : "") +
              ". Export this pack and import it on another environment to reuse the training.")
            : "Empty pack — open a message and click “Mark as not malicious”.";
        }
        if (!rows.length) {
          tbody.innerHTML = "";
          if (empty) empty.style.display = "";
          return;
        }
        if (empty) empty.style.display = "none";
        tbody.innerHTML = rows.map(function (row) {
          return "<tr><td>" + escapeHtml(row.kind || "") + "</td>" +
            "<td style='font-family:monospace;font-size:13px;'>" + escapeHtml(row.value || "") + "</td>" +
            "<td>" + escapeHtml(String(row.confirmations || 1)) + "</td></tr>";
        }).join("");
      })
      .catch(function () {
        tbody.innerHTML = "";
        if (empty) empty.style.display = "";
      });
  }

  var _fbExport = document.getElementById("feedbackExportBtn");
  if (_fbExport) {
    _fbExport.addEventListener("click", function () {
      fetch("/api/feedback/export", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
        .then(function (pack) {
          var blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
          var a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "good_indicators.json";
          a.click();
          URL.revokeObjectURL(a.href);
          toast(ICON.download, "Downloaded good_indicators.json");
        })
        .catch(function (err) { toast(ICON.warning, err.message || String(err)); });
    });
  }
  var _fbImport = document.getElementById("feedbackImportFile");
  if (_fbImport) {
    _fbImport.addEventListener("change", function () {
      var file = _fbImport.files && _fbImport.files[0];
      _fbImport.value = "";
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        var pack;
        try { pack = JSON.parse(String(reader.result || "")); }
        catch (e) { toast(ICON.warning, "Not valid JSON"); return; }
        fetch("/api/feedback/import", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pack: pack })
        }).then(function (r) {
          if (!r.ok) return r.json().then(function (err) { throw new Error(err.detail || r.status); });
          return r.json();
        }).then(function (imported) {
          toast(ICON.good, "Imported " + (imported.indicators || []).length + " indicators");
          loadFeedbackPack();
        }).catch(function (err) { toast(ICON.warning, err.message || String(err)); });
      };
      reader.readAsText(file);
    });
  }

  var __el10 = document.getElementById("listsAddForm"); if (__el10) __el10.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var type = document.getElementById("listsAddType").value;
    var value = document.getElementById("listsAddValue").value.trim();
    var note = document.getElementById("listsAddNote").value.trim();
    if (!value) return;
    var btn = document.getElementById("listsAddBtn");
    btn.disabled = true;
    fetch("/api/lists/" + encodeURIComponent(_listsActiveTab), {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: type, value: value, note: note })
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
      toast(ICON.good, "Added " + value + " to " + _listsActiveTab);
      document.getElementById("listsAddValue").value = "";
      document.getElementById("listsAddNote").value = "";
      loadLists();
    }).catch(function (err) { toast(ICON.warning, err.message || String(err)); })
      .finally(function () { btn.disabled = false; });
  });

  // ===== SLACK CONFIG =====
  function loadSlackConfig() {
    if (!isAdmin()) return;
    fetch("/api/slack-config", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (cfg) {
        document.getElementById("slackEnabled").checked = !!cfg.enabled;
        document.getElementById("slackThreshold").value = cfg.threshold || "SUSPICIOUS";
        document.getElementById("slackWebhookMasked").textContent =
          cfg.webhook_url_masked ? "Current: " + cfg.webhook_url_masked : "";
        var badge = document.getElementById("slackBadge");
        if (badge) {
          badge.textContent = cfg.enabled ? "Enabled" : "Disabled";
          badge.style.background = cfg.enabled ? "var(--status-ok)" : "var(--status-neutral)";
          badge.style.color = cfg.enabled ? "#fff" : "var(--ink)";
        }
      }).catch(function () {});
  }

  var __el11 = document.getElementById("slackConfigForm"); if (__el11) __el11.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = document.getElementById("slackSaveBtn");
    btn.disabled = true;
    var msg = document.getElementById("slackMsg");
    msg.textContent = "";
    var url = document.getElementById("slackWebhookUrl").value.trim();
    var threshold = document.getElementById("slackThreshold").value;
    var enabled = document.getElementById("slackEnabled").checked;
    fetch("/api/slack-config", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: enabled, webhook_url: url, threshold: threshold })
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
      msg.textContent = "Saved.";
      document.getElementById("slackWebhookUrl").value = "";
      loadSlackConfig();
      toast(ICON.good, "Slack config saved");
    }).catch(function (err) {
      msg.style.color = "var(--status-critical)";
      msg.textContent = err.message || String(err);
    }).finally(function () { btn.disabled = false; });
  });

  // ===== ORGANIZATIONAL CONTEXT =====
  function loadOrgContext() {
    if (!isAdmin()) return;
    fetch("/api/org", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (org) { renderOrgContext(org.context_notes || []); })
      .catch(function () { renderOrgContext([]); });
  }

  function renderOrgContext(notes) {
    var list = document.getElementById("orgContextList");
    var empty = document.getElementById("orgContextEmpty");
    if (!list) return;
    if (!notes.length) {
      list.innerHTML = "";
      if (empty) empty.style.display = "";
      return;
    }
    if (empty) empty.style.display = "none";
    list.innerHTML = notes.map(function (n) {
      return "<div class='org-context-item'>" +
        "<p>" + escapeHtml(n.text || "") + "</p>" +
        "<button type='button' class='btn btn-sm btn-danger rm-org-context-btn' data-id='" +
          escapeHtml(n.id || "") + "'>Remove</button>" +
        "</div>";
    }).join("");
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest(".rm-org-context-btn");
    if (!btn) return;
    var noteId = btn.dataset.id;
    if (!noteId) return;
    fetch("/api/org/context/" + encodeURIComponent(noteId), {
      method: "DELETE", credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
      toast(ICON.good, "Removed organizational context");
      loadOrgContext();
    }).catch(function (err) { toast(ICON.warning, err.message || String(err)); });
  });

  var orgContextForm = document.getElementById("orgContextForm");
  if (orgContextForm) {
    orgContextForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var input = document.getElementById("orgContextText");
      var text = (input && input.value || "").trim();
      if (!text) return;
      var btn = document.getElementById("orgContextAddBtn");
      var msg = document.getElementById("orgContextMsg");
      if (btn) btn.disabled = true;
      if (msg) { msg.style.color = "var(--status-ok)"; msg.textContent = ""; }
      fetch("/api/org/context", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text })
      }).then(function (r) {
        if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
        if (input) input.value = "";
        if (msg) msg.textContent = "Added.";
        toast(ICON.good, "Organizational context added");
        loadOrgContext();
      }).catch(function (err) {
        if (msg) {
          msg.style.color = "var(--status-critical)";
          msg.textContent = err.message || String(err);
        }
        toast(ICON.warning, err.message || String(err));
      }).finally(function () { if (btn) btn.disabled = false; });
    });
  }

  // ===== NOTIFY CONFIG =====
  function loadNotifyConfig() {
    if (!isAdmin()) return;
    fetch("/api/notify-config", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (cfg) {
        document.getElementById("notifyEnabled").checked = !!cfg.enabled;
        document.getElementById("notifySmtpHost").value = cfg.smtp_host || "";
        document.getElementById("notifySmtpPort").value = cfg.smtp_port || 587;
        document.getElementById("notifySmtpUser").value = cfg.smtp_user || "";
        document.getElementById("notifyFromAddr").value = cfg.from_addr || "";
        document.getElementById("notifyThreshold").value = cfg.threshold || "SUSPICIOUS";
        var passSet = document.getElementById("notifyPassSet");
        if (passSet) passSet.textContent = cfg.smtp_pass_set ? "✓ Password set" : "✗ Password not set";
        var badge = document.getElementById("notifyBadge");
        if (badge) {
          badge.textContent = cfg.enabled ? "Enabled" : "Disabled";
          badge.style.background = cfg.enabled ? "var(--status-ok)" : "var(--status-neutral)";
          badge.style.color = cfg.enabled ? "#fff" : "var(--ink)";
        }
      }).catch(function () {});
  }

  var __el12 = document.getElementById("notifyConfigForm"); if (__el12) __el12.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = document.getElementById("notifySaveBtn");
    btn.disabled = true;
    var msg = document.getElementById("notifyMsg");
    msg.textContent = "";
    fetch("/api/notify-config", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: document.getElementById("notifyEnabled").checked,
        smtp_host: document.getElementById("notifySmtpHost").value.trim(),
        smtp_port: parseInt(document.getElementById("notifySmtpPort").value, 10) || 587,
        smtp_user: document.getElementById("notifySmtpUser").value.trim(),
        from_addr: document.getElementById("notifyFromAddr").value.trim(),
        threshold: document.getElementById("notifyThreshold").value
      })
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.status); });
      msg.textContent = "Saved.";
      loadNotifyConfig();
      toast(ICON.good, "Notification config saved");
    }).catch(function (err) {
      msg.style.color = "var(--status-critical)";
      msg.textContent = err.message || String(err);
    }).finally(function () { btn.disabled = false; });
  });

  function chipHtml(cls, label) {
    return '<span class="chip ' + cls + '">' + escapeHtml(label) + "</span>";
  }

  function segsVerdictTier(verdict) {
    if (verdict === "MALICIOUS") return 3;
    if (verdict === "SUSPICIOUS") return 2;
    if (verdict === "LOW") return 1;
    return 0;
  }

  function llmRiskTier(risk) {
    risk = String(risk || "").toUpperCase();
    if (risk === "CRITICAL") return 3;
    if (risk === "HIGH") return 2;
    if (risk === "MEDIUM") return 1;
    return 0;
  }

  function llmClassTier(label) {
    if (label === "Malware" || label === "Malicious") return 3;
    if (label === "Phishing" || label === "BEC") return 2;
    if (label === "Suspicious" || label === "Spam") return 1;
    return 0;
  }

  function dispositionChipCls(disp) {
    disp = String(disp || "").toUpperCase();
    if (disp === "REJECT") return "v-malicious";
    if (disp === "QUARANTINE") return "v-suspicious";
    if (disp === "LOG") return "v-low";
    return "v-clean";
  }

  function analyzeEnginesDisagree(pipe, threat, classLabel) {
    var segsT = segsVerdictTier(pipe.verdict);
    var llmT = Math.max(llmRiskTier(threat.risk_level), llmClassTier(classLabel));
    if (Math.abs(segsT - llmT) >= 2) return true;
    if (segsT >= 2 && llmT <= 0) return true;
    if (llmT >= 2 && segsT <= 0) return true;
    var disp = String(pipe.disposition || "").toUpperCase();
    if ((disp === "QUARANTINE" || disp === "REJECT") && llmT <= 0) return true;
    return false;
  }

  function charsetFromCt(ct) {
    var m = String(ct || "").match(/charset\s*=\s*["']?([^"';\s]+)/i);
    return m ? m[1].trim() : "utf-8";
  }

  function decodeBytesToString(binary, charset) {
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
    var cs = String(charset || "utf-8").replace(/[^a-zA-Z0-9._-]/g, "") || "utf-8";
    try { return new TextDecoder(cs).decode(bytes); } catch (e1) {
      try { return new TextDecoder("utf-8").decode(bytes); } catch (e2) { return binary; }
    }
  }

  function decodeTransferBinary(text, enc) {
    enc = String(enc || "").toLowerCase();
    if (enc === "base64") {
      try { return atob(String(text).replace(/\s+/g, "")); } catch (e) { return ""; }
    }
    if (enc === "quoted-printable") {
      return String(text)
        .replace(/=\r?\n/g, "")
        .replace(/=([0-9A-Fa-f]{2})/g, function (_, h) {
          return String.fromCharCode(parseInt(h, 16));
        });
    }
    return String(text || "");
  }

  function decodeTransferText(text, enc, charset) {
    enc = String(enc || "").toLowerCase();
    if (enc === "base64" || enc === "quoted-printable") {
      return decodeBytesToString(decodeTransferBinary(text, enc), charset);
    }
    return String(text || "");
  }

  function decodeTransferEncoding(text, enc) {
    return decodeTransferText(text, enc, "utf-8");
  }

  function decodeRfc2047(s) {
    if (!s || s.indexOf("=?") === -1) return s || "";
    var collapsed = String(s).replace(/\?=\s+=\?/g, "?==?");
    return collapsed.replace(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g, function (_, cs, enc, data) {
      try {
        var bin;
        if (enc.toUpperCase() === "B") {
          bin = atob(data.replace(/\s+/g, ""));
        } else {
          bin = data.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, function (__, h) {
            return String.fromCharCode(parseInt(h, 16));
          });
        }
        return decodeBytesToString(bin, cs);
      } catch (e) { return _; }
    });
  }

  function parseEml(raw) {
    raw = String(raw || "");
    var nl = raw.indexOf("\r\n") !== -1 ? "\r\n" : "\n";
    var sep = raw.indexOf(nl + nl);
    var headerBlock = sep === -1 ? raw : raw.slice(0, sep);
    var bodyRaw = sep === -1 ? "" : raw.slice(sep + nl.length * 2);
    var unfolded = headerBlock.replace(/\r?\n([ \t]+)/g, " ");
    var lines = unfolded.split(/\r?\n/);
    var headers = {};
    var order = [];
    for (var i = 0; i < lines.length; i++) {
      var m = lines[i].match(/^([^:]+):\s*(.*)/);
      if (m) {
        var k = m[1].toLowerCase();
        var v = decodeRfc2047(m[2]);
        if (!headers[k]) { headers[k] = v; order.push(k); }
      }
    }
    function extractFromMime(body, ct, cte) {
      var boundary = ((ct.match(/boundary=["']?([^"';\r\n]+)["']?/i) || [])[1] || "").trim();
      if (!boundary) {
        var decoded = decodeTransferText(body, cte, charsetFromCt(ct));
        var ctMain = (ct.split(";")[0] || "").trim().toLowerCase();
        return {
          plain: ctMain === "text/html" ? "" : decoded,
          html: ctMain === "text/html" ? decoded : "",
          atts: [],
          cids: {}
        };
      }
      var esc = boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      var parts = body.split(new RegExp("--" + esc + "(?:--)?"));
      var plain = "";
      var html = "";
      var atts = [];
      var cids = {};
      function rememberCid(id, url) {
        var key = String(id || "").replace(/^<|>$/g, "").trim().toLowerCase();
        if (!key || !url) return;
        cids[key] = url;
        var bare = key.replace(/@.*$/, "");
        if (bare && !cids[bare]) cids[bare] = url;
      }
      for (var p = 1; p < parts.length; p++) {
        var chunk = parts[p].replace(/^\r?\n/, "");
        if (!String(chunk).replace(/\s+/g, "")) continue;
        var blank = chunk.match(/\r?\n\r?\n/);
        if (!blank) continue;
        var ps = chunk.indexOf(blank[0]);
        var phdr = chunk.slice(0, ps).replace(/\r?\n([ \t]+)/g, " ");
        var pbdy = chunk.slice(ps + blank[0].length);
        var pct = ((phdr.match(/content-type:\s*([^\r\n]+)/i) || [])[1] || "").trim();
        var pctMain = pct.split(";")[0].trim().toLowerCase();
        var pcd = ((phdr.match(/content-disposition:\s*([^\r\n]+)/i) || [])[1] || "").trim().toLowerCase();
        var pcte = ((phdr.match(/content-transfer-encoding:\s*([^\r\n]+)/i) || [])[1] || "").trim().toLowerCase();
        var pname = decodeRfc2047(((phdr.match(/(?:filename|name)\*?=\s*["']?([^"';\r\n]+)["']?/i) || [])[1] || "").trim());
        var pcid = ((phdr.match(/content-id:\s*<?([^>\s\r\n]+)>?/i) || [])[1] || "").trim().toLowerCase();
        if (pctMain === "text/plain") {
          if (!plain) plain = decodeTransferText(pbdy, pcte, charsetFromCt(pct));
        } else if (pctMain === "text/html") {
          if (!html) html = decodeTransferText(pbdy, pcte, charsetFromCt(pct));
        } else if (pctMain.indexOf("multipart/") === 0) {
          var sub = extractFromMime(pbdy, pct, "");
          if (!plain && sub.plain) plain = sub.plain;
          if (!html && sub.html) html = sub.html;
          atts = atts.concat(sub.atts);
          Object.keys(sub.cids).forEach(function (cid) { rememberCid(cid, sub.cids[cid]); });
        } else {
          if (pcid) {
            var bin = decodeTransferBinary(pbdy, pcte);
            if (bin) {
              try {
                rememberCid(pcid, "data:" + (pctMain || "application/octet-stream") + ";base64," + btoa(bin));
              } catch (e) {}
            }
          }
          if (pcd.indexOf("inline") === -1 || !pcid) {
            if (pname || pcd.indexOf("attachment") !== -1) atts.push(pname || pctMain);
          }
        }
      }
      return { plain: plain, html: html, atts: atts, cids: cids };
    }
    var ct = headers["content-type"] || "text/plain";
    var cte = (headers["content-transfer-encoding"] || "").trim().toLowerCase();
    var result = extractFromMime(bodyRaw, ct, cte);
    var plain = (result.plain || "").trim();
    var htmlBody = (result.html || "").trim();
    return {
      headers: headers,
      order: order,
      body: plain || htmlBody,
      plain: plain,
      html: htmlBody,
      attachments: result.atts,
      cids: result.cids
    };
  }

  function escapeHtmlStr(s) {
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  var _viewerPayloads = {};
  var _viewerSeq = 0;

  function cidLookup(cids, id) {
    if (!cids) return "";
    var raw = String(id || "").replace(/^cid:/i, "").replace(/^<|>$/g, "").trim();
    var key = raw;
    try { key = decodeURIComponent(raw.replace(/\+/g, "%20")); } catch (e) {}
    key = String(key || "").replace(/^<|>$/g, "").trim().toLowerCase();
    if (!key) return "";
    if (cids[key]) return cids[key];
    var bare = key.replace(/@.*$/, "");
    if (bare && cids[bare]) return cids[bare];
    var names = Object.keys(cids);
    for (var i = 0; i < names.length; i++) {
      var n = names[i];
      if (n === key || n === bare) return cids[n];
      if (bare && n.replace(/@.*$/, "") === bare) return cids[n];
    }
    return "";
  }

  function absolutizeEmailUrl(url, base) {
    var u = String(url || "").trim();
    if (!u) return u;
    if (/^(cid:|data:|blob:|mailto:|javascript:|#)/i.test(u)) return u;
    if (/^https?:\/\//i.test(u)) return u.replace(/^http:\/\//i, "https://");
    if (u.indexOf("//") === 0) return "https:" + u;
    if (!base) return u;
    try { return new URL(u, base).href; } catch (e) { return u; }
  }

  function sanitizeEmailHtml(html, cids) {
    var out = String(html || "");
    var base = "";
    out = out.replace(/<base\b[^>]*>/gi, function (tag) {
      var m = tag.match(/\bhref\s*=\s*(['"])([^'"]+)\1/i) || tag.match(/\bhref\s*=\s*([^\s>]+)/i);
      if (m && !base) base = String(m[2] || m[1] || "").replace(/^['"]|['"]$/g, "");
      return "";
    });
    out = out.replace(/cid:([^"'>\s]+)/gi, function (_, id) {
      return cidLookup(cids, id) || ("cid:" + id);
    });
    out = out.replace(/\s(src|href|background)\s*=\s*(['"])([^'"]*)\2/gi, function (all, attr, q, url) {
      return " " + attr + "=" + q + absolutizeEmailUrl(url, base) + q;
    });
    out = out.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, function (all, q, url) {
      var resolved = absolutizeEmailUrl(url, base);
      var wrap = q || "'";
      return "url(" + wrap + resolved + wrap + ")";
    });
    out = out.replace(/<script[\s\S]*?<\/script>/gi, "");
    out = out.replace(/<iframe[\s\S]*?<\/iframe>/gi, "");
    out = out.replace(/<(object|embed|applet|form)\b[\s\S]*?<\/\1>/gi, "");
    out = out.replace(/<(object|embed|applet|form|meta|base|link)\b[^>]*\/?>/gi, "");
    out = out.replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "");
    out = out.replace(/\s(href|src|action|xlink:href)\s*=\s*(['"])\s*javascript:[^'"]*\2/gi, " $1=$2#$2");
    return out;
  }

  function wrapEmailHtml(bodyHtml) {
    return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
      "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; img-src data: blob: https: http:; media-src data: blob: https: http:;\">" +
      "<base target=\"_blank\" rel=\"noopener noreferrer\">" +
      "<style>html,body{margin:0;padding:12px 16px;background:#fff;color:#222;}" +
      "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.5;}" +
      "img{max-width:100%;height:auto;}table{max-width:100%;}</style></head><body>" +
      bodyHtml + "</body></html>";
  }

  function emailViewerSnippet(parsed) {
    var plain = String((parsed && parsed.plain) || "").replace(/\s+/g, " ").trim();
    if (plain) return plain.slice(0, 280);
    var html = String((parsed && parsed.html) || "")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    return html.slice(0, 280);
  }

  function sizeEmailFrame(frame) {
    try {
      var inDetail = !!(frame.closest && frame.closest(".detail-mail"));
      if (inDetail) {
        frame.style.position = "absolute";
        frame.style.inset = "0";
        frame.style.width = "100%";
        frame.style.height = "100%";
        return;
      }
      var doc = frame.contentDocument;
      if (!doc || !doc.documentElement) return;
      var h = Math.max(
        doc.body ? doc.body.scrollHeight : 0,
        doc.documentElement.scrollHeight || 0
      );
      frame.style.height = Math.min(Math.max(h + 24, 280), 1600) + "px";
    } catch (e) {}
  }

  function bindEmailViewer(root) {
    if (!root) return;
    Array.prototype.forEach.call(root.querySelectorAll(".email-viewer[data-viewer-id]"), function (el) {
      var id = el.getAttribute("data-viewer-id");
      var payload = _viewerPayloads[id];
      delete _viewerPayloads[id];
      el.removeAttribute("data-viewer-id");
      if (!payload) return;
      var parsed = payload.parsed || payload;
      var scan = payload.scan || {};
      var stage = el.querySelector(".email-viewer-stage");
      var htmlBtn = el.querySelector("[data-view-mode='html']");
      var plainBtn = el.querySelector("[data-view-mode='plain']");
      var hlBtn = el.querySelector("[data-view-mode='highlights']");
      var peek = el.querySelector("[data-expand-mail]");
      var collapseBtn = el.querySelector("[data-collapse-mail]");
      var hasHtml = !!(parsed.html && parsed.html.trim());
      var hasPlain = !!(parsed.plain && parsed.plain.trim());
      var mode = hasHtml ? "html" : "plain";
      var inDetail = !!(el.closest && el.closest(".detail-mail"));
      var expanded = !inDetail;

      function paint() {
        if (!stage || !expanded) return;
        getHlTip().hidden = true;
        if (mode === "highlights") {
          paintHighlightsView(stage, parsed, scan);
        } else if (mode === "html" && hasHtml) {
          stage.innerHTML = "";
          var frame = document.createElement("iframe");
          frame.className = "email-viewer-frame";
          frame.title = "Email body";
          frame.setAttribute("sandbox", "allow-same-origin allow-popups allow-popups-to-escape-sandbox");
          frame.setAttribute("referrerpolicy", "no-referrer");
          frame.srcdoc = wrapEmailHtml(sanitizeEmailHtml(parsed.html, parsed.cids || {}));
          frame.addEventListener("load", function () { sizeEmailFrame(frame); });
          stage.appendChild(frame);
        } else {
          var text = hasPlain ? parsed.plain : "";
          stage.innerHTML = text
            ? '<div class="email-viewer-body">' + escapeHtmlStr(text) + "</div>"
            : '<div class="email-viewer-body email-viewer-empty">No message body found.</div>';
        }
        if (htmlBtn) htmlBtn.classList.toggle("is-active", mode === "html");
        if (plainBtn) plainBtn.classList.toggle("is-active", mode === "plain");
        if (hlBtn) hlBtn.classList.toggle("is-active", mode === "highlights");
      }

      function setOpen(on) {
        expanded = !!on;
        el.classList.toggle("is-expanded", expanded);
        el.classList.toggle("is-collapsed", inDetail && !expanded);
        if (peek) peek.hidden = expanded;
        if (collapseBtn) collapseBtn.hidden = !expanded;
        if (expanded) paint();
        else if (stage) {
          stage.innerHTML = "";
          getHlTip().hidden = true;
        }
      }

      function chooseMode(next) {
        mode = next;
        if (inDetail && !expanded) setOpen(true);
        else paint();
      }

      if (htmlBtn) htmlBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        if (hasHtml) chooseMode("html");
      });
      if (plainBtn) plainBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        chooseMode("plain");
      });
      if (hlBtn) hlBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        chooseMode("highlights");
      });
      if (peek) peek.addEventListener("click", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        setOpen(true);
      });
      if (collapseBtn) collapseBtn.addEventListener("click", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        setOpen(false);
      });
      var headers = el.querySelector(".email-viewer-headers");
      if (inDetail && headers) {
        headers.addEventListener("click", function (ev) {
          var t = ev.target;
          if (t && t.closest && t.closest("button")) return;
          if (!expanded) setOpen(true);
        });
      }
      bindHighlightHovers(el);
      setOpen(expanded);
    });
  }

  function renderEmailViewer(parsed, scan) {
    var SHOW = ["from","to","cc","bcc","subject","date","reply-to","message-id"];
    var LABEL = { from:"From", to:"To", cc:"Cc", bcc:"Bcc", subject:"Subject", date:"Date", "reply-to":"Reply-To", "message-id":"Message-ID" };
    var rows = "";
    for (var i = 0; i < SHOW.length; i++) {
      var k = SHOW[i];
      if (parsed.headers[k]) {
        var cls = k === "subject" ? " email-viewer-subject" : "";
        rows += '<div class="email-viewer-hrow' + cls + '">' +
          '<span class="email-viewer-label">' + LABEL[k] + '</span>' +
          '<span class="email-viewer-value">' + escapeHtmlStr(parsed.headers[k]) + '</span>' +
          '</div>';
      }
    }
    var hasHtml = !!(parsed.html && parsed.html.trim());
    var hasPlain = !!(parsed.plain && parsed.plain.trim());
    var snippet = emailViewerSnippet(parsed);
    var toggle = '<div class="email-viewer-toggle">' +
      '<button type="button"' + (hasHtml ? ' class="is-active"' : " disabled") + ' data-view-mode="html">HTML</button>' +
      '<button type="button"' + (!hasHtml && hasPlain ? ' class="is-active"' : "") + ' data-view-mode="plain">Plain text</button>' +
      '<button type="button" data-view-mode="highlights">Highlights</button>' +
      '<button type="button" class="email-viewer-collapse" data-collapse-mail hidden>Collapse</button>' +
      "</div>";
    var peek = '<button type="button" class="email-viewer-peek" data-expand-mail>' +
      '<span class="email-viewer-peek-text">' +
      escapeHtmlStr(snippet || "No preview") +
      (snippet.length >= 280 ? "…" : "") +
      "</span>" +
      '<span class="email-viewer-peek-hint">Click to expand</span>' +
      "</button>";
    var attHtml = "";
    if (parsed.attachments.length) {
      attHtml = '<div class="email-viewer-attachments">';
      for (var a = 0; a < parsed.attachments.length; a++) {
        attHtml += '<span class="email-viewer-att">📎 ' + escapeHtmlStr(parsed.attachments[a]) + '</span>';
      }
      attHtml += '</div>';
    }
    var id = "emlv-" + (++_viewerSeq);
    _viewerPayloads[id] = { parsed: parsed, scan: scan || {} };
    return '<div class="email-viewer" data-viewer-id="' + id + '">' +
      '<div class="email-viewer-headers">' + rows + toggle + '</div>' +
      peek +
      '<div class="email-viewer-stage"></div>' + attHtml + '</div>';
  }

  function renderAnalyzeResults(data) {
    var threat = (data.analysis && data.analysis.threat_assessment) || {};
    var content = (data.analysis && data.analysis.content_analysis) || {};
    var pipe = data.pipeline || {};
    var risk = String(threat.risk_level || "?").toUpperCase();
    var riskInfo = RISK_CHIP[risk] || { cls: "v-low", label: risk };
    var vinfo = VERDICTS[pipe.verdict] || VERDICTS.CLEAN;
    var classification = resolveAnalyzeClassification(data);
    var classInfo = CLASSIFICATION_CHIP[classification] || { cls: "v-low", label: classification };
    var landingMismatch = !!(data.analysis && data.analysis.landing_page_analysis &&
      data.analysis.landing_page_analysis.some(function (x) { return x && x.context_mismatch; }));

    var modelLabel = formatLlmModel(
      data.model || pipe.aiModel || ((pipe.stages || {}).content_ai || {}).modelId,
      pipe.aiProvider || ((pipe.stages || {}).content_ai || {}).provider
    );
    document.getElementById("analyzeResultTitle").textContent = data.filename || "Report";
    document.getElementById("analyzeResultSub").textContent =
      (pipe.subject || content.summary || "").slice(0, 120);
    document.getElementById("analyzeElapsed").textContent =
      (data.elapsed_ms ? (data.elapsed_ms / 1000).toFixed(1) + "s" : "") +
      (modelLabel ? " · " + modelLabel : "");
    var summarySub = document.getElementById("analyzeSummarySub");
    if (summarySub) {
      summarySub.textContent = modelLabel ? ("LLM: " + modelLabel) : "From the LLM content analysis";
    }

    // API quota warning — surface when VT or AbuseIPDB daily limit was hit
    var quotaWarnEl = document.getElementById("analyzeWarning");
    var quotaFlags = data.quota_flags || [];
    if (quotaFlags.length) {
      var quotaNames = quotaFlags.map(function (f) {
        return f === "quota_exhausted_vt" ? "VirusTotal" :
               f === "quota_exhausted_abuseipdb" ? "AbuseIPDB" : f;
      }).join(" and ");
      quotaWarnEl.textContent = "⚠️ API quota limit reached: " + quotaNames +
        " daily lookup limit exhausted — some indicators were not checked. " +
        "Results may be incomplete. Quota resets at midnight UTC.";
      quotaWarnEl.style.display = "";
    } else {
      quotaWarnEl.textContent = "";
      quotaWarnEl.style.display = "none";
    }

    var segsValue = vinfo.label + (pipe.score != null ? " · " + Number(pipe.score).toFixed(0) : "");
    var dispValue = pipe.disposition || "—";
    var dispCls = dispositionChipCls(dispValue);
    var reasons = pipe.reasons || [];
    var topSegsFlags = reasons.slice(0, 3).map(function (r) {
      return "<li>" + escapeHtml(describeFlag(r)) + "</li>";
    }).join("");
    var enginesDisagree = analyzeEnginesDisagree(pipe, threat, classInfo.label);
    var segsHarsher = segsVerdictTier(pipe.verdict) > Math.max(
      llmRiskTier(threat.risk_level), llmClassTier(classInfo.label));

    document.getElementById("analyzeDecisionPanel").innerHTML =
      '<div class="decision-box primary">' +
        '<div class="dec-kicker">LLM deep review' +
          (modelLabel ? " · " + escapeHtml(modelLabel) : "") +
          " — advisory</div>" +
        '<div class="dec-row">' +
          '<div class="dec-action ' + classInfo.cls + '">' + escapeHtml(classInfo.label) + "</div>" +
          chipHtml(riskInfo.cls, riskInfo.label +
            (threat.risk_score != null ? " · " + threat.risk_score + "/100" : "")) +
        "</div>" +
        '<div class="dec-help">Human-readable investigation for triage notes. ' +
        "Does <strong>not</strong> change gateway delivery by itself.</div>" +
        (landingMismatch ? '<ul class="dec-flags"><li>Landing page context mismatch detected</li></ul>' : "") +
      "</div>" +
      '<div class="decision-box secondary">' +
        '<div class="dec-kicker">LLM advisory</div>' +
        '<div class="dec-row">' +
          chipHtml(classInfo.cls, classInfo.label) +
          chipHtml(riskInfo.cls, riskInfo.label +
            (threat.risk_score != null ? " · " + threat.risk_score : "")) +
          (landingMismatch ? chipHtml("v-malicious", "Landing mismatch") : "") +
        "</div>" +
        '<div class="dec-help">Investigation report for analysts — review only.</div>' +
      "</div>";

    var guideEl = document.getElementById("analyzeGuide");
    if (enginesDisagree) {
      if (segsHarsher) {
        guideEl.innerHTML =
          "<strong>These engines disagree — follow the gateway for delivery.</strong> " +
          "SEGS would <strong>" + escapeHtml(String(dispValue)) + "</strong> (" +
          escapeHtml(vinfo.label) + (pipe.score != null ? " · " + Number(pipe.score).toFixed(0) : "") +
          ") while the LLM says <strong>" + escapeHtml(classInfo.label) + "</strong> (" +
          escapeHtml(riskInfo.label) + "). " +
          "Treat as suspicious operationally; use the LLM summary &amp; findings below to decide release vs keep blocked.";
      } else {
        guideEl.innerHTML =
          "<strong>These engines disagree — LLM sees more risk than SEGS.</strong> " +
          "The LLM classifies this as <strong>" + escapeHtml(classInfo.label) + "</strong> but SEGS only scored " +
          "<strong>" + escapeHtml(vinfo.label) + "</strong> → <strong>" + escapeHtml(String(dispValue)) + "</strong>. " +
          "Consider manual quarantine or tuning SEGS rules if the LLM findings look right.";
      }
    } else {
      guideEl.innerHTML =
        "<strong>Both engines align.</strong> Gateway " + escapeHtml(vinfo.label) +
        " → <strong>" + escapeHtml(String(dispValue)) + "</strong>; LLM " +
        escapeHtml(classInfo.label) + " (" + escapeHtml(riskInfo.label) + ").";
    }

    document.getElementById("analyzeChips").hidden = true;

    document.getElementById("analyzeScoreboard").innerHTML =
      '<div class="score-card primary">' +
        '<div class="sc-label">① Gateway score (authoritative)</div>' +
        '<div class="sc-value">' + chipHtml(vinfo.cls, segsValue) + "</div>" +
        '<div class="sc-help">Deterministic rules/stages — controls quarantine &amp; delivery.</div>' +
      "</div>" +
      '<div class="score-card primary">' +
        '<div class="sc-label">② Live action</div>' +
        '<div class="sc-value">' + chipHtml(dispCls, dispValue) + "</div>" +
        '<div class="sc-help">What happens if this exact message hits the gateway today.</div>' +
      "</div>" +
      '<div class="score-card">' +
        '<div class="sc-label">③ SEGS rule hits</div>' +
        (topSegsFlags
          ? '<ul class="dec-flags" style="margin:8px 0 0;">' + topSegsFlags + "</ul>"
          : '<div class="sc-help" style="margin-top:6px;font-style:italic;">No red flags fired.</div>') +
      "</div>";

    var disagreeBanner = document.getElementById("analyzeDisagree");
    if (enginesDisagree) {
      disagreeBanner.classList.add("show");
      disagreeBanner.innerHTML = segsHarsher
        ? ("<strong>Gateway is stricter.</strong> Do not release just because the LLM says " +
           escapeHtml(classInfo.label) + ". Check <strong>SEGS reasons</strong> below — those rules fired " +
           escapeHtml(vinfo.label) + " and would " + escapeHtml(String(dispValue)) + " this mail.")
        : ("<strong>LLM is stricter.</strong> SEGS scored " + escapeHtml(vinfo.label) +
           " but the deep review says " + escapeHtml(classInfo.label) +
           ". Read investigation findings — you may want to quarantine manually.");
    } else {
      disagreeBanner.classList.remove("show");
      disagreeBanner.innerHTML = "";
    }

    var warn = document.getElementById("analyzeWarning");
    if (data.consistency_warning) {
      warn.style.display = "block";
      warn.textContent = data.consistency_warning;
    } else {
      warn.style.display = "none";
      warn.textContent = "";
    }

    // Behavioral Correlation panel — reference only, 4 rule rows + clickable prior-email modal
    var intelStage = (pipe.stages || {}).intel || {};
    var behavDetails = intelStage.behavioralDetails || [];
    _behavModalData = [];
    var BEHAV_RULES = [
      {
        key: "behavioral_sender_ip_drift", severity: "suspicious",
        label: "Sender IP Consistency",
        desc: function (d) {
          return "Sender '" + d.ioc_value + "' observed from " + d.behavioral_count +
            " different originating IPs over the past 6 months";
        }
      },
      {
        key: "behavioral_ip_many_senders", severity: "suspicious",
        label: "IP Sender Diversity",
        desc: function (d) {
          return "Originating IP " + d.ioc_value + " was used by " + fmtNum(d.behavioral_count) +
            " different senders over the past 6 months";
        }
      },
      {
        key: "behavioral_ip_shortener", severity: "suspicious",
        label: "IP Link-Shortener Abuse",
        desc: function (d) {
          return "Originating IP " + d.ioc_value + " previously sent emails with link-shortener URLs (" +
            fmtNum(d.behavioral_count) + " occurrence" + (d.behavioral_count === 1 ? "" : "s") + ")";
        }
      },
      {
        key: "behavioral_shared_shortener", severity: "malicious",
        label: "Coordinated Shortener Campaign",
        desc: function (d) {
          return "Link shortener '" + d.ioc_value + "' also used by " + fmtNum(d.behavioral_count) +
            " other sender" + (d.behavioral_count === 1 ? "" : "s") + " over the past 6 months";
        }
      }
    ];
    var behHtml = "";
    BEHAV_RULES.forEach(function (rule) {
      var finding = null;
      for (var ri = 0; ri < behavDetails.length; ri++) {
        if (behavDetails[ri].rule === rule.key) { finding = behavDetails[ri]; break; }
      }
      if (!finding) {
        behHtml += '<div class="beh-rule">' +
          '<span class="beh-rule-icon" style="color:var(--status-good);">' + ICON.good + '</span>' +
          '<div><strong>' + rule.label + '</strong>' +
          '<div class="beh-rule-detail">No concerns detected in the past 6 months</div></div></div>';
      } else {
        var iconSvg = rule.severity === "malicious" ? ICON.critical : ICON.serious;
        var iconColor = rule.severity === "malicious" ? "var(--status-critical)" : "var(--status-serious)";
        var descText = rule.desc(finding);
        var flaggedBtn = "";
        if (finding.flagged_count > 0) {
          var midx = _behavModalData.length;
          _behavModalData.push({ title: rule.label, sub: descText, emails: finding.emails || [] });
          flaggedBtn = '<button class="beh-flagged-link" data-beh-midx="' + midx + '">' +
            finding.flagged_count + ' prior flagged email' + (finding.flagged_count === 1 ? "" : "s") + ' \u2197</button>';
        }
        behHtml += '<div class="beh-rule">' +
          '<span class="beh-rule-icon" style="color:' + iconColor + ';">' + iconSvg + '</span>' +
          '<div><strong>' + rule.label + '</strong>' +
          '<div class="beh-rule-detail">' + escapeHtml(descText) + flaggedBtn + '</div></div></div>';
      }
    });
    document.getElementById("behavioralRules").innerHTML = behHtml;
    document.getElementById("analyzeBehavioral").style.display = "";

    var campDetails = intelStage.campaignDetails || intelStage.campaign_details || [];
    var campEl = document.getElementById("campaignRules");
    var campCard = document.getElementById("analyzeCampaigns");
    if (campEl && campCard) {
      if (!campDetails.length) {
        campCard.style.display = "none";
        campEl.innerHTML = "";
      } else {
        var KIND_LABEL = {
          hash: "Shared attachment",
          url_path: "Shared landing URL",
          url_host: "Shared URL host",
          content: "Shared template",
          subj: "Shared subject",
          msgid: "Same Message-ID blast",
          mixed: "Mixed pivots"
        };
        campEl.innerHTML = campDetails.map(function (d) {
          var kind = d.kind || "";
          var label = KIND_LABEL[kind] || kind || "Campaign";
          var desc = (d.members || "?") + " emails · " + (d.senders || "?") + " senders · " +
            (d.mailboxes || "?") + " mailboxes";
          if (d.flagged) desc += " · " + d.flagged + " flagged";
          var extra = "";
          if (d.attack_class) extra += '<div class="beh-rule-detail">' + escapeHtml(campaignAttackLabel(d.attack_class) || d.attack_class) + "</div>";
          if (d.ai_summary) extra += '<div class="beh-rule-detail">' + escapeHtml(String(d.ai_summary).slice(0, 280)) + "</div>";
          return '<div class="beh-rule">' +
            '<span class="beh-rule-icon" style="color:var(--status-serious);">' + ICON.serious + '</span>' +
            '<div><strong>' + escapeHtml(d.ai_title || label) + '</strong>' +
            '<div class="beh-rule-detail">' + escapeHtml(desc) +
            "</div>" + extra + "</div></div>";
        }).join("");
        campCard.style.display = "";
      }
    }

    document.getElementById("analyzeSummary").textContent =
      content.summary || pipe.aiSummary || "(No summary returned)";
    var stEl = document.getElementById("analyzeBodyStructure");
    if (stEl) stEl.innerHTML = bodyStructureHtml(bodyStructureFromAnalyze(content, pipe));

    var findings = (data.analysis && data.analysis.investigation_findings) || [];
    var findEl = document.getElementById("analyzeFindings");
    findEl.innerHTML = findings.length
      ? findings.map(function (f) { return "<li>" + escapeHtml(stripListPrefix(f)) + "</li>"; }).join("")
      : "<li>No investigation findings returned.</li>";

    var actions = (data.analysis && data.analysis.recommended_actions) || [];
    var actEl = document.getElementById("analyzeActions");
    actEl.innerHTML = actions.length
      ? actions.map(function (a) { return "<li>" + escapeHtml(stripListPrefix(a)) + "</li>"; }).join("")
      : "<li>No recommended actions returned.</li>";

    var inds = threat.indicators || [];
    var indEl = document.getElementById("analyzeIndicators");
    indEl.innerHTML = inds.length
      ? inds.map(function (i) { return "<li>" + escapeHtml(String(i)) + "</li>"; }).join("")
      : "<li>No indicators returned.</li>";

    var reasonEl = document.getElementById("analyzePipeReasons");
    reasonEl.innerHTML = reasons.length
      ? reasons.map(function (r) { return "<li>" + escapeHtml(describeFlag(r)) + "</li>"; }).join("")
      : "<li>No SEGS red flags fired.</li>";

    var flowHost = document.getElementById("analyzeFlow");
    if (flowHost) {
      var flowEntry = {
        stages: pipe.stages || {},
        hasStageDetail: !!(pipe.stages && Object.keys(pipe.stages).length),
        verdict: pipe.verdict,
        score: pipe.score,
        reasons: pipe.reasons || [],
        hardOverride: pipe.hard_override || pipe.hardOverride || "",
        threatClass: pipe.threatClass || "",
        threatConfidence: pipe.threatConfidence || 0,
        aiSummary: pipe.aiSummary || "",
        aiProvider: pipe.aiProvider || "",
        aiModel: pipe.aiModel || "",
        iocs: pipe.iocs || data.iocs || {},
        fanoutMailboxes: (pipe.stages && pipe.stages.fanout && pipe.stages.fanout.mailboxes) || [],
        fanoutRecipients: (pipe.stages && pipe.stages.fanout && pipe.stages.fanout.recipients) || []
      };
      flowHost.innerHTML = "";
      mountAssessmentFlow(flowHost, flowEntry, true);
    }

    document.getElementById("analyzeMarkdown").textContent = data.markdown || "";
    document.getElementById("analyzeMarkdown").style.display = "block";
    document.getElementById("analyzeToggleMd").textContent = "Collapse";

    var emlContentCard = document.getElementById("analyzeEmailContentCard");
    var emlContentEl = document.getElementById("analyzeEmailContent");
    if (analyzeRawEml) {
      emlContentEl.innerHTML = renderEmailViewer(parseEml(analyzeRawEml), scanContextFromEmail({
        reasons: pipe.reasons || [],
        stages: pipe.stages || {},
        subject: pipe.subject || "",
        iocs: pipe.iocs || {}
      }));
      bindEmailViewer(emlContentEl);
      emlContentEl.style.display = "";
      document.getElementById("analyzeToggleEml").textContent = "Collapse";
      emlContentCard.style.display = "";
    } else {
      emlContentCard.style.display = "none";
    }

    document.getElementById("analyzeResults").classList.add("show");
  }

  // ---- Behavioral Correlation modal ----
  function openBehavioralModal(midx) {
    var meta = _behavModalData[midx];
    if (!meta) return;
    if (typeof ui.onOpenBehavioral === "function") {
      ui.onOpenBehavioral(meta);
      return;
    }
    var titleEl = document.getElementById("behavioralModalTitle");
    if (!titleEl) return;
    titleEl.textContent = meta.title;
    document.getElementById("behavioralModalSub").textContent = meta.sub;
    var list = document.getElementById("behavioralModalList");
    if (!meta.emails || !meta.emails.length) {
      list.innerHTML = '<p style="color:var(--ink-muted);font-size:12px;">No prior flagged email records available.</p>';
    } else {
      list.innerHTML = meta.emails.map(function (e) {
        var dateStr = e.seen_at ? new Date(e.seen_at * 1000).toLocaleString() : "unknown date";
        var verdict = e.verdict || "UNKNOWN";
        var vClass = { MALICIOUS: "v-malicious", SUSPICIOUS: "v-suspicious", LOW: "v-low", CLEAN: "v-clean" }[verdict] || "";
        var msgId = (e.message_id || "—").slice(0, 72);
        return '<div class="beh-email-row">' +
          '<span class="chip ' + vClass + '" style="flex-shrink:0;font-size:10px;margin-top:2px;">' + escapeHtml(verdict) + '</span>' +
          '<div class="beh-email-detail">' +
            '<span class="beh-email-from">' + escapeHtml(e.sender || "(unknown sender)") + '</span>' +
            '<span class="beh-email-id">' + escapeHtml(msgId) + '</span>' +
            '<span class="beh-email-date">' + escapeHtml(dateStr) + '</span>' +
          '</div></div>';
      }).join("");
    }
    document.getElementById("behavioralModalOverlay").classList.add("show");
  }

  var __el13 = document.getElementById("behavioralModalClose"); if (__el13) __el13.addEventListener("click", function () {
    document.getElementById("behavioralModalOverlay").classList.remove("show");
  });
  var __el14 = document.getElementById("behavioralModalOverlay"); if (__el14) __el14.addEventListener("click", function (evt) {
    if (evt.target === this) this.classList.remove("show");
  });
  document.addEventListener("click", function (evt) {
    var btn = evt.target.closest ? evt.target.closest(".beh-flagged-link") : null;
    if (!btn) return;
    var midx = parseInt(btn.getAttribute("data-beh-midx"), 10);
    if (!isNaN(midx)) openBehavioralModal(midx);
  });
  // ---- end behavioral modal ----

  /* ============================== PASSWORD CHANGE MODAL ============================== */
  (function () {
    var overlay = document.getElementById("pwModalOverlay");
    var usernameSpan = document.getElementById("pwModalUsername");
    var newInput = document.getElementById("pwModalNew");
    var confirmInput = document.getElementById("pwModalConfirm");
    var submitBtn = document.getElementById("pwModalSubmit");
    var errorDiv = document.getElementById("pwModalError");
    var targetId = null;
    if (!overlay || !newInput || !confirmInput || !submitBtn) return;

    var checks = {
      len:     function (v) { return v.length >= 8; },
      upper:   function (v) { return /[A-Z]/.test(v); },
      lower:   function (v) { return /[a-z]/.test(v); },
      digit:   function (v) { return /\d/.test(v); },
      special: function (v) { return /[^A-Za-z0-9]/.test(v); }
    };

    function showPwError(msg) {
      errorDiv.textContent = msg;
      errorDiv.classList.toggle("show", !!msg);
    }

    function validate() {
      var val = newInput.value;
      var allPass = true;
      Object.keys(checks).forEach(function (k) {
        var pass = checks[k](val);
        document.getElementById("pwck-" + k).classList.toggle("pass", pass);
        if (!pass) allPass = false;
      });
      var match = val && confirmInput.value === val;
      submitBtn.disabled = !(allPass && match);
      if (confirmInput.value && !match) {
        showPwError("Passwords do not match.");
      } else {
        showPwError("");
      }
    }

    window.openPwModal = function (id, name) {
      targetId = id;
      usernameSpan.textContent = name;
      newInput.value = "";
      confirmInput.value = "";
      showPwError("");
      Object.keys(checks).forEach(function (k) {
        document.getElementById("pwck-" + k).classList.remove("pass");
      });
      submitBtn.disabled = true;
      overlay.classList.add("show");
      setTimeout(function () { newInput.focus(); }, 50);
    };

    function closePwModal() {
      overlay.classList.remove("show");
      newInput.value = "";
      confirmInput.value = "";
      showPwError("");
    }

    newInput.addEventListener("input", validate);
    confirmInput.addEventListener("input", validate);

    var __el15 = document.getElementById("pwModalCancel"); if (__el15) __el15.addEventListener("click", closePwModal);
    overlay.addEventListener("click", function (evt) { if (evt.target === overlay) closePwModal(); });
    document.addEventListener("keydown", function (evt) {
      if (evt.key === "Escape" && overlay.classList.contains("show")) closePwModal();
    });

    submitBtn.addEventListener("click", function () {
      var pw = newInput.value;
      if (!targetId || submitBtn.disabled) return;
      showPwError("");
      submitBtn.disabled = true;
      submitBtn.textContent = "Saving…";
      var name = usernameSpan.textContent;
      fetch("/api/users/" + encodeURIComponent(targetId) + "/password", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw })
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) {
            var detail = j && j.detail;
            if (Array.isArray(detail)) detail = detail.map(function (d) { return d.msg || JSON.stringify(d); }).join("; ");
            throw new Error(detail || ("Password reset failed (" + r.status + ")"));
          }
          return j;
        }, function () {
          if (!r.ok) throw new Error("Password reset failed (" + r.status + ")");
          return {};
        });
      }).then(function () {
        closePwModal();
        toast(ICON.good, "Password updated for " + name);
        loadFeed();
      }).catch(function (err) {
        showPwError(err.message || String(err));
        submitBtn.disabled = false;
        submitBtn.textContent = "Set password";
      });
    });
  })();
  /* ============================== end password modal ============================== */

  function runAnalyze() {
    if (!analyzeFile || !canAct()) return;
    var errEl = document.getElementById("analyzeError");
    var statusEl = document.getElementById("analyzeStatus");
    var statusText = document.getElementById("analyzeStatusText");
    var btn = document.getElementById("analyzeBtn");
    errEl.classList.remove("show");
    errEl.textContent = "";
    document.getElementById("analyzeResults").classList.remove("show");
    document.getElementById("analyzeDecisionPanel").innerHTML = "";
    document.getElementById("analyzeGuide").innerHTML = "";
    document.getElementById("analyzeBehavioral").style.display = "none";
    document.getElementById("behavioralRules").innerHTML = "";
    var campReset = document.getElementById("analyzeCampaigns");
    if (campReset) campReset.style.display = "none";
    var campRules = document.getElementById("campaignRules");
    if (campRules) campRules.innerHTML = "";
    _behavModalData = [];
    btn.disabled = true;
    statusEl.classList.add("show");
    var started = Date.now();
    statusText.textContent = "Analyzing… 0s";
    if (analyzeTimer) clearInterval(analyzeTimer);
    analyzeTimer = setInterval(function () {
      statusText.textContent = "Analyzing… " + Math.floor((Date.now() - started) / 1000) + "s";
    }, 1000);

    if (analyzeAbort) analyzeAbort.abort();
    analyzeAbort = new AbortController();
    var timeoutId = setTimeout(function () { analyzeAbort.abort(); }, 120000);

    var fd = new FormData();
    fd.append("file", analyzeFile, analyzeFile.name);

    fetch("/api/analyze/eml", {
      method: "POST",
      credentials: "same-origin",
      body: fd,
      signal: analyzeAbort.signal
    }).then(function (r) {
      return r.json().then(function (d) {
        if (!r.ok) {
          var detail = d.detail;
          if (Array.isArray(detail)) detail = detail.map(function (x) { return x.msg || x; }).join("; ");
          throw new Error(detail || ("HTTP " + r.status));
        }
        return d;
      });
    }).then(function (data) {
      renderAnalyzeResults(data);
      toast(ICON.good, "Analysis complete");
    }).catch(function (err) {
      var msg = err.name === "AbortError" ? "Timed out after 120s — try again or a smaller message." : (err.message || String(err));
      errEl.textContent = msg;
      errEl.classList.add("show");
      toast(ICON.warning, "Analyze failed — " + msg);
    }).finally(function () {
      clearTimeout(timeoutId);
      if (analyzeTimer) { clearInterval(analyzeTimer); analyzeTimer = null; }
      statusEl.classList.remove("show");
      btn.disabled = !analyzeFile || !canAct();
    });
  }

  (function wireAnalyzeUi() {
    var dz = document.getElementById("analyzeDropzone");
    var input = document.getElementById("analyzeFileInput");
    if (!dz || !input) return;
    dz.addEventListener("click", function () { input.click(); });
    dz.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
    input.addEventListener("change", function () {
      var f = input.files && input.files[0];
      if (f && !/\.eml$/i.test(f.name)) {
        toast(ICON.warning, "Only .eml files are accepted");
        input.value = "";
        setAnalyzeFile(null);
        return;
      }
      setAnalyzeFile(f || null);
    });
    ["dragenter", "dragover"].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      dz.addEventListener(ev, function (e) {
        e.preventDefault();
        dz.classList.remove("dragover");
        if (ev === "drop" && e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
          var f = e.dataTransfer.files[0];
          if (!/\.eml$/i.test(f.name)) { toast(ICON.warning, "Only .eml files are accepted"); return; }
          input.value = "";
          setAnalyzeFile(f);
        }
      });
    });
    var __el16 = document.getElementById("analyzeBtn"); if (__el16) __el16.addEventListener("click", runAnalyze);
    var __el17 = document.getElementById("analyzeToggleMd"); if (__el17) __el17.addEventListener("click", function () {
      var pre = document.getElementById("analyzeMarkdown");
      var hide = pre.style.display !== "none";
      pre.style.display = hide ? "none" : "block";
      this.textContent = hide ? "Expand" : "Collapse";
    });
    var __el18 = document.getElementById("analyzeToggleEml"); if (__el18) __el18.addEventListener("click", function () {
      var el = document.getElementById("analyzeEmailContent");
      var hide = el.style.display !== "none";
      el.style.display = hide ? "none" : "";
      this.textContent = hide ? "Expand" : "Collapse";
    });
  })();

  /* ============================== NAV / TABS ============================== */
  var PAGE_META: any = {
    overview:   ["Overview",              ""],
    quarantine: ["Quarantine", "Held mail only — empty while monitor-only (nothing is taken out of the inbox)"],
    analyze:    ["Analyze",               "Upload an .eml for LLM analysis (DeepSeek R1) and SEGS scoring"],
    senders:    ["Sender profiles",       "Typical send/receive mix, counterparties, hours, and AI identity-risk — unusual activity vs that baseline"],
    campaigns:  ["Campaigns",            "AI campaign insight over clustered emails — shared lure, tactics, and infrastructure; reference only"],
    workers:    ["Workers",               "Gmail poll queues mail for AI assessment; finished assessments fan out to campaign and sender-profile jobs"],
    audit:      ["Audit log",             "Gateway decisions plus every signed-in user's console activity"],
    settings:   ["Settings",             "Enforcement, org context, sender lists, and notifications — admin only"],
    profile:    ["Profile",               "Your password, passkeys, and activity in this console"]
  };
  var PAGE_PATHS = {
    overview: "/overview",
    quarantine: "/quarantine",
    analyze: "/analyze",
    senders: "/senders",
    campaigns: "/campaigns",
    workers: "/workers",
    audit: "/audit",
    settings: "/settings",
    profile: "/profile"
  };

  function pathForPage(page?: any, detailId?: any) {
    if (page === "detail") {
      return "/mail/" + encodeURIComponent(detailId || "");
    }
    return PAGE_PATHS[page] || "/overview";
  }

  function parseRoute(pathname) {
    var path = String(pathname || "/").split("?")[0];
    if (path.length > 1 && path.charAt(path.length - 1) === "/") path = path.slice(0, -1);
    if (!path || path === "/" || path === "/overview" || path === "/index.html") {
      return { page: "overview" };
    }
    if (path.indexOf("/mail/") === 0) {
      try {
        var id = decodeURIComponent(path.slice("/mail/".length));
        if (id) return { page: "detail", detailId: id };
      } catch (err) {}
      return { page: "overview" };
    }
    var key = path.slice(1);
    if (key === "queue") return { page: "workers" };
    if (key === "settings" || key.indexOf("settings/") === 0) return { page: "settings" };
    if (PAGE_PATHS[key]) return { page: key };
    return { page: "overview" };
  }

  function syncHistory(page, opts) {
    opts = opts || {};
    if (opts.silent) return;
    var path = pathForPage(page, page === "detail" ? state.detailId : null);
    if (window.location.pathname === path) return;
    var payload = { page: page, detailId: state.detailId || null };
    if (opts.replace) history.replaceState(payload, "", path);
    else history.pushState(payload, "", path);
  }

  function applyRoute(pathname, opts) {
    var route = parseRoute(pathname);
    if (route.page === "detail") {
      if (state.activePage !== "detail") state.detailReturnPage = state.activePage || "overview";
      state.detailId = route.detailId;
      setPage("detail", opts);
      var e = findEmail(route.detailId);
      if (e) populateDetailPage(e);
      return;
    }
    state.detailId = null;
    setPage(route.page, opts);
  }

  function isModifiedClick(ev) {
    return !!(ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button !== 0);
  }

  function setPage(page, opts) {
    opts = opts || {};
    var admin = window.__SEG_CURRENT_USER__ && window.__SEG_CURRENT_USER__.role === "admin";
    if (page === "settings" && !admin) {
      if (!opts.silent) toast(ICON.warning, "Settings requires Admin role");
      page = "overview";
      opts = { replace: true, silent: opts.silent };
    }
    if (page === "detail" && !state.detailId) {
      page = "overview";
    }
    if (!PAGE_META[page] && page !== "detail") page = "overview";
    if (state.activePage === "detail" && page !== "detail") lockContentGrant();
    state.activePage = page;
    if (typeof ui.onNavigate === "function") {
      ui.onNavigate(pathForPage(page, page === "detail" ? state.detailId : null), opts);
      return;
    }
    Array.prototype.forEach.call(document.querySelectorAll(".page"), function (p) {
      if (!p.id) return;
      p.classList.toggle("active", p.id === "page-" + page);
    });
    var navPage = page === "detail" ? (state.detailReturnPage || "overview") : page;
    Array.prototype.forEach.call(document.querySelectorAll(".nav-item"), function (n) {
      var isActive = n.dataset.page === navPage;
      if (isActive) n.setAttribute("aria-current", "page"); else n.removeAttribute("aria-current");
    });
    if (page === "detail") {
      var e = findEmail(state.detailId);
      var sibs = e ? threadSiblings(e) : [];
      var title = (e && e.subject) || "Message";
      if (sibs.length > 1) title = stripThreadSubject(sibs[0].subject) || title;
      document.getElementById("pageTitle").textContent = title;
      document.getElementById("pageSub").textContent = e
        ? (sibs.length > 1
          ? sibs.length + " messages in thread · " + (e.fromName || e.fromAddr || "") + " · " + fmtDateTime(e.ts)
          : ((e.fromName || e.fromAddr || "") + " · " + fmtDateTime(e.ts)))
        : "Message details";
    } else {
      document.getElementById("pageTitle").textContent = PAGE_META[page][0];
      document.getElementById("pageSub").textContent = PAGE_META[page][1];
    }
    if (page === "settings") { loadEnforcement(); loadPolicy().then(renderPolicyPanel); if (admin) { loadUsers(); loadPasskeys(); loadLists(); loadFeedbackPack(); loadSlackConfig(); loadNotifyConfig(); loadOrgContext(); } }
    if (page === "overview") renderOriginMap();
    if (page === "senders") {
      renderSenderAssessment();
      renderSenderProfiles();
    }
    if (page === "campaigns") renderCampaigns();
    if (page === "workers") renderWorkers();
    syncHistory(page, opts);
  }
  Array.prototype.forEach.call(document.querySelectorAll(".nav-item"), function (btn) {
    btn.addEventListener("click", function (ev) {
      if (isModifiedClick(ev)) return;
      ev.preventDefault();
      setPage(btn.dataset.page);
    });
  });
  var __el19 = document.getElementById("brandHome"); if (__el19) __el19.addEventListener("click", function (ev) {
    if (isModifiedClick(ev)) return;
    ev.preventDefault();
    setPage("overview");
  });
  var workersQueueLink = document.getElementById("workersQueueLink");
  if (workersQueueLink) {
    workersQueueLink.addEventListener("click", function (ev) {
      if (isModifiedClick(ev)) return;
      ev.preventDefault();
      setPage("workers");
    });
  }
  var workersCampaignsLink = document.getElementById("workersCampaignsLink");
  if (workersCampaignsLink) {
    workersCampaignsLink.addEventListener("click", function (ev) {
      if (isModifiedClick(ev)) return;
      ev.preventDefault();
      setPage("campaigns");
    });
  }
  var __el20 = document.getElementById("detailBack"); if (__el20) __el20.addEventListener("click", closeDetailPage);
  window.addEventListener("popstate", function () {
    applyRoute(window.location.pathname, { silent: true });
  });
  Array.prototype.forEach.call(document.querySelectorAll("#qTabs .tab"), function (btn) {
    btn.addEventListener("click", function () {
      state.qFilter = btn.dataset.qtab;
      Array.prototype.forEach.call(document.querySelectorAll("#qTabs .tab"), function (b) { b.classList.toggle("active", b === btn); });
      renderQuarantine();
    });
  });
  var __el21 = document.getElementById("qSearch"); if (__el21) __el21.addEventListener("input", function (e) { state.qSearch = e.target.value; renderQuarantine(); });
  var __el22 = document.getElementById("feedSearch"); if (__el22) __el22.addEventListener("input", function (e) { state.feedSearch = e.target.value; renderFeed(); });
  var __el23 = document.getElementById("auditSearch"); if (__el23) __el23.addEventListener("input", function (e) { state.auditSearch = e.target.value; renderAudit(); });
  var __el24 = document.getElementById("auditWazuhOnly"); if (__el24) __el24.addEventListener("click", function () {
    state.auditWazuhOnly = !state.auditWazuhOnly;
    this.classList.toggle("btn-primary", state.auditWazuhOnly);
    renderAudit();
  });
  var senderSearch = document.getElementById("senderProfileSearch");
  if (senderSearch) {
    senderSearch.addEventListener("input", function (e) {
      state.senderProfileQuery = e.target.value;
      renderSenderProfiles();
    });
  }
  var senderReady = document.getElementById("senderProfileReadyOnly");
  if (senderReady) {
    senderReady.addEventListener("click", function () {
      state.senderProfileReadyOnly = !state.senderProfileReadyOnly;
      this.classList.toggle("btn-primary", state.senderProfileReadyOnly);
      renderSenderProfiles();
    });
  }
  var campaignSearch = document.getElementById("campaignSearch");
  if (campaignSearch) {
    campaignSearch.addEventListener("input", function (e) {
      state.campaignQuery = e.target.value;
      renderCampaigns();
    });
  }
  var campaignFlagged = document.getElementById("campaignFlaggedOnly");
  if (campaignFlagged) {
    campaignFlagged.addEventListener("click", function () {
      state.campaignFlaggedOnly = !state.campaignFlaggedOnly;
      this.classList.toggle("btn-primary", state.campaignFlaggedOnly);
      renderCampaigns();
    });
  }

  /* ============================== THEME ============================== */
  function applyTheme(mode) {
    if (mode === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", mode);
    Array.prototype.forEach.call(document.querySelectorAll("[data-theme-btn]"), function (b) {
      b.classList.toggle("active", b.dataset.themeBtn === mode);
    });
    try { localStorage.setItem("pdax-ew-theme", mode); } catch (err) {}
    // Recreate Chart.js instances so theme colors refresh.
    if (mixChartInst) { mixChartInst.destroy(); mixChartInst = null; }
    if (volumeChartInst) { volumeChartInst.destroy(); volumeChartInst = null; }
    if (senderAssessChartInst) { senderAssessChartInst.destroy(); senderAssessChartInst = null; }
    if (senderHostilityChartInst) { senderHostilityChartInst.destroy(); senderHostilityChartInst = null; }
    [originMapCtl, detailOriginMapCtl].forEach(function (ctl) {
      if (ctl.map && typeof ctl.map.destroy === "function") {
        try { ctl.map.destroy(); } catch (err) {}
      }
      ctl.map = null;
      ctl.host = null;
      ctl.fingerprint = "";
    });
    if (document.getElementById("mixChart")) renderThreatMix();
    if (document.getElementById("volumeChart")) renderChart();
    if (document.getElementById("originMap")) renderOriginMap();
    if (document.getElementById("senderAssessChart")) renderSenderAssessment();
    if (state.activePage === "detail" && state.detailId && document.getElementById("detailOriginMap")) {
      renderDetailOriginMap(findEmail(state.detailId));
    }
    if (typeof ui.onData === "function") ui.onData({ theme: mode });
  }
  Array.prototype.forEach.call(document.querySelectorAll("[data-theme-btn]"), function (b) {
    b.addEventListener("click", function () { applyTheme(b.dataset.themeBtn); });
  });
  var savedTheme = "system";
  try { savedTheme = localStorage.getItem("pdax-ew-theme") || "system"; } catch (err) {}
  applyTheme(savedTheme);

  /* ============================== RENDER ALL / LIVE LOOP ============================== */
  var lastUpdate = Date.now();
  function renderAll() {
    renderStats();
    renderThreatMix();
    renderChart();
    renderOriginMap();
    renderFeed();
    renderQueue();
    renderQuarantine();
    renderAudit();
    renderSenderAssessment();
    renderSenderProfiles();
    renderCampaigns();
    renderWorkers();
    // Don't rebuild the detail page on the 15s poll — remounting would interrupt HTML render.
  }
  function workerPill(slot, reachable) {
    if (!reachable) return { cls: "is-down", text: "Unreachable" };
    if (slot && (slot.fetch_paused || (slot.last_stats && slot.last_stats.paused)))
      return { cls: "is-off", text: "Paused" };
    if (slot && slot.running) return { cls: "is-run", text: "Running" };
    if (slot && slot.last_ok === false) return { cls: "is-error", text: "Error" };
    if (slot && slot.enabled === false) return { cls: "is-off", text: "Off" };
    if (slot && slot.alive) return { cls: "is-idle", text: "Idle" };
    return { cls: "is-off", text: "Stopped" };
  }
  function workerAgo(slot) {
    var ts = Number(slot && (slot.last_finished_at || slot.last_started_at)) || 0;
    if (!ts) return "No cycle yet";
    return fmtAgo(ts * 1000);
  }
  function workerQueueNums(slot, kind, queues) {
    var key = kind && {
      poll: "poll",
      static: "static",
      llm: "content_ai",
      thread_ai: "thread_ai",
      campaign: "campaign",
      profile: "profile",
      sender_risk: "sender_risk",
      retry: "retry"
    }[kind];
    var q = key && queues && queues[key];
    var waiting;
    var running;
    if (q && typeof q === "object") {
      waiting = Number(q.waiting);
      running = Number(q.running);
      if (!isFinite(waiting) || waiting < 0) waiting = 0;
      if (!isFinite(running) || running < 0) running = 0;
      if (running === 0 && slot && slot.running) running = 1;
      return { waiting: waiting, running: running };
    }
    waiting = Number(slot && slot.queue_waiting);
    running = Number(slot && slot.queue_running);
    if (!isFinite(waiting) || waiting < 0) waiting = 0;
    if (!isFinite(running) || running < 0) running = 0;
    return { waiting: waiting, running: running };
  }
  function workerQueueLine(slot) {
    var q = workerQueueNums(slot);
    return fmtNum(q.waiting) + " in queue · " + (q.running ? (fmtNum(q.running) + " processing") : "none processing");
  }
  function workerQueueHtml(slot, kind, queues) {
    var q = workerQueueNums(slot, kind, queues);
    var busy = q.waiting > 0 || q.running > 0;
    var waitWord = kind === "poll" ? "awaiting static" : "in queue";
    var runBit = q.running ? (" · " + fmtNum(q.running) + " processing") : " · none processing";
    return '<div class="wk-queue' + (busy ? " is-busy" : " is-idle") + '">' +
      '<span class="wk-n">' + fmtNum(q.waiting) + "</span>" +
      '<span class="wk-n-sub">' + waitWord + runBit + "</span></div>";
  }
  function queuesRows(queues) {
    queues = queues || {};
    function cell(key) {
      var q = queues[key] || {};
      var w = Number(q.waiting) || 0;
      var r = Number(q.running) || 0;
      return fmtNum(w) + " waiting" + (r ? (" · " + fmtNum(r) + " processing") : "");
    }
    return [
      ["Gmail poll", cell("poll")],
      ["Static checks", cell("static")],
      ["Content AI", cell("content_ai")],
      ["Thread AI", cell("thread_ai")],
      ["Sender profiles", cell("profile")],
      ["Sender risk", cell("sender_risk")],
      ["Campaign clustering", cell("campaign")],
      ["Timed out / retry", cell("retry")]
    ];
  }
  function queueWaiting(queues, key) {
    var q = (queues || {})[key] || {};
    return Number(q.waiting) || 0;
  }
  function queueRunning(queues, key) {
    var q = (queues || {})[key] || {};
    return Number(q.running) || 0;
  }
  function workerCopy(slot, kind, queues) {
    if (!slot) return "No data.";
    if (slot.running) {
      return slot.last_error
        ? ("Cycle in progress — last issue: " + String(slot.last_error))
        : "Cycle in progress.";
    }
    if (slot.last_error) return String(slot.last_error);
    var st = slot.last_stats || {};
    var every = slot.interval_seconds ? "Every " + slot.interval_seconds + "s." : "";
    if (kind === "profile") {
      var ins = Number(st.inserted) || 0;
      var ident = Number(st.identity_updated) || 0;
      var req = Number(st.request_recorded) || 0;
      if (!slot.last_finished_at) return "Waiting for first cycle. " + every;
      if (!(ins || ident || req)) return "Last cycle idle. " + every;
      var bits = [];
      if (ins) bits.push(fmtNum(ins) + " CLEAN/LOW hops learned");
      if (ident) bits.push(fmtNum(ident) + " identity skip(s)");
      if (req) bits.push(fmtNum(req) + " request-class row(s)");
      return bits.join(" · ") + ". " + every;
    }
    if (kind === "retry") {
      if (!slot.last_finished_at) return "Waiting for first cycle. " + every;
      var q = Number(st.queued) || 0;
      return q ? ("Queued " + fmtNum(q) + " timed-out email" + (q === 1 ? "" : "s") + ". " + every)
        : ("Nothing timed out. " + every);
    }
    if (kind === "poll") {
      if (slot.fetch_paused || st.paused) {
        var drain = (Number(st.static_queued) || 0) + (Number(st.llm_queued) || 0);
        return "Gmail fetch paused. Pipeline still drains emails already in the system."
          + (drain ? (" Last cycle queued " + fmtNum(drain) + ".") : "")
          + (every ? (" " + every) : "");
      }
      if (!slot.last_finished_at) return "Waiting for first cycle. " + every;
      var n = Number(st.processed) || 0;
      var mb = Number(st.mailboxes) || 0;
      var err = Number(st.errors) || 0;
      var llmQ = Number(st.llm_queued) || 0;
      return (mb ? fmtNum(mb) + " mailboxes · " : "") + fmtNum(n) + " scanned"
        + (llmQ ? " · queued " + fmtNum(llmQ) + " for AI" : "")
        + (err ? " · " + fmtNum(err) + " errors" : "") + ". " + every;
    }
    if (kind === "llm") {
      var qn = workerQueueNums(slot, kind, queues);
      var q = qn.waiting;
      var campP = Number(st.campaign_pending) || 0;
      var profP = Number(st.profile_pending) || 0;
      var riskP = Number(st.sender_risk_pending) || 0;
      if (q || qn.running) {
        return qn.running
          ? (fmtNum(qn.running) + " processing · " + fmtNum(q) + " waiting.")
          : (fmtNum(q) + " email" + (q === 1 ? "" : "s") + " in the AI assessment queue.");
      }
      var follow = campP + profP + riskP;
      if (follow) return "AI queue idle · " + fmtNum(follow) + " follow-up job" + (follow === 1 ? "" : "s") + " pending.";
      return "AI assessment queue idle.";
    }
    if (kind === "static") {
      if (slot.running) return "Running deterministic stages on an email.";
      return slot.last_finished_at ? ("Last email " + (st.queue_id || "done") + ".") : "Waiting for static jobs.";
    }
    if (kind === "thread_ai") {
      if (slot.running) return "Scoring a completed thread.";
      return slot.last_finished_at
        ? ("Last thread " + (st.thread_id || "") + (st.verdict ? (" · " + st.verdict) : "") + ".")
        : "Waiting until every email in a thread has AI.";
    }
    if (kind === "campaign") {
      if (!slot.last_finished_at) return "Waiting for first cycle. " + every;
      var cams = Number(st.campaigns) || 0;
      var flagged = Number(st.flagged_campaigns) || 0;
      if (!cams) return "No clusters this cycle. " + every;
      return fmtNum(cams) + " campaign" + (cams === 1 ? "" : "s")
        + (flagged ? " · " + fmtNum(flagged) + " with flagged emails" : "")
        + ". " + every;
    }
    if (kind === "sender_risk") {
      if (!slot.last_finished_at) return "Waiting for first cycle. " + every;
      var n = Number(st.assessed) || 0;
      var llm = Number(st.llm) || 0;
      return n
        ? ("Assessed " + fmtNum(n) + " sender" + (n === 1 ? "" : "s")
          + (llm ? (" · " + fmtNum(llm) + " LLM") : " · heuristic") + ". " + every)
        : ("No stale senders. " + every);
    }
    return every || "—";
  }
  function workerKv(rows) {
    return "<dl class='wk-kv'>" + rows.map(function (r) {
      return "<div class='wk-kv-row'><dt>" + escapeHtml(r[0]) + "</dt><dd>" + r[1] + "</dd></div>";
    }).join("") + "</dl>";
  }
  function workerTileHtml(title, host, slot, kind, reachable, queues) {
    var pill = workerPill(slot, reachable);
    var st = (slot && slot.last_stats) || {};
    var qn = workerQueueNums(slot, kind, queues);
    var extra = [];
    extra.push(["Last cycle", escapeHtml(workerAgo(slot))]);
    extra.push(["Interval", escapeHtml((slot && slot.interval_seconds) ? (slot.interval_seconds + "s") : "—")]);
      extra.push(["Cycles", escapeHtml(fmtNum((slot && slot.cycles) || 0))]);
    if (kind === "poll") {
      extra.push(["Fetch", (slot && (slot.fetch_paused || st.paused)) ? "Paused" : "On"]);
      extra.push(["Last scan", escapeHtml(fmtNum(Number(st.processed) || 0) + " messages")]);
      extra.push(["Errors", escapeHtml(fmtNum(Number(st.errors) || 0))]);
      if (st.elapsed_seconds) extra.push(["Duration", escapeHtml(st.elapsed_seconds + "s")]);
      if (Number(st.llm_queued) || 0) extra.push(["Queued for AI", escapeHtml(fmtNum(st.llm_queued))]);
    }
    if (kind === "llm") {
      extra.push(["In AI queue", escapeHtml(fmtNum(qn.waiting))]);
      extra.push(["Processing", escapeHtml(fmtNum(qn.running))]);
      extra.push(["Campaign follow-up", escapeHtml(fmtNum(Number(st.campaign_pending) || 0))]);
      extra.push(["Profile follow-up", escapeHtml(fmtNum(Number(st.profile_pending) || 0))]);
      extra.push(["Sender-risk follow-up", escapeHtml(fmtNum(Number(st.sender_risk_pending) || 0))]);
    }
    if (kind === "profile") {
      extra.push(["Learned", escapeHtml(fmtNum(Number(st.inserted) || 0))]);
      extra.push(["Identity skips", escapeHtml(fmtNum(Number(st.identity_updated) || 0))]);
      extra.push(["Request-class", escapeHtml(fmtNum(Number(st.request_recorded) || 0))]);
    }
    if (kind === "retry") {
      extra.push(["Last queued", escapeHtml(fmtNum(Number(st.queued) || 0))]);
    }
    if (kind === "campaign") {
      extra.push(["Campaigns", escapeHtml(fmtNum(Number(st.campaigns) || 0))]);
      extra.push(["Flagged clusters", escapeHtml(fmtNum(Number(st.flagged_campaigns) || 0))]);
      extra.push(["Members", escapeHtml(fmtNum(Number(st.members) || 0))]);
    }
    if (kind === "sender_risk") {
      extra.push(["Assessed", escapeHtml(fmtNum(Number(st.assessed) || 0))]);
      extra.push(["LLM narratives", escapeHtml(fmtNum(Number(st.llm) || 0))]);
    }
    return '<div class="worker-tile">' +
      '<div class="wk-top"><div><div class="wk-name">' + escapeHtml(title) + "</div>" +
      '<div class="wk-host">' + escapeHtml(host) + "</div></div>" +
      '<span class="wk-pill ' + pill.cls + '">' + escapeHtml(pill.text) + "</span></div>" +
      workerQueueHtml(slot, kind, queues) +
      '<p class="wk-copy">' + escapeHtml(workerCopy(slot, kind, queues)) + "</p>" +
      workerKv(extra) +
      "</div>";
  }
  function workerLabel(name) {
    if (name === "profile") return "profiles";
    if (name === "inconclusive_retry") return "retry";
    if (name === "gmail_poll") return "poll";
    if (name === "gmail_llm") return "AI";
    if (name === "static") return "static";
    if (name === "thread_ai") return "thread AI";
    if (name === "campaign") return "campaign";
    if (name === "sender_risk") return "sender risk";
    return name || "worker";
  }
  function coverageLine(cov) {
    cov = cov || {};
    var bits = [fmtNum(Number(cov.configured || 0)) + " configured"];
    if (Number(cov.discovered || 0)) bits.push(fmtNum(Number(cov.discovered)) + " from fanout");
    if (Number(cov.skipped || 0)) bits.push(fmtNum(Number(cov.skipped)) + " skipped (not impersonatable)");
    return escapeHtml(bits.join(" · "));
  }
  function mailboxSub(ops, cfg, pollSlot) {
    if (ops && ops.gmail_fetch === false) return "Fetch paused — assessing existing emails";
    var every = "every " + (cfg.poll_seconds || (pollSlot && pollSlot.interval_seconds) || 30) + "s";
    var disc = Number((ops.coverage || {}).discovered || 0);
    return disc ? (every + " · " + fmtNum(disc) + " added from fanout") : ("Polled " + every);
  }
  function renderWorkers() {
    var data = state.workers;
    var grid = document.getElementById("workersGrid");
    var list = document.getElementById("workersEvents");
    var updated = document.getElementById("workersUpdated");
    if (!grid) return;
    var pendingN = pendingEmails().length;
    var retryN = retryableEmails().length;
    var queues = (data && data.queues) || {};
    var staticWait = queueWaiting(queues, "static");
    var staticRun = queueRunning(queues, "static");
    var aiWait = queueWaiting(queues, "content_ai");
    var aiRun = queueRunning(queues, "content_ai");
    var followWait = queueWaiting(queues, "campaign") + queueWaiting(queues, "profile") + queueWaiting(queues, "sender_risk");
    var timedWait = queueWaiting(queues, "retry");
    var navN = document.getElementById("navWorkersCount");
    var down = data && !fleetReachable(data);
    var badge = down ? 1 : retryN;
    if (navN) {
      navN.textContent = fmtNum(badge);
      navN.dataset.zero = badge === 0;
      navN.classList.toggle("is-pending", !!down);
    }
    if (!data) {
      grid.innerHTML = "<div class='empty-state'>Loading worker status…</div>";
      renderCampaigns();
      return;
    }
    var rec = data.receiver || {};
    var recOk = fleetReachable(data);
    var ops = data.ops || {};
    var cfg = ops.config || {};
    var poll = pickWorkerSlot(data, "poll");
    var staticW = pickWorkerSlot(data, "static");
    var llm = pickWorkerSlot(data, "llm");
    var thread = pickWorkerSlot(data, "thread_ai");
    var profile = pickWorkerSlot(data, "profile");
    var risk = pickWorkerSlot(data, "sender_risk");
    var retry = pickWorkerSlot(data, "retry");
    var pollSlot = Object.assign({}, poll.slot || {}, { fetch_paused: ops.gmail_fetch === false });
    var llmSlot = llm.slot;
    var retrySlot = retry.slot;
    var staticSlot = staticW.slot;
    var threadSlot = thread.slot;
    var profileSlot = profile.slot;
    var riskSlot = risk.slot;
    var mailboxN = Number(rec.users) || Number((pollSlot.last_stats || {}).mailboxes) || ops.gmail_users || 0;
    grid.innerHTML =
      workerTileHtml(
        "Gmail poll",
        poll.reachable ? (mailboxN + " mailboxes") : poll.host,
        pollSlot, "poll", poll.reachable, queues
      ) +
      workerTileHtml("Static checks", staticW.host, staticSlot, "static", staticW.reachable, queues) +
      workerTileHtml("AI assessment", llm.host, llmSlot, "llm", llm.reachable, queues) +
      workerTileHtml("Thread AI", thread.host, threadSlot, "thread_ai", thread.reachable, queues) +
      workerTileHtml("Sender profiles", profile.host, profileSlot, "profile", profile.reachable, queues) +
      workerTileHtml("Sender risk AI", risk.host, riskSlot, "sender_risk", risk.reachable, queues) +
      workerTileHtml("LLM auto-retry", retry.host, retrySlot, "retry", retry.reachable, queues);

    var statsEl = document.getElementById("workersStatGrid");
    if (statsEl) {
      var recLabel = recOk
        ? (rec.source === "heartbeat" ? "Via data volume" : "HTTP health")
        : "Unreachable";
      var tiles = [
        { label: "Receiver", value: recOk ? "Up" : "Down", sub: recLabel, accentVar: recOk ? "var(--status-good)" : "var(--status-warning)" },
        { label: "Mailboxes", value: fmtNum(Number(rec.users || (ops.coverage && ops.coverage.polling) || ops.gmail_users || 0)), sub: mailboxSub(ops, cfg, pollSlot), accentVar: "var(--accent)" },
        { label: "Static queue", value: fmtNum(staticWait), sub: staticRun ? (fmtNum(staticRun) + " processing") : "none processing", accentVar: "var(--accent)" },
        { label: "AI queue", value: fmtNum(aiWait), sub: aiRun ? (fmtNum(aiRun) + " processing") : (retryN ? fmtNum(retryN) + " timed out" : "none processing"), accentVar: "var(--status-serious)" },
        { label: "Follow-up", value: fmtNum(followWait), sub: "campaign · profile · sender risk", accentVar: "var(--status-good)" },
        { label: "Timed out", value: fmtNum(timedWait), sub: retryN ? fmtNum(retryN) + " auto-retry" : "waiting on retry worker", accentVar: "var(--status-warning)" }
      ];
      statsEl.innerHTML = tiles.map(function (t) {
        return '<div class="stat-tile" style="--tile-accent:' + t.accentVar + '">' +
          '<div class="stat-label">' + escapeHtml(t.label) + "</div>" +
          '<div class="stat-value mono">' + t.value + "</div>" +
          '<div class="stat-sub">' + escapeHtml(t.sub) + "</div></div>";
      }).join("");
    }

    var qEl = document.getElementById("workersQueue");
    if (qEl) {
      var queued = (retrySlot.last_queued || []).slice(0, 8);
      var qBits = queued.length
        ? queued.map(function (id) {
            return "<button type='button' class='wk-qid' data-qid='" + escapeHtml(id) + "'>" +
              escapeHtml(id) + "</button>";
          }).join(" · ")
        : "None this cycle";
      qEl.innerHTML = workerKv(queuesRows(queues).concat([
        ["Last auto-retry batch", qBits],
        ["Wait window", (cfg.llm_timeout_seconds || 120) + "s then auto-retry"]
      ]));
      Array.prototype.forEach.call(qEl.querySelectorAll(".wk-qid"), function (btn) {
        btn.addEventListener("click", function () { openDetailPage(btn.getAttribute("data-qid")); });
      });
    }
    var events = data.events || [];
    if (list) {
      list.innerHTML = events.length
        ? events.slice(0, 20).map(function (e) {
            var when = e.ts ? fmtAgo(Number(e.ts) * 1000) : "";
            var who = (e.process === "gmail_receiver" ? "receiver" : (e.process || "api")) +
              " · " + workerLabel(e.worker);
            return "<li class='" + (e.ok === false ? "is-bad" : "") + "'>" +
              "<span class='we-meta'>" + escapeHtml(when) + " · " + escapeHtml(who) + "</span>" +
              escapeHtml(e.summary || "") + "</li>";
          }).join("")
        : "<li>No notable worker activity yet this process lifetime.</li>";
    }
    if (updated) {
      updated.textContent = recOk
        ? (rec.source === "heartbeat" ? "Receiver via shared data volume" : "Workers via HTTP health")
        : "Workers not reachable";
    }
  }
  var refreshTimer = null;
  function refreshDelayMs() {
    var page = state.activePage || "overview";
    if (page === "workers") return 5000;
    if (page === "audit" || page === "senders" || page === "campaigns") return 60000;
    if (page === "overview" || page === "quarantine" || page === "queue") {
      return feedOverview().aiPendingTotal ? 4000 : 15000;
    }
    return 0;
  }
  function scheduleRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    var delay = refreshDelayMs();
    if (!delay) return;
    refreshTimer = setTimeout(function () {
      loadFeed().then(function () { lastUpdate = Date.now(); }).finally(scheduleRefresh);
    }, delay);
  }
  function getLastUpdate() { return lastUpdate; }
  function getTheme() {
    try { return localStorage.getItem("pdax-ew-theme") || "system"; } catch (err) { return "system"; }
  }

export {
  ICON, VERDICTS, PAGE_META, PAGE_PATHS, THRESHOLDS, POLICY, SENDER_RISK,
  state, lastUpdate,
  displayVerdict, isAiPending, isAiTimedOut, isLlmAssessment, verdictIsFinal,
  pendingEmails, retryableEmails, queueEmails, heldEmails, feedOverview,
  pipelineStatusOf, pipelineStatusLabel, pendingChipLabel,
  chipForEmail, scoreCell, actionTakenLabel, chip, riskChip,
  fmtTime, fmtDateTime, fmtAgo, fmtExpires, fmtUnix, fmtNum,
  escapeHtml, stripListPrefix,
  groupAsThreads, threadKeyOf, threadSiblings, threadAssessmentOf, stripThreadSubject,
  FEED_PAGE_SIZE, pageFeedThreads, feedPageWindow, resetFeedPage,
  chipForThreadGroup,
  categoriesForFlags, describeFlag, verdictMargin,
  loadFeed, loadPolicy, loadOrg, setPolicyCategory, runSpotlightSearch,
  assessmentsJustFinished, threadAssessmentsJustFinished, senderProfilesJustFinished,
  loadEnforcement, applyEnforcement,
  findEmail, openDetailPage, closeDetailPage, lockContentGrant,
  loadFeedItem, mergePinnedFeed,
  populateDetailPage, refreshDetailPage, setPage,
  mountAssessmentFlow, buildPreviewBodyHtml, buildPreviewFootHtml, buildDetailMailHtml, buildThreadStripHtml, buildThreadSidebarHtml,
  loadEmailContent, fetchEmlInto, showContentLock, parseEml, sanitizeEmailHtml, scanContextFromEmail,
  renderEmailViewer, bindEmailViewer, emailViewerSnippet,
  renderOriginMap, renderDetailOriginMap, bindOriginMap, toggleOriginFilter,
  renderThreatMix, renderChart, renderSenderAssessment, renderSenderProfiles, renderCampaigns,
  renderAll, renderWorkers, renderFeed, renderQueue, renderQuarantine, renderAudit, renderStats, renderPolicyPanel,
  copyReport, downloadEml, confirmRelease, confirmKeepBlocked, executePendingAction,
  reevaluateEntry, markEmailBenign, unmarkEmailBenign,
  canAct, isAdmin,
  applyTheme, refreshDelayMs, getLastUpdate, getTheme,
  senderAssessmentOf, senderCopies, senderVerdicts, senderMixBarHtml, senderLaneHtml,
  networkRoleLabel, freqValues, mixChipsHtml, peerListHtml, hoursBarHtml,
  filteredSenderProfiles, selectSenderProfile,
  campaignKindLabel, campaignAttackLabel, campaignTitle, campaignQueueId, filteredCampaigns,
  workerPill, workerAgo, workerCopy, workerKv, workerTileHtml, workerLabel, coverageLine, mailboxSub,
  workerQueueLine, workerQueueNums, queuesRows, queueWaiting, queueRunning,
  registerPasskey, assertPasskey, refreshCurrentUser,
  runAnalyze, setAnalyzeFile, renderAnalyzeResults, openBehavioralModal,
  contentAiFacts, formatLlmModel, bodyStructureFromEntry, bodyStructureHtml,
  pathForPage, parseRoute, feedMatchesOverviewFilter, feedMatchesOrigin, feedMatchesSearch,
  overviewTableFeed, collectOriginPoints, feedUrl,
  OVERVIEW_FILTER_LABEL, TYPE_LABEL, ENFORCE_LABELS, ENFORCE_BADGE_CLS
};
