import { afterEach, describe, expect, it, vi } from "vitest";
import {
  displayVerdict,
  escapeHtml,
  fmtAgo,
  fmtNum,
  groupAsThreads,
  heldEmails,
  isAdmin,
  parseRoute,
  pathForPage,
  pendingChipLabel,
  pageFeedThreads,
  feedPageWindow,
  FEED_PAGE_SIZE,
  pipelineStatusLabel,
  queueEmails,
  feedOverview,
  state,
  stripListPrefix,
  stripThreadSubject,
  verdictIsFinal,
  workerQueueLine,
  workerQueueNums,
  queuesRows,
  assessmentsJustFinished,
  threadAssessmentsJustFinished,
  senderProfilesJustFinished,
  feedMatchesOverviewFilter,
  mountAssessmentFlow,
  buildPreviewBodyHtml,
  buildThreadSidebarHtml,
  findEmail,
  mergePinnedFeed,
  categoriesForFlags,
  loadFeed,
  openDetailPage,
  ui,
  collectOriginPoints,
  feedUrl,
  refreshDelayMs,
  campaignTitle,
  campaignKindLabel,
} from "./dashboard";
import { resetEngine } from "../test/engine";
import { sampleEmail, viewerUser } from "../test/fixtures";

describe("verdict helpers", () => {
  afterEach(() => resetEngine());

  it("hides the score as PENDING while LLM assessment is outstanding", () => {
    resetEngine();
    const e = sampleEmail({
      aiSummary: "",
      aiProvider: "",
      sourceKind: "gmail",
      verdict: "MALICIOUS",
      score: 90,
    });
    expect(displayVerdict(e)).toBe("PENDING");
    expect(verdictIsFinal(e)).toBe(false);
  });

  it("malicious overview tile matches a malicious copy even when the thread is clean", () => {
    resetEngine();
    state.overviewFilter = "malicious";
    const e = sampleEmail({ verdict: "MALICIOUS", threadVerdict: "CLEAN", score: 90 });
    expect(feedMatchesOverviewFilter(e)).toBe(true);
  });

  it("malicious overview tile matches a thread assessed malicious", () => {
    resetEngine();
    state.overviewFilter = "malicious";
    const e = sampleEmail({ verdict: "CLEAN", threadVerdict: "MALICIOUS" });
    expect(feedMatchesOverviewFilter(e)).toBe(true);
  });

  it("safe overview tile does not hide behind a malicious thread verdict", () => {
    resetEngine();
    state.overviewFilter = "safe";
    const e = sampleEmail({ verdict: "MALICIOUS", threadVerdict: "MALICIOUS", score: 90 });
    expect(feedMatchesOverviewFilter(e)).toBe(false);
  });

  it("returns INCONCLUSIVE when the LLM timed out", () => {
    resetEngine();
    const e = sampleEmail({
      aiSummary: "",
      aiProvider: "",
      sourceKind: "gmail",
      aiTimedOut: true,
      verdict: "SUSPICIOUS",
    });
    expect(displayVerdict(e)).toBe("INCONCLUSIVE");
    expect(verdictIsFinal(e)).toBe(true);
  });

  it("honors a hard override immediately", () => {
    resetEngine();
    const e = sampleEmail({
      hardOverride: true,
      verdict: "CLEAN",
      aiSummary: "",
      aiProvider: "",
      sourceKind: "gmail",
    });
    expect(displayVerdict(e)).toBe("CLEAN");
    expect(verdictIsFinal(e)).toBe(true);
  });
});

describe("pipeline status", () => {
  afterEach(() => resetEngine());

  it("labels queued / static / ai copies", () => {
    resetEngine();
    const queued = sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "queued",
    });
    const checking = sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "static",
    });
    const waiting = sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "ai",
    });
    expect(pipelineStatusLabel(queued)).toBe("Queued");
    expect(pipelineStatusLabel(checking)).toBe("Static checks");
    expect(pipelineStatusLabel(waiting)).toBe("Content AI");
    expect(pipelineStatusLabel(sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "dead_letter",
    }))).toBe("Needs review");
    expect(pipelineStatusLabel(sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "error",
    }))).toBe("Assessment error");
    expect(pendingChipLabel(queued)).toBe("Queued");
    expect(pendingChipLabel(checking)).toBe("Checking");
    expect(pendingChipLabel(waiting)).toBe("Assessing");
    expect(pendingChipLabel(sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "dead_letter",
    }))).toBe("Needs review");
    expect(pendingChipLabel(sampleEmail({
      aiSummary: "", aiProvider: "", sourceKind: "gmail", pipelineStatus: "error",
    }))).toBe("Error");
  });
});

describe("queues and quarantine", () => {
  afterEach(() => resetEngine());

  it("puts pending and timed-out copies in the AI queue", () => {
    resetEngine([
      sampleEmail({ id: "clean", aiSummary: "ok", aiProvider: "gemini" }),
      sampleEmail({ id: "wait", aiSummary: "", aiProvider: "", sourceKind: "gmail" }),
      sampleEmail({ id: "retry", aiSummary: "", aiProvider: "", sourceKind: "gmail", aiTimedOut: true, queueId: "q1" }),
    ]);
    const ids = queueEmails().map((e: { id: string }) => e.id);
    expect(ids).toEqual(["wait", "retry"]);
  });

  it("only lists spool-held copies as quarantine", () => {
    resetEngine([
      sampleEmail({ id: "inbox", sourceKind: "gmail" }),
      sampleEmail({ id: "held", sourceKind: "spool", bucket: "quarantine", verdict: "SUSPICIOUS" }),
      sampleEmail({ id: "blocked", sourceKind: "spool", bucket: "rejected", verdict: "MALICIOUS" }),
    ]);
    expect(heldEmails().map((e: { id: string }) => e.id)).toEqual(["held", "blocked"]);
  });
});

describe("threads and routing", () => {
  it("groups messages that share a thread key and picks the worst final copy", () => {
    resetEngine();
    const a = sampleEmail({
      id: "a",
      threadKey: "t1",
      ts: 1,
      verdict: "CLEAN",
      score: 5,
      aiProvider: "gemini",
      aiSummary: "ok",
    });
    const b = sampleEmail({
      id: "b",
      threadKey: "t1",
      ts: 2,
      verdict: "MALICIOUS",
      score: 88,
      aiProvider: "gemini",
      aiSummary: "bad",
    });
    const groups = groupAsThreads([a, b]);
    expect(groups).toHaveLength(1);
    expect(groups[0].latest.id).toBe("b");
    expect(groups[0].worst.id).toBe("b");
    expect(groups[0].messages).toHaveLength(2);
  });

  it("strips Re/Fwd prefixes from thread subjects", () => {
    expect(stripThreadSubject("Re: Fwd: Invoice")).toBe("Invoice");
  });

  it("pages the live feed 100 conversations at a time, newest first", () => {
    resetEngine();
    const now = 1_000_000;
    const messages = Array.from({ length: 250 }, (_, i) =>
      sampleEmail({
        id: "m" + i,
        threadKey: "t" + i,
        ts: now + i,
        subject: "Mail " + i,
      }),
    );
    const groups = groupAsThreads(messages);
    expect(groups[0].latest.id).toBe("m249");
    expect(groups[groups.length - 1].latest.id).toBe("m0");
    expect(FEED_PAGE_SIZE).toBe(100);

    state.feedPage = 1;
    const p1 = pageFeedThreads(groups);
    expect(p1.total).toBe(250);
    expect(p1.pages).toBe(3);
    expect(p1.items).toHaveLength(100);
    expect(p1.from).toBe(1);
    expect(p1.to).toBe(100);
    expect(p1.items[0].latest.id).toBe("m249");
    expect(p1.items[99].latest.id).toBe("m150");

    state.feedPage = 3;
    const p3 = pageFeedThreads(groups);
    expect(p3.items).toHaveLength(50);
    expect(p3.from).toBe(201);
    expect(p3.to).toBe(250);
    expect(p3.items[0].latest.id).toBe("m49");
    expect(p3.items[49].latest.id).toBe("m0");

    state.feedPage = 99;
    const clamped = pageFeedThreads(groups);
    expect(clamped.page).toBe(3);

    expect(feedPageWindow(1, 3)).toEqual([1, 2, 3]);
    expect(feedPageWindow(5, 12)).toEqual([1, 0, 4, 5, 6, 0, 12]);
  });

  it("maps console paths", () => {
    expect(pathForPage("workers")).toBe("/workers");
    expect(parseRoute("/queue")).toEqual({ page: "workers" });
    expect(pathForPage("detail", "msg 1")).toBe("/mail/msg%201");
    expect(parseRoute("/mail/abc")).toEqual({ page: "detail", detailId: "abc" });
    expect(parseRoute("/settings")).toEqual({ page: "settings" });
    expect(parseRoute("/settings/organization")).toEqual({ page: "settings" });
    expect(parseRoute("/settings/users")).toEqual({ page: "settings" });
    expect(parseRoute("/settings/notifications")).toEqual({ page: "settings" });
    expect(parseRoute("/profile")).toEqual({ page: "profile" });
    expect(parseRoute("/nope")).toEqual({ page: "overview" });
  });

  it("finds a copy by id or queueId and keeps pinned rows on the feed", () => {
    const listed = sampleEmail({ id: "gmail-new", queueId: "gmail-new" });
    const aged = sampleEmail({ id: "gmail-old", queueId: "gmail-old", subject: "Aged off" });
    resetEngine([listed]);
    expect(findEmail("gmail-new").id).toBe("gmail-new");
    expect(mergePinnedFeed([listed], [aged, listed]).map((e: { id: string }) => e.id))
      .toEqual(["gmail-new", "gmail-old"]);
    expect(findEmail("gmail-old")).toBeUndefined();
    state.feed = mergePinnedFeed(state.feed, [aged]);
    expect(findEmail("gmail-old").subject).toBe("Aged off");
  });

  it("finds filtered-tile copies that aged off the live feed page", () => {
    const aged = sampleEmail({ id: "gmail-old-mal", queueId: "gmail-old-mal", verdict: "MALICIOUS" });
    resetEngine([]);
    state.filteredFeed = [aged];
    expect(findEmail("gmail-old-mal").id).toBe("gmail-old-mal");
  });

  it("opens detail for a filtered copy that is not in state.feed", () => {
    resetEngine([]);
    state.filteredFeed = [sampleEmail({ id: "gmail-old-mal", queueId: "gmail-old-mal" })];
    const nav = vi.fn();
    ui.onNavigate = nav;
    openDetailPage("gmail-old-mal");
    expect(nav).toHaveBeenCalledWith("/mail/gmail-old-mal");
    ui.onNavigate = null;
  });

  it("opens detail by queue id even when the copy is not cached yet", () => {
    resetEngine([]);
    const nav = vi.fn();
    ui.onNavigate = nav;
    openDetailPage("gmail-unknown");
    expect(nav).toHaveBeenCalledWith("/mail/gmail-unknown");
    ui.onNavigate = null;
  });

  it("uses unclipped stats for overview totals instead of feed.length", () => {
    const now = Date.now();
    resetEngine([
      sampleEmail({ id: "a", ts: now, aiPending: true, sourceKind: "gmail" }),
      sampleEmail({ id: "b", ts: now, aiPending: true, sourceKind: "gmail" }),
    ]);
    state.feedStats = {
      total: 2487,
      pending: 2100,
      inconclusive: 12,
      clean: 300,
      low: 40,
      suspicious: 20,
      malicious: 15,
      aiPendingTotal: 2100,
      aiTimedOutTotal: 12,
      hourly: [],
      feedLimit: 500,
      inboxesMonitored: 17,
      inboxesPolling: 4,
      inboxesConfigured: 3,
      inboxesDiscovered: 14,
      assessed: 375,
      threadAssessed: 40,
    };
    const ov = feedOverview();
    expect(ov.total).toBe(2487);
    expect(ov.pendingN).toBe(2100);
    expect(ov.aiPendingTotal).toBe(2100);
    expect(ov.truncated).toBe(true);
    expect(ov.inboxesMonitored).toBe(17);
    expect(ov.inboxesPolling).toBe(4);
    expect(ov.inboxesDiscovered).toBe(14);
    expect(ov.assessed).toBe(375);
    expect(ov.threadAssessed).toBe(40);
  });

  it("counts all feed mail when stats are absent, not only the last 24h", () => {
    const now = Date.now();
    resetEngine([
      sampleEmail({ id: "old", ts: now - 5 * 86400 * 1000, verdict: "MALICIOUS" }),
      sampleEmail({ id: "fresh", ts: now, verdict: "CLEAN" }),
    ]);
    const ov = feedOverview();
    expect(ov.total).toBe(2);
    expect(ov.counts.MALICIOUS).toBe(1);
    expect(ov.counts.CLEAN).toBe(1);
  });

  it("does not bundle workers into the overview feed poll", async () => {
    resetEngine();
    state.activePage = "overview";
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockClear();
    await loadFeed();
    const urls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(urls.filter((u) => u.includes("/api/feed")).length).toBe(1);
    expect(urls.some((u) => u.includes("/api/workers"))).toBe(false);
    expect(urls.some((u) => u.includes("/api/campaigns"))).toBe(false);
    expect(urls.some((u) => u.includes("/api/sender-profiles"))).toBe(false);
    expect(urls.some((u) => u.includes("/api/audit"))).toBe(false);
  });

  it("requests one filtered feed when a tile and origin are set", async () => {
    resetEngine();
    state.activePage = "overview";
    state.overviewFilter = "malicious";
    state.originCountry = "PH";
    expect(feedUrl()).toBe("/api/feed?verdict=malicious&origin=PH");
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockClear();
    await loadFeed();
    const urls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(urls.filter((u) => u.includes("/api/feed")).length).toBe(1);
    expect(urls[0]).toContain("verdict=malicious");
    expect(urls[0]).toContain("origin=PH");
  });

  it("does not poll /api/feed on settings or detail", async () => {
    resetEngine();
    state.activePage = "settings";
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockClear();
    await loadFeed();
    expect(fetchMock.mock.calls.map((c) => String(c[0])).some((u) => u.includes("/api/feed"))).toBe(false);
    state.activePage = "detail";
    fetchMock.mockClear();
    await loadFeed();
    expect(fetchMock.mock.calls.map((c) => String(c[0])).some((u) => u.includes("/api/feed"))).toBe(false);
  });

  it("paints the origin map from snapshot stats, not the feed page", () => {
    resetEngine([
      sampleEmail({ id: "page-only", originCountry: "US" }),
    ]);
    state.feedStats = {
      total: 800,
      origin: {
        located: 800,
        countries: [{ country: "PH", name: "Philippines", count: 800, worst: "LOW", lat: 12.9, lon: 121.8 }],
        points: [{ lat: 14.6, lon: 121.0, country: "PH", name: "Philippines", city: "Makati", count: 40, worst: "SUSPICIOUS" }],
      },
    };
    const collected = collectOriginPoints();
    expect(collected.located).toBe(800);
    expect(collected.total).toBe(800);
    expect(collected.countries).toHaveLength(1);
    expect(collected.countries[0].country).toBe("PH");
    expect(collected.countries[0].count).toBe(800);
    expect(collected.points[0].count).toBe(40);
  });

  it("polls settings/detail never and workers at 5s", () => {
    resetEngine();
    state.activePage = "settings";
    expect(refreshDelayMs()).toBe(0);
    state.activePage = "detail";
    expect(refreshDelayMs()).toBe(0);
    state.activePage = "workers";
    expect(refreshDelayMs()).toBe(5000);
    state.activePage = "audit";
    expect(refreshDelayMs()).toBe(60000);
    state.activePage = "overview";
    state.feedStats = { total: 1, aiPendingTotal: 3 };
    expect(refreshDelayMs()).toBe(4000);
    state.feedStats = { total: 1, aiPendingTotal: 0 };
    expect(refreshDelayMs()).toBe(15000);
  });
});

describe("campaign titles", () => {
  it("prefers the AI title and never falls back to a pivot hash or cam id", () => {
    expect(campaignTitle({
      id: "cam-a1b2c3d4e5f6",
      kind: "hash",
      pattern: "hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ai_title: "Payroll password reset",
      subjects: ["Re: invoice"],
    })).toBe("Payroll password reset");
    expect(campaignTitle({
      id: "cam-a1b2c3d4e5f6",
      kind: "hash",
      pattern: "hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      subjects: ["Q3 wire request"],
    })).toBe("Q3 wire request");
    expect(campaignTitle({
      id: "cam-a1b2c3d4e5f6",
      kind: "hash",
      pattern: "hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    })).toBe(campaignKindLabel("hash"));
    expect(campaignTitle({
      id: "cam-a1b2c3d4e5f6",
      kind: "hash",
      pattern: "hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    })).not.toMatch(/aaaaaaaa|cam-a1b2/);
  });
});

describe("formatters and auth", () => {
  it("escapes HTML", () => {
    expect(escapeHtml(`<script>"x"&'`)).toBe("&lt;script&gt;&quot;x&quot;&amp;&#39;");
  });

  it("strips numbered list prefixes from LLM actions", () => {
    expect(stripListPrefix("1. Delete the mail")).toBe("Delete the mail");
    expect(stripListPrefix("- Quarantine")).toBe("Quarantine");
  });

  it("formats recent timestamps", () => {
    expect(fmtAgo(Date.now())).toBe("just now");
    expect(fmtAgo(Date.now() - 12_000)).toBe("12s ago");
  });

  it("comma-delimits counts for display", () => {
    expect(fmtNum(0)).toBe("0");
    expect(fmtNum(42)).toBe("42");
    expect(fmtNum(1234)).toBe("1,234");
    expect(fmtNum(1234567)).toBe("1,234,567");
    expect(fmtNum("8192")).toBe("8,192");
  });

  it("gates admin on the current user role", () => {
    resetEngine();
    expect(isAdmin()).toBe(true);
    window.__SEG_CURRENT_USER__ = viewerUser;
    expect(isAdmin()).toBe(false);
  });
});

describe("worker queue line", () => {
  it("summarizes waiting vs processing", () => {
    expect(workerQueueLine({ queue_waiting: 14, queue_running: 2 })).toBe("14 in queue · 2 processing");
    expect(workerQueueLine({ queue_waiting: 1234, queue_running: 8 })).toBe("1,234 in queue · 8 processing");
    expect(workerQueueLine({ queue_waiting: 0, queue_running: 0 })).toBe("0 in queue · none processing");
    expect(workerQueueLine({})).toBe("0 in queue · none processing");
  });

  it("uses shared queues snapshot so tile counts match the job-queues card", () => {
    const queues = {
      content_ai: { waiting: 42, running: 3 },
      static: { waiting: 7, running: 1 },
    };
    expect(workerQueueNums({ queue_waiting: 0, queue_running: 0 }, "llm", queues)).toEqual({
      waiting: 42,
      running: 3,
    });
    expect(workerQueueNums({ queue_waiting: 0 }, "static", queues).waiting).toBe(7);
    const rows = queuesRows(queues);
    expect(rows.map((r: string[]) => r[0])).toEqual([
      "Gmail poll",
      "Static checks",
      "Content AI",
      "Thread AI",
      "Sender profiles",
      "Sender risk",
      "Campaign clustering",
      "Timed out / retry",
    ]);
    expect(rows.find((r: string[]) => r[0] === "Content AI")?.[1]).toBe("42 waiting · 3 processing");
    expect(rows.find((r: string[]) => r[0] === "Static checks")?.[1]).toBe("7 waiting · 1 processing");
  });
});

describe("completion toasts", () => {
  afterEach(() => resetEngine());

  it("detects a content assessment that just finished", () => {
    const pending = sampleEmail({
      id: "msg-1", queueId: "gmail-1", aiPending: true, aiProvider: "", aiSummary: "",
    });
    const done = sampleEmail({
      id: "msg-1", queueId: "gmail-1", aiPending: false, aiProvider: "glm", aiSummary: "Phish.",
    });
    expect(assessmentsJustFinished([pending], [done]).map((e: { id: string }) => e.id)).toEqual(["msg-1"]);
    expect(assessmentsJustFinished([], [done])).toEqual([]);
    expect(assessmentsJustFinished([done], [done])).toEqual([]);
  });

  it("detects a thread assessment that just finished, once per conversation", () => {
    const a = sampleEmail({
      id: "msg-a", threadKey: "t1", subject: "Re: Wire request",
      threadSummary: "", threadVerdict: "",
    });
    const b = sampleEmail({
      id: "msg-b", threadKey: "t1", subject: "Re: Wire request",
      threadSummary: "", threadVerdict: "", ts: Date.now(),
    });
    const aDone = sampleEmail({
      id: "msg-a", threadKey: "t1", subject: "Re: Wire request",
      threadSummary: "Follow-up turns the invoice into a wire request.",
      threadVerdict: "SUSPICIOUS",
    });
    const bDone = sampleEmail({
      id: "msg-b", threadKey: "t1", subject: "Re: Wire request",
      threadSummary: "Follow-up turns the invoice into a wire request.",
      threadVerdict: "SUSPICIOUS", ts: Date.now(),
    });
    expect(threadAssessmentsJustFinished([a, b], [aDone, bDone]).map((e: { id: string }) => e.id))
      .toEqual(["msg-a"]);
    expect(threadAssessmentsJustFinished([], [aDone, bDone])).toEqual([]);
    expect(threadAssessmentsJustFinished([aDone, bDone], [aDone, bDone])).toEqual([]);
  });

  it("detects a sender risk profile that just finished", () => {
    const learning = { sender: "vendor@acme.example", n: 3, ready: false, ai_risk: "" };
    const assessed = { sender: "vendor@acme.example", n: 6, ready: true, ai_risk: "LOW" };
    expect(senderProfilesJustFinished([learning], [assessed]).map((p: { sender: string }) => p.sender))
      .toEqual(["vendor@acme.example"]);
    expect(senderProfilesJustFinished([], [assessed])).toEqual([]);
    expect(senderProfilesJustFinished([assessed], [assessed])).toEqual([]);
  });

  it("detects a sender baseline becoming ready without AI risk yet", () => {
    const learning = { sender: "ops@pdax.ph", n: 2, ready: false, ai_risk: "" };
    const ready = { sender: "ops@pdax.ph", n: 5, ready: true, ai_risk: "" };
    expect(senderProfilesJustFinished([learning], [ready]).map((p: { sender: string }) => p.sender))
      .toEqual(["ops@pdax.ph"]);
  });
});

describe("assessment breakdown", () => {
  afterEach(() => resetEngine());

  it("renders static, content, and thread acts with per-check rows", () => {
    resetEngine();
    const e = sampleEmail({
      hasStageDetail: true,
      reasons: ["spf_fail", "urgency_language"],
      stages: {
        headers: { status: "ok", score: 40, flags: ["spf_fail"] },
        sender: { status: "ok", score: 0, flags: [] },
        urls: { status: "ok", score: 0, flags: [] },
        deception: { status: "ok", score: 0, flags: [] },
        attachments: { status: "ok", score: 0, flags: [] },
        intel: { status: "ok", score: 0, flags: [] },
        fanout: { status: "ok", score: 0, flags: [], mailboxes: [] },
        origin_ip: { status: "ok", score: 0, flags: [], ip: "1.1.1.1", country: "US" },
        content_ai: {
          status: "ok", score: 12, flags: ["urgency_language"],
          summary: "Asks for urgent payment.", provider: "gemini",
          modelId: "google/gemini-2.5-flash", nluIntent: "bec_payment", nluConfidence: 0.8,
        },
      },
      threadSummary: "Follow-up turns the invoice into a wire request.",
      threadVerdict: "SUSPICIOUS",
      gmailThreadId: "t1",
    });
    state.feed = [e];
    const host = document.createElement("div");
    mountAssessmentFlow(host, e, true);
    expect(host.textContent).toContain("Static checks");
    expect(host.textContent).toContain("Content AI");
    expect(host.textContent).toContain("Thread AI");
    expect(host.textContent).toContain("SPF");
    expect(host.textContent).toContain("Deterministic detectors");
    expect(host.querySelectorAll("[data-ab-tab]")).toHaveLength(3);
    const contentTab = host.querySelector('[data-ab-tab="content"]') as HTMLButtonElement;
    contentTab.click();
    expect(host.querySelector('[data-ab-panel="content"]')?.hasAttribute("hidden")).toBe(false);
    expect(host.textContent).toContain("Looks like a normal invoice.");
    expect(host.textContent).toContain("Threat class");
    const threadTab = host.querySelector('[data-ab-tab="thread"]') as HTMLButtonElement;
    threadTab.click();
    expect(host.textContent).toContain("Follow-up turns the invoice into a wire request.");
  });

  it("does not paint Not a VPN as a finding on a cloud/VPS hop", () => {
    resetEngine();
    const e = sampleEmail({
      hasStageDetail: true,
      verdict: "CLEAN",
      score: 8,
      stages: {
        headers: { status: "ok", score: 0, flags: [] },
        origin_ip: {
          status: "ok", score: 30, flags: ["origin_ip:1.2.3.4", "origin_ip_hosting", "origin_ip_search"],
          ip: "1.2.3.4", vpn: false, hosting: true,
          networkRoleLabel: "Cloud / VPS hosting", isp: "Oracle Cloud", country: "US",
        },
        sender: { status: "ok", score: 0, flags: [] },
        urls: { status: "ok", score: 0, flags: [] },
        deception: { status: "ok", score: 0, flags: [] },
        attachments: { status: "ok", score: 0, flags: [] },
        intel: { status: "ok", score: 0, flags: [] },
        fanout: { status: "ok", score: 0, flags: [], mailboxes: [] },
        content_ai: { status: "ok", score: 0, flags: [] },
      },
    });
    state.feed = [e];
    const host = document.createElement("div");
    mountAssessmentFlow(host, e, true);
    const originPill = host.querySelector('[data-ab-stage-id="origin_ip"]') as HTMLButtonElement;
    originPill.click();
    expect(originPill.textContent).toContain("Clear");
    expect(originPill.textContent).not.toMatch(/finding/i);
    expect(originPill.className).not.toMatch(/tone-warning|tone-serious|tone-critical/);
    const vpnCard = Array.from(host.querySelectorAll(".ab-check")).find(
      (el) => el.textContent?.includes("Not a VPN"),
    ) as HTMLElement;
    expect(vpnCard).toBeTruthy();
    expect(vpnCard.classList.contains("is-clear")).toBe(true);
    expect(vpnCard.classList.contains("is-hit")).toBe(false);
    expect(vpnCard.textContent).toContain("Clear");
    expect(host.textContent).toContain("Cloud / VPS");
  });

  it("still marks a real VPN hop as a finding", () => {
    resetEngine();
    const e = sampleEmail({
      hasStageDetail: true,
      verdict: "LOW",
      stages: {
        origin_ip: {
          status: "ok", score: 52, flags: ["origin_ip:9.9.9.9", "origin_ip_vpn"],
          ip: "9.9.9.9", vpn: true, hosting: false,
          networkRoleLabel: "VPN / proxy",
        },
      },
    });
    state.feed = [e];
    const host = document.createElement("div");
    mountAssessmentFlow(host, e, true);
    const vpnCard = Array.from(host.querySelectorAll(".ab-check")).find(
      (el) => el.textContent?.includes("VPN likely"),
    ) as HTMLElement;
    expect(vpnCard).toBeTruthy();
    expect(vpnCard.classList.contains("is-hit")).toBe(true);
    expect(vpnCard.textContent).toContain("Finding");
  });

  it("keeps thread assessment out of the AI analysis sidebar", () => {
    resetEngine();
    const e = sampleEmail({
      threadSummary: "Conversation is a wire lure.",
      threadVerdict: "MALICIOUS",
    });
    state.feed = [e];
    expect(buildPreviewBodyHtml(e)).not.toContain("Thread assessment");
    const side = buildThreadSidebarHtml(e);
    expect(side).toContain("Thread assessment");
    expect(side).toContain("Conversation is a wire lure.");
  });
});

describe("categoriesForFlags", () => {
  it("does not throw when reasons is a string or missing", () => {
    expect(() => categoriesForFlags("spf_pass")).not.toThrow();
    expect(categoriesForFlags(null)).toEqual([]);
    expect(categoriesForFlags(undefined)).toEqual([]);
  });
});

