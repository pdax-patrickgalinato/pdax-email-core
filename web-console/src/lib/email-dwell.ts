/** Report console email opens / dwell / cached-file downloads to the audit log. */

export type EmailViewEvent = "open" | "leave" | "download";

export type EmailViewPayload = {
  queue_id: string;
  event: EmailViewEvent;
  dwell_ms?: number;
  subject?: string;
  from_addr?: string;
};

export function emailViewBody(email: {
  queueId?: string;
  id?: string;
  subject?: string;
  fromAddr?: string;
} | null | undefined, event: EmailViewEvent, dwellMs = 0): EmailViewPayload | null {
  if (!email) return null;
  const queue_id = String(email.queueId || email.id || "").trim();
  if (!queue_id) return null;
  const body: EmailViewPayload = {
    queue_id,
    event,
    subject: String(email.subject || "").slice(0, 500),
    from_addr: String(email.fromAddr || "").slice(0, 320),
  };
  if (event === "leave") body.dwell_ms = Math.max(0, Math.round(dwellMs));
  return body;
}

export function reportEmailView(payload: EmailViewPayload | null): void {
  if (!payload) return;
  const json = JSON.stringify(payload);
  if (payload.event !== "open" && typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
    try {
      const blob = new Blob([json], { type: "application/json" });
      if (navigator.sendBeacon("/api/activity/email-view", blob)) return;
    } catch {
      /* fall through to fetch */
    }
  }
  fetch("/api/activity/email-view", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: json,
    keepalive: true,
  }).catch(() => {});
}

export type DwellSession = {
  visibleMs: () => number;
  pause: () => void;
  resume: () => void;
};

export function startDwellClock(now: () => number = Date.now): DwellSession {
  let acc = 0;
  let started = now();
  let running = true;
  return {
    visibleMs() {
      return acc + (running ? Math.max(0, now() - started) : 0);
    },
    pause() {
      if (!running) return;
      acc += Math.max(0, now() - started);
      running = false;
    },
    resume() {
      if (running) return;
      started = now();
      running = true;
    },
  };
}
