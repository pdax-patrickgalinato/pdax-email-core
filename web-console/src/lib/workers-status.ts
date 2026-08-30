/** Pick a console tile slot from ILB process probes, then receiver, then API. */

export type WorkerKind =
  | "poll"
  | "static"
  | "llm"
  | "thread_ai"
  | "retry"
  | "profile"
  | "campaign"
  | "sender_risk";

export type WorkerSlotPick = {
  slot: Record<string, any>;
  reachable: boolean;
  host: string;
};

const KIND_TO_PROCESS: Record<WorkerKind, [string, string][]> = {
  poll: [["gmail_poll", "gmail_poll"]],
  static: [["static", "static"]],
  llm: [["content_ai", "gmail_llm"]],
  thread_ai: [["thread_ai", "thread_ai"]],
  retry: [["retry", "inconclusive_retry"]],
  profile: [["sender", "profile"], ["profile", "profile"]],
  campaign: [["campaign", "campaign"]],
  sender_risk: [["sender", "sender_risk"], ["sender_risk", "sender_risk"]],
};

const ALL_KINDS: WorkerKind[] = [
  "poll",
  "static",
  "llm",
  "thread_ai",
  "retry",
  "profile",
  "campaign",
  "sender_risk",
];

function live(slot: Record<string, any> | undefined | null): boolean {
  return !!(slot && (slot.alive || slot.running || slot.last_finished_at));
}

export function pickWorkerSlot(
  data: { processes?: Record<string, any>; receiver?: Record<string, any>; api?: Record<string, any> } | null | undefined,
  kind: WorkerKind,
): WorkerSlotPick {
  const rec = data?.receiver || {};
  const api = data?.api || {};
  const procs = data?.processes || {};
  for (const [procName, slotName] of KIND_TO_PROCESS[kind]) {
    const snap = procs[procName];
    const fromProc = snap && snap[slotName];
    if (snap && (live(fromProc) || snap.source === "probe" || snap.reachable === true)) {
      return { slot: fromProc || {}, reachable: true, host: "Worker process" };
    }
  }
  const [, slotName] = KIND_TO_PROCESS[kind][0];
  if (rec.reachable !== false && live(rec[slotName])) {
    return { slot: rec[slotName], reachable: true, host: "Gmail receiver" };
  }
  if (live(api[slotName])) {
    return { slot: api[slotName], reachable: true, host: "API process" };
  }
  const recOk = rec.reachable !== false;
  return {
    slot: rec[slotName] || api[slotName] || {},
    reachable: recOk,
    host: recOk ? "Worker process" : "Needs worker",
  };
}

export function fleetReachable(
  data: { processes?: Record<string, any>; receiver?: Record<string, any>; api?: Record<string, any> } | null | undefined,
): boolean {
  if (data?.receiver?.reachable === true) return true;
  return ALL_KINDS.some((kind) => pickWorkerSlot(data, kind).reachable);
}
