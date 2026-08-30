/** Natural-language spotlight search → structured mail filters. */

export type ThreadAssessmentFilter = "missing" | "present";
export type ContentAssessmentFilter = "missing" | "present" | "timedout";
export type VerdictFilter = "CLEAN" | "LOW" | "SUSPICIOUS" | "MALICIOUS" | "PENDING" | "INCONCLUSIVE";
export type ActionFilter = "quarantined" | "held" | "released" | "blocked";

export type SearchIntent = {
  labels: string[];
  threadAssessment?: ThreadAssessmentFilter;
  contentAssessment?: ContentAssessmentFilter;
  verdicts?: VerdictFilter[];
  action?: ActionFilter;
  from?: string;
  to?: string;
  text: string;
};

export type SearchableMail = {
  fromName?: string;
  fromAddr?: string;
  toName?: string;
  toAddr?: string;
  toAddrs?: string[];
  subject?: string;
  mailbox?: string;
  verdict?: string;
  threadVerdict?: string;
  status?: string;
  actionLabel?: string;
  contentPending?: boolean;
  contentTimedOut?: boolean;
  threadAssessed?: boolean;
};

type Rule = {
  re: RegExp;
  apply: (intent: SearchIntent) => void;
};

const RULES: Rule[] = [
  {
    re: /\b(?:without|w\/o|no|missing|lacking|not\s+yet|haven'?t|hasn'?t|pending|awaiting|waiting\s+(?:on|for))\b[\s\w-]{0,40}\bthread\b[\s\w-]{0,24}\b(?:assess(?:ment|ments|ed|ing)?|ai)\b/g,
    apply: (i) => {
      i.threadAssessment = "missing";
      pushLabel(i, "No thread assessment");
    },
  },
  {
    re: /\bthread\b[\s\w-]{0,24}\b(?:assess(?:ment|ments|ed|ing)?|ai)\b[\s\w-]{0,24}\b(?:pending|missing|outstanding|yet|none|await(?:ing)?|incomplete|not\s+done)\b/g,
    apply: (i) => {
      i.threadAssessment = "missing";
      pushLabel(i, "No thread assessment");
    },
  },
  {
    re: /\b(?:no|without|w\/o)\s+thread\s+(?:assess(?:ment|ments)?|ai)\b/g,
    apply: (i) => {
      i.threadAssessment = "missing";
      pushLabel(i, "No thread assessment");
    },
  },
  {
    re: /\bthread\b[\s\w-]{0,16}\b(?:assess(?:ment|ments|ed)?|ai)\b[\s\w-]{0,16}\b(?:done|complete|completed|finished|ready|present)\b/g,
    apply: (i) => {
      i.threadAssessment = "present";
      pushLabel(i, "Has thread assessment");
    },
  },
  {
    re: /\bwith\s+thread\s+(?:assess(?:ment|ments)?|ai)\b/g,
    apply: (i) => {
      i.threadAssessment = "present";
      pushLabel(i, "Has thread assessment");
    },
  },
  {
    re: /\b(?:timed\s*out|timeout|inconclusive)\b[\s\w-]{0,16}\b(?:ai|llm|assess)?|\b(?:ai|llm|assess(?:ment)?)\b[\s\w-]{0,16}\b(?:timed\s*out|timeout|inconclusive)\b/g,
    apply: (i) => {
      i.contentAssessment = "timedout";
      i.verdicts = ["INCONCLUSIVE"];
      pushLabel(i, "AI timed out");
    },
  },
  {
    re: /\b(?:without|w\/o|no|missing|lacking|not\s+yet|haven'?t|pending|awaiting|waiting\s+(?:on|for))\b[\s\w-]{0,32}\b(?:content|llm|copy)?\s*(?:ai|assess(?:ment|ments|ed|ing)?)\b/g,
    apply: (i) => {
      if (i.contentAssessment) return;
      i.contentAssessment = "missing";
      pushLabel(i, "Awaiting content AI");
    },
  },
  {
    re: /\b(?:pending|awaiting|waiting\s+(?:on|for)|not\s+yet\s+assessed)\b/g,
    apply: (i) => {
      if (i.threadAssessment || i.contentAssessment) return;
      i.contentAssessment = "missing";
      pushLabel(i, "Awaiting content AI");
    },
  },
  {
    re: /\bmalicious\b/g,
    apply: (i) => {
      addVerdict(i, "MALICIOUS");
      pushLabel(i, "Malicious");
    },
  },
  {
    re: /\bsuspicious\b/g,
    apply: (i) => {
      addVerdict(i, "SUSPICIOUS");
      pushLabel(i, "Suspicious");
    },
  },
  {
    re: /\b(?:clean|safe|benign)\b/g,
    apply: (i) => {
      addVerdict(i, "CLEAN");
      addVerdict(i, "LOW");
      pushLabel(i, "Safe");
    },
  },
  {
    re: /\bblocked\b/g,
    apply: (i) => {
      i.action = "blocked";
      pushLabel(i, "Blocked");
    },
  },
  {
    re: /\bquarantined?\b/g,
    apply: (i) => {
      i.action = "quarantined";
      pushLabel(i, "Quarantined");
    },
  },
  {
    re: /\bheld\b/g,
    apply: (i) => {
      i.action = "held";
      pushLabel(i, "Held");
    },
  },
  {
    re: /\breleased\b/g,
    apply: (i) => {
      i.action = "released";
      pushLabel(i, "Released");
    },
  },
];

const FILLER =
  /\b(?:i|i'd|i'm|me|want|wanna|like|need|please|would|could|can|you|we|let'?s|show|see|find|list|get|give|bring|pull|display|open|look(?:ing)?|all|the|emails?|e-?mails?|messages?|mails?|copies|items?|ones?|that|which|who|what|are|is|was|be|been|being|have|has|had|a|an|of|for|in|on|at|to|my|our|this|those|these|here|there|still|yet|just|also|only|some|any|every)\b/g;

function pushLabel(intent: SearchIntent, label: string) {
  if (intent.labels.indexOf(label) === -1) intent.labels.push(label);
}

function addVerdict(intent: SearchIntent, v: VerdictFilter) {
  const cur = intent.verdicts || [];
  if (cur.indexOf(v) === -1) cur.push(v);
  intent.verdicts = cur;
}

export function parseSearchIntent(query: string): SearchIntent {
  const intent: SearchIntent = { labels: [], text: "" };
  let rest = " " + String(query || "").trim().toLowerCase() + " ";

  const fromM = rest.match(/\bfrom\s+(\S+)/);
  if (fromM && fromM[1] && !/^(the|all|my|our)$/.test(fromM[1])) {
    intent.from = fromM[1].replace(/[“”"']/g, "");
    rest = rest.replace(fromM[0], " ");
    pushLabel(intent, "From " + intent.from);
  }
  const toM = rest.match(/\bto\s+(\S*@\S+|\S+\.\S+)/);
  if (toM && toM[1]) {
    intent.to = toM[1].replace(/[“”"']/g, "");
    rest = rest.replace(toM[0], " ");
    pushLabel(intent, "To " + intent.to);
  }

  for (let r = 0; r < RULES.length; r++) {
    const rule = RULES[r];
    rule.re.lastIndex = 0;
    if (!rule.re.test(rest)) continue;
    rule.re.lastIndex = 0;
    rest = rest.replace(rule.re, " ");
    rule.apply(intent);
  }

  FILLER.lastIndex = 0;
  intent.text = rest
    .replace(FILLER, " ")
    .replace(/[?.,!;:()[\]{}]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return intent;
}

export function searchIntentActive(intent: SearchIntent): boolean {
  return !!(
    intent.threadAssessment ||
    intent.contentAssessment ||
    (intent.verdicts && intent.verdicts.length) ||
    intent.action ||
    intent.from ||
    intent.to ||
    intent.text
  );
}

function haystack(mail: SearchableMail): string {
  return [
    mail.fromName,
    mail.fromAddr,
    mail.toName,
    mail.toAddr,
    mail.subject,
    mail.mailbox,
    mail.verdict,
    mail.threadVerdict,
    mail.actionLabel,
    mail.status,
  ]
    .concat(mail.toAddrs || [])
    .join(" ")
    .toLowerCase();
}

export function mailMatchesIntent(mail: SearchableMail, intent: SearchIntent): boolean {
  if (intent.threadAssessment === "missing" && mail.threadAssessed) return false;
  if (intent.threadAssessment === "present" && !mail.threadAssessed) return false;
  if (intent.contentAssessment === "missing" && !mail.contentPending) return false;
  if (intent.contentAssessment === "present" && mail.contentPending) return false;
  if (intent.contentAssessment === "timedout" && !mail.contentTimedOut) return false;
  if (intent.verdicts && intent.verdicts.length) {
    const shown = String(mail.verdict || "").toUpperCase();
    const thread = String(mail.threadVerdict || "").toUpperCase();
    const hit = intent.verdicts.some((v) => v === shown || v === thread);
    if (!hit) return false;
  }
  if (intent.action === "released" && mail.status !== "released") return false;
  if (intent.action === "blocked") {
    if (mail.status === "released") return false;
    if (String(mail.verdict || "").toUpperCase() !== "MALICIOUS") return false;
  }
  if (intent.action === "quarantined") {
    if (mail.status === "released") return false;
    if (String(mail.verdict || "").toUpperCase() !== "SUSPICIOUS") return false;
  }
  if (intent.action === "held") {
    if (mail.status === "released") return false;
    const v = String(mail.verdict || "").toUpperCase();
    if (v !== "SUSPICIOUS" && v !== "MALICIOUS") return false;
  }
  if (intent.from) {
    const blob = ((mail.fromName || "") + " " + (mail.fromAddr || "")).toLowerCase();
    if (blob.indexOf(intent.from) === -1) return false;
  }
  if (intent.to) {
    const blob = [mail.toName, mail.toAddr, mail.mailbox]
      .concat(mail.toAddrs || [])
      .join(" ")
      .toLowerCase();
    if (blob.indexOf(intent.to) === -1) return false;
  }
  if (intent.text && haystack(mail).indexOf(intent.text) === -1) return false;
  return true;
}
