export type Role = "admin" | "analyst" | "viewer";

export type VerdictKey = "CLEAN" | "LOW" | "SUSPICIOUS" | "MALICIOUS" | "PENDING" | "INCONCLUSIVE";

export type ThemeMode = "light" | "dark" | "system";

export type OverviewFilter = "all" | "safe" | "suspicious" | "malicious";

export type QuarantineFilter = "all" | "blocked" | "quarantined" | "released";

export type PageKey =
  | "overview"
  | "quarantine"
  | "analyze"
  | "senders"
  | "campaigns"
  | "workers"
  | "audit"
  | "settings"
  | "profile"
  | "detail";

export type AuthUser = {
  id: string;
  username: string;
  role: Role;
  disabled?: boolean;
  created_at?: number;
  passkey_count?: number;
};

export type OrgNote = {
  id: string;
  text: string;
};

export type Org = {
  display_name?: string;
  context_notes?: OrgNote[];
};

export type Email = {
  id: string;
  ts: number;
  fromAddr?: string;
  fromName?: string;
  toAddr?: string;
  toName?: string;
  toAddrs?: string[];
  subject?: string;
  mailbox?: string;
  verdict?: VerdictKey | string;
  score?: number;
  status?: string;
  sourceKind?: string;
  bucket?: string;
  queueId?: string;
  originCountry?: string;
  reasons?: string[];
  stages?: Record<string, Record<string, unknown>>;
  aiSummary?: string;
  aiProvider?: string;
  aiModel?: string;
  aiPending?: boolean;
  aiTimedOut?: boolean;
  aiQueuedAt?: number;
  pipelineStatus?: string;
  hardOverride?: boolean;
  threadKey?: string;
  threadVerdict?: string;
  threadSummary?: string;
  analystLabel?: string;
  expiresAt?: number;
  [key: string]: unknown;
};

export type ThreadGroup = {
  key: string;
  messages: Email[];
  latest: Email;
  worst: Email;
  subject: string;
};

export type AuditEntry = {
  ts: number;
  type?: string;
  title: string;
  detail: string;
  actor?: string;
  action?: string;
  wazuh?: boolean;
  tag?: string;
  kind?: string;
};

export type SenderProfile = {
  sender: string;
  n?: number;
  ready?: boolean;
  sent_count?: number;
  received_count?: number;
  majority_role?: string;
  countries?: Record<string, number> | Array<{ key?: string; value?: string; n?: number }>;
  asns?: Record<string, number> | Array<{ key?: string; value?: string; n?: number }>;
  vpn_rate?: number;
  ai_risk?: string;
  [key: string]: unknown;
};

export type Campaign = {
  id: string;
  kind?: string;
  members?: number;
  senders?: number;
  flagged?: number;
  pattern?: string;
  mailboxes?: number;
  subjects?: string[];
  sender_list?: string[];
  mailbox_list?: string[];
  dests?: unknown[];
  ai_title?: string;
  ai_summary?: string;
  attack_class?: string;
  confidence?: string;
  insight?: {
    lure?: string;
    patterns?: string[];
    tactics?: string[];
    targeting?: string;
    infrastructure?: string;
    why_clustered?: string;
    false_positive_risk?: string;
    false_positive_note?: string;
    analyst_actions?: string[];
    threat_mix?: Record<string, number>;
    intent_mix?: Record<string, number>;
    shared_iocs?: {
      urls?: string[];
      hosts?: string[];
      domains?: string[];
      hashes?: string[];
      ips?: string[];
    };
    member_briefs?: Array<{
      queue_id?: string;
      from?: string;
      mailbox?: string;
      subject?: string;
      verdict?: string;
      intent?: string;
      summary?: string;
    }>;
    analyzed?: number;
  };
  ai_provider?: string;
  ai_model?: string;
  [key: string]: unknown;
};

export type WorkerEvent = {
  ts?: number;
  process?: string;
  worker?: string;
  ok?: boolean;
  summary?: string;
};

export type WorkerQueueCounts = {
  waiting?: number;
  running?: number;
};

export type WorkersStatus = {
  api?: Record<string, unknown>;
  receiver?: Record<string, unknown>;
  ops?: Record<string, unknown>;
  events?: WorkerEvent[];
  queues?: Record<string, WorkerQueueCounts>;
  [key: string]: unknown;
};

export type PolicyCategory = {
  key: string;
  label: string;
  enabled: boolean;
};

export type Policy = {
  categories?: PolicyCategory[];
};

export type ConfirmSpec = {
  kind: string;
  id: string;
  title: string;
  body: string;
  detail?: string;
  confirmLabel?: string;
};

export type PasswordModalSpec = {
  id: string;
  name: string;
};

export type BehavioralEmail = {
  seen_at?: number;
  verdict?: string;
  sender?: string;
  message_id?: string;
};

export type BehavioralSpec = {
  title: string;
  sub?: string;
  emails?: BehavioralEmail[];
};

export type ToastItem = {
  id: string;
  icon?: string;
  msg: string;
};

export type FeedOverviewStats = {
  windowSeconds?: number;
  total: number;
  pending?: number;
  inconclusive?: number;
  clean?: number;
  low?: number;
  suspicious?: number;
  malicious?: number;
  assessed?: number;
  threadAssessed?: number;
  mailboxes?: number;
  aiPendingTotal?: number;
  aiTimedOutTotal?: number;
  hourly?: { start: number; count: number; low?: number; suspicious?: number; malicious?: number }[];
  feedLimit?: number;
  inboxesMonitored?: number;
  inboxesPolling?: number;
  inboxesConfigured?: number;
  inboxesDiscovered?: number;
  inboxesSkipped?: number;
  quarantined?: number;
  held?: number;
  computedAt?: number;
  origin?: {
    located?: number;
    countries?: Array<{
      country: string;
      name?: string;
      count: number;
      worst?: string;
      lat?: number;
      lon?: number;
      city?: string;
    }>;
    points?: Array<{
      lat: number;
      lon: number;
      country?: string;
      name?: string;
      city?: string;
      count: number;
      worst?: string;
    }>;
  };
};

export type ConsoleState = {
  feed: Email[];
  feedStats: FeedOverviewStats | null;
  llmConfigured: boolean;
  llmAssessTimeoutMs: number;
  activePage: string;
  qFilter: string;
  overviewFilter: string;
  originCountry: string;
  feedSearch: string;
  qSearch: string;
  auditSearch: string;
  auditWazuhOnly: boolean;
  audit: AuditEntry[];
  senderProfiles: SenderProfile[];
  senderProfileQuery: string;
  senderProfileReadyOnly: boolean;
  senderProfileSelected: string;
  senderProfileDetail: unknown;
  senderProfileMinN: number;
  senderAssessFilter: string;
  workers: WorkersStatus | null;
  campaigns: Campaign[];
  campaignQuery: string;
  campaignFlaggedOnly: boolean;
  campaignSelected: string;
  detailId: string | null;
  detailReturnPage: string;
};

export type UiHooks = {
  onData: ((payload?: { finished?: Email[] }) => void) | null;
  onToast: ((icon: string, msg: string) => void) | null;
  onConfirm: ((spec: ConfirmSpec) => void) | null;
  onNavigate: ((path: string, opts?: { replace?: boolean }) => void) | null;
  onOpenPassword: ((id: string, name: string) => void) | null;
  onOpenBehavioral: ((meta: BehavioralSpec) => void) | null;
};

export type VerdictInfo = {
  key: string;
  label: string;
  cls: string;
  icon: string;
  action: string;
};

export type Passkey = {
  id: string;
  name?: string;
  created_at?: number;
};

export type ListEntry = {
  address?: string;
  domain?: string;
  note?: string;
};

export type Indicator = {
  kind: string;
  value: string;
  confirmations?: number;
};

export type Enforcement = {
  mode: string;
  updated_by?: string;
  updated_at?: string;
};

export type IngestConfig = {
  gmail_fetch: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type SlackConfig = {
  enabled: boolean;
  threshold: string;
  webhook_url: string;
  webhook_url_masked?: string;
};

export type NotifyConfig = {
  enabled: boolean;
  smtp_host: string;
  smtp_port: number | string;
  smtp_user: string;
  from_addr: string;
  threshold: string;
  password_set?: boolean;
  smtp_pass_set?: boolean;
};

export type SsoConfig = {
  enabled: boolean;
  live?: boolean;
  provider?: string;
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  client_id: string;
  client_secret?: string;
  client_secret_set?: boolean;
  client_secret_masked?: string;
  redirect_uri: string;
  discovery_url: string;
  allowed_domains: string;
  default_role: Role;
  updated_by?: string;
  updated_at?: string;
};
