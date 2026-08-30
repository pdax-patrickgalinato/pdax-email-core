/** Indexed console destinations and toggles for Spotlight (macOS-style). */

import type { ThemeMode } from "../types";

export type SpotlightGroup = "Pages" | "Settings" | "Appearance";

export type SpotlightAction =
  | { kind: "go"; path: string }
  | { kind: "theme"; mode: ThemeMode }
  | { kind: "logout" };

export type SpotlightItem = {
  id: string;
  group: SpotlightGroup;
  title: string;
  subtitle: string;
  keywords: string[];
  admin?: boolean;
  suggest?: boolean;
  action: SpotlightAction;
};

export const CONSOLE_CATALOG: SpotlightItem[] = [
  {
    id: "page-overview",
    group: "Pages",
    title: "Overview",
    subtitle: "Live feed, threat mix, and origin map",
    keywords: ["home", "inbox", "mail", "feed", "dashboard"],
    suggest: true,
    action: { kind: "go", path: "/overview" },
  },
  {
    id: "page-quarantine",
    group: "Pages",
    title: "Quarantine",
    subtitle: "Held mail",
    keywords: ["held", "hold", "blocked"],
    suggest: true,
    action: { kind: "go", path: "/quarantine" },
  },
  {
    id: "page-analyze",
    group: "Pages",
    title: "Analyze",
    subtitle: "Upload an .eml for scoring",
    keywords: ["eml", "upload", "sample"],
    action: { kind: "go", path: "/analyze" },
  },
  {
    id: "page-senders",
    group: "Pages",
    title: "Senders",
    subtitle: "Sender profiles and identity risk",
    keywords: ["profile", "identity", "baseline"],
    action: { kind: "go", path: "/senders" },
  },
  {
    id: "page-campaigns",
    group: "Pages",
    title: "Campaigns",
    subtitle: "Clustered lures and infrastructure",
    keywords: ["cluster", "campaign"],
    action: { kind: "go", path: "/campaigns" },
  },
  {
    id: "page-workers",
    group: "Pages",
    title: "Workers",
    subtitle: "Queues, Gmail poll, and AI backlog",
    keywords: ["queue", "gmail", "poll", "ecs", "backlog"],
    action: { kind: "go", path: "/workers" },
  },
  {
    id: "page-audit",
    group: "Pages",
    title: "Audit",
    subtitle: "Gateway decisions and console activity",
    keywords: ["log", "activity", "dwell"],
    action: { kind: "go", path: "/audit" },
  },
  {
    id: "page-profile",
    group: "Pages",
    title: "Profile",
    subtitle: "Password, passkeys, and your activity",
    keywords: ["account", "passkey", "password", "webauthn", "security key"],
    action: { kind: "go", path: "/profile" },
  },
  {
    id: "settings-gateway",
    group: "Settings",
    title: "Settings",
    subtitle: "Gateway enforcement and ingest",
    keywords: ["preferences", "config", "enforcement", "shadow", "gateway"],
    admin: true,
    suggest: true,
    action: { kind: "go", path: "/settings" },
  },
  {
    id: "settings-organization",
    group: "Settings",
    title: "Organization",
    subtitle: "Context notes, allowlist, and blocklist",
    keywords: ["org", "context", "blocklist", "allowlist", "block", "allow"],
    admin: true,
    action: { kind: "go", path: "/settings/organization" },
  },
  {
    id: "settings-notifications",
    group: "Settings",
    title: "Notifications",
    subtitle: "Slack alerts and recipient email",
    keywords: ["slack", "smtp", "alert", "email notice"],
    admin: true,
    action: { kind: "go", path: "/settings/notifications" },
  },
  {
    id: "settings-users",
    group: "Settings",
    title: "Users & SSO",
    subtitle: "Local accounts and JumpCloud SSO",
    keywords: ["sso", "jumpcloud", "scim", "accounts", "people", "login"],
    admin: true,
    action: { kind: "go", path: "/settings/users" },
  },
  {
    id: "theme-light",
    group: "Appearance",
    title: "Light appearance",
    subtitle: "Switch the console to light mode",
    keywords: ["theme", "appearance", "day", "bright", "toggle"],
    suggest: true,
    action: { kind: "theme", mode: "light" },
  },
  {
    id: "theme-dark",
    group: "Appearance",
    title: "Dark appearance",
    subtitle: "Switch the console to dark mode",
    keywords: ["theme", "appearance", "night", "dark mode", "toggle"],
    suggest: true,
    action: { kind: "theme", mode: "dark" },
  },
  {
    id: "theme-system",
    group: "Appearance",
    title: "Match system appearance",
    subtitle: "Follow the OS light or dark setting",
    keywords: ["theme", "appearance", "auto", "system"],
    action: { kind: "theme", mode: "system" },
  },
  {
    id: "action-logout",
    group: "Pages",
    title: "Log out",
    subtitle: "Sign out of this console",
    keywords: ["sign out", "logout", "exit"],
    action: { kind: "logout" },
  },
];

function haystack(item: SpotlightItem): string {
  return (item.group + " " + item.title + " " + item.subtitle + " " + item.keywords.join(" ")).toLowerCase();
}

export function scoreCatalogItem(item: SpotlightItem, query: string): number {
  const q = String(query || "")
    .trim()
    .toLowerCase();
  if (!q) return item.suggest ? 1 : 0;
  const title = item.title.toLowerCase();
  if (title === q) return 100;
  if (title.startsWith(q)) return 90;
  const tokens = q.split(/\s+/).filter(Boolean);
  const hay = haystack(item);
  if (!tokens.every((t) => hay.indexOf(t) !== -1)) return 0;
  if (title.indexOf(q) !== -1) return 70;
  if (item.keywords.some((k) => k.toLowerCase().indexOf(q) !== -1 || q.indexOf(k.toLowerCase()) !== -1)) {
    return 55;
  }
  return 40;
}

export function matchCatalog(
  query: string,
  opts: { admin: boolean; items?: SpotlightItem[] } = { admin: true },
): SpotlightItem[] {
  const items = (opts.items || CONSOLE_CATALOG).filter((item) => !item.admin || opts.admin);
  const q = String(query || "").trim();
  if (!q) {
    return items.filter((item) => item.suggest).slice(0, 10);
  }
  return items
    .map((item) => ({ item, score: scoreCatalogItem(item, q) }))
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score || a.item.title.localeCompare(b.item.title))
    .slice(0, 12)
    .map((row) => row.item);
}
