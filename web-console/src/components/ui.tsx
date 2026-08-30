import type { CSSProperties, ElementType, ReactNode } from "react";
import {
  ICON,
  POLICY,
  VERDICTS,
  categoriesForFlags,
  displayVerdict,
  fmtNum,
  pendingChipLabel,
  threadAssessmentOf,
} from "../lib/dashboard";
import type { Email, ThreadGroup, VerdictKey } from "../types";

export function Icon({ name }: { name: string }) {
  const html = ICON[name] as string | undefined;
  if (!html) return null;
  return <span className="seg-icon" dangerouslySetInnerHTML={{ __html: html }} />;
}

type ChipProps = {
  verdict?: VerdictKey | string;
  email?: Email;
  quiet?: boolean;
  children?: ReactNode;
  className?: string;
};

export function Chip({ verdict, email, quiet, children, className }: ChipProps) {
  let shown: string | undefined = verdict;
  if (email) {
    shown = displayVerdict(email) as string;
    if (shown === "PENDING" && !quiet) {
      return (
        <span className="chip v-pending">
          <span className="analyze-spinner" aria-hidden="true" />
          {pendingChipLabel(email)}
        </span>
      );
    }
  }
  const v = VERDICTS[shown as string] || VERDICTS.PENDING;
  return (
    <span className={["chip", v.cls, className].filter(Boolean).join(" ")}>
      <Icon name={v.icon} />
      {children || v.label}
    </span>
  );
}

export function ThreadChip({ group, display }: { group?: ThreadGroup; display?: Email }) {
  if (display && display.hardOverride) return <Chip email={display} />;
  const t = threadAssessmentOf(group && group.messages);
  if (t && t.threadVerdict) return <Chip verdict={t.threadVerdict} />;
  return <Chip email={display} />;
}

export function ScoreCell({ email }: { email: Email }) {
  const shown = displayVerdict(email) as string;
  if (shown === "PENDING" || shown === "INCONCLUSIVE") return "—";
  return email.score != null ? fmtNum(email.score) : "—";
}

export function AddrCell({ addr, name, extraCount }: { addr?: string; name?: string; extraCount?: number }) {
  const addrStr = String(addr || "").trim();
  const nameStr = String(name || "").trim();
  if (!addrStr && !nameStr) {
    return (
      <div className="cell-content-min">
        <span className="addr-muted">—</span>
      </div>
    );
  }
  const email = addrStr || nameStr;
  const showName = nameStr && nameStr.toLowerCase() !== email.toLowerCase();
  return (
    <div className="cell-content-min">
      <span className="addr-email">
        {email}
        {(extraCount || 0) > 0 ? <span className="addr-more">+{fmtNum(extraCount)}</span> : null}
      </span>
      {showName ? <span className="addr">{nameStr}</span> : null}
    </div>
  );
}

export function FromCell({ email }: { email: Email }) {
  return <AddrCell addr={email.fromAddr} name={email.fromName} extraCount={0} />;
}

export function ToCell({ email }: { email: Email }) {
  const extras = email.toAddrs && email.toAddrs.length > 1 ? email.toAddrs.length - 1 : 0;
  return <AddrCell addr={email.toAddr} name={email.toName} extraCount={extras} />;
}

export function CategoryChips({ reasons }: { reasons?: string[] }) {
  const cats = categoriesForFlags(reasons) as string[];
  if (!cats.length) return null;
  return (
    <div className="cat-chip-row">
      {cats.map((c) => {
        const row = (POLICY.categories || []).find((x: { key: string }) => x.key === c);
        return (
          <span key={c} className="cat-chip">
            {(row && row.label) || c}
          </span>
        );
      })}
    </div>
  );
}

type StatTileProps = {
  filter?: string;
  active?: boolean;
  label: string;
  value: number | string;
  icon?: string;
  accentVar?: string;
  sub?: string;
  onClick?: () => void;
};

export function StatTile({ filter, active, label, value, icon, accentVar, sub, onClick }: StatTileProps) {
  const Tag = onClick ? "button" : "div";
  return (
    <Tag
      type={onClick ? "button" : undefined}
      className={"stat-tile" + (active ? " active" : "")}
      data-filter={filter}
      style={{ "--tile-accent": accentVar } as CSSProperties}
      onClick={onClick}
    >
      <div className="stat-label">
        {icon ? <Icon name={icon} /> : null}
        {label}
      </div>
      <div className="stat-value mono">
        {typeof value === "number" ? fmtNum(value) : value}
      </div>
      <div className="stat-sub">{sub}</div>
    </Tag>
  );
}

export function HtmlBlock({
  html,
  className,
  tag: Tag = "div",
  ...rest
}: {
  html?: string;
  className?: string;
  tag?: ElementType;
} & Record<string, unknown>) {
  return <Tag className={className} dangerouslySetInnerHTML={{ __html: html || "" }} {...rest} />;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}
