import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { feedOverview, fmtAgo, fmtNum, heldEmails, isAdmin, state } from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import type { Email, ThemeMode } from "../types";

type NavItem = {
  page: string;
  to: string;
  label: string;
  icon: ReactNode;
  count?: "quarantine" | "campaigns" | "workers";
  admin?: boolean;
};

const NAV: NavItem[] = [
  {
    page: "overview",
    to: "/overview",
    label: "Overview",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 12l3-3 4 4 5-7 6 9" />
        <path d="M3 20h18" />
      </svg>
    ),
  },
  {
    page: "quarantine",
    to: "/quarantine",
    label: "Quarantine",
    count: "quarantine",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="7" width="18" height="14" rx="2" />
        <path d="M3 7l3-4h12l3 4" />
        <path d="M9 12h6" />
      </svg>
    ),
  },
  {
    page: "analyze",
    to: "/analyze",
    label: "Analyze",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <path d="M14 2v6h6" />
        <path d="M9 15l2 2 4-4" />
      </svg>
    ),
  },
  {
    page: "senders",
    to: "/senders",
    label: "Senders",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M22 21v-2a4 4 0 00-3-3.87" />
        <path d="M16 3.13a4 4 0 010 7.75" />
      </svg>
    ),
  },
  {
    page: "campaigns",
    to: "/campaigns",
    label: "Campaigns",
    count: "campaigns",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="6" cy="12" r="3" />
        <circle cx="18" cy="7" r="3" />
        <circle cx="18" cy="17" r="3" />
        <path d="M8.7 10.7l6.6-3.4M8.7 13.3l6.6 3.4" />
      </svg>
    ),
  },
  {
    page: "workers",
    to: "/workers",
    label: "Workers",
    count: "workers",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
      </svg>
    ),
  },
  {
    page: "audit",
    to: "/audit",
    label: "Audit",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 3h6l2 4H7l2-4z" />
        <path d="M5 7h14l-1 13a2 2 0 01-2 2H8a2 2 0 01-2-2L5 7z" />
        <path d="M10 11v6M14 11v6" />
      </svg>
    ),
  },
  {
    page: "settings",
    to: "/settings",
    label: "Settings",
    admin: true,
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z" />
      </svg>
    ),
  },
];

export default function Sidebar() {
  const { user, org, theme, setTheme, lastUpdate, campaigns, workers } = useConsole();
  const [, setClock] = useState(0);
  const location = useLocation();
  const navigate = useNavigate();
  useEffect(() => {
    const id = window.setInterval(() => setClock((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, []);
  const held = (heldEmails() as Email[]).filter((e) => e.status !== "released").length;
  const ov = feedOverview();
  const campaignN = (campaigns || []).length;
  const recDown = workers && workers.receiver && (workers.receiver as { reachable?: boolean }).reachable === false;
  const retryN = ov.aiTimedOutTotal;
  const workerBadge = recDown ? 1 : retryN;
  const brand = org && org.display_name ? org.display_name + " Secure Email Gateway Service (SEGS)" : "SEGS";

  function countFor(kind: NavItem["count"]) {
    if (kind === "quarantine") return { n: held, pending: false, zero: held === 0 };
    if (kind === "campaigns") return { n: campaignN, pending: false, zero: campaignN === 0 };
    if (kind === "workers") return { n: workerBadge, pending: !!recDown, zero: workerBadge === 0 };
    return null;
  }

  function logout() {
    fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" })
      .catch(() => {})
      .then(() => {
        window.location.href = "/login";
      });
  }

  const onMail = location.pathname.indexOf("/mail/") === 0;
  const returnPage = state.detailReturnPage || "overview";
  const themes: [ThemeMode, string, ReactNode][] = [
    [
      "light",
      "Light theme",
      <svg key="l" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
      </svg>,
    ],
    [
      "dark",
      "Dark theme",
      <svg key="d" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 12.8A9 9 0 1111.2 3 7 7 0 0021 12.8z" />
      </svg>,
    ],
    [
      "system",
      "Match system",
      <svg key="s" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="4" width="18" height="13" rx="2" />
        <path d="M8 21h8M12 17v4" />
      </svg>,
    ],
  ];

  return (
    <aside className="sidebar" aria-label="Console navigation">
      <a
        className="brand"
        href="/overview"
        title="Go to Overview"
        aria-label="Go to Overview"
        onClick={(ev) => {
          if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button !== 0) return;
          ev.preventDefault();
          navigate("/overview");
        }}
      >
        <div className="brand-mark">
          <img src="/logo.png" alt="SEGS logo" width="36" height="36" />
        </div>
        <div className="brand-text">
          <div className="brand-name">{brand}</div>
          <div className="brand-sub">Gateway console</div>
        </div>
      </a>
      <nav className="side-nav" aria-label="Pages">
        {NAV.map((item) => {
          if (item.admin && !isAdmin()) return null;
          const count = countFor(item.count);
          return (
            <NavLink
              key={item.page}
              className="nav-item"
              to={item.to}
              data-page={item.page}
              {...(onMail ? { "aria-current": item.page === returnPage ? ("page" as const) : undefined } : {})}
            >
              {item.icon}
              <span className="nav-label">{item.label}</span>
              {count ? (
                <span className={"nav-count" + (count.pending ? " is-pending" : "")} data-zero={count.zero ? "true" : "false"}>
                  {fmtNum(count.n)}
                </span>
              ) : null}
            </NavLink>
          );
        })}
      </nav>
      <div className="sidebar-foot">
        <span className="sidebar-live">
          <span className="live-dot" />
          <span className="nav-label">Live · {fmtAgo(lastUpdate)}</span>
        </span>
        <div className="theme-toggle" role="group" aria-label="Theme">
          {themes.map(([mode, label, icon]) => (
            <button
              key={mode}
              type="button"
              className={theme === mode ? "active" : ""}
              aria-label={label}
              onClick={() => setTheme(mode)}
            >
              {icon}
            </button>
          ))}
        </div>
        <NavLink to="/profile" className="user-chip" title="Your profile" aria-label="Your profile">
          <span>{(user && user.username) || "—"}</span>
          <span className="user-role">{(user && user.role) || "—"}</span>
        </NavLink>
        <button type="button" className="btn btn-sm" title="Sign out" onClick={logout}>
          Log out
        </button>
      </div>
    </aside>
  );
}
