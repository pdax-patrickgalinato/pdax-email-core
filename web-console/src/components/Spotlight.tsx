import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { useNavigate } from "react-router-dom";
import {
  openDetailPage,
  resetFeedPage,
  runSpotlightSearch,
  state,
  VERDICTS,
} from "../lib/dashboard";
import { matchCatalog, type SpotlightItem } from "../lib/spotlightCatalog";
import { useConsole } from "../context/ConsoleContext";
import type { Email } from "../types";

type MailHit = {
  id: string;
  title: string;
  subtitle: string;
};

type SpotlightRow =
  | { kind: "catalog"; item: SpotlightItem }
  | { kind: "mailAll"; title: string; subtitle: string }
  | { kind: "mail"; hit: MailHit };

function mailHitsFromState(): MailHit[] {
  const rows = Array.isArray(state.searchHits) ? (state.searchHits as Email[]) : [];
  return rows.slice(0, 8).map((e) => {
    const id = String(e.id || e.queueId || "");
    const who = e.fromName || e.fromAddr || "Unknown sender";
    const shown = String(e.verdict || "").toUpperCase();
    const label = (VERDICTS[shown] && VERDICTS[shown].label) || shown;
    return {
      id,
      title: e.subject || "(no subject)",
      subtitle: who + (label ? " · " + label : ""),
    };
  });
}

export default function Spotlight() {
  const { bump, setTheme, tick, user } = useConsole();
  const navigate = useNavigate();
  const [query, setQuery] = useState(() => state.feedSearch || "");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [mailHits, setMailHits] = useState<MailHit[]>([]);
  const [mailPending, setMailPending] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const admin = (user && user.role) === "admin";
  void tick;

  const catalog = useMemo(() => matchCatalog(query, { admin }), [query, admin]);
  const q = query.trim();

  const rows: SpotlightRow[] = useMemo(() => {
    const out: SpotlightRow[] = catalog.map((item) => ({ kind: "catalog", item }));
    if (q) {
      const extra = Array.isArray(state.searchHits) && state.searchHits.length > 8;
      out.push({
        kind: "mailAll",
        title: "Search mail for “" + q + "”",
        subtitle: mailPending
          ? "Querying the mail database…"
          : mailHits.length
            ? mailHits.length + (extra ? "+" : "") + " matching messages — open on Overview"
            : "Show matches on Overview",
      });
      mailHits.forEach((hit) => {
        if (hit.id) out.push({ kind: "mail", hit });
      });
    }
    return out;
  }, [catalog, q, mailHits, mailPending]);

  useEffect(() => {
    setActive(0);
  }, [query, mailHits.length]);

  useEffect(() => {
    const qNow = query.trim();
    if (!qNow) {
      setMailHits([]);
      setMailPending(false);
      runSpotlightSearch("").then(() => bump());
      return;
    }
    setMailPending(true);
    const handle = window.setTimeout(() => {
      runSpotlightSearch(qNow, state.overviewFilter).then(() => {
        setMailHits(mailHitsFromState());
        setMailPending(false);
        bump();
      });
    }, 450);
    return () => window.clearTimeout(handle);
  }, [query, bump]);

  useEffect(() => {
    function onDoc(ev: MouseEvent) {
      if (!rootRef.current || rootRef.current.contains(ev.target as Node)) return;
      setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const runRow = useCallback(
    (row: SpotlightRow | undefined) => {
      if (!row) return;
      if (row.kind === "catalog") {
        const action = row.item.action;
        if (action.kind === "go") {
          navigate(action.path);
          setOpen(false);
          return;
        }
        if (action.kind === "theme") {
          setTheme(action.mode);
          setOpen(false);
          return;
        }
        fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" })
          .catch(() => {})
          .then(() => {
            window.location.href = "/login";
          });
        return;
      }
      if (row.kind === "mailAll") {
        navigate("/overview");
        setOpen(false);
        return;
      }
      openDetailPage(row.hit.id);
      setOpen(false);
    },
    [navigate, setTheme],
  );

  useEffect(() => {
    function onKey(ev: KeyboardEvent) {
      const meta = ev.metaKey || ev.ctrlKey;
      if (meta && (ev.key === "k" || ev.key === "K")) {
        ev.preventDefault();
        setOpen(true);
        inputRef.current?.focus();
        inputRef.current?.select();
        return;
      }
      if (ev.key === "Escape" && open) {
        ev.preventDefault();
        ev.stopPropagation();
        setOpen(false);
        inputRef.current?.blur();
      }
    }
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, [open]);

  function onInputKey(ev: ReactKeyboardEvent<HTMLInputElement>) {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      setOpen(true);
      setActive((i) => Math.min(i + 1, Math.max(rows.length - 1, 0)));
      return;
    }
    if (ev.key === "ArrowUp") {
      ev.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
      return;
    }
    if (ev.key === "Enter") {
      ev.preventDefault();
      if (!open) setOpen(true);
      runRow(rows[active]);
    }
  }

  let lastGroup = "";

  return (
    <div className="spotlight-bar">
      <div className="spotlight" ref={rootRef}>
        <div className={"spotlight-field" + (open ? " is-open" : "")}>
          <svg className="spotlight-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <circle cx="11" cy="11" r="7" />
            <path d="M20 20l-3.5-3.5" strokeLinecap="round" />
          </svg>
          <input
            ref={inputRef}
            id="feedSearch"
            className="spotlight-input"
            type="search"
            role="combobox"
            aria-label="Search mail and console"
            aria-expanded={open}
            aria-controls="spotlight-results"
            aria-autocomplete="list"
            placeholder="Search mail, pages, and settings"
            autoComplete="off"
            value={query}
            onFocus={() => setOpen(true)}
            onChange={(e) => {
              const next = e.target.value;
              setQuery(next);
              state.feedSearch = next;
              resetFeedPage();
              setOpen(true);
            }}
            onKeyDown={onInputKey}
          />
          <kbd className="spotlight-kbd">⌘K</kbd>
        </div>
        {open ? (
          <div className="spotlight-results" id="spotlight-results" role="listbox">
            {!rows.length ? (
              <div className="spotlight-empty">No matching pages or settings</div>
            ) : (
              rows.map((row, i) => {
                const group =
                  row.kind === "catalog" ? row.item.group : row.kind === "mailAll" || row.kind === "mail" ? "Mail" : "";
                const showGroup = group !== lastGroup;
                lastGroup = group;
                const selected = i === active;
                const key = row.kind === "catalog" ? row.item.id : row.kind === "mail" ? "mail-" + row.hit.id : "mail-all";
                const title = row.kind === "catalog" ? row.item.title : row.kind === "mail" ? row.hit.title : row.title;
                const sub =
                  row.kind === "catalog" ? row.item.subtitle : row.kind === "mail" ? row.hit.subtitle : row.subtitle;
                const hint =
                  row.kind === "catalog"
                    ? row.item.action.kind === "theme"
                      ? "Toggle"
                      : row.item.action.kind === "logout"
                        ? "Action"
                        : "Open"
                    : row.kind === "mail"
                      ? "Open"
                      : "Show";
                return (
                  <div key={key}>
                    {showGroup ? <div className="spotlight-group">{group}</div> : null}
                    <button
                      type="button"
                      role="option"
                      id={"spotlight-opt-" + i}
                      aria-selected={selected}
                      className={"spotlight-row" + (selected ? " is-active" : "")}
                      onMouseEnter={() => setActive(i)}
                      onClick={() => runRow(row)}
                    >
                      <span className="spotlight-row-text">
                        <span className="spotlight-row-title">{title}</span>
                        <span className="spotlight-row-sub">{sub}</span>
                      </span>
                      <span className="spotlight-row-hint">{hint}</span>
                    </button>
                  </div>
                );
              })
            )}
            {state.searchError ? <div className="spotlight-error">{state.searchError}</div> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
