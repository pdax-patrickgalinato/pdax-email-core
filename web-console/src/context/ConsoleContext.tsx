import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  applyTheme,
  getTheme,
  loadFeed,
  loadOrg,
  loadPolicy,
  lockContentGrant,
  refreshDelayMs,
  state,
  ui,
} from "../lib/dashboard";
import type {
  AuditEntry,
  AuthUser,
  BehavioralSpec,
  Campaign,
  ConfirmSpec,
  Email,
  Org,
  PasswordModalSpec,
  SenderProfile,
  ThemeMode,
  ToastItem,
  WorkersStatus,
} from "../types";

export type ConsoleValue = {
  user: AuthUser;
  setUser: Dispatch<SetStateAction<AuthUser | null>>;
  org: Org | null;
  setOrg: Dispatch<SetStateAction<Org | null>>;
  tick: number;
  bump: () => void;
  toasts: ToastItem[];
  confirm: ConfirmSpec | null;
  setConfirm: Dispatch<SetStateAction<ConfirmSpec | null>>;
  pwModal: PasswordModalSpec | null;
  setPwModal: Dispatch<SetStateAction<PasswordModalSpec | null>>;
  behavioral: BehavioralSpec | null;
  setBehavioral: Dispatch<SetStateAction<BehavioralSpec | null>>;
  theme: ThemeMode;
  setTheme: (mode: ThemeMode) => void;
  lastUpdate: number;
  feed: Email[];
  audit: AuditEntry[];
  senderProfiles: SenderProfile[];
  campaigns: Campaign[];
  workers: WorkersStatus | null;
};

const ConsoleContext = createContext<ConsoleValue | null>(null);

type ProviderProps = {
  children: ReactNode;
  user: AuthUser;
  setUser: Dispatch<SetStateAction<AuthUser | null>>;
  org: Org | null;
  setOrg: Dispatch<SetStateAction<Org | null>>;
};

export function ConsoleProvider({ children, user, setUser, org, setOrg }: ProviderProps) {
  const [tick, setTick] = useState(0);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [confirm, setConfirm] = useState<ConfirmSpec | null>(null);
  const [pwModal, setPwModal] = useState<PasswordModalSpec | null>(null);
  const [behavioral, setBehavioral] = useState<BehavioralSpec | null>(null);
  const [theme, setThemeState] = useState<ThemeMode>(() => (getTheme() as ThemeMode) || "system");
  const [lastUpdate, setLastUpdate] = useState(Date.now());
  const navigate = useNavigate();
  const location = useLocation();
  const bump = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    window.__SEG_CURRENT_USER__ = user;
  }, [user]);

  useEffect(() => {
    const path = location.pathname.split("?")[0];
    const prev = state.activePage;
    if (path.indexOf("/mail/") === 0) {
      state.activePage = "detail";
      try {
        state.detailId = decodeURIComponent(path.slice("/mail/".length));
      } catch {
        state.detailId = null;
      }
    } else {
      const key = path.replace(/^\//, "") || "overview";
      state.activePage = key.split("/")[0] || "overview";
      state.detailId = null;
    }
    if (prev === "detail" && state.activePage !== "detail") lockContentGrant();
  }, [location.pathname]);

  useEffect(() => {
    ui.onData = () => {
      setLastUpdate(Date.now());
      bump();
    };
    ui.onToast = (icon: string, msg: string) => {
      const id = Math.random().toString(36).slice(2);
      setToasts((t) => [...t, { id, icon, msg }]);
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5200);
    };
    ui.onConfirm = (spec: ConfirmSpec) => setConfirm(spec);
    ui.onNavigate = (path: string, opts?: { replace?: boolean }) => {
      if (opts && opts.replace) navigate(path, { replace: true });
      else navigate(path);
    };
    ui.onOpenPassword = (id: string, name: string) => setPwModal({ id, name });
    ui.onOpenBehavioral = (meta: BehavioralSpec) => setBehavioral(meta);
    applyTheme(theme);
    return () => {
      ui.onData = null;
      ui.onToast = null;
      ui.onConfirm = null;
      ui.onNavigate = null;
      ui.onOpenPassword = null;
      ui.onOpenBehavioral = null;
    };
  }, [bump, navigate, theme]);

  useEffect(() => {
    let cancelled = false;
    Promise.all([loadPolicy(), loadOrg()]).then((results) => {
      if (cancelled) return;
      const orgBody = results[1] as Org | undefined;
      if (orgBody && setOrg) setOrg(orgBody);
      setLastUpdate(Date.now());
      bump();
    });
    return () => {
      cancelled = true;
    };
  }, [bump, setOrg]);

  useEffect(() => {
    let stopped = false;
    let timer = 0;
    const loop = () => {
      loadFeed().finally(() => {
        if (stopped) return;
        const delay = refreshDelayMs();
        if (!delay) return;
        timer = window.setTimeout(loop, delay);
      });
    };
    loop();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [location.pathname]);

  const setTheme = useCallback((mode: ThemeMode) => {
    setThemeState(mode);
    applyTheme(mode);
  }, []);

  const value = useMemo<ConsoleValue>(
    () => ({
      user,
      setUser,
      org,
      setOrg,
      tick,
      bump,
      toasts,
      confirm,
      setConfirm,
      pwModal,
      setPwModal,
      behavioral,
      setBehavioral,
      theme,
      setTheme,
      lastUpdate,
      feed: state.feed as Email[],
      audit: state.audit as AuditEntry[],
      senderProfiles: state.senderProfiles as SenderProfile[],
      campaigns: state.campaigns as Campaign[],
      workers: state.workers as WorkersStatus | null,
    }),
    [user, setUser, org, setOrg, tick, bump, toasts, confirm, pwModal, behavioral, theme, setTheme, lastUpdate]
  );

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>;
}

export function useConsole(): ConsoleValue {
  const ctx = useContext(ConsoleContext);
  if (!ctx) throw new Error("useConsole must be used inside ConsoleProvider");
  return ctx;
}
