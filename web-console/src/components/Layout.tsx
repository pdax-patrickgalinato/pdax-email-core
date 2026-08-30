import { useEffect } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { PAGE_META, findEmail, fmtDateTime, state, stripThreadSubject, threadSiblings } from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";
import Sidebar from "./Sidebar";
import Spotlight from "./Spotlight";
import ConfirmModal from "./ConfirmModal";
import PasswordModal from "./PasswordModal";
import BehavioralModal from "./BehavioralModal";
import ToastStack from "./ToastStack";
import type { Email } from "../types";

function idFromPath(pathname: string): string {
  if (pathname.indexOf("/mail/") !== 0) return "";
  try {
    return decodeURIComponent(pathname.slice("/mail/".length));
  } catch {
    return "";
  }
}

function pageMeta(pathname: string): [string, string] {
  if (pathname.indexOf("/mail/") === 0) {
    const e = findEmail(idFromPath(pathname) || state.detailId) as Email | undefined;
    const sibs = e ? (threadSiblings(e) as Email[]) : [];
    let title = (e && e.subject) || "Message";
    if (sibs.length > 1) title = stripThreadSubject(sibs[0].subject) || title;
    const sub = e
      ? sibs.length > 1
        ? sibs.length + " messages in thread · " + (e.fromName || e.fromAddr || "") + " · " + fmtDateTime(e.ts)
        : (e.fromName || e.fromAddr || "") + " · " + fmtDateTime(e.ts)
      : "Message details";
    return [title, sub];
  }
  if (pathname === "/settings/organization" || pathname.indexOf("/settings/organization/") === 0) {
    return ["Organization", "Context notes the AI uses, plus sender blocklist and allowlist"];
  }
  if (pathname === "/settings/notifications" || pathname.indexOf("/settings/notifications/") === 0) {
    return ["Notifications", "Slack analyst alerts and recipient email notices"];
  }
  if (pathname === "/settings/users" || pathname.indexOf("/settings/users/") === 0) {
    return ["Users & SSO", "Local accounts and JumpCloud single sign-on"];
  }
  if (pathname === "/profile" || pathname.indexOf("/profile/") === 0) {
    return ["Profile", "Your password, passkeys, and activity in this console"];
  }
  const key = pathname.replace(/^\//, "") || "overview";
  return (PAGE_META[key] || PAGE_META.overview) as [string, string];
}

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { tick, confirm, setConfirm, pwModal, setPwModal, behavioral, setBehavioral } = useConsole();
  const [title, sub] = pageMeta(location.pathname);
  void tick;

  useEffect(() => {
    function onKey(ev: KeyboardEvent) {
      if (ev.key !== "Escape") return;
      if (confirm) {
        setConfirm(null);
        return;
      }
      if (pwModal) {
        setPwModal(null);
        return;
      }
      if (behavioral) {
        setBehavioral(null);
        return;
      }
      if (location.pathname.indexOf("/mail/") === 0) {
        navigate("/" + (state.detailReturnPage || "overview"));
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [confirm, pwModal, behavioral, location.pathname, navigate, setConfirm, setPwModal, setBehavioral]);

  return (
    <div className="shell">
      <Sidebar />
      <div className="main">
        <Spotlight />
        <div className="topbar">
          <div className="topbar-title">
            <h1>{title}</h1>
            {sub ? <p>{sub}</p> : null}
          </div>
        </div>
        <div className="content">
          <Outlet />
        </div>
      </div>
      <ConfirmModal />
      <PasswordModal />
      <BehavioralModal />
      <ToastStack />
    </div>
  );
}
