import { useEffect, useState } from "react";
import { ICON, loadFeed, ui } from "../lib/dashboard";
import { api } from "../lib/api";
import { errorMessage } from "../lib/errors";
import { PASSWORD_CHECKS, passwordMeetsPolicy } from "../lib/password";
import { useConsole } from "../context/ConsoleContext";

export default function PasswordModal() {
  const { pwModal, setPwModal } = useConsole();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setPw("");
    setConfirm("");
    setError("");
    setBusy(false);
  }, [pwModal]);

  if (!pwModal) return null;

  const allPass = passwordMeetsPolicy(pw);
  const match = Boolean(pw && confirm === pw);
  const canSubmit = allPass && match && !busy;

  function close() {
    setPwModal(null);
  }

  async function submit() {
    if (!canSubmit || !pwModal) return;
    setBusy(true);
    setError("");
    try {
      await api("/api/users/" + encodeURIComponent(pwModal.id) + "/password", {
        method: "POST",
        body: JSON.stringify({ password: pw }),
      });
      close();
      if (ui.onToast) ui.onToast(ICON.good, "Password updated for " + pwModal.name);
      loadFeed();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <div
      className="modal-overlay show"
      onClick={(ev) => {
        if (ev.target === ev.currentTarget) close();
      }}
    >
      <div className="modal" style={{ width: "min(420px,100%)" }}>
        <h3>
          Set password — <span style={{ color: "var(--accent)" }}>{pwModal.name}</span>
        </h3>
        <div className="pw-modal-fields">
          <label>
            New password
            <input
              type="password"
              autoComplete="new-password"
              placeholder="Enter new password"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
            />
          </label>
          <label>
            Confirm password
            <input
              type="password"
              autoComplete="new-password"
              placeholder="Repeat new password"
              value={confirm}
              onChange={(e) => {
                setConfirm(e.target.value);
                if (e.target.value && e.target.value !== pw) setError("Passwords do not match.");
                else setError("");
              }}
            />
          </label>
        </div>
        <ul id="pwChecklist">
          {PASSWORD_CHECKS.map((c) => (
            <li key={c.id} className={"pwck-item" + (c.test(pw) ? " pass" : "")}>
              {c.label}
            </li>
          ))}
        </ul>
        {error ? (
          <div className="users-error show" style={{ marginTop: "8px" }}>
            {error}
          </div>
        ) : null}
        <div className="modal-actions" style={{ marginTop: "16px" }}>
          <button className="btn btn-sm" type="button" onClick={close}>
            Cancel
          </button>
          <button className="btn btn-sm btn-primary" type="button" disabled={!canSubmit} onClick={submit}>
            {busy ? "Saving…" : "Set password"}
          </button>
        </div>
      </div>
    </div>
  );
}
