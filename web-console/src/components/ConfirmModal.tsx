import { executePendingAction } from "../lib/dashboard";
import { useConsole } from "../context/ConsoleContext";

export default function ConfirmModal() {
  const { confirm, setConfirm } = useConsole();
  if (!confirm) return null;

  function cancel() {
    setConfirm(null);
  }

  function ok() {
    if (!confirm) return;
    executePendingAction(confirm.kind, confirm.id).finally(() => setConfirm(null));
  }

  return (
    <div
      className="modal-overlay show"
      onClick={(ev) => {
        if (ev.target === ev.currentTarget) cancel();
      }}
    >
      <div className="modal">
        <h3>{confirm.title}</h3>
        <p>{confirm.body}</p>
        <div className="modal-detail mono">{confirm.detail}</div>
        <div className="modal-actions">
          <button className="btn btn-sm" type="button" onClick={cancel}>
            Cancel
          </button>
          <button className="btn btn-sm btn-primary" type="button" onClick={ok}>
            {confirm.confirmLabel || "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}
