import { useConsole } from "../context/ConsoleContext";

export default function ToastStack() {
  const { toasts } = useConsole();
  return (
    <div className="toast-stack">
      {toasts.map((t) => (
        <div key={t.id} className="toast">
          <span dangerouslySetInnerHTML={{ __html: t.icon || "" }} />
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  );
}
