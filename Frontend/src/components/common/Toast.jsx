/**
 * src/components/common/Toast.jsx
 *
 * Legacy toaster, kept for its twelve consumers. `useToasts()` returns
 * `{ toasts, push, dismiss }` and `ToastContainer` renders them — same API,
 * same 4 s default duration, same 220 ms exit animation, same click-to-dismiss.
 *
 * Checkpoint 3C batch 12 — the minimal accessibility shim: the container is
 * always mounted and carries two live regions, assertive for errors and
 * polite for everything else, so a toast is announced when it appears. A
 * live region that is created at the same moment as its content is not
 * reliably announced, which is why the regions exist before any toast does
 * (the same structure CcureToastProvider uses). Each toast also gets a named
 * dismiss button, so keyboard users can dismiss what mouse users could.
 */
import { useCallback, useState } from "react";

let toastCounter = 0;

export function useToasts() {
  const [toasts, setToasts] = useState([]);

  const push = useCallback((message, type = "info", duration = 4000) => {
    const id = ++toastCounter;
    setToasts((prev) => [...prev, { id, message, type }]);

    setTimeout(() => {
      setToasts((prev) =>
        prev.map((toast) =>
          toast.id === id ? { ...toast, exiting: true } : toast,
        ),
      );
      setTimeout(
        () => setToasts((prev) => prev.filter((toast) => toast.id !== id)),
        220,
      );
    }, duration);
  }, []);

  const dismiss = useCallback((id) => {
    setToasts((prev) =>
      prev.map((toast) =>
        toast.id === id ? { ...toast, exiting: true } : toast,
      ),
    );
    setTimeout(
      () => setToasts((prev) => prev.filter((toast) => toast.id !== id)),
      220,
    );
  }, []);

  return { toasts, push, dismiss };
}

const TOAST_ICONS = {
  success: "✓",
  error: "✕",
  info: "ℹ",
};

function ToastItem({ toast, dismiss }) {
  return (
    <div
      className={`toast toast--${toast.type}${toast.exiting ? " toast--exit" : ""}`}
      onClick={() => dismiss(toast.id)}
    >
      <span className="toast-icon" aria-hidden="true">
        {TOAST_ICONS[toast.type]}
      </span>
      <span className="toast-msg">{toast.message}</span>
      <button
        type="button"
        className="toast-dismiss"
        aria-label="Dismiss notification"
        onClick={(e) => {
          e.stopPropagation();
          dismiss(toast.id);
        }}
      >
        <span aria-hidden="true">×</span>
      </button>
    </div>
  );
}

export function ToastContainer({ toasts = [], dismiss }) {
  const urgent = toasts.filter((t) => t.type === "error");
  const calm = toasts.filter((t) => t.type !== "error");
  return (
    <div className="toast-container">
      {/* aria-live without a role: announced the same, but invisible to a
          page's own role="alert"/"status" queries and censuses, which the
          migrated pages use for THEIR messages. */}
      <div
        aria-live="assertive"
        aria-atomic="false"
        data-toast-region="assertive"
      >
        {urgent.map((toast) => (
          <ToastItem key={toast.id} toast={toast} dismiss={dismiss} />
        ))}
      </div>
      <div aria-live="polite" aria-atomic="false" data-toast-region="polite">
        {calm.map((toast) => (
          <ToastItem key={toast.id} toast={toast} dismiss={dismiss} />
        ))}
      </div>
    </div>
  );
}
