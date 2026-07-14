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

export function ToastContainer({ toasts, dismiss }) {
  if (!toasts.length) return null;

  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`toast toast--${toast.type}${toast.exiting ? " toast--exit" : ""}`}
          onClick={() => dismiss(toast.id)}
        >
          <span className="toast-icon">{TOAST_ICONS[toast.type]}</span>
          <span className="toast-msg">{toast.message}</span>
        </div>
      ))}
    </div>
  );
}
