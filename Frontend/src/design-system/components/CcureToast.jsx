import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import CcureAlert from "./CcureAlert";
const ToastContext = createContext(null);
let sequence = 0;

/** One timer owner for providers and the application's legacy toast adapter. */
export function useCcureToasts({
  defaultDuration = 5000,
  exitDuration = 0,
} = {}) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef(new Map());
  const cancel = useCallback((id) => {
    for (const timer of timers.current.get(id) ?? []) clearTimeout(timer);
    timers.current.delete(id);
  }, []);
  const dismiss = useCallback(
    (id) => {
      cancel(id);
      if (exitDuration > 0) {
        setToasts((list) =>
          list.map((t) => (t.id === id ? { ...t, exiting: true } : t)),
        );
        timers.current.set(id, [
          setTimeout(() => {
            setToasts((list) => list.filter((t) => t.id !== id));
            timers.current.delete(id);
          }, exitDuration),
        ]);
      } else setToasts((list) => list.filter((t) => t.id !== id));
    },
    [cancel, exitDuration],
  );
  const push = useCallback(
    (message, { variant = "info", duration = defaultDuration, title } = {}) => {
      const id = ++sequence;
      setToasts((list) => [...list, { id, message, variant, title }]);
      if (duration > 0)
        timers.current.set(id, [setTimeout(() => dismiss(id), duration)]);
      return id;
    },
    [defaultDuration, dismiss],
  );
  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const handles of pending.values()) handles.forEach(clearTimeout);
      pending.clear();
    };
  }, []);
  return { toasts, push, dismiss };
}

/** UX4G Alert composition: the approved package has no standalone Toast. */
export function CcureToastList({
  toasts = [],
  dismiss,
  dismissOnClick = false,
  className = "",
}) {
  const urgent = toasts.filter((t) =>
    ["danger", "warning"].includes(t.variant),
  );
  const calm = toasts.filter((t) => !["danger", "warning"].includes(t.variant));
  const renderToast = (toast) => (
    <CcureAlert
      key={toast.id}
      live={false}
      variant={toast.variant}
      title={toast.title}
      className={`cc-toast cc-toast--${toast.variant} ${toast.exiting ? "cc-toast--exit" : ""}`}
      onDismiss={() => dismiss(toast.id)}
      dismissLabel="Dismiss notification"
      onClick={
        dismissOnClick
          ? (event) => {
              if (!event.target.closest("button")) dismiss(toast.id);
            }
          : undefined
      }
    >
      {toast.message}
    </CcureAlert>
  );
  return (
    <div className={`cc-toaster-stack ${className}`}>
      <div
        role="region"
        aria-label="Notifications"
        aria-live="assertive"
        aria-atomic="false"
        data-toast-region="assertive"
      >
        {urgent.map(renderToast)}
      </div>
      <div aria-live="polite" aria-atomic="false" data-toast-region="polite">
        {calm.map(renderToast)}
      </div>
    </div>
  );
}
export function CcureToastProvider({ children }) {
  const { toasts, push, dismiss } = useCcureToasts();
  const api = useMemo(
    () => ({
      push,
      dismiss,
      info: (message, options) =>
        push(message, { ...options, variant: "info" }),
      success: (message, options) =>
        push(message, { ...options, variant: "success" }),
      warning: (message, options) =>
        push(message, { ...options, variant: "warning" }),
      danger: (message, options) =>
        push(message, { ...options, variant: "danger" }),
    }),
    [push, dismiss],
  );
  return (
    <ToastContext.Provider value={api}>
      {children}
      {createPortal(
        <CcureToastList toasts={toasts} dismiss={dismiss} />,
        document.body,
      )}
    </ToastContext.Provider>
  );
}
export function useCcureToast() {
  const context = useContext(ToastContext);
  if (!context)
    throw new Error("useCcureToast must be used within a CcureToastProvider");
  return context;
}
export default CcureToastProvider;
