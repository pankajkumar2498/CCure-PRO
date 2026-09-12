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

/**
 * CcureToast
 *
 * Transient, out-of-flow notification.
 *
 * ── The one thing that makes this accessible ────────────────────────────────
 * The live region is mounted for the entire session, empty, and toasts are
 * inserted INTO it. It is not created when the first toast appears.
 *
 * Assistive technology subscribes to a live region when it enters the
 * accessibility tree and announces subsequent *mutations*. A region that
 * arrives already containing its message has no mutation to report, so the
 * message is frequently never announced at all — which is the default outcome
 * of the obvious implementation, and is silent in exactly the way that makes it
 * survive review. `components/common/Toast.jsx` returns `null` when the list is
 * empty and has no `aria-live` at all.
 *
 * ── Politeness ──────────────────────────────────────────────────────────────
 * Two regions, not one. `assertive` interrupts the screen reader mid-sentence
 * and is right for a failure the user must not miss; `polite` waits for a
 * pause. A single region has to pick one, and either choice is wrong half the
 * time. Because the level is fixed per region, the toast must be routed to the
 * region matching its severity — it cannot be changed after the fact.
 */

const ToastContext = createContext(null);

const ICONS = { info: "ℹ", success: "✓", warning: "⚠", danger: "✕" };
const DEFAULT_DURATION = 5000;

let seq = 0;

export function CcureToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  // Timers are cleared on unmount; leaving them would fire setState on an
  // unmounted provider during a route change.
  const timers = useRef(new Map());

  const dismiss = useCallback((id) => {
    setToasts((list) => list.filter((t) => t.id !== id));
    const handle = timers.current.get(id);
    if (handle) {
      clearTimeout(handle);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback(
    (
      message,
      { variant = "info", duration = DEFAULT_DURATION, title } = {},
    ) => {
      const id = ++seq;
      setToasts((list) => [...list, { id, message, variant, title }]);
      /* duration <= 0 means "stay until dismissed". A danger toast carrying a
         message the user must act on should not evaporate while they read it;
         the caller decides, but the escape hatch has to exist. */
      if (duration > 0) {
        timers.current.set(
          id,
          setTimeout(() => dismiss(id), duration),
        );
      }
      return id;
    },
    [dismiss],
  );

  useEffect(() => {
    const pending = timers.current;
    return () => {
      pending.forEach(clearTimeout);
      pending.clear();
    };
  }, []);

  const api = useMemo(
    () => ({
      push,
      dismiss,
      info: (m, o) => push(m, { ...o, variant: "info" }),
      success: (m, o) => push(m, { ...o, variant: "success" }),
      warning: (m, o) => push(m, { ...o, variant: "warning" }),
      danger: (m, o) => push(m, { ...o, variant: "danger" }),
    }),
    [push, dismiss],
  );

  const assertive = toasts.filter(
    (t) => t.variant === "danger" || t.variant === "warning",
  );
  const polite = toasts.filter(
    (t) => t.variant !== "danger" && t.variant !== "warning",
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      {createPortal(
        <>
          {/* Both regions are always rendered, always empty-capable, and never
              conditionally mounted. That is the requirement described above. */}
          <div
            className="cc-toaster"
            role="region"
            aria-label="Notifications"
            aria-live="assertive"
            aria-atomic="false"
          >
            {assertive.map((t) => (
              <Toast key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
            ))}
          </div>
          <div
            className="cc-toaster"
            aria-live="polite"
            aria-atomic="false"
            /* Visually stacked beneath the assertive region. Both are fixed to
               the same corner; the offset keeps them from overlapping when
               both hold messages. */
            style={{ marginTop: assertive.length ? "0.5rem" : 0 }}
          >
            {polite.map((t) => (
              <Toast key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
            ))}
          </div>
        </>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}

function Toast({ toast, onDismiss }) {
  return (
    <div className={`cc-toast cc-toast--${toast.variant}`}>
      <span className="cc-alert__icon" aria-hidden="true">
        {ICONS[toast.variant] ?? ICONS.info}
      </span>
      <div className="cc-toast__body">
        {toast.title ? (
          <div className="cc-alert__title">{toast.title}</div>
        ) : null}
        <div>{toast.message}</div>
      </div>
      {/* A real button, not an onClick on the container. The old implementation
          dismissed on clicking anywhere in the toast, which is unreachable by
          keyboard and makes selecting the message text dismiss it. */}
      <button
        type="button"
        className="cc-toast__dismiss"
        onClick={onDismiss}
        aria-label="Dismiss notification"
      >
        <span aria-hidden="true">×</span>
      </button>
    </div>
  );
}

export function useCcureToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useCcureToast must be used within a CcureToastProvider");
  }
  return ctx;
}

export default CcureToastProvider;
