/** Legacy API adapter. Timers, live regions and UX4G Alerts belong to the DS. */
import { useCallback } from "react";
import { CcureToastList, useCcureToasts } from "../../design-system";

export function useToasts() {
  const {
    toasts,
    push: pushToast,
    dismiss,
  } = useCcureToasts({ defaultDuration: 4000, exitDuration: 220 });
  const push = useCallback(
    (message, type = "info", duration = 4000) => {
      pushToast(message, {
        variant: type === "error" ? "danger" : type,
        duration,
      });
    },
    [pushToast],
  );
  // Keep the application's historical toast shape, including `type`.
  return {
    toasts: toasts.map((toast) => ({
      ...toast,
      type: toast.variant === "danger" ? "error" : toast.variant,
    })),
    push,
    dismiss,
  };
}

export function ToastContainer({ toasts = [], dismiss }) {
  return (
    <CcureToastList
      toasts={toasts.map((toast) => ({
        ...toast,
        variant: toast.type === "error" ? "danger" : toast.type,
      }))}
      dismiss={dismiss}
      dismissOnClick
    />
  );
}
