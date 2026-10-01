import { useEffect } from "react";

/* Closes on a pointer-down outside `ref` (the legacy behaviour) AND on Escape,
   restoring focus to `restoreTo` when Escape or an outside click closed it. */
export default function useDismiss(ref, open, onClose, restoreTo) {
  useEffect(() => {
    if (!open) return undefined;
    const onMouseDown = (event) => {
      if (ref.current && !ref.current.contains(event.target)) {
        if (restoreTo?.current && restoreTo.current.contains(event.target))
          return;
        onClose();
      }
    };
    const onKey = (event) => {
      if (event.key === "Escape") {
        onClose();
        restoreTo?.current?.focus?.();
      }
    };
    document.addEventListener("mousedown", onMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [ref, open, onClose, restoreTo]);
}
