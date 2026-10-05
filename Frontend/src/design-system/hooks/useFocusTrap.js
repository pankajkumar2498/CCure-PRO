import { useEffect, useRef } from "react";

/**
 * Focusable elements, in the order the browser would tab through them.
 *
 * `:not([tabindex="-1"])` matters on every entry, not just the last: an element
 * explicitly removed from the tab order must stay out of it even when it is a
 * button. Without that, a trap can park focus on something the author
 * deliberately made unreachable.
 */
const FOCUSABLE = [
  "a[href]",
  "area[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "iframe",
  "audio[controls]",
  "video[controls]",
  "[contenteditable]:not([contenteditable='false'])",
  "[tabindex]",
]
  .map((s) => `${s}:not([tabindex="-1"])`)
  .join(",");

function focusableWithin(root) {
  if (!root) return [];
  return Array.from(root.querySelectorAll(FOCUSABLE)).filter((el) => {
    // offsetParent is null for display:none, but also for position:fixed —
    // which a dialog's own children can legitimately be. Checking the client
    // rects as well avoids excluding those.
    if (el.hidden) return false;
    if (el.closest("[inert]")) return false;
    return el.offsetParent !== null || el.getClientRects().length > 0;
  });
}

/**
 * Traps keyboard focus inside `ref` while `active`, and restores it afterwards.
 *
 * Three behaviours, and each exists because omitting it is a distinct WCAG
 * failure rather than a rough edge:
 *
 *   * **Focus enters the dialog on open.** Otherwise focus stays on the page
 *     behind, and a screen-reader user is told a dialog opened while their
 *     cursor is still in content the dialog has visually covered.
 *
 *   * **Tab cycles within.** Otherwise the third Tab press lands in the page
 *     behind the overlay — reachable by keyboard, invisible to the eye, and
 *     still activatable.
 *
 *   * **Focus is restored on close.** Otherwise focus resets to <body> and the
 *     next Tab starts from the top of the document, which for this application
 *     means traversing the whole sidebar to get back to where the user was.
 *
 * The trap deliberately does NOT handle Escape. Closing is the owner's
 * decision — some dialogs must not be dismissed by a stray keypress — so
 * CcureModal owns that and this hook stays a pure focus concern.
 *
 * ── Nesting (Checkpoint 3C batch 14) ────────────────────────────────────────
 * Two traps can be active at once: a confirmation raised from inside a form
 * dialog, or the change-password dialog over the account dialog. Each is a
 * separate portal, so from the outer trap's point of view the inner dialog is
 * "outside" — and two `focusin` listeners each pulling focus back into their
 * own root is an infinite loop (measured: "Maximum call stack size exceeded"
 * the moment the nested dialog mounted). Active traps therefore form a stack,
 * and only the INNERMOST one acts on Tab and focusin. When it unmounts it
 * restores focus to what it recorded — the opener inside the outer dialog —
 * and the outer trap resumes. Single-dialog behaviour is unchanged.
 */
const ACTIVE_TRAPS = [];
export const isTopTrap = (root) =>
  ACTIVE_TRAPS[ACTIVE_TRAPS.length - 1] === root;

export default function useFocusTrap(ref, active, { initialFocus } = {}) {
  // Captured in a ref rather than state: writing it must not schedule a render,
  // and it has to survive the whole open lifetime unchanged.
  const restoreRef = useRef(null);

  useEffect(() => {
    if (!active) return undefined;

    const root = ref.current;
    if (!root) return undefined;

    restoreRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    ACTIVE_TRAPS.push(root);

    // Move focus in. Preference order: caller's choice, then the first natural
    // stop, then the dialog itself — the last needing tabindex="-1" on the
    // container, which CcureModal sets.
    const target =
      (initialFocus && initialFocus.current) ||
      focusableWithin(root)[0] ||
      root;
    // rAF so the element is laid out before we focus it; focusing a node that
    // is still display:none silently does nothing.
    //
    // By the time the frame fires, focus may already be inside the dialog: a
    // child with autoFocus, or a user (or a test's userEvent.type) who clicked
    // into a field first. Moving it then is a focus steal — the first stop in
    // every CcureModal is its close button, so half a typed password would
    // land on a button. Measured under CI load: the frame fired between two
    // keystrokes, the field never filled, submit stayed disabled and the API
    // mock was never called. Only place focus if nothing inside holds it.
    const raf = requestAnimationFrame(() => {
      if (!isTopTrap(root)) return;
      const current = document.activeElement;
      if (current && current !== root && root.contains(current)) return;
      target?.focus?.();
    });

    const onKeyDown = (e) => {
      if (e.key !== "Tab" || !isTopTrap(root)) return;

      const items = focusableWithin(root);
      if (items.length === 0) {
        // Nothing to move to — keep focus on the container rather than letting
        // it escape to the page behind.
        e.preventDefault();
        root.focus?.();
        return;
      }

      const first = items[0];
      const last = items[items.length - 1];
      const current = document.activeElement;

      if (e.shiftKey && (current === first || !root.contains(current))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (current === last || !root.contains(current))) {
        e.preventDefault();
        first.focus();
      }
    };

    /**
     * Focus can also leave without Tab — a click on the page behind, or
     * programmatic focus from a component that does not know a dialog is open.
     * `focusin` bubbles, so one document-level listener catches every case and
     * pulls focus back.
     */
    const onFocusIn = (e) => {
      if (!isTopTrap(root)) return;
      if (!root.contains(e.target)) {
        e.stopPropagation();
        (focusableWithin(root)[0] || root).focus?.();
      }
    };

    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("focusin", onFocusIn, true);

    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("focusin", onFocusIn, true);
      const at = ACTIVE_TRAPS.lastIndexOf(root);
      if (at >= 0) ACTIVE_TRAPS.splice(at, 1);

      // Restore only if the element is still in the document. A dialog that
      // deleted the row its trigger lived in would otherwise focus a detached
      // node, which silently focuses <body> and loses the position anyway —
      // but throws off anything watching activeElement.
      const el = restoreRef.current;
      if (el && document.contains(el)) el.focus?.();
      restoreRef.current = null;
    };
  }, [ref, active, initialFocus]);
}
