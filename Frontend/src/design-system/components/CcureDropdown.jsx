import { forwardRef, useCallback, useLayoutEffect, useId, useRef } from "react";

const itemsIn = (root) =>
  Array.from(root?.querySelectorAll('[role="menuitem"]') ?? []).filter(
    (el) => !el.disabled && el.getAttribute("aria-disabled") !== "true",
  );

/** Controlled official dropdown styling with React-owned APG menu behavior. */
export default function CcureDropdown({
  open,
  onOpenChange,
  label,
  id: providedId,
  trigger,
  children,
  className = "",
  menuClassName = "",
  align = "start",
}) {
  const generatedId = useId();
  const id = providedId || generatedId;
  const anchor = useRef(null);
  const button = useRef(null);
  const menu = useRef(null);
  const lastOnOpenChange = useRef(onOpenChange);
  lastOnOpenChange.current = onOpenChange;
  const focusLast = useRef(false);
  const close = useCallback((restore = false) => {
    if (restore) button.current?.focus();
    lastOnOpenChange.current(false);
  }, []);
  useLayoutEffect(() => {
    if (!open) return undefined;
    const items = itemsIn(menu.current);
    (focusLast.current ? items.at(-1) : items[0])?.focus();
    focusLast.current = false;
    const outside = (event) => {
      if (!anchor.current?.contains(event.target)) close();
    };
    const focusOutside = (event) => {
      if (!anchor.current?.contains(event.target)) close();
    };
    document.addEventListener("mousedown", outside);
    document.addEventListener("focusin", focusOutside);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("focusin", focusOutside);
    };
  }, [open, close]);
  function menuKey(event) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close(true);
      return;
    }
    const items = itemsIn(menu.current);
    const index = items.indexOf(document.activeElement);
    let next;
    if (event.key === "ArrowDown") next = items[(index + 1) % items.length];
    if (event.key === "ArrowUp")
      next = items[(index - 1 + items.length) % items.length];
    if (event.key === "Home") next = items[0];
    if (event.key === "End") next = items.at(-1);
    if (
      event.key.length === 1 &&
      !event.ctrlKey &&
      !event.altKey &&
      event.key !== " "
    ) {
      next = [...items.slice(index + 1), ...items.slice(0, index + 1)].find(
        (el) =>
          el.textContent
            .trim()
            .toLowerCase()
            .startsWith(event.key.toLowerCase()),
      );
    }
    if (next) {
      event.preventDefault();
      next.focus();
    }
    // Tab keeps its native default. The focusin listener closes when focus leaves.
  }
  return (
    <div
      ref={anchor}
      className={`cc-dropdown cc-ux4g cc-dropdown--${align} ux4g-dropdown ux4g-dropdown-button ux4g-dropdown-m ${open ? "is-open" : ""} ${className}`}
    >
      {trigger({
        ref: button,
        buttonProps: {
          "aria-haspopup": "menu",
          "aria-expanded": open,
          "aria-controls": open ? id : undefined,
          onClick: () => onOpenChange(!open),
          onKeyDown: (event) => {
            if (["ArrowDown", "ArrowUp"].includes(event.key)) {
              event.preventDefault();
              focusLast.current = event.key === "ArrowUp";
              if (open) {
                const items = itemsIn(menu.current);
                (focusLast.current ? items.at(-1) : items[0])?.focus();
              } else onOpenChange(true);
            }
            if (event.key === "Escape" && open) {
              event.preventDefault();
              close(true);
            }
          },
        },
      })}
      {open ? (
        <div
          ref={menu}
          id={id}
          role="menu"
          aria-label={label}
          className={`cc-dropdown__menu ux4g-dropdown-menu ${menuClassName}`}
          onKeyDown={menuKey}
          onClickCapture={(event) => {
            const item = event.target.closest('[role="menuitem"]');
            if (
              item &&
              !item.disabled &&
              item.getAttribute("aria-disabled") !== "true"
            )
              close(true);
          }}
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}

export const CcureMenuItem = forwardRef(function CcureMenuItem(
  { className = "", children, ...props },
  ref,
) {
  return (
    <button
      {...props}
      ref={ref}
      type="button"
      role="menuitem"
      tabIndex={-1}
      className={`cc-menuitem ux4g-dropdown-single-option ${className}`}
    >
      {children}
    </button>
  );
});
