import { useCallback, useId, useRef, useState } from "react";

/**
 * CcureTabs / CcureTabPanel
 *
 * Controlled — React owns the selected tab, as the architecture requires. The
 * UX4G runtime's tab behaviour is not used and cannot be: its inline-script
 * delivery is blocked by `script-src 'self'`, and imperative DOM code would
 * contend with the reconciler for the same nodes.
 *
 * The application's existing tab bars (AssetDetail, ComplianceWorkspace,
 * SecurityDashboard, ProfileModal) are `<button className={active ? "active" : ""}>`
 * with a conditionally rendered panel. Measured across the whole codebase:
 * **zero `role="tab"`, zero `aria-selected`, zero `aria-controls`.** To a
 * screen reader those are unlabelled buttons that change the page for no
 * announced reason.
 *
 * What the WAI-ARIA tabs pattern requires, and this implements:
 *
 *   * `role="tablist"` / `role="tab"` / `role="tabpanel"`
 *   * `aria-selected`, and `aria-controls` ↔ `aria-labelledby` both ways
 *   * **roving tabindex** — the tab list is ONE tab stop, not one per tab.
 *     With eight tabs the naive version costs eight Tab presses to get past
 *     the bar; the pattern is Tab to enter, arrows to move.
 *   * Arrow keys (wrapping), Home and End
 *
 * `activateOnFocus` follows the ARIA guidance: automatic activation is right
 * when panels are cheap, manual (Enter/Space) when selecting a tab triggers
 * real work — which on a scan-results page it does.
 */
export default function CcureTabs({
  tabs = [],
  value,
  onChange,
  label,
  id,
  activateOnFocus = true,
  className = "",
}) {
  // `useId` is called unconditionally — hooks cannot be skipped — but `id`
  // wins when supplied. useCcureTabs passes its own id through listProps so
  // the tab list and its panels derive their ids from the SAME base. Letting
  // each generate its own is the silent-mismatch failure described above:
  // aria-controls points at an element that does not exist, and a broken
  // association is indistinguishable from a working one without a reader.
  const generatedId = useId();
  const baseId = id ?? generatedId;
  const refs = useRef({});

  const tabId = (id) => `${baseId}-tab-${id}`;
  const panelId = (id) => `${baseId}-panel-${id}`;

  const enabled = tabs.filter((t) => !t.disabled);

  const move = useCallback(
    (targetId) => {
      if (!targetId) return;
      refs.current[targetId]?.focus();
      if (activateOnFocus) onChange?.(targetId);
    },
    [activateOnFocus, onChange],
  );

  const onKeyDown = useCallback(
    (e) => {
      const idx = enabled.findIndex((t) => t.id === value);
      if (idx === -1 && !["Home", "End"].includes(e.key)) return;

      switch (e.key) {
        case "ArrowRight":
        case "ArrowDown":
          e.preventDefault();
          move(enabled[(idx + 1) % enabled.length]?.id);
          break;
        case "ArrowLeft":
        case "ArrowUp":
          e.preventDefault();
          move(enabled[(idx - 1 + enabled.length) % enabled.length]?.id);
          break;
        case "Home":
          e.preventDefault();
          move(enabled[0]?.id);
          break;
        case "End":
          e.preventDefault();
          move(enabled[enabled.length - 1]?.id);
          break;
        default:
          break;
      }
    },
    [enabled, value, move],
  );

  return (
    <div
      role="tablist"
      // Two tab bars on one page are announced identically without this.
      aria-label={label}
      className={`cc-tabs ${className}`.trim()}
      onKeyDown={onKeyDown}
    >
      {tabs.map((tab) => {
        const selected = tab.id === value;
        return (
          <button
            key={tab.id}
            ref={(el) => {
              refs.current[tab.id] = el;
            }}
            type="button"
            role="tab"
            id={tabId(tab.id)}
            aria-selected={selected}
            aria-controls={panelId(tab.id)}
            // Roving tabindex: only the selected tab is in the tab order.
            tabIndex={selected ? 0 : -1}
            disabled={tab.disabled}
            className="cc-tab"
            onClick={() => onChange?.(tab.id)}
          >
            <span>{tab.label}</span>
            {tab.count != null ? (
              <span className="cc-tab__count">{tab.count}</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

/**
 * The panel for one tab. `tabsId` must be the same `useId` base the tab list
 * used, so pass the value returned by `useCcureTabs` rather than wiring ids by
 * hand — mismatched ids break the association silently, and a broken
 * `aria-controls` looks exactly like a working one.
 */
export function CcureTabPanel({
  id,
  tabsId,
  active,
  children,
  className = "",
}) {
  if (!active) return null;
  return (
    <div
      role="tabpanel"
      id={`${tabsId}-panel-${id}`}
      aria-labelledby={`${tabsId}-tab-${id}`}
      // Focusable so that following the tab moves the reading position into
      // the panel; -1 keeps it out of the natural tab order.
      tabIndex={0}
      className={`cc-tabpanel ${className}`.trim()}
    >
      {children}
    </div>
  );
}

/**
 * Pairs a tab list with its panels without the caller managing ids.
 *
 *   const tabs = useCcureTabs("system_info");
 *   <CcureTabs {...tabs.listProps} tabs={TABS} label="Asset sections" />
 *   <CcureTabPanel {...tabs.panelProps("services")}>…</CcureTabPanel>
 */
export function useCcureTabs(initial, controlled) {
  const id = useId();
  const [internal, setInternal] = useState(initial);

  // A caller that owns the state passes `controlled`; otherwise the hook keeps
  // it. Both shapes expose the same props object, so a component does not have
  // to know which it is getting.
  const value = controlled ? controlled.value : internal;
  const onChange = controlled ? controlled.onChange : setInternal;

  return {
    id,
    value,
    onChange,
    // `id` is part of listProps precisely so a caller cannot forget it.
    listProps: { id, value, onChange },
    panelProps: (panel) => ({ id: panel, tabsId: id, active: value === panel }),
  };
}
