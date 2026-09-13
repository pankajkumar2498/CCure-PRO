/**
 * What makes two captures of the same build byte-identical.
 *
 * Injected before any page script runs. Three sources of run-to-run variation
 * are removed, and each is a real one on these pages:
 *
 *   * the clock — "3d ago", certificate expiry bands and "Last updated" all read
 *     Date; the page sees a fixed instant instead
 *   * animation — skeleton shimmer, pulses and transitions are resolved to their
 *     end state so a capture never lands mid-frame
 *   * Math.random — replaced by a seeded generator
 *
 * It also records the time of the last DOM mutation, which is how the runner
 * decides a page has settled.
 */

export const FIXED_TIME = Date.parse("2026-09-12T10:00:00Z");

const FREEZE_CSS = `*,*::before,*::after{animation-duration:0s!important;animation-delay:0s!important;animation-iteration-count:1!important;transition:none!important;caret-color:transparent!important;scroll-behavior:auto!important}`;

export function freezeScript({ fixedTime = FIXED_TIME } = {}) {
  return `(() => {
  if (window.__harnessFrozen) return;
  window.__harnessFrozen = true;
  const FIXED = ${fixedTime};
  const RealDate = Date;
  function FrozenDate(...args) {
    if (!(this instanceof FrozenDate)) return new RealDate(FIXED).toString();
    return args.length ? new RealDate(...args) : new RealDate(FIXED);
  }
  FrozenDate.prototype = RealDate.prototype;
  FrozenDate.now = () => FIXED;
  FrozenDate.parse = RealDate.parse;
  FrozenDate.UTC = RealDate.UTC;
  window.Date = FrozenDate;

  let seed = 20260912;
  Math.random = () => {
    seed = (seed * 16807) % 2147483647;
    return (seed - 1) / 2147483646;
  };

  window.__harnessLastMutation = performance.now();
  const start = () => {
    const style = document.createElement("style");
    style.setAttribute("data-harness", "freeze");
    style.textContent = ${JSON.stringify(FREEZE_CSS)};
    (document.head || document.documentElement).appendChild(style);
    new MutationObserver(() => {
      window.__harnessLastMutation = performance.now();
    }).observe(document.documentElement, {
      subtree: true,
      childList: true,
      attributes: true,
      characterData: true,
    });
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();`;
}

/** Seeds sessionStorage once per origin, before the application reads it. */
export function sessionSeedScript(origin, entries) {
  if (!entries || !Object.keys(entries).length) return null;
  const sets = Object.entries(entries)
    .map(
      ([k, v]) =>
        `sessionStorage.setItem(${JSON.stringify(k)}, ${JSON.stringify(JSON.stringify(v))});`,
    )
    .join("");
  return `(() => { try { if (location.origin !== ${JSON.stringify(origin)} || sessionStorage.getItem("__harness_seeded")) return; ${sets} sessionStorage.setItem("__harness_seeded", "1"); } catch (e) {} })();`;
}
