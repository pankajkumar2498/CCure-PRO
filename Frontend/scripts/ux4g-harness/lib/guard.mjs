/**
 * Routes no capture may ever reach.
 *
 * Phase 3 (the vulnerability audit) starts the port scan and the audit from an
 * effect on mount. Fixture answers refuse every write, so nothing could reach
 * a real system, but a capture that mounts that page is still a capture that
 * tried to start a scan. Batch 18 adds Phase 2 states, and Phase 2 redirects
 * to Phase 3 in automatic mode, so this makes the mount impossible instead of
 * merely detectable.
 *
 * Injected before any page script runs:
 *
 *   * a document whose own URL is a blocked route stops loading before the
 *     application's module script executes, so nothing boots
 *   * `history.pushState` and `history.replaceState` refuse a blocked URL by
 *     throwing a `DataCloneError`. React Router's browser history rethrows that
 *     error name instead of falling back to a full page load, and it throws
 *     before the router's listener runs, so the router's location never
 *     changes and the route's element is never rendered. The page that asked
 *     to navigate fails loudly instead (an exception and an error boundary).
 *
 * Every refusal is recorded in `window.__harnessBlockedNavigations`, copied
 * into the capture's log, and fails `run.mjs`.
 *
 * Batch 24: a state that captures Phase 3 itself declares `allowPhase3`, and
 * for that state alone the two Phase 3 routes load. Every other state keeps
 * the whole list, so a Phase 2 hand-off still cannot mount the page, and
 * `/scan/advanced-scan` stays blocked for every state. What a Phase 3 state may
 * then write is decided separately, by the router (router.mjs).
 */

export const BLOCKED_ROUTES = [
  "^/scan/vulnerability-audit(?:/|$)",
  "^/scan/advanced-scan(?:/|$)",
  "^/scan/[^/]+/phase3(?:/|$)",
];

export const PHASE3_ROUTES = [
  "^/scan/vulnerability-audit(?:/|$)",
  "^/scan/[^/]+/phase3(?:/|$)",
];

export function routeGuardScript({ allowPhase3 = false } = {}) {
  const routes = allowPhase3
    ? BLOCKED_ROUTES.filter((r) => !PHASE3_ROUTES.includes(r))
    : BLOCKED_ROUTES;
  return `(() => {
  if (window.__harnessGuarded) return;
  window.__harnessGuarded = true;
  const BLOCKED = ${JSON.stringify(routes)}.map((s) => new RegExp(s));
  const blocked = (window.__harnessBlockedNavigations = []);
  const pathOf = (url) => {
    try {
      return new URL(String(url), location.href).pathname;
    } catch (e) {
      return "";
    }
  };
  const isBlocked = (url) => BLOCKED.some((re) => re.test(pathOf(url)));

  if (isBlocked(location.href)) {
    blocked.push("load " + location.pathname);
    window.stop();
    return;
  }

  for (const method of ["pushState", "replaceState"]) {
    const real = history[method].bind(history);
    history[method] = function (state, title, url) {
      if (url !== undefined && url !== null && isBlocked(url)) {
        blocked.push(method + " " + pathOf(url));
        throw new DOMException(
          "harness: navigation to a Phase 3 route is blocked",
          "DataCloneError",
        );
      }
      return real(state, title, url);
    };
  }
})();`;
}
