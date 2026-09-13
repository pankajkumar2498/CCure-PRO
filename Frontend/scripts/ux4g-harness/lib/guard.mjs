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
 */

export const BLOCKED_ROUTES = [
  "^/scan/vulnerability-audit(?:/|$)",
  "^/scan/advanced-scan(?:/|$)",
  "^/scan/[^/]+/phase3(?:/|$)",
];

export function routeGuardScript() {
  return `(() => {
  if (window.__harnessGuarded) return;
  window.__harnessGuarded = true;
  const BLOCKED = ${JSON.stringify(BLOCKED_ROUTES)}.map((s) => new RegExp(s));
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
