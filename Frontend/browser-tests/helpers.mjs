import { expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { route } from "../scripts/ux4g-harness/lib/router.mjs";
import {
  freezeScript,
  sessionSeedScript,
} from "../scripts/ux4g-harness/lib/freeze.mjs";
import { routeGuardScript } from "../scripts/ux4g-harness/lib/guard.mjs";
import { census } from "../scripts/ux4g-harness/lib/measure.mjs";

export async function openState(
  page,
  state,
  { width = 1440, theme = "light" } = {},
) {
  const log = {
    unexpectedRequests: [],
    pageErrors: [],
    consoleErrors: [],
    csp: [],
    requests: [],
  };
  const origin = "http://127.0.0.1:3277";
  await page.setViewportSize({ width, height: 1000 });
  page.on("pageerror", (error) => log.pageErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") log.consoleErrors.push(message.text());
    if (/Blocked aria-hidden/i.test(message.text()))
      log.pageErrors.push(message.text());
  });
  page.on("dialog", async (dialog) => {
    log.pageErrors.push(`Native ${dialog.type()} dialog`);
    await dialog.dismiss();
  });
  await page.context().routeWebSocket("**", (socket) => {
    log.unexpectedRequests.push(`WebSocket ${socket.url()}`);
    socket.close();
  });
  await page.context().route("**/*", async (request) => {
    const url = new URL(request.request().url());
    if (url.origin !== origin) {
      log.unexpectedRequests.push(url.href);
      await request.abort();
      return;
    }
    if (!url.pathname.startsWith("/api/")) {
      await request.continue();
      return;
    }
    const method = request.request().method();
    const answer = route({ ...state, theme }, method, url.pathname);
    log.requests.push({
      method,
      path: url.pathname,
      query: url.search,
      body: request.request().postData(),
    });
    if (["refusedWrite", "unstubbed"].includes(answer.kind))
      log.unexpectedRequests.push(`${method} ${url.pathname}: ${answer.kind}`);
    if (
      state.pendingRequests?.includes(
        `${method} ${url.pathname.replace(/^\/api/, "")}`,
      )
    )
      return;
    if (answer.pending) return; // Never forwarded; the request remains pending until teardown.
    await request.fulfill({
      status: answer.status || 200,
      contentType: answer.contentType || "application/json",
      body: answer.raw ?? JSON.stringify(answer.body ?? {}),
    });
  });
  await page.addInitScript({ content: freezeScript() });
  await page.addInitScript({
    content: routeGuardScript({ allowPhase3: state.allowPhase3 === true }),
  });
  const seed = sessionSeedScript(origin, state.session);
  if (seed) await page.addInitScript({ content: seed });
  if (state.init) await page.addInitScript({ content: state.init });
  await page.addInitScript(() => {
    window.__browserCsp = [];
    document.addEventListener("securitypolicyviolation", (event) =>
      window.__browserCsp.push(
        `${event.violatedDirective}:${event.blockedURI}`,
      ),
    );
  });
  const response = await page.goto(state.route);
  expect(response.headers()["content-security-policy"]).toContain(
    "script-src 'self'",
  );
  // A state's readyTimeout, as scripts/ux4g-harness/run.mjs reads it, but never
  // below playwright.config.mjs's 10 s expect timeout: a state declares it for
  // the harness's Chromium, and WebKit on a hosted runner is slower.
  await expect
    .poll(
      () =>
        page.evaluate(
          (expression) => Boolean((0, eval)(expression)),
          state.ready,
        ),
      { timeout: Math.max(state.readyTimeout ?? 0, 10_000) },
    )
    .toBe(true);
  for (const action of state.actions || []) {
    if (action.click)
      await page.evaluate((expression) => {
        const el = (0, eval)(expression);
        if (!el) throw new Error(`Missing action target: ${expression}`);
        el.focus();
        el.click();
      }, action.click);
    if (action.waitFor)
      await expect
        .poll(() =>
          page.evaluate(
            (expression) => Boolean((0, eval)(expression)),
            action.waitFor,
          ),
        )
        .toBe(true);
  }
  await page.evaluate(() => document.fonts.ready);
  return log;
}

export async function assertPage(page, log, { accessibility = true } = {}) {
  const result = await page.evaluate(census);
  expect(result.errorBoundary, "Unexpected error boundary").toBe(false);
  expect(result.overflowElements, "Page-level horizontal overflow").toEqual([]);
  expect(result.overflowX, "Page-level horizontal overflow").toBe(false);
  expect(log.unexpectedRequests, "Undeclared or external API requests").toEqual(
    [],
  );
  expect(log.pageErrors, "Browser exceptions or native dialogs").toEqual([]);
  // Expected synthetic HTTP failures are checked by state readiness/error UI.
  expect(
    log.consoleErrors.filter((line) => !/^Failed to load resource:/.test(line)),
    "Application console errors",
  ).toEqual([]);
  expect(
    await page.evaluate(() => window.__browserCsp),
    "CSP violations",
  ).toEqual([]);
  if (accessibility) {
    const axe = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(
      axe.violations.map((v) => ({
        id: v.id,
        nodes: v.nodes.map((n) => ({
          target: n.target,
          summary: n.failureSummary,
        })),
      })),
      "WCAG A/AA automated checks",
    ).toEqual([]);
  }
  return result;
}
