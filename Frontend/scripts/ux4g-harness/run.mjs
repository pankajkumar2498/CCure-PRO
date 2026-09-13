#!/usr/bin/env node
/**
 * Capture every state in the catalogue against one served build.
 *
 *   node scripts/ux4g-harness/run.mjs --base http://127.0.0.1:3216 --label pre-a
 *        [--out DIR] [--states ar-,vb-cve] [--themes light] [--inject NAME]
 *
 * Writes DIR/report.json and DIR/shots/*.png. DIR defaults to
 * <tmp>/ccure-ux4g-harness/<label>. Nothing is written inside the repository.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { launchChrome, sleep } from "./lib/chrome.mjs";
import { freezeScript, sessionSeedScript } from "./lib/freeze.mjs";
import { routeGuardScript } from "./lib/guard.mjs";
import { census, focusSnapshot } from "./lib/measure.mjs";
import { route } from "./lib/router.mjs";
import { STATES } from "./lib/states.mjs";
import { INJECTIONS } from "./lib/injections.mjs";

const KEYS = {
  Tab: { key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 },
  Enter: {
    key: "Enter",
    code: "Enter",
    windowsVirtualKeyCode: 13,
    text: "\r",
    unmodifiedText: "\r",
  },
  Space: {
    key: " ",
    code: "Space",
    windowsVirtualKeyCode: 32,
    text: " ",
    unmodifiedText: " ",
  },
  Escape: { key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 },
  ArrowRight: {
    key: "ArrowRight",
    code: "ArrowRight",
    windowsVirtualKeyCode: 39,
  },
};

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) args[a.slice(2)] = true;
    else {
      args[a.slice(2)] = next;
      i += 1;
    }
  }
  return args;
}

export function selectStates(filter) {
  if (!filter) return STATES;
  const wanted = String(filter)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return STATES.filter((s) =>
    wanted.some((w) => s.id === w || s.id.startsWith(w)),
  );
}

function matchRequest(line, { method = "GET", path: p, query = {} }) {
  const m = line.match(/^(\w+) ([^?\s]+)(?:\?(\S+))? ->/);
  if (!m || m[1] !== method || m[2] !== p) return false;
  const params = new URLSearchParams(m[3] || "");
  return Object.entries(query).every(([k, v]) => params.get(k) === String(v));
}

async function captureState(cdp, { base, state, theme, injection, shotsDir }) {
  const origin = new URL(base).origin;
  const ctx = { ...state, theme };
  const log = {
    requests: [],
    refusedWrites: [],
    offOrigin: [],
    unstubbed: [],
    csp: [],
    exceptions: [],
    consoleErrors: [],
  };
  let lastNet = Date.now();

  const { browserContextId } = await cdp.send("Target.createBrowserContext", {
    disposeOnDetach: true,
  });
  const { targetId } = await cdp.send("Target.createTarget", {
    url: "about:blank",
    browserContextId,
  });
  const { sessionId } = await cdp.send("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  const S = (m, p) => cdp.send(m, p, sessionId);

  const off = cdp.on(async (m) => {
    if (m.sessionId !== sessionId) return;
    try {
      if (m.method === "Fetch.requestPaused") {
        lastNet = Date.now();
        const { requestId, request } = m.params;
        const u = new URL(request.url);
        if (u.origin !== origin) {
          log.offOrigin.push(`${request.method} ${u.origin}${u.pathname}`);
          await S("Fetch.failRequest", {
            requestId,
            errorReason: "BlockedByClient",
          });
          return;
        }
        if (!u.pathname.startsWith("/api/")) {
          await S("Fetch.continueRequest", { requestId });
          return;
        }
        const q = [...u.searchParams.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => `${k}=${v}`)
          .join("&");
        const r = route(ctx, request.method, u.pathname);
        const status = r.status || 200;
        log.requests.push(
          `${request.method} ${u.pathname}${q ? `?${q}` : ""} -> ${status}`,
        );
        if (r.kind === "refusedWrite")
          log.refusedWrites.push(`${request.method} ${u.pathname}`);
        if (r.kind === "unstubbed") log.unstubbed.push(u.pathname);
        await S("Fetch.fulfillRequest", {
          requestId,
          responseCode: status,
          responseHeaders: [
            { name: "Content-Type", value: "application/json" },
          ],
          body: Buffer.from(JSON.stringify(r.body ?? {})).toString("base64"),
        });
        return;
      }
      if (m.method === "Runtime.exceptionThrown") {
        const d = m.params.exceptionDetails;
        log.exceptions.push(
          String(d?.exception?.description || d?.text || "")
            .split("\n")[0]
            .slice(0, 160),
        );
      }
      if (
        m.method === "Runtime.consoleAPICalled" &&
        m.params.type === "error"
      ) {
        log.consoleErrors.push(
          m.params.args
            .map((a) => a.value ?? a.description ?? "")
            .join(" ")
            .split("\n")[0]
            .slice(0, 160),
        );
      }
      if (
        m.method === "Audits.issueAdded" &&
        m.params.issue.code === "ContentSecurityPolicyIssue"
      ) {
        const d = m.params.issue.details?.contentSecurityPolicyIssueDetails;
        log.csp.push(
          `${d?.violatedDirective || "csp"}:${d?.contentSecurityPolicyViolationType || ""}`,
        );
      }
    } catch {
      /* the target closed while a request was in flight */
    }
  });

  const [vw, vh] = state.viewport || [1440, 1800];
  await S("Page.enable");
  await S("Runtime.enable");
  await S("Audits.enable");
  await S("Network.enable");
  await S("Network.setBlockedURLs", { urls: ["ws://*", "wss://*"] });
  await S("Emulation.setDeviceMetricsOverride", {
    width: vw,
    height: vh,
    deviceScaleFactor: 1,
    mobile: vw < 600,
  });
  await S("Emulation.setEmulatedMedia", {
    features: [
      { name: "prefers-color-scheme", value: "light" },
      { name: "prefers-reduced-motion", value: "no-preference" },
    ],
  });
  await S("Emulation.setTimezoneOverride", { timezoneId: "UTC" }).catch(
    () => {},
  );
  await S("Emulation.setLocaleOverride", { locale: "en-US" }).catch(() => {});
  await S("Fetch.enable", {
    patterns: [{ urlPattern: "*", requestStage: "Request" }],
  });
  await S("Page.addScriptToEvaluateOnNewDocument", { source: freezeScript() });
  // Before any state script: no capture may mount a Phase 3 route (guard.mjs).
  await S("Page.addScriptToEvaluateOnNewDocument", {
    source: routeGuardScript(),
  });
  const seed = sessionSeedScript(origin, state.session);
  if (seed) await S("Page.addScriptToEvaluateOnNewDocument", { source: seed });
  // A state may prepare the document before the application boots — router
  // state, for instance, that a real navigation would have carried.
  if (state.init)
    await S("Page.addScriptToEvaluateOnNewDocument", { source: state.init });
  if (injection)
    await S("Page.addScriptToEvaluateOnNewDocument", {
      source: INJECTIONS[injection].script,
    });

  const evaluate = async (expression) => {
    const r = await S("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
    return r.result?.value;
  };
  const safeEval = async (expression) => {
    try {
      return await evaluate(expression);
    } catch {
      return undefined;
    }
  };
  const waitFor = async (expr, timeout = 20000) => {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      if (
        await safeEval(
          `(() => { try { return !!(${expr}); } catch (e) { return false; } })()`,
        )
      )
        return true;
      await sleep(200);
    }
    return false;
  };
  const settle = async (max = 10000) => {
    const end = Date.now() + max;
    await safeEval(
      "document.fonts ? document.fonts.ready.then(() => true) : true",
    );
    while (Date.now() < end) {
      const quiet = await safeEval(
        "performance.now() - (window.__harnessLastMutation || 0)",
      );
      if (quiet > 700 && Date.now() - lastNet > 700) return true;
      await sleep(150);
    }
    return false;
  };
  const press = async (name) => {
    const k = KEYS[name];
    await S("Input.dispatchKeyEvent", { type: "keyDown", ...k });
    await S("Input.dispatchKeyEvent", {
      type: "keyUp",
      key: k.key,
      code: k.code,
      windowsVirtualKeyCode: k.windowsVirtualKeyCode,
    });
  };
  const blur = () =>
    safeEval(
      "(() => { const a = document.activeElement; if (a && a.blur) a.blur(); window.scrollTo(0, 0); return true; })()",
    );
  const focused = () => safeEval(`(${focusSnapshot.toString()})()`);

  await S("Page.navigate", { url: base + state.route });
  const ready = await waitFor(state.ready, state.readyTimeout || 20000);
  await settle();

  const actions = [];
  for (const a of state.actions || []) {
    if (a.click) {
      const ok = await safeEval(
        `(() => { const el = ${a.click}; if (!el) return false; el.scrollIntoView({ block: "center" }); el.click(); return true; })()`,
      );
      actions.push(`click:${Boolean(ok)}`);
    }
    if (a.waitFor)
      actions.push(`waitFor:${await waitFor(a.waitFor, a.timeout || 10000)}`);
    await settle();
  }

  await safeEval("(() => { window.scrollTo(0, 0); return true; })()");
  await settle(3000);
  const measured = await evaluate(
    `(${census.toString()})(${JSON.stringify({ tracked: state.tracked || [] })})`,
  );
  const shot = await S("Page.captureScreenshot", { format: "png" });
  const png = Buffer.from(shot.data, "base64");
  const screenshot = createHash("sha256").update(png).digest("hex");
  const screenshotFile = shotsDir
    ? path.join(shotsDir, `${state.id}.${theme}.png`)
    : null;
  if (screenshotFile) writeFileSync(screenshotFile, png);

  /* Tab order, from the top of the document, until focus wraps. */
  const tabOrder = [];
  await blur();
  for (let i = 0; i < (state.tabLimit || 160); i += 1) {
    await press("Tab");
    const f = await focused();
    const key = f ? `${f.tag}${f.role ? `[${f.role}]` : ""}:${f.name}` : "body";
    if (i > 0 && key === tabOrder[0]) break;
    tabOrder.push(key);
  }

  const probes = {};
  for (const p of state.probes || []) {
    const fromRequest = log.requests.length;
    await blur();
    await settle(2000);
    let reached = false;
    let focus = null;
    for (let i = 0; i < (p.limit || 220); i += 1) {
      await press("Tab");
      const hit = await safeEval(
        `(() => { const el = document.activeElement; if (!el || el === document.body) return false; try { return !!(${p.tabTo}); } catch (e) { return false; } })()`,
      );
      if (hit) {
        reached = true;
        focus = await focused();
        break;
      }
    }
    const result = { reached, focus };
    if (reached && p.press) {
      await press(p.press);
      await sleep(p.wait || 400);
      await settle(4000);
      if (p.expect)
        result.expect = await waitFor(p.expect, p.expectTimeout || 3000);
      if (p.expectRequest)
        result.request = log.requests
          .slice(fromRequest)
          .some((r) => matchRequest(r, p.expectRequest));
      for (const step of p.then || []) {
        if (step.press) await press(step.press);
        await sleep(step.wait || 300);
        await settle(3000);
        result.then = result.then || [];
        result.then.push({
          expect: step.expect ? await waitFor(step.expect, 2000) : null,
          focus: await focused(),
        });
      }
    }
    probes[p.id] = result;
  }

  const blockedNavigations =
    (await safeEval("(window.__harnessBlockedNavigations || []).slice()")) ||
    [];

  off();
  await cdp.send("Target.closeTarget", { targetId }).catch(() => {});
  await cdp
    .send("Target.disposeBrowserContext", { browserContextId })
    .catch(() => {});

  const sorted = (xs) => [...xs].sort();
  return {
    ready,
    actions,
    ...measured,
    screenshot,
    screenshotFile,
    tabOrder,
    probes,
    repeatable: state.repeatable || [],
    log: {
      requests: sorted(log.requests),
      refusedWrites: sorted(log.refusedWrites),
      offOrigin: sorted(log.offOrigin),
      unstubbed: sorted(new Set(log.unstubbed)),
      csp: sorted(log.csp),
      exceptions: sorted(log.exceptions),
      consoleErrors: sorted(log.consoleErrors),
      blockedNavigations: sorted(blockedNavigations),
    },
  };
}

export async function runCapture({
  base,
  label,
  out,
  states,
  themes,
  injection,
  screenshots = true,
  quiet = false,
}) {
  if (injection && !INJECTIONS[injection])
    throw new Error(`Unknown injection: ${injection}`);
  const dir = path.resolve(
    out || path.join(os.tmpdir(), "ccure-ux4g-harness", label),
  );
  const shotsDir = screenshots ? path.join(dir, "shots") : null;
  mkdirSync(shotsDir || dir, { recursive: true });

  const chrome = await launchChrome();
  const results = {};
  try {
    for (const state of states) {
      for (const theme of state.themes) {
        if (themes && !themes.includes(theme)) continue;
        const r = await captureState(chrome.cdp, {
          base,
          state,
          theme,
          injection,
          shotsDir,
        });
        results[`${state.id}.${theme}`] = r;
        if (!quiet) {
          const l = r.log;
          console.log(
            `${state.id}.${theme}: ready=${r.ready} actions=[${r.actions.join(",")}] requests=${l.requests.length} unstubbed=${l.unstubbed.length} writes=${l.refusedWrites.length} offOrigin=${l.offOrigin.length} csp=${l.csp.length} exceptions=${l.exceptions.length} blocked=${l.blockedNavigations.length} contrastFails=${r.contrast.fails.length} db=${r.classes.dbElements}`,
          );
        }
      }
    }
  } finally {
    await chrome.close();
  }

  const report = { label, base, injection: injection || null, states: results };
  writeFileSync(path.join(dir, "report.json"), JSON.stringify(report, null, 1));
  return { dir, report };
}

// `process.argv[1]` is absent when the module is imported from `node -e`.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const args = parseArgs(process.argv.slice(2));
  if (!args.base || !args.label) {
    console.error(
      "usage: run.mjs --base URL --label NAME [--out DIR] [--states a,b] [--themes light,dark] [--inject NAME]",
    );
    process.exit(2);
  }
  const { dir, report } = await runCapture({
    base: args.base.replace(/\/$/, ""),
    label: args.label,
    out: args.out,
    states: selectStates(args.states),
    themes: args.themes ? String(args.themes).split(",") : null,
    injection: args.inject || null,
  });
  console.log(`report: ${path.join(dir, "report.json")}`);
  const blocked = Object.entries(report.states).filter(
    ([, s]) => s.log.blockedNavigations.length,
  );
  if (blocked.length) {
    for (const [key, s] of blocked)
      console.error(
        `BLOCKED NAVIGATION in ${key}: ${s.log.blockedNavigations.join(", ")}`,
      );
    process.exit(1);
  }
}
