/**
 * Deliberate regressions for the sensitivity gate.
 *
 * Each is injected into a capture of an unchanged build and must be detected in
 * the category listed under `expect`. A harness that reports "identical" for a
 * page someone has broken is worse than no harness, so this is what proves it
 * would not.
 */

const css = (rules) => `(() => {
  const add = () => {
    const s = document.createElement("style");
    s.setAttribute("data-harness", "inject");
    s.textContent = ${JSON.stringify(rules)};
    (document.head || document.documentElement).appendChild(s);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", add, { once: true });
  else add();
})();`;

// Re-applied on every mutation, so React re-renders cannot undo it. Each body
// checks before writing: an unconditional attribute write is itself a mutation
// and would loop.
const observe = (body) => `(() => {
  const apply = () => { ${body} };
  const start = () => {
    apply();
    new MutationObserver(apply).observe(document.documentElement, { subtree: true, childList: true, attributes: true });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();`;

const once = (body) => `(() => {
  const run = () => setTimeout(() => { ${body} }, 400);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run, { once: true });
  else run();
})();`;

export const INJECTIONS = {
  "header-colour": {
    expect: ["styles", "screenshot"],
    script: css("table th, table th *{color:rgb(255,0,255)!important}"),
  },
  "strip-aria-states": {
    expect: ["ariaStates"],
    script: observe(
      "for (const el of document.querySelectorAll('[aria-pressed],[aria-selected],[aria-sort]')) { el.removeAttribute('aria-pressed'); el.removeAttribute('aria-selected'); el.removeAttribute('aria-sort'); }",
    ),
  },
  "strip-accessible-names": {
    expect: ["names"],
    script: observe(
      "for (const el of document.querySelectorAll('input[aria-label],select[aria-label],button[aria-label]')) el.removeAttribute('aria-label');",
    ),
  },
  "remove-focus-ring": {
    expect: ["probes"],
    script: css(
      "*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}",
    ),
  },
  "untabbable-controls": {
    expect: ["tabOrder", "probes"],
    script: observe(
      "for (const el of document.querySelectorAll('[role=tab],button')) if (el.getAttribute('tabindex') !== '-1') el.setAttribute('tabindex', '-1');",
    ),
  },
  "legacy-class": {
    expect: ["classes"],
    script: observe(
      "for (const el of document.querySelectorAll('h1')) if (!el.classList.contains('db-btn')) el.classList.add('db-btn');",
    ),
  },
  "write-attempt": {
    expect: ["writes"],
    script: once(
      "fetch('/api/assets/a-1', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: '{}' }).catch(() => {});",
    ),
  },
  "inline-script": {
    expect: ["csp"],
    script: once(
      "const s = document.createElement('script'); s.textContent = 'window.__harnessInline = 1'; document.body.appendChild(s);",
    ),
  },
  // The CSP (`img-src 'self'`) refuses this before any request exists, so it
  // is detected as a CSP violation. The off-origin request log is the second
  // line: it records anything that gets as far as the network.
  "off-origin-image": {
    expect: ["csp"],
    script: once(
      "const i = new Image(); i.alt = ''; i.src = 'https://example.invalid/harness.png'; document.body.appendChild(i);",
    ),
  },
  "layout-shift": {
    expect: ["rects", "screenshot"],
    script: css("h1{margin-top:23px!important}"),
  },
  // Batch 18: a click-only element inside <main>, which is exactly where the
  // pointer census could not see before (see `clickable` in measure.mjs).
  "pointer-only-target": {
    expect: ["clickable"],
    script: observe(
      "const main = document.querySelector('main'); if (main && !main.querySelector('[data-harness-pointer]')) { const d = document.createElement('div'); d.setAttribute('data-harness-pointer', ''); d.style.cursor = 'pointer'; d.textContent = 'Harness pointer-only target'; d.addEventListener('click', () => {}); main.prepend(d); }",
    ),
  },
};
