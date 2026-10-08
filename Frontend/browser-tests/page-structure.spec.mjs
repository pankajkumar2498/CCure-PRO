import { test, expect } from "@playwright/test";
import { PAGE_STATES } from "./catalogue.mjs";
import { openState } from "./helpers.mjs";

/* B.13: every page inside a shell has the same structure — one <h1>, drawn by
   CcurePageHeader inside CcurePage, at the same size and inset. Expected values
   are read from the design tokens on the page itself, so the check follows the
   tokens rather than restating their pixels. Sign-in screens have their own
   shell and are not part of this rule. */
const SHELL_STATES = PAGE_STATES.filter(
  (state) => !/^b5-/.test(state.id) && !state.viewport,
);

async function measure(page) {
  return page.evaluate(() => {
    const main = document.querySelector("main");
    const headings = [...main.querySelectorAll("h1")];
    const h1 = headings[0];
    const probe = document.createElement("div");
    probe.style.cssText =
      "position:absolute;visibility:hidden;font-size:var(--ccure-text-2xl);" +
      "font-weight:var(--ccure-weight-bold);padding-left:calc(2 * var(--ccure-space-lg));" +
      "padding-right:var(--ccure-space-lg)";
    document.body.appendChild(probe);
    const p = getComputedStyle(probe);
    const expected = {
      size: p.fontSize,
      weight: p.fontWeight,
      wide: Math.round(parseFloat(p.paddingLeft)),
      narrow: Math.round(parseFloat(p.paddingRight)),
    };
    probe.remove();
    const style = h1 ? getComputedStyle(h1) : null;
    return {
      count: headings.length,
      inSharedHeader: Boolean(h1?.closest(".cc-page .cc-page-header")),
      size: style?.fontSize,
      weight: style?.fontWeight,
      inset: h1
        ? Math.round(
            h1.getBoundingClientRect().left - main.getBoundingClientRect().left,
          )
        : null,
      expected,
    };
  });
}

for (const state of SHELL_STATES) {
  test(`page structure ${state.id}`, async ({ page }) => {
    // Opened narrow and then widened, as closure.spec does: the network map's
    // readiness check compares canvas frames, and at 1440px in WebKit each
    // comparison encodes a canvas large enough to push it past the poll limit.
    await openState(page, state, { width: 390 });
    const narrow = await measure(page);
    expect(narrow.count, "one <h1> in main").toBe(1);
    expect(narrow.inSharedHeader, "the <h1> is CcurePageHeader's").toBe(true);
    expect(narrow.inset, "title inset at 390px").toBe(narrow.expected.narrow);

    await page.setViewportSize({ width: 1440, height: 1000 });
    const wide = await measure(page);
    expect(wide.count, "one <h1> in main at 1440px").toBe(1);
    expect(wide.size, "title size").toBe(wide.expected.size);
    expect(wide.weight, "title weight").toBe(wide.expected.weight);
    expect(wide.inset, "title inset at 1440px").toBe(wide.expected.wide);
  });
}
