import { test } from "@playwright/test";
import { PAGE_STATES, FLOW_STATES } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

for (const state of PAGE_STATES) {
  test(`page ${state.id}`, async ({ context }) => {
    const widths = [320, 375, 390, 414, 768, 1024, 1280, 1440, 1920];
    for (const theme of ["light", "dark"]) {
      // A fresh page prevents a previous state's polling/cancelled requests
      // from leaking into the next theme's exception and CSP census.
      const page = await context.newPage();
      const log = await openState(page, state, { width: widths[0], theme });
      for (const width of widths) {
        await page.setViewportSize({ width, height: 1000 });
        await test.step(`${theme} ${width}px`, () =>
          assertPage(page, log, {
            accessibility: width === 320 || width === 1440,
          }));
      }
      await page.close();
      await context.unrouteAll({ behavior: "wait" });
    }
  });
}
for (const state of FLOW_STATES) {
  test(`state ${state.id}`, async ({ page }) => {
    const log = await openState(page, state, { width: 320 });
    await assertPage(page, log);
  });
}
