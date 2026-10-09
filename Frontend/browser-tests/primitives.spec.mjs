import { test, expect } from "@playwright/test";
import { openState, assertPage } from "./helpers.mjs";

const fixture = {
  route: "/__ux4g-fixture/",
  ready: "document.body.innerText.includes('UX4G adapter validation')",
};
test("shared official primitives pass names, semantics and contrast in both themes", async ({
  context,
}) => {
  for (const theme of ["light", "dark"]) {
    const state = { ...fixture, route: `/__ux4g-fixture/?theme=${theme}` };
    const page = await context.newPage();
    const log = await openState(page, state, { width: 320, theme });
    await assertPage(page, log);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await assertPage(page, log);
    await page.close();
    await context.unrouteAll({ behavior: "wait" });
  }
});
test("nested shared overlays isolate all background layers and restore focus in order", async ({
  page,
}) => {
  const log = await openState(page, fixture, { width: 320 });
  const opener = page.getByRole("button", { name: "Open modal", exact: true });
  await opener.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("dialog", { name: "Review changes" }),
  ).toBeVisible();
  const nested = page.getByRole("button", { name: "Open nested drawer" });
  await nested.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "Preferences" })).toBeVisible();
  await expect(
    page.getByRole("dialog", { name: "Review changes" }),
  ).toHaveCount(0);
  for (let i = 0; i < 16; i++) {
    await page.keyboard.press(i % 3 ? "Tab" : "Shift+Tab");
    expect(
      await page
        .getByRole("dialog")
        .evaluate((node) => node.contains(document.activeElement)),
    ).toBe(true);
  }
  await assertPage(page, log);
  await page.keyboard.press("Escape");
  await expect(nested).toBeFocused();
  await expect(page.locator("#root")).toHaveAttribute("inert", "");
  await page.keyboard.press("Escape");
  await expect(opener).toBeFocused();
  await expect(page.locator("#root")).not.toHaveAttribute("inert", "");
});
