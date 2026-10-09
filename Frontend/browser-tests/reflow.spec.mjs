import { test, expect } from "@playwright/test";
import { PAGE_STATES, COMMON_STATES, FLOW_STATES } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

const selected = [
  "common-home",
  "common-users",
  "b5-register-320",
  "ar-assets",
  "sd-default",
  "ns-setup",
  "extra-schedules",
  "extra-credentialed",
];
test("Common modules use the full available shell width on desktop", async ({
  context,
}) => {
  for (const state of COMMON_STATES) {
    const page = await context.newPage();
    await openState(page, state, { width: 1280 });
    for (const width of [1280, 1920]) {
      await page.setViewportSize({ width, height: 1000 });
      const difference = await page
        .locator("main > .cc-page")
        .evaluate((inner) =>
          Math.abs(
            inner.getBoundingClientRect().width -
              inner.parentElement.getBoundingClientRect().width,
          ),
        );
      expect(
        difference,
        `${state.id}: fluid page width at ${width}`,
      ).toBeLessThanOrEqual(1);
    }
    await page.close();
    await context.unrouteAll({ behavior: "wait" });
  }
});
for (const state of PAGE_STATES.filter((s) => selected.includes(s.id))) {
  test(`200% and 400% equivalent reflow ${state.id}`, async ({ page }) => {
    const log = await openState(page, state);
    // W3C SC 1.4.10 equivalence: a 1280 x 1000 viewport at 2x and 4x.
    for (const scale of [2, 4]) {
      await page.setViewportSize({ width: 1280 / scale, height: 1000 / scale });
      await test.step(`${scale * 100}% equivalent`, () =>
        assertPage(page, log));
      expect(await page.locator("h1").first().isVisible()).toBe(true);
    }
  });
}
test("200% text size keeps shared forms and navigation operable", async ({
  page,
}) => {
  const state = PAGE_STATES.find((s) => s.id === "b5-register-320");
  const log = await openState(page, state, { width: 768 });
  await page.evaluate(() => {
    document.documentElement.style.fontSize = `${parseFloat(getComputedStyle(document.documentElement).fontSize) * 2}px`;
  });
  await assertPage(page, log);
  const field = page.getByRole("textbox", { name: /Full Name/ });
  await field.fill("A reader using enlarged text");
  await expect(field).toHaveValue("A reader using enlarged text");
  for (const button of await page.locator(".auth-form button").all())
    expect(
      await button.evaluate((el) => el.clientHeight >= el.scrollHeight - 1),
      "Enlarged button text must fit",
    ).toBe(true);
});

function longText(value) {
  if (Array.isArray(value)) return value.map(longText);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, val]) => [
      key,
      typeof val === "string" &&
      ["name", "title", "full_name", "description", "reason"].includes(key)
        ? `${val} ${"LongUnbrokenValue".repeat(16)} descriptive text for wrapping and localization`
        : longText(val),
    ]),
  );
}
test("long organization, account and administration text reflows", async ({
  page,
}) => {
  const state = COMMON_STATES.find((s) => s.id === "common-users");
  const log = await openState(
    page,
    {
      ...state,
      persona: longText(state.persona),
      stubs: longText(state.stubs),
    },
    { width: 320 },
  );
  await assertPage(page, log);
  for (const width of [320, 375, 390, 414, 768, 1024, 1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1000 });
    await assertPage(page, log, {
      accessibility: width === 320 || width === 1440,
    });
    const bounds = await page.locator(".sh-org-btn").evaluate((button) => {
      const control = button.getBoundingClientRect();
      const header = button.closest(".cc-header").getBoundingClientRect();
      return {
        top: control.top - header.top,
        bottom: header.bottom - control.bottom,
      };
    });
    expect(
      bounds.top,
      `Organization control is clipped at ${width}`,
    ).toBeGreaterThanOrEqual(0);
    expect(
      bounds.bottom,
      `Organization control overlaps content at ${width}`,
    ).toBeGreaterThanOrEqual(0);
  }
});
test("long Audit names, evidence and filters remain inside local scroll regions", async ({
  page,
}) => {
  const state = PAGE_STATES.find((s) => s.id === "ar-assets");
  const log = await openState(
    page,
    { ...state, stubs: longText(state.stubs) },
    { width: 320 },
  );
  await assertPage(page, log);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await assertPage(page, log);
});
test("drawers and destructive dialogs reflow at 400% equivalent viewport", async ({
  page,
}) => {
  const state = FLOW_STATES.find((s) => s.id === "vb-drawer-accept");
  const log = await openState(page, state, { width: 320 });
  await page.setViewportSize({ width: 320, height: 250 });
  await assertPage(page, log);
  const dialog = page.getByRole("dialog");
  const box = await dialog.boundingBox();
  expect(box.width).toBeLessThanOrEqual(320);
  expect(box.height).toBeLessThanOrEqual(250);
  await page.keyboard.press("Escape");
});
