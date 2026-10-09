import { test, expect } from "@playwright/test";
import { COMMON_STATES, PAGE_STATES } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

export async function tabTo(page, selector) {
  for (let index = 0; index < 90; index++) {
    await page.keyboard.press("Tab");
    if (
      await page.evaluate((s) => document.activeElement?.matches(s), selector)
    )
      return;
  }
  throw new Error(`Keyboard cannot reach ${selector}`);
}
export async function visibleFocus(page) {
  expect(
    await page.evaluate(() => {
      const el = document.activeElement;
      const painted =
        el
          ?.closest(".cc-choice,.cc-checkbox")
          ?.querySelectorAll(
            ".ux4g-radiomark,.ux4g-switch-track,.ux4g-checkmark",
          ) || [];
      for (const node of painted)
        if (getComputedStyle(node).boxShadow !== "none") return true;
      for (
        let node = el;
        node && node !== document.body;
        node = node.parentElement
      ) {
        const s = getComputedStyle(node);
        if (
          s.outlineStyle !== "none" &&
          parseFloat(s.outlineWidth) >= 2 &&
          node.getBoundingClientRect().width > 0
        )
          return true;
      }
      return false;
    }),
    "Keyboard focus must have a visible indicator",
  ).toBe(true);
}
const home = COMMON_STATES[0];
async function assertAccessibilityDialogs(page, info, names) {
  // Chromium exposes its actual accessibility tree through CDP. Other engines
  // retain the cross-browser role, inert, focus and axe assertions below.
  if (info.project.name !== "chromium") return;
  const session = await page.context().newCDPSession(page);
  try {
    await expect
      .poll(async () => {
        const { nodes } = await session.send("Accessibility.getFullAXTree");
        return nodes
          .filter((node) => !node.ignored && node.role?.value === "dialog")
          .map((node) => node.name?.value)
          .sort();
      })
      .toEqual([...names].sort());
  } finally {
    await session.detach();
  }
}
test("mobile navigation confines focus, isolates background and restores the opener on Escape", async ({
  page,
}, info) => {
  const log = await openState(page, home, { width: 320 });
  expect(await page.getByRole("navigation", { name: "Sections" }).count()).toBe(
    0,
  );
  await tabTo(page, ".cc-header__nav-toggle");
  await visibleFocus(page);
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Navigation" });
  await expect(dialog).toBeVisible();
  await assertAccessibilityDialogs(page, info, ["Navigation"]);
  await expect(page.locator("#root")).toHaveAttribute("inert", "");
  for (let i = 0; i < 16; i++) {
    await page.keyboard.press(i % 2 ? "Shift+Tab" : "Tab");
    expect(
      await dialog.evaluate((node) => node.contains(document.activeElement)),
    ).toBe(true);
    await visibleFocus(page);
  }
  await assertPage(page, log);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Open navigation" }),
  ).toBeFocused();
  await expect(page.locator("#root")).not.toHaveAttribute("inert", "");
});

test("account menu arrows, Home/End, Escape and keyboard activation preserve account actions", async ({
  page,
}) => {
  const log = await openState(page, home);
  await tabTo(page, ".sh-user-btn");
  await visibleFocus(page);
  await page.keyboard.press("ArrowDown");
  await expect(
    page.getByRole("menuitem", { name: "My Account" }),
  ).toBeFocused();
  await page.keyboard.press("End");
  await expect(page.getByRole("menuitem", { name: "Sign Out" })).toBeFocused();
  await page.keyboard.press("Home");
  await expect(
    page.getByRole("menuitem", { name: "My Account" }),
  ).toBeFocused();
  await visibleFocus(page);
  await assertPage(page, log);
  await page.keyboard.press("Escape");
  await expect(page.locator(".sh-user-btn")).toBeFocused();
});

test("organization choices expose menu radio selection and preserve Escape focus", async ({
  page,
}) => {
  const log = await openState(page, home);
  await tabTo(page, ".sh-org-btn");
  await page.keyboard.press("ArrowDown");
  const items = page.getByRole("menuitemradio");
  await expect(items.first()).toBeFocused();
  await expect(items.first()).toHaveAttribute("aria-checked", "true");
  await visibleFocus(page);
  await assertPage(page, log);
  await page.keyboard.press("Escape");
  await expect(page.locator(".sh-org-btn")).toBeFocused();
});

test("nested account password dialog isolates its parent and restores both opener levels", async ({
  page,
}, info) => {
  const state = PAGE_STATES.find((s) => s.id === "common-home");
  const log = await openState(page, state, { width: 390 });
  await tabTo(page, ".sh-user-btn");
  await page.keyboard.press("ArrowDown");
  await expect(
    page.getByRole("menuitem", { name: "My Account" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  const account = page.getByRole("dialog");
  await expect(account).toHaveCount(1);
  await page.getByRole("tab", { name: "Security", exact: true }).focus();
  await page.keyboard.press("Enter");
  const opener = page.getByRole("button", { name: /Change password/i });
  await opener.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toHaveCount(1);
  await expect(page.locator('[role="dialog"][aria-hidden="true"]')).toHaveCount(
    0,
  );
  expect(await page.locator('[role="dialog"]').count()).toBe(2);
  await assertAccessibilityDialogs(page, info, ["Change Password"]);
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press("Tab");
    expect(
      await page
        .getByRole("dialog")
        .evaluate((node) => node.contains(document.activeElement)),
    ).toBe(true);
  }
  await assertPage(page, log);
  await page.keyboard.press("Escape");
  await expect(opener).toBeFocused();
  await assertAccessibilityDialogs(page, info, ["My Account"]);
  await expect(page.locator("#root")).toHaveAttribute("inert", "");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".sh-user-btn")).toBeFocused();
});

test("native settings radio arrows and Space operate the selected choice", async ({
  page,
}) => {
  const log = await openState(page, home, { width: 390 });
  await tabTo(page, 'button[aria-label="Settings"]');
  await page.keyboard.press("Enter");
  const radios = page.getByRole("radio");
  await expect(radios.first()).toBeAttached();
  await expect(page.locator(".cc-choice").first()).toBeVisible();
  await radios.first().focus();
  await page.keyboard.press("ArrowRight");
  await expect(radios.nth(1)).toBeChecked();
  await expect(radios.nth(1)).toBeFocused();
  await visibleFocus(page);
  await assertPage(page, log);
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("button", { name: "Settings", exact: true }),
  ).toBeFocused();
});
