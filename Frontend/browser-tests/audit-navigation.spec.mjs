import { test, expect } from "@playwright/test";
import { COMMON_STATES, PAGE_STATES } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

const audit = PAGE_STATES.find((state) => state.route === "/audit-dashboard");
const launcher = PAGE_STATES.find((state) => state.route === "/scan");
const reports = PAGE_STATES.find((state) => state.route === "/reports");

for (const [width, theme] of [
  [320, "light"],
  [320, "dark"],
  [1440, "light"],
  [1440, "dark"],
]) {
  test(`Audit navigation retains page scan and report access at ${width}px in ${theme} mode`, async ({
    page,
  }) => {
    const log = await openState(
      page,
      {
        ...audit,
        stubs: { ...audit.stubs, ...launcher.stubs, ...reports.stubs },
      },
      { width, theme },
    );
    await expect(
      page.getByRole("heading", { level: 1, name: "Audit Dashboard" }),
    ).toBeVisible();
    const header = page.locator(".cc-header");
    for (const name of [/New Scan/i, /Notifications/i, /^Help$|Help Center/i]) {
      await expect(header.getByRole("button", { name })).toHaveCount(0);
    }
    // The existing page action still opens the same scan-template workflow.
    const scan = page.getByRole("main").getByRole("link", { name: /New Scan/ });
    await expect(scan).toHaveCount(1);
    await expect(scan).toHaveAttribute("href", "/scan");
    await assertPage(page, log);
    await scan.click();
    await expect(page).toHaveURL("/scan");
    await expect(
      page.getByRole("heading", { name: "Scan Templates" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /^Basic Network Scan/ }),
    ).toBeEnabled();
    await expect(
      page.getByRole("button", { name: /^Asset Discovery/ }),
    ).toBeEnabled();
    await expect(
      page.getByRole("button", { name: /^Vulnerability Audit/ }),
    ).toBeEnabled();
    await assertPage(page, log);

    if (width === 320) {
      await page.getByRole("button", { name: "Open navigation" }).click();
    }
    const nav = page.getByRole("navigation", { name: "Sections" });
    await expect(
      nav.getByRole("link", { name: "Executive Report" }),
    ).toHaveCount(0);
    await nav
      .getByRole("link", { name: "Security Reports", exact: true })
      .click();
    await expect(page).toHaveURL("/reports");
    await page
      .getByRole("tab", { name: "Executive Report", exact: true })
      .click();
    await expect(page).toHaveURL("/reports?tab=executive");
    await expect(
      page.getByRole("tab", { name: "Executive Report", exact: true }),
    ).toHaveAttribute("aria-selected", "true");
    await expect(
      page.getByRole("heading", { name: "Executive Report Generation" }),
    ).toBeVisible();
    await assertPage(page, log);
    await page.reload();
    await expect(
      page.getByRole("tab", { name: "Executive Report", exact: true }),
    ).toHaveAttribute("aria-selected", "true");
    if (width === 320) {
      await page.getByRole("button", { name: "Open navigation" }).click();
    }
    await expect(
      page
        .getByRole("navigation", { name: "Sections" })
        .getByRole("link", { name: "Security Reports", exact: true }),
    ).toHaveAttribute("aria-current", "page");
    if (width === 320) await page.keyboard.press("Escape");
    await assertPage(page, log);
    // The dashboard's existing notification card keeps its list request.
    // Only the removed header's notification stream is absent.
    expect(
      log.requests.some((r) => r.path === "/api/notifications/stream"),
    ).toBe(false);
  });
}

for (const width of [320, 1440]) {
  test(`Common Platform retains its notification disclosure at ${width}px`, async ({
    page,
  }) => {
    const log = await openState(page, COMMON_STATES[0], { width });
    const bell = page
      .getByRole("banner")
      .getByRole("button", { name: /notifications/i });
    await bell.click();
    await expect(
      page.getByRole("group", { name: "Notifications", exact: true }),
    ).toBeVisible();
    await assertPage(page, log);
    await page.keyboard.press("Escape");
    await expect(
      page.getByRole("group", { name: "Notifications", exact: true }),
    ).toHaveCount(0);
    await expect(bell).toBeFocused();
    expect(log.requests.some((r) => r.path === "/api/notifications")).toBe(
      true,
    );
  });
}
