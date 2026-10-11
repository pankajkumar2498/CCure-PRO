import { test, expect } from "@playwright/test";
import { COMMON_STATES, PAGE_STATES } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

const home = COMMON_STATES[0];
const audit = PAGE_STATES.find((state) => state.route === "/audit-dashboard");

for (const [name, state] of [
  ["platform", home],
  ["Audit", audit],
]) {
  for (const width of [320, 1440]) {
    test(`${name} header theme saves and survives reload at ${width}px`, async ({
      page,
    }) => {
      let prefs = {
        theme: "light",
        sidebar_collapsed: false,
        default_rows_per_page: 10,
        email_alerts: true,
        in_app_alerts: true,
        products: { audit: { default_scan_type: "asset" } },
      };
      const writes = [];
      let holdRead = false;
      let releaseRead;
      // Every read/write is synthetic and held in this test's memory.
      await page.route(
        (url) => url.pathname === "/api/user/preferences",
        async (request) => {
          const method = request.request().method();
          expect(["GET", "PUT"]).toContain(method);
          if (method === "PUT") {
            const change = request.request().postDataJSON();
            writes.push(change);
            prefs = { ...prefs, ...change };
          } else if (holdRead) {
            await new Promise((resolve) => {
              releaseRead = resolve;
            });
          }
          await request.fulfill({ json: prefs });
        },
      );
      const log = await openState(page, state, { width });
      const header = page.locator(".cc-header");
      await expect(page).toHaveTitle("CCurePRO Platform");
      const dark = header.getByRole("button", { name: "Switch to dark mode" });
      await expect(dark).toBeEnabled();
      await expect(dark.locator('[data-icon="moon"]')).toHaveCount(1);
      await dark.focus();
      await page.keyboard.press("Enter");
      const light = header.getByRole("button", {
        name: "Switch to light mode",
      });
      await expect(light).toBeEnabled();
      await expect(light.locator('[data-icon="sun"]')).toHaveCount(1);
      expect(writes).toEqual([{ theme: "dark" }]);
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      await assertPage(page, log);

      holdRead = true;
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(light).toBeVisible();
      await expect(light).toBeDisabled();
      // While account preferences are pending, the confirmed cache avoids a light render.
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      await expect.poll(() => Boolean(releaseRead)).toBe(true);
      holdRead = false;
      releaseRead();
      await expect(light).toBeEnabled();
      await light.click();
      await expect(dark).toBeEnabled();
      expect(writes).toEqual([{ theme: "dark" }, { theme: "light" }]);
      expect(
        await page.evaluate(() => localStorage.getItem("ccure.theme")),
      ).toBe("light");
      await page.reload();
      await expect(dark).toBeEnabled();
      await expect(page.locator("html")).not.toHaveAttribute(
        "data-theme",
        "dark",
      );
      await assertPage(page, log);

      // Settings retains its existing location in each shell; theme has one control.
      if (name === "Audit" && width === 320) {
        await page.getByRole("button", { name: "Open navigation" }).click();
      }
      await page.getByRole("button", { name: "Settings", exact: true }).click();
      const settings = page.getByRole("dialog", {
        name: "Settings",
        exact: true,
      });
      await expect(
        settings.getByRole("radiogroup", { name: "Rows per page" }),
      ).toBeVisible();
      await expect(
        settings.getByRole("radiogroup", { name: "Theme" }),
      ).toHaveCount(0);
      await settings.getByRole("button", { name: "Save Settings" }).click();
      await expect(settings.getByRole("status")).toHaveText("Saved");
      expect(writes.at(-1)).not.toHaveProperty("theme");
      expect(prefs.theme).toBe("light");
      expect(prefs.products.audit.default_scan_type).toBe("asset");
    });
  }
}

test("platform identity and theme remain consistent across product entry pages", async ({
  page,
}) => {
  const log = await openState(page, home, { theme: "dark" });
  await expect(
    page.getByRole("heading", { name: "CCurePRO Home" }),
  ).toBeVisible();
  await expect(page.locator(".cc-sidebar__brand-name")).toHaveText("CCurePRO");
  for (const [route, title] of [
    ["/policy-dashboard", "CCure Policy Pro"],
    ["/rank-dashboard", "CCure Rank"],
    ["/ir-dashboard", "CCure IR"],
  ]) {
    await page
      .getByRole("navigation", { name: "Sections" })
      .getByRole("link", { name: title })
      .click();
    await expect(page).toHaveURL(route);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("list", { name: "CCurePRO Platform" }),
    ).toBeVisible();
    await expect(page).toHaveTitle("CCurePRO Platform");
    await expect(
      page
        .locator(".cc-header")
        .getByRole("button", { name: "Switch to light mode" }),
    ).toBeVisible();
    await assertPage(page, log);
  }
});

test("a failed theme save retains the confirmed theme and allows retry", async ({
  page,
}) => {
  const log = await openState(page, home);
  await page.route(
    (url) => url.pathname === "/api/user/preferences",
    async (request) => {
      expect(request.request().method()).toBe("PUT");
      expect(request.request().postDataJSON()).toEqual({ theme: "dark" });
      await request.fulfill({
        status: 503,
        json: { detail: "Synthetic failure" },
      });
    },
  );
  const button = page.getByRole("button", { name: "Switch to dark mode" });
  await expect(button).toBeEnabled();
  await button.click();
  await expect(
    page.getByText("Could not save the theme preference. Please try again."),
  ).toBeVisible();
  await expect(button).toBeEnabled();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", "dark");
  expect(await page.evaluate(() => localStorage.getItem("ccure.theme"))).toBe(
    "light",
  );
  await assertPage(page, log);
});
