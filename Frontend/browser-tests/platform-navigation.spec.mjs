import { test, expect } from "@playwright/test";
import { COMMON_STATES, COMMON_STUBS, PAGE_STATES } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

const home = COMMON_STATES[0];
const audit = PAGE_STATES.find((state) => state.route === "/audit-dashboard");
const platformLinks = [
  ["CCure Policy Pro", "/policy-dashboard", "CCure Policy Pro"],
  ["CCure Rank", "/rank-dashboard", "CCure Rank"],
  ["CCure IR", "/ir-dashboard", "CCure IR"],
  ["User Management", "/admin/users", "User Management"],
  ["Deleted Users", "/admin/users/deleted", "Deleted Users"],
  ["Email Domain Rules", "/admin/email-domains", "Email Domain Rules"],
  ["Organizations", "/admin/organizations", "Organizations"],
  ["Roles & Permissions", "/admin/roles", "Roles & Permissions"],
  ["Audit Logs", "/admin/audit-logs", "Audit Logs"],
  ["Home", "/", "CCurePRO Home"],
];

for (const [width, theme] of [
  [320, "light"],
  [320, "dark"],
  [1440, "light"],
  [1440, "dark"],
]) {
  test(`Common Platform navigation preserves its shell at ${width}px in ${theme} mode`, async ({
    page,
  }) => {
    const documents = [];
    page.on("request", (request) => {
      if (request.resourceType() === "document") documents.push(request.url());
    });
    const log = await openState(
      page,
      {
        ...home,
        stubs: { ...COMMON_STUBS, ...audit.stubs },
      },
      { width, theme },
    );
    await expect(
      page.getByRole("heading", { level: 1, name: "CCurePRO Home" }),
    ).toBeVisible();
    await page.evaluate(() => {
      window.__platformNavigation = {
        header: document.querySelector(".cc-header"),
        sidebar: document.querySelector(".cc-sidebar"),
        nav: document.querySelector(".cc-sidebar__nav"),
        session: JSON.stringify({ ...sessionStorage }),
      };
    });
    const assertPersistent = async () => {
      expect(
        await page.evaluate(() => {
          const mounted = window.__platformNavigation;
          return {
            header: document.querySelector(".cc-header") === mounted?.header,
            sidebar: document.querySelector(".cc-sidebar") === mounted?.sidebar,
            nav: document.querySelector(".cc-sidebar__nav") === mounted?.nav,
            session: JSON.stringify({ ...sessionStorage }) === mounted?.session,
          };
        }),
      ).toEqual({ header: true, sidebar: true, nav: true, session: true });
      await expect(page.locator(".cc-shell")).toHaveCount(1);
      expect(documents).toHaveLength(1);
    };

    for (const [name, route, title] of platformLinks) {
      if (width === 320)
        await page.getByRole("button", { name: "Open navigation" }).click();
      const nav = page.getByRole("navigation", { name: "Sections" });
      await nav.getByRole("link", { name, exact: true }).click();
      await expect(page).toHaveURL(route);
      await expect(
        page.getByRole("heading", { level: 1, name: title, exact: true }),
      ).toBeVisible();
      await assertPersistent();
      if (width === 320) {
        // The existing mobile drawer still closes after selecting a page.
        await expect(nav).toHaveCount(0);
        await page.getByRole("button", { name: "Open navigation" }).click();
      }
      await expect(
        page
          .getByRole("navigation", { name: "Sections" })
          .getByRole("link", { name, exact: true }),
      ).toHaveAttribute("aria-current", "page");
      if (width === 320) await page.keyboard.press("Escape");
      await assertPage(page, log);
    }
    // The shared registry belongs to the shell, not to each page visit.
    expect(
      log.requests.filter(
        (request) => request.path === "/api/platform/modules",
      ),
    ).toHaveLength(1);

    // Browser history updates the same outlet and active navigation.
    await page.goBack();
    await expect(page).toHaveURL("/admin/audit-logs");
    await expect(
      page.getByRole("heading", { level: 1, name: "Audit Logs" }),
    ).toBeVisible();
    await assertPersistent();
    await page.goForward();
    await expect(page).toHaveURL("/");
    await assertPersistent();

    // Crossing the product boundary keeps Audit's own shell and return link.
    if (width === 320)
      await page.getByRole("button", { name: "Open navigation" }).click();
    await page
      .getByRole("navigation", { name: "Sections" })
      .getByRole("link", { name: "CCure Audit", exact: true })
      .click();
    await expect(page).toHaveURL("/audit-dashboard");
    await expect(
      page.getByRole("heading", { level: 1, name: "Audit Dashboard" }),
    ).toBeVisible();
    await expect(page.locator(".cc-shell")).toHaveCount(1);
    await assertPage(page, log);
    expect(documents).toHaveLength(1);
    await page
      .getByRole("link", { name: "CCurePRO Home", exact: true })
      .click();
    await expect(page).toHaveURL("/");
    await expect(
      page.getByRole("heading", { level: 1, name: "CCurePRO Home" }),
    ).toBeVisible();
    await expect(page.locator(".cc-shell")).toHaveCount(1);
    await assertPage(page, log);
    expect(documents).toHaveLength(1);
  });
}

test("desktop sidebar retains its scroll position on platform navigation", async ({
  page,
}) => {
  const log = await openState(page, home);
  await page.setViewportSize({ width: 1440, height: 500 });
  const sidebar = page.locator(".cc-sidebar");
  const scrollTop = await sidebar.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    return element.scrollTop;
  });
  expect(scrollTop).toBeGreaterThan(0);
  await page
    .getByRole("navigation", { name: "Sections" })
    .getByRole("link", { name: "Audit Logs", exact: true })
    .click();
  await expect(page).toHaveURL("/admin/audit-logs");
  await expect(
    page.getByRole("heading", { level: 1, name: "Audit Logs" }),
  ).toBeVisible();
  expect(await sidebar.evaluate((element) => element.scrollTop)).toBe(
    scrollTop,
  );
  await assertPage(page, log);
});
