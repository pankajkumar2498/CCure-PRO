import { test, expect } from "@playwright/test";
import { COMMON_STATES, COMMON_STUBS } from "./catalogue.mjs";
import { openState, assertPage } from "./helpers.mjs";

const state = COMMON_STATES.find((s) => s.id === "common-registration");
const initial = COMMON_STUBS["/admin/registration-settings"];
const path = "/api/admin/registration-settings";
const fulfill = (route, body, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

test("Registration settings open from User Management and preserve navigation and focus", async ({
  page,
}) => {
  const log = await openState(page, {
    ...COMMON_STATES.find((s) => s.id === "common-users"),
    route: "/admin/users?org_id=7",
  });
  const trigger = page.getByRole("button", {
    name: "Registration settings",
    exact: true,
  });
  await expect(
    page.getByRole("link", { name: "Registration Settings", exact: true }),
  ).toHaveCount(0);
  expect(log.requests.filter((r) => r.path === path)).toHaveLength(0);
  await trigger.click();
  const dialog = page.getByRole("dialog", {
    name: "Registration settings",
    exact: true,
  });
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL(/org_id=7&registration=settings$/);
  await dialog.getByText("Allow self-registration", { exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await expect(page).toHaveURL(/\/admin\/users\?org_id=7$/);
  expect(log.requests.filter((r) => r.method === "PATCH")).toHaveLength(0);
  await trigger.click();
  await expect(dialog.getByRole("checkbox")).not.toBeChecked();
  expect(log.requests.filter((r) => r.path === path)).toHaveLength(2);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(trigger).toBeFocused();
  await page.goto("/admin/registration-settings");
  await expect(page).toHaveURL(/\/admin\/users\?registration=settings$/);
  await expect(dialog.getByRole("checkbox")).toBeVisible();
  await assertPage(page, log);
});

test("User administrators without registration permission cannot open the dialog through the URL", async ({
  page,
}) => {
  const persona = structuredClone(state.persona);
  persona.authorization.permissions.platform =
    persona.authorization.permissions.platform.filter(
      (key) => !key.startsWith("platform.registration."),
    );
  const log = await openState(page, {
    ...state,
    persona,
    ready: "document.body.innerText.includes('User Management')",
  });
  await expect(
    page.getByRole("button", { name: "Registration settings", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(log.requests.filter((r) => r.path === path)).toHaveLength(0);
  await assertPage(page, log);
});

test("Superadmin policy saves control public signup across repeated reloads", async ({
  page,
}) => {
  let policy = { ...initial };
  await page.route(
    (url) => [path, "/api/auth/config"].includes(url.pathname),
    (route) => {
      if (new URL(route.request().url()).pathname === "/api/auth/config") {
        return fulfill(route, {
          self_registration_enabled: policy.self_registration_enabled,
        });
      }
      if (route.request().method() === "PATCH") {
        const body = route.request().postDataJSON();
        expect(body.revision).toBe(policy.revision);
        policy = {
          ...policy,
          self_registration_enabled:
            body.self_registration_enabled ?? policy.deployment_default,
          source:
            body.self_registration_enabled === null
              ? "deployment"
              : "administrator",
          revision: policy.revision + 1,
        };
      }
      return fulfill(route, policy);
    },
  );
  const log = await openState(page, state, { width: 320 });
  const toggle = page.getByRole("checkbox", {
    name: "Allow self-registration",
  });
  await expect(toggle).toBeVisible();
  await toggle.focus();
  await page.keyboard.press("Space");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Self-registration enabled.")).toBeVisible();
  await assertPage(page, log);
  await page.goto("/login");
  for (let i = 0; i < 3; i++) {
    await expect(
      page.getByRole("link", { name: "Register here" }),
    ).toBeVisible();
    await page.reload();
  }
  await page.getByRole("link", { name: "Register here" }).click();
  await expect(page.locator("#fullName")).toBeVisible();
  await page.goto(state.route);
  await expect(toggle).toBeChecked();
  await page.getByText("Allow self-registration", { exact: true }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Self-registration disabled.")).toBeVisible();
  await page.goto("/login");
  for (let i = 0; i < 3; i++) {
    await expect(
      page.getByText(/Accounts are created by your administrator/),
    ).toBeVisible();
    await expect(page.getByRole("link", { name: "Register here" })).toHaveCount(
      0,
    );
    await page.reload();
  }
  await assertPage(page, log);
});

test("Registration settings use authenticator step-up and can restore the deployment default", async ({
  page,
}) => {
  let policy = { ...initial };
  let prompted = false;
  await page.route(
    (url) => url.pathname === path,
    (route) => {
      if (route.request().method() === "PATCH") {
        if (!route.request().headers()["x-reauth-code"]) {
          prompted = true;
          return fulfill(route, { detail: { code: "reauth_required" } }, 403);
        }
        expect(route.request().headers()["x-reauth-code"]).toBe("123456");
        const body = route.request().postDataJSON();
        policy = {
          ...policy,
          self_registration_enabled: body.self_registration_enabled ?? false,
          source:
            body.self_registration_enabled === null
              ? "deployment"
              : "administrator",
          revision: policy.revision + 1,
        };
      }
      return fulfill(route, policy);
    },
  );
  const log = await openState(page, state, { width: 320 });
  await page.getByText("Allow self-registration", { exact: true }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Confirm with your authenticator",
  });
  await expect(dialog).toBeVisible();
  expect(prompted).toBe(true);
  await assertPage(page, log);
  await page.getByLabel("Authenticator code").fill("123456");
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.getByText("Self-registration enabled.")).toBeVisible();
  await page.getByRole("button", { name: "Use deployment default" }).click();
  await expect(dialog).toBeVisible();
  await page.getByLabel("Authenticator code").fill("123456");
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(
    page.getByText("Now using the deployment default."),
  ).toBeVisible();
  await expect(page.getByRole("checkbox")).not.toBeChecked();
  await assertPage(page, log);
});

test("Conflicting policy saves retain the confirmed state and offer a reload", async ({
  page,
}) => {
  await page.route(
    (url) => url.pathname === path,
    (route) =>
      route.request().method() === "PATCH"
        ? fulfill(
            route,
            {
              detail:
                "Registration settings changed. Reload them before saving again.",
            },
            409,
          )
        : fulfill(route, initial),
  );
  const log = await openState(page, state, { width: 320 });
  await page.getByText("Allow self-registration", { exact: true }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText(/Registration settings changed/)).toBeVisible();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Reload settings" }),
  ).toBeEnabled();
  await assertPage(page, log);
});
