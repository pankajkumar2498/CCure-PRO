import { test, expect } from "@playwright/test";
import { AUTH_STATES } from "../scripts/ux4g-harness/b5-b6.mjs";
import { openState, assertPage } from "./helpers.mjs";

const auth = (name) =>
  AUTH_STATES.find((state) => state.id === `b5-${name}-320`);
const widths = [320, 375, 390, 414, 768, 1024, 1280, 1440, 1920];

async function assertIdentity(page) {
  await expect(page.locator(".auth-platform-header")).toContainText(
    "CCure PRO",
  );
  await expect(page.locator(".auth-platform-description")).toBeVisible();
  await expect(page.locator(".auth-platform-description")).toHaveText(
    "Enterprise Security / Vulnerability Management Platform",
  );
  await expect(page).toHaveTitle(/\| CCure PRO Platform$/);
  await expect(page.locator("h1")).toHaveCount(1);
  // Excludes legally controlled dialog content, which retains its approved text.
  expect(await page.locator(".auth-layout").innerText()).not.toMatch(
    /\baudit\b|SOC\s?2|256-bit|TLS\s?1\.[23]|certified|\bcompliant\b|encrypted reset/i,
  );
}

async function assertResponsive(page, log) {
  for (const width of widths) {
    await page.setViewportSize({ width, height: 1000 });
    await assertIdentity(page);
    await assertPage(page, log, {
      accessibility: width === 320 || width === 1440,
    });
  }
}

// Additional failure fixtures are page-local, synthetic responses. No API
// request is forwarded, including pending writes and session refresh failures.
async function response(page, endpoint, status, body) {
  await page.route(
    (url) => url.pathname === `/api${endpoint}`,
    (request) =>
      request.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(body),
      }),
  );
}

for (const name of ["login", "register", "forgot", "reset", "verify"]) {
  test(`Authentication identity and document title: ${name}`, async ({
    page,
  }) => {
    await openState(page, auth(name), { width: 320 });
    await assertIdentity(page);
  });
}

test("Authentication password reveal is keyboard reachable with visible focus", async ({
  page,
}) => {
  const log = await openState(page, auth("login"), { width: 320 });
  await page.keyboard.press("Tab");
  await expect(page.locator("#emailOrUsername")).toBeFocused();
  await page.keyboard.type("analyst");
  await page.keyboard.press("Tab");
  await expect(page.locator("#password")).toBeFocused();
  await page.keyboard.type("Example!Passphrase1");
  await page.keyboard.press("Tab");
  const toggle = page.getByRole("button", {
    name: "Toggle Password visibility",
  });
  await expect(toggle).toBeFocused();
  expect(
    await toggle.evaluate((node) => {
      const style = getComputedStyle(node);
      return (
        style.outlineStyle !== "none" && parseFloat(style.outlineWidth) >= 2
      );
    }),
  ).toBe(true);
  await page.keyboard.press("Enter");
  await expect(page.locator("#password")).toHaveAttribute("type", "text");
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("Space");
  await expect(page.locator("#password")).toHaveAttribute("type", "password");
  expect(
    log.requests.some((request) => request.path.endsWith("/auth/login")),
  ).toBe(false);
  await assertPage(page, log);
});

test("Authentication sign-in required validation and failure", async ({
  page,
}) => {
  await page.route(
    (url) => url.pathname === "/api/auth/login",
    (request) => {
      const body = request.request().postDataJSON();
      expect(body).toEqual({
        email_or_username: "analyst",
        password: "Example!Passphrase1",
      });
      return request.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({
          message: "Unable to sign in. Check your credentials.",
        }),
      });
    },
  );
  const log = await openState(page, auth("login"), { width: 320 });
  const submit = page.locator('button[type="submit"]');
  await submit.click();
  await expect(page.locator("#emailOrUsername:invalid")).toHaveCount(1);
  await page.locator("#emailOrUsername").fill("analyst");
  await page.locator("#password").fill("Example!Passphrase1");
  await submit.click();
  await expect(page.getByRole("alert")).toContainText("Unable to sign in");
  await assertResponsive(page, log);
});

for (const [name, endpoint, fields] of [
  [
    "login",
    "/auth/login",
    { emailOrUsername: "analyst", password: "Example!Passphrase1" },
  ],
  ["forgot", "/auth/forgot-password", { emailOrUsername: "analyst" }],
  [
    "reset",
    "/auth/reset-password",
    { password: "Example!Passphrase1", confirm: "Example!Passphrase1" },
  ],
  [
    "register",
    "/auth/register",
    {
      fullName: "Security Analyst",
      username: "analyst",
      email: "analyst@example.test",
      password: "Example!Passphrase1",
      confirm: "Example!Passphrase1",
    },
  ],
]) {
  test(`Authentication loading is announced and prevents repeat submission: ${name}`, async ({
    page,
  }) => {
    const log = await openState(
      page,
      {
        ...auth(name),
        writes: { [`POST ${endpoint}`]: {} },
        pendingRequests: [`POST ${endpoint}`],
      },
      { width: 320 },
    );
    for (const [id, value] of Object.entries(fields))
      await page.locator(`#${id}`).fill(value);
    if (name === "register") {
      await page.getByRole("checkbox").focus();
      await page.keyboard.press("Space");
      await expect(page.getByRole("checkbox")).toBeChecked();
    }
    await page.locator('button[type="submit"]').click();
    await expect(page.locator('button[type="submit"]')).toBeDisabled();
    await expect(page.locator('button[type="submit"]')).toHaveAttribute(
      "aria-busy",
      "true",
    );
    await assertResponsive(page, log);
  });
}

test("Authentication reset mismatch stays associated with its field", async ({
  page,
}) => {
  const log = await openState(page, auth("reset"), { width: 320 });
  await page.locator("#password").fill("Example!Passphrase1");
  await page.locator("#confirm").fill("Different!Passphrase1");
  await expect(page.locator("#confirm")).toHaveAttribute(
    "aria-invalid",
    "true",
  );
  await expect(page.locator("#confirm")).toHaveAttribute(
    "aria-describedby",
    /confirm-error/,
  );
  await page.locator('button[type="submit"]').click();
  await expect(page.locator(".auth-message[role=alert]")).toContainText(
    "Passwords do not match",
  );
  await assertResponsive(page, log);
});

test("Authentication missing reset link offers recovery", async ({ page }) => {
  const log = await openState(
    page,
    {
      ...auth("reset"),
      route: "/reset-password",
      ready: "!!document.querySelector('[role=alert]')",
    },
    { width: 320 },
  );
  await expect(page.locator("#password")).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: /Request new reset link/ }),
  ).toHaveAttribute("href", "/forgot-password");
  await assertResponsive(page, log);
});

test("Authentication expired session explains the next step", async ({
  page,
}) => {
  await response(page, "/auth/me", 500, {
    message: "Synthetic expired session",
  });
  const log = await openState(
    page,
    {
      ...auth("login"),
      route: "/",
      ready: "!!document.querySelector('#password')",
    },
    { width: 320 },
  );
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("status")).toContainText(
    "Your session expired. Please sign in again.",
  );
  await assertResponsive(page, log);
});

test("Authentication compatibility error uses the same CCure presentation", async ({
  page,
}) => {
  const log = await openState(
    page,
    {
      ...auth("login"),
      route: "/",
      persona: { id: "synthetic-incompatible" },
      ready: "document.body.innerText.includes('Account access unavailable')",
    },
    { width: 320 },
  );
  await expect(page.getByRole("alert")).toContainText("authorization contract");
  await assertResponsive(page, log);
});

test("Authentication registration unavailable state names the platform", async ({
  page,
}) => {
  const log = await openState(
    page,
    {
      ...auth("register"),
      stubs: {
        ...auth("register").stubs,
        "/auth/config": { self_registration_enabled: false },
      },
      ready:
        "document.body.innerText.includes('Accounts are created by an administrator')",
    },
    { width: 320 },
  );
  await expect(page.locator("#fullName")).toHaveCount(0);
  await assertResponsive(page, log);
});

for (const enabled of [false, true]) {
  test(`Authentication registration policy remains ${enabled} across reloads`, async ({
    page,
  }) => {
    const log = await openState(page, {
      ...auth("login"),
      stubs: {
        ...auth("login").stubs,
        "/auth/config": { self_registration_enabled: enabled },
      },
    });
    for (let visit = 0; visit < 3; visit += 1) {
      if (visit) await page.reload();
      if (enabled) {
        await expect(
          page.getByRole("link", { name: "Register here" }),
        ).toBeVisible();
        await expect(
          page.getByText(/created by your administrator/),
        ).toHaveCount(0);
      } else {
        await expect(
          page.getByText(/created by your administrator/),
        ).toBeVisible();
        await expect(
          page.getByRole("link", { name: "Register here" }),
        ).toHaveCount(0);
      }
    }
    expect(
      log.requests.filter((r) => r.path === "/api/auth/config"),
    ).toHaveLength(3);
    expect(log.requests.some((r) => r.path === "/api/auth/check-email")).toBe(
      false,
    );
    await assertPage(page, log);
  });
}

test("Authentication waits for delayed configuration without moving credentials or flashing signup", async ({
  page,
}) => {
  let pending;
  await page.route(
    (url) => url.pathname === "/api/auth/config",
    (request) => {
      pending = request;
    },
  );
  const log = await openState(page, auth("login"), { width: 320 });
  await expect(page.getByRole("status")).toContainText(
    "Checking registration availability",
  );
  await expect(page.getByRole("link", { name: "Register here" })).toHaveCount(
    0,
  );
  await expect(page.getByText(/created by your administrator/)).toHaveCount(0);
  const before = await page.locator(".auth-card").boundingBox();
  await page.locator("#emailOrUsername").fill("analyst");
  await page.locator("#password").fill("Example!Passphrase1");
  await pending.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ self_registration_enabled: false }),
  });
  await expect(page.getByText(/created by your administrator/)).toBeVisible();
  await expect(page.getByRole("link", { name: "Register here" })).toHaveCount(
    0,
  );
  await expect(page.locator("#emailOrUsername")).toHaveValue("analyst");
  await expect(page.locator("#password")).toHaveValue("Example!Passphrase1");
  const after = await page.locator(".auth-card").boundingBox();
  expect(after.y).toBeCloseTo(before.y, 0);
  expect(after.height).toBeCloseTo(before.height, 0);
  await assertPage(page, log);
});

for (const [name, status, body] of [
  ["throttled", 429, { message: "Synthetic rate limit" }],
  ["unauthorized", 401, { message: "Synthetic auth failure" }],
  ["malformed", 200, { available: true }],
]) {
  test(`Authentication ${name} configuration stays unknown and can be retried`, async ({
    page,
  }) => {
    let attempts = 0;
    await page.route(
      (url) => url.pathname === "/api/auth/config",
      (request) => {
        attempts += 1;
        return request.fulfill({
          status: attempts === 1 ? status : 200,
          contentType: "application/json",
          body: JSON.stringify(
            attempts === 1 ? body : { self_registration_enabled: false },
          ),
        });
      },
    );
    const log = await openState(page, auth("login"), { width: 320 });
    await expect(page.getByRole("status")).toContainText(
      "Registration options are unavailable",
    );
    await expect(page.getByRole("link", { name: "Register here" })).toHaveCount(
      0,
    );
    await expect(page.getByText(/created by your administrator/)).toHaveCount(
      0,
    );
    await expect(page.getByRole("button", { name: /Sign In/ })).toBeEnabled();
    await assertPage(page, log);
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(page.getByText(/created by your administrator/)).toBeVisible();
    expect(attempts).toBe(2);
    await assertPage(page, log);
  });
}

test("Authentication direct registration waits for configuration and recovers without exposing a form", async ({
  page,
}) => {
  const log = await openState(
    page,
    {
      ...auth("register"),
      stubs: {
        ...auth("register").stubs,
        "/auth/config": {
          __status: 503,
          body: { message: "Synthetic outage" },
        },
      },
      ready:
        "document.body.innerText.includes('Registration options are unavailable')",
    },
    { width: 320 },
  );
  await expect(page.locator("#fullName")).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "Back to sign in" }),
  ).toHaveAttribute("href", "/login");
  await assertPage(page, log);
});

test("Authentication MFA email code and error retain the challenge", async ({
  page,
}) => {
  await response(page, "/auth/login/verify-mfa", 400, {
    detail: "Invalid verification code.",
  });
  const state = AUTH_STATES.find((s) => s.id === "b5-mfa-390");
  const log = await openState(
    page,
    {
      ...state,
      writes: { ...state.writes, "POST /auth/login/send-email-otp": {} },
    },
    { width: 320 },
  );
  await expect(page.locator("#mfaCode")).toBeFocused();
  await page.getByRole("button", { name: "Send code to email" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Verification code sent to your email.",
  );
  await page.locator("#mfaCode").fill("123456");
  await page.locator('button[type="submit"]').click();
  await expect(page.getByRole("alert")).toContainText(
    "Invalid verification code",
  );
  await assertResponsive(page, log);
  await page.getByRole("button", { name: /Back to credentials/ }).click();
  await expect(page.locator("#password")).toBeVisible();
  await expect(page.locator("#mfaCode")).toHaveCount(0);
});

test("Authentication MFA verification loading prevents repeat submission", async ({
  page,
}) => {
  const state = AUTH_STATES.find((s) => s.id === "b5-mfa-390");
  const log = await openState(
    page,
    {
      ...state,
      writes: { ...state.writes, "POST /auth/login/verify-mfa": {} },
      pendingRequests: ["POST /auth/login/verify-mfa"],
    },
    { width: 320 },
  );
  await page.locator("#mfaCode").fill("123456");
  await page.locator('button[type="submit"]').click();
  await expect(page.locator('button[type="submit"]')).toBeDisabled();
  await expect(page.locator('button[type="submit"]')).toHaveAttribute(
    "aria-busy",
    "true",
  );
  await assertResponsive(page, log);
});

test("Authentication email verification pending state has an announced loader", async ({
  page,
}) => {
  const log = await openState(
    page,
    {
      ...auth("verify"),
      route: "/verify-email?token=synthetic-verify",
      writes: { "POST /auth/verify-email": {} },
      pendingRequests: ["POST /auth/verify-email"],
      ready: "!!document.querySelector('.cc-loader')",
    },
    { width: 320 },
  );
  await expect(page.getByRole("status")).toContainText(
    "One moment while we confirm your link.",
  );
  expect(
    log.requests.filter((request) =>
      request.path.endsWith("/auth/verify-email"),
    ),
  ).toHaveLength(1);
  await assertResponsive(page, log);
});

test("Authentication legal dialogs preserve focus and approved copy", async ({
  page,
}) => {
  const log = await openState(page, auth("register"), { width: 320 });
  for (const name of ["Terms of Service", "Privacy Policy"]) {
    const opener = page.getByRole("button", { name, exact: true });
    await opener.focus();
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("dialog", { name: new RegExp(`^${name}`) }),
    ).toBeVisible();
    await expect(page.getByRole("dialog")).toContainText("CCure Audit PRO");
    await assertPage(page, log);
    await page.keyboard.press("Escape");
    await expect(opener).toBeFocused();
    await expect(page.getByRole("checkbox")).not.toBeChecked();
  }
});

test("Authentication rendering failures recover through sign-in without scan claims or private diagnostics", async ({
  page,
}) => {
  const diagnostics = [];
  page.on("console", async (message) => {
    if (message.type() !== "error") return;
    for (const argument of message.args()) {
      const detail = await argument.evaluate((value) =>
        typeof value?.message === "string" ? value.message : null,
      );
      if (detail) diagnostics.push({ text: message.text(), detail });
    }
  });
  const log = await openState(
    page,
    {
      ...auth("verify"),
      route: "/verify-email?token=synthetic-render-failure",
      writes: {
        "POST /auth/verify-email": {
          status: "verified",
          detail: { SYNTHETIC_PRIVATE_TOKEN: "synthetic-secret" },
        },
      },
      ready:
        "document.body.innerText.includes('Authentication page unavailable')",
    },
    { width: 320 },
  );
  const expectedFault = (message) =>
    /Minified React error #31|Objects are not valid as a React child/.test(
      message,
    ) && message.includes("SYNTHETIC_PRIVATE_TOKEN");
  // This case deliberately injects one invalid React child. Only diagnostics
  // identifying that exact synthetic fault are expected; other exceptions,
  // accessibility findings, and undeclared requests still fail the gate.
  // Firefox represents console.error(Error) as the opaque text "Error".
  // Read that specific object's message and account for each event once.
  await expect
    .poll(() => diagnostics.some(({ detail }) => expectedFault(detail)))
    .toBe(true);
  const unexpectedLog = () => {
    const known = new Map();
    for (const { text, detail } of diagnostics) {
      if (expectedFault(detail)) known.set(text, (known.get(text) || 0) + 1);
    }
    return {
      ...log,
      pageErrors: log.pageErrors.filter((message) => !expectedFault(message)),
      consoleErrors: log.consoleErrors.filter((message) => {
        if (!known.get(message)) return true;
        known.set(message, known.get(message) - 1);
        return false;
      }),
    };
  };
  expect(await page.locator(".auth-layout").innerText()).not.toMatch(
    /scan result|saved|SYNTHETIC_PRIVATE_TOKEN|synthetic-secret/i,
  );
  await assertResponsive(page, unexpectedLog());
  await page.getByRole("link", { name: "Return to sign in" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.locator("#password")).toBeVisible();
  await assertIdentity(page);
  await assertPage(page, unexpectedLog());
});
