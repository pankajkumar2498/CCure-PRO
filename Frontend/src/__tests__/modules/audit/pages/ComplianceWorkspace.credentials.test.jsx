/**
 * ComplianceWorkspace (`/compliance`) — the Credentials Manager tab: the saved
 * credentials list, the Register Credential form and credential deletion.
 * Checkpoint 3C batch 29 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 29 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The tab reads GET /compliance/credentials once and lists each credential by
 * nickname, username, port and method — the API returns no secret and none is
 * shown. An organisation admin or superadmin sees a Delete action on every row
 * and the Register Credential form; anyone else sees the list only. Saving
 * posts the name, username, method, the password or the key (the other null)
 * and the port as a number, then clears the form and re-reads the list.
 * Deleting asks, naming the credential, then sends one DELETE carrying only the
 * credential's id in its path. Every refusal is reported with the API's detail.
 *
 * ── Secrets ────────────────────────────────────────────────────────────────
 * The password and key used here are synthetic, low-entropy placeholders. The
 * afterEach fails any test in which either reached a URL, the console or
 * browser storage.
 *
 * Only the axios instance, the shell and the signed-in user are replaced.
 * No remediation, approval, evidence or report path is exercised.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

import ComplianceWorkspace from "@audit/pages/ComplianceWorkspace";
import api from "@shell/api/axiosInstance";
import { AUDIT_SRC } from "../../../testPaths";
import { personaFrom } from "../../../fixtures/authorization";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let user;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(user) }),
}));

// What an account may do is the permissions the backend lists for it. Only the
// administrators hold manage_frameworks (RBAC-6: a permission, not a role name).
const person = (roleName, id = 1) =>
  personaFrom({
    id,
    username: `user-${id}`,
    role: { name: roleName },
    permissionKeys:
      roleName === "analyst"
        ? ["audit.compliance.read"]
        : ["audit.compliance.read", "audit.compliance.manage_frameworks"],
  });
const ANALYST = person("analyst");
const ORG_ADMIN = person("Org Admin", 2);
const SUPERADMIN = person("superadmin", 3);

/* ── Fixtures ────────────────────────────────────────────────────────────── */
// Synthetic, low-entropy stand-ins. Neither is a credential for anything.
const PASS = "synthetic-pass";
const KEY = "synthetic key text";
const CREDENTIALS = [
  {
    id: "cred-1",
    name: "Linux fleet",
    username: "auditor",
    auth_method: "password",
    port: 22,
    created_at: "2026-08-01T10:00:00Z",
  },
  {
    id: "cred-2",
    name: "Bastion keys",
    username: "svc-audit",
    auth_method: "key",
    port: 2222,
    created_at: "2026-08-02T10:00:00Z",
  },
];
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const refusal = (detail) => ({
  response: { status: 403, data: { detail, message: detail } },
  message: "Request failed with status code 403",
});

/* ── Harness ────────────────────────────────────────────────────────────── */
let credentials;
let listReply;
let postReply;
let deleteReply;
let confirmSpy;
let consoleSpies;

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const frame = async () => {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 40));
  });
  await flush();
};
const mount = async () => {
  const view = render(<ComplianceWorkspace />);
  await flush();
  return view;
};
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);
const gets = () => api.get.mock.calls.map(([u]) => u);
const credentialReads = () =>
  gets().filter((u) => u === "/compliance/credentials");

const tabBar = () =>
  [...document.querySelectorAll("div")].find(
    (d) =>
      /* Nine since P3-2 added the Schedules tab. The identity of the bar is
         the two labels below; the count is incidental and is kept exact so a
         wrapper cannot satisfy it. */
      d.children.length === 9 &&
      /Approvals Queue/.test(d.textContent || "") &&
      /Marketplace/.test(d.textContent || ""),
  );
const openTab = async (label) => {
  const tab = [...tabBar().children].find(
    (c) => (c.textContent || "").trim() === label,
  );
  fireEvent.click(tab);
  await flush();
};
const openCredentials = () => openTab("Credentials Manager");
const click = async (el, init) => {
  fireEvent.click(el, init);
  await flush();
};
const change = async (el, value) => {
  fireEvent.change(el, { target: { value } });
  await flush();
};
const credentialTable = () =>
  [...document.querySelectorAll("table")].find((t) =>
    /Nickname/.test(t.tHead?.textContent || ""),
  );
const headers = () =>
  [...credentialTable().tHead.rows[0].cells].map((c) => squash(c));
const rowOf = (name) =>
  [...credentialTable().tBodies[0].rows].find(
    (r) => r.cells.length > 1 && squash(r.cells[0]) === name,
  );
const rowTexts = () =>
  [...credentialTable().tBodies[0].rows]
    .filter((r) => r.cells.length > 1)
    .map((r) => [...r.cells].map((c) => squash(c)));
const deleteOf = (name) =>
  within(rowOf(name)).getByRole("button", { name: /^Delete\b/ });
const registerForm = () =>
  [...document.querySelectorAll("form")].find((f) =>
    /Save Target Credential/.test(f.textContent || ""),
  );
const textInputs = (form) => [...form.querySelectorAll('input[type="text"]')];
const portInput = (form) => form.querySelector('input[type="number"]');
const methodSelect = (form) =>
  [...form.querySelectorAll("select")].find(
    (s) => [...s.options].map((o) => o.value).join(",") === "password,key",
  );
const passwordInput = (form) => form.querySelector('input[type="password"]');
const keyInput = (form) => form.querySelector("textarea");
const saveButton = (form) =>
  within(form).getByRole("button", { name: "Save Target Credential" });
const fill = async (form, { name, username, port, method, secret }) => {
  const [nameField, userField] = textInputs(form);
  await change(nameField, name);
  await change(userField, username);
  if (port !== undefined) await change(portInput(form), port);
  if (method) await change(methodSelect(form), method);
  if (secret !== undefined)
    await change(
      method === "key" ? keyInput(form) : passwordInput(form),
      secret,
    );
};
// Deletes the way a person does: Delete, then answers the question — the
// browser's confirm on the legacy page, the dialog where there is one.
// Returns the question's text.
const answerDelete = async (name, accept) => {
  let asked = null;
  confirmSpy.mockImplementation((message) => {
    asked = message;
    return accept;
  });
  const button = deleteOf(name);
  button.focus();
  await click(button);
  const dialog = screen.queryByRole("dialog");
  if (dialog) {
    asked = squash(dialog);
    await click(
      within(dialog).getByRole("button", {
        name: accept ? /^Delete credential$/ : /^Cancel$/,
      }),
    );
  }
  return asked;
};
// Everything in the page a reader or a script could see except the secret
// fields' own values: text nodes and attributes, with the password and key
// fields themselves taken out.
const visibleOutsideSecretFields = () => {
  const clone = document.body.cloneNode(true);
  for (const el of clone.querySelectorAll(
    'input[type="password"], textarea, input[autocomplete="new-password"]',
  ))
    el.remove();
  const attrs = [...clone.querySelectorAll("*")].flatMap((el) =>
    [...el.attributes].map((a) => a.value),
  );
  return `${clone.textContent}\n${attrs.join("\n")}`;
};

beforeEach(() => {
  user = ORG_ADMIN;
  credentials = CREDENTIALS.map((c) => ({ ...c }));
  listReply = () =>
    Promise.resolve({ data: credentials.map((c) => ({ ...c })) });
  postReply = (url, body) => {
    credentials = [
      ...credentials,
      {
        id: `cred-${credentials.length + 1}`,
        name: body.name,
        username: body.username,
        auth_method: body.auth_method,
        port: body.port,
        created_at: "2026-09-01T10:00:00Z",
      },
    ];
    return Promise.resolve({ data: credentials.at(-1) });
  };
  deleteReply = (url) => {
    const id = url.split("/").pop();
    credentials = credentials.filter((c) => c.id !== id);
    return Promise.resolve({
      data: { message: "Credential deleted successfully" },
    });
  };
  Element.prototype.scrollIntoView = vi.fn();
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url) => {
    if (url === "/compliance/credentials") return listReply();
    if (url === "/compliance/marketplace")
      return Promise.resolve({ data: { data: [] } });
    if (url.startsWith("/compliance/summary"))
      return Promise.resolve({
        data: { score_pct: 70, weighted_score_pct: 60, kpis: {} },
      });
    return Promise.resolve({ data: { data: [] } });
  });
  api.post.mockImplementation((...args) => postReply(...args));
  api.delete.mockImplementation((...args) => deleteReply(...args));
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
  consoleSpies = ["error", "warn", "log", "info", "debug"].map((m) =>
    vi.spyOn(console, m).mockImplementation(() => {}),
  );
  window.localStorage.clear();
  window.sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  // Only a credential is ever created or deleted, and a deletion carries
  // nothing but its URL. Nothing is put or patched, and no remediation,
  // approval, evidence or report path is reached.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls)
    expect(url).toBe("/compliance/credentials");
  for (const args of api.delete.mock.calls) {
    expect(args).toHaveLength(1);
    expect(args[0]).toMatch(/^\/compliance\/credentials\/cred-[0-9]+$/);
  }
  const urls = [
    ...gets(),
    ...api.post.mock.calls.map(([u]) => u),
    ...api.delete.mock.calls.map(([u]) => u),
  ];
  for (const url of urls) {
    expect(url).not.toMatch(/remediat|approv|evidence|reports/);
    expect(url).not.toContain(PASS);
    expect(url).not.toContain("synthetic");
  }
  // No secret reaches the console or browser storage.
  const logged = JSON.stringify(
    consoleSpies.flatMap((s) =>
      s.mock.calls.map((args) =>
        args.map((a) =>
          a instanceof Error ? `${a.message} ${a.stack}` : String(a),
        ),
      ),
    ),
  );
  expect(logged).not.toContain(PASS);
  expect(logged).not.toContain(KEY);
  const stored = JSON.stringify({
    ...window.localStorage,
    ...window.sessionStorage,
  });
  expect(stored).not.toContain(PASS);
  expect(stored).not.toContain(KEY);
  confirmSpy.mockRestore();
  for (const s of consoleSpies) s.mockRestore();
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace Credentials Manager — contract", () => {
  describe("The list", () => {
    it("reads the saved credentials once and lists each by nickname, username, port and method", async () => {
      await mount();
      const before = credentialReads().length;
      await openCredentials();
      expect(credentialReads().length - before).toBe(1);
      expect(headers()).toEqual([
        "Nickname",
        "Username",
        "Port",
        "Auth Method",
        "Actions",
      ]);
      expect(rowTexts()).toEqual([
        ["Linux fleet", "auditor", "22", "Password", "Delete"],
        ["Bastion keys", "svc-audit", "2222", "SSH Key", "Delete"],
      ]);
      expect(bodyText()).toContain("Saved Credentials");
      expect(bodyText()).toContain("Showing 1–2 of 2 credentials");
      expect(bodyText()).not.toMatch(/2026-08-0[12]/);
      expect(api.post).not.toHaveBeenCalled();
      expect(api.delete).not.toHaveBeenCalled();
    });

    it("anyone but an organisation admin or superadmin sees the list only — no Actions, no Delete, no form", async () => {
      user = ANALYST;
      await mount();
      await openCredentials();
      expect(headers()).toEqual([
        "Nickname",
        "Username",
        "Port",
        "Auth Method",
      ]);
      expect(rowTexts()).toEqual([
        ["Linux fleet", "auditor", "22", "Password"],
        ["Bastion keys", "svc-audit", "2222", "SSH Key"],
      ]);
      expect(
        screen.queryAllByRole("button", { name: /^Delete\b/ }),
      ).toHaveLength(0);
      expect(registerForm()).toBeUndefined();
      expect(bodyText()).not.toContain("Register Credential");
    });

    it.each([
      ["an organisation admin", ORG_ADMIN],
      ["a superadmin", SUPERADMIN],
    ])(
      "%s sees Delete on every row and the Register Credential form",
      async (_, who) => {
        user = who;
        await mount();
        await openCredentials();
        expect(deleteOf("Linux fleet")).toBeEnabled();
        expect(deleteOf("Bastion keys")).toBeEnabled();
        expect(registerForm()).toBeTruthy();
        expect(bodyText()).toContain("Register Credential");
      },
    );

    it("an empty list says so", async () => {
      credentials = [];
      await mount();
      await openCredentials();
      expect(bodyText()).toContain("No saved credentials registered.");
      // The pager's own summary: PaginationBar's, or PagingControls' since
      // Batch 31.
      expect(bodyText()).toMatch(
        /No credentials found|Showing 0–0 of 0 credentials/,
      );
    });

    it("a list that cannot be read reports the page error and lists nothing", async () => {
      listReply = () => Promise.reject(new Error("Network Error"));
      await mount();
      await openCredentials();
      expect(bodyText()).toContain(
        "Connection or Database Error: Network Error",
      );
      expect(rowTexts()).toEqual([]);
      expect(console.error).toHaveBeenCalledWith(
        "Failed to load compliance data",
        expect.any(Error),
      );
    });
  });

  describe("Registering a credential", () => {
    it("offers a nickname, a username, port 22, the method and a masked password — no key field until chosen", async () => {
      await mount();
      await openCredentials();
      const form = registerForm();
      const [name, username] = textInputs(form);
      expect(name).toBeRequired();
      expect(name).toHaveAttribute("placeholder", "e.g. Production Webservers");
      expect(username).toBeRequired();
      expect(username).toHaveAttribute("placeholder", "e.g. root");
      expect(portInput(form)).toHaveValue(22);
      expect(portInput(form)).toBeRequired();
      const method = methodSelect(form);
      expect(method.value).toBe("password");
      expect([...method.options].map((o) => o.textContent.trim())).toEqual([
        "Password",
        "Private SSH Key",
      ]);
      const password = passwordInput(form);
      expect(password).toHaveAttribute("type", "password");
      expect(password).toBeRequired();
      expect(password).toHaveAttribute("placeholder", "••••••••");
      expect(keyInput(form)).toBeNull();
      expect(saveButton(form)).toHaveAttribute("type", "submit");
    });

    it("choosing Private SSH Key swaps the password for a required key field", async () => {
      await mount();
      await openCredentials();
      const form = registerForm();
      await change(methodSelect(form), "key");
      expect(passwordInput(form)).toBeNull();
      const key = keyInput(form);
      expect(key).toBeRequired();
      expect(key.getAttribute("placeholder")).toMatch(
        /^-{5}BEGIN OpenSSH PRIVATE KEY-{5}\.\.\.$/,
      );
      await change(methodSelect(form), "password");
      expect(keyInput(form)).toBeNull();
      expect(passwordInput(form)).toBeTruthy();
    });

    it("saving with a password posts the name, username, method, the password, a null key and the port as a number; says so, clears the form and re-reads the list", async () => {
      await mount();
      await openCredentials();
      const form = registerForm();
      await fill(form, {
        name: "Web tier",
        username: "deploy",
        port: "2200",
        secret: PASS,
      });
      const before = credentialReads().length;
      await click(saveButton(form));
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/credentials",
          {
            name: "Web tier",
            username: "deploy",
            auth_method: "password",
            password: PASS,
            key_content: null,
            port: 2200,
          },
        ],
      ]);
      expect(bodyText()).toContain("Credential saved successfully.");
      expect(credentialReads().length - before).toBe(1);
      const after = registerForm();
      expect(textInputs(after).map((i) => i.value)).toEqual(["", ""]);
      expect(passwordInput(after)).toHaveValue("");
      expect(portInput(after)).toHaveValue(22);
      expect(methodSelect(after).value).toBe("password");
      expect(rowOf("Web tier")).toBeTruthy();
    });

    it("saving with a key posts the key and a null password, and keeps the method chosen", async () => {
      await mount();
      await openCredentials();
      const form = registerForm();
      await fill(form, {
        name: "Jump hosts",
        username: "ops",
        method: "key",
        secret: KEY,
      });
      await click(saveButton(form));
      expect(api.post.mock.calls[0][1]).toEqual({
        name: "Jump hosts",
        username: "ops",
        auth_method: "key",
        password: null,
        key_content: KEY,
        port: 22,
      });
      const after = registerForm();
      expect(methodSelect(after).value).toBe("key");
      expect(keyInput(after)).toHaveValue("");
    });

    it("a port that parses to nothing is sent as 22", async () => {
      await mount();
      await openCredentials();
      const form = registerForm();
      await fill(form, {
        name: "Zero",
        username: "z",
        port: "0",
        secret: PASS,
      });
      await click(saveButton(form));
      expect(api.post.mock.calls[0][1].port).toBe(22);
    });

    it("a refused save reports the API's detail, then its message, then the error's message, keeps what was typed and re-reads nothing", async () => {
      postReply = () =>
        Promise.reject({
          response: {
            status: 400,
            data: { detail: "A credential with this name already exists" },
          },
          message: "Request failed with status code 400",
        });
      await mount();
      await openCredentials();
      const form = registerForm();
      await fill(form, { name: "Linux fleet", username: "a", secret: PASS });
      const before = credentialReads().length;
      await click(saveButton(form));
      expect(bodyText()).toContain(
        "Failed to save credential: A credential with this name already exists",
      );
      postReply = () =>
        Promise.reject({
          response: { data: { message: "Service unavailable" } },
          message: "x",
        });
      await click(saveButton(form));
      expect(bodyText()).toContain(
        "Failed to save credential: Service unavailable",
      );
      postReply = () => Promise.reject(new Error("Network Error"));
      await click(saveButton(form));
      expect(bodyText()).toContain("Failed to save credential: Network Error");
      expect(textInputs(registerForm())[0]).toHaveValue("Linux fleet");
      expect(passwordInput(registerForm())).toHaveValue(PASS);
      expect(credentialReads().length - before).toBe(0);
    });

    it("a validation refusal, shaped as the API scrubs it, never puts the password or key anywhere in the page but their own fields", async () => {
      postReply = () =>
        Promise.reject({
          response: {
            status: 422,
            data: {
              success: false,
              message: "Request validation failed.",
              detail: [
                {
                  loc: ["body", "password"],
                  msg: "Value error",
                  type: "value_error",
                  ctx: { note: "Value redacted for security." },
                },
              ],
            },
          },
          message: "Request failed with status code 422",
        });
      await mount();
      await openCredentials();
      const form = registerForm();
      await fill(form, { name: "Scrubbed", username: "a", secret: PASS });
      await click(saveButton(form));
      expect(bodyText()).toContain("Failed to save credential:");
      expect(visibleOutsideSecretFields()).not.toContain(PASS);
      await change(methodSelect(registerForm()), "key");
      await change(keyInput(registerForm()), KEY);
      await click(saveButton(registerForm()));
      expect(visibleOutsideSecretFields()).not.toContain(KEY);
    });

    it("after a successful save neither secret is left anywhere in the page", async () => {
      await mount();
      await openCredentials();
      const form = registerForm();
      await fill(form, { name: "Clean", username: "a", secret: PASS });
      await click(saveButton(form));
      expect(document.body.innerHTML).not.toContain(PASS);
      await fill(registerForm(), {
        name: "Clean key",
        username: "b",
        method: "key",
        secret: KEY,
      });
      await click(saveButton(registerForm()));
      expect(document.body.innerHTML).not.toContain(KEY);
    });
  });

  describe("Deleting a credential", () => {
    it("Delete asks first, naming the credential, and declining sends nothing", async () => {
      await mount();
      await openCredentials();
      const asked = await answerDelete("Linux fleet", false);
      expect(asked).toContain("Are you sure you want to delete Linux fleet?");
      expect(api.delete).not.toHaveBeenCalled();
      expect(bodyText()).not.toContain("Credential deleted successfully.");
      expect(rowOf("Linux fleet")).toBeTruthy();
    });

    it("confirming sends one DELETE for that credential with nothing else, says so and re-reads the list", async () => {
      await mount();
      await openCredentials();
      const before = credentialReads().length;
      await answerDelete("Bastion keys", true);
      expect(api.delete.mock.calls).toEqual([
        ["/compliance/credentials/cred-2"],
      ]);
      expect(bodyText()).toContain("Credential deleted successfully.");
      expect(credentialReads().length - before).toBe(1);
      expect(rowOf("Bastion keys")).toBeUndefined();
    });

    it("a refused deletion reports the API's detail, then its message, then the error's message, and keeps the row", async () => {
      deleteReply = () =>
        Promise.reject(
          refusal("Missing permission compliance:manage_integrations"),
        );
      await mount();
      await openCredentials();
      await answerDelete("Linux fleet", true);
      expect(bodyText()).toContain(
        "Delete failed: Missing permission compliance:manage_integrations",
      );
      deleteReply = () =>
        Promise.reject({
          response: { data: { message: "Locked" } },
          message: "x",
        });
      await answerDelete("Linux fleet", true);
      expect(bodyText()).toContain("Delete failed: Locked");
      deleteReply = () => Promise.reject(new Error("Network Error"));
      await answerDelete("Linux fleet", true);
      expect(bodyText()).toContain("Delete failed: Network Error");
      expect(rowOf("Linux fleet")).toBeTruthy();
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 29 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const LEGACY = /^(db-|compliance-form$|mono$)/;
const describedText = (el) =>
  (el.getAttribute("aria-describedby") || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => squash(document.getElementById(id)))
    .join(" ");

describe("ComplianceWorkspace Credentials Manager — batch 29", () => {
  it("the list is a captioned table under a heading, each credential its row's header and its method a badge", async () => {
    await mount();
    await openCredentials();
    expect(
      screen.getByRole("heading", { level: 2, name: "Saved Credentials" }),
    ).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Saved credentials" });
    expect(
      within(table).getByRole("rowheader", { name: "Linux fleet" }),
    ).toBeInTheDocument();
    expect(squash(rowOf("Bastion keys").querySelector(".cc-badge"))).toBe(
      "SSH Key",
    );
    expect(deleteOf("Linux fleet")).toHaveAccessibleName("Delete Linux fleet");
  });

  it("every field is labelled; the password is masked, described, never autofilled and has a named visibility toggle; the key is described", async () => {
    await mount();
    await openCredentials();
    const form = registerForm();
    expect(within(form).getByLabelText(/^Name \/ Nickname/)).toBeRequired();
    expect(within(form).getByLabelText(/^Username/)).toBeRequired();
    expect(within(form).getByLabelText(/^Port/)).toHaveAttribute(
      "type",
      "number",
    );
    expect(within(form).getByLabelText(/^Authentication Method/).tagName).toBe(
      "SELECT",
    );
    const password = within(form).getByLabelText(/^Password/);
    expect(password).toHaveAttribute("type", "password");
    expect(password).toBeRequired();
    expect(password).toHaveAttribute("autocomplete", "new-password");
    expect(describedText(password)).toMatch(/stored encrypted/i);
    const toggle = within(form).getByRole("button", {
      name: "Toggle Password visibility",
    });
    expect(toggle).toHaveAttribute("aria-pressed", "false");

    await change(within(form).getByLabelText(/^Authentication Method/), "key");
    const key = within(registerForm()).getByLabelText(/^Private Key Content/);
    expect(key.tagName).toBe("TEXTAREA");
    expect(key).toBeRequired();
    expect(describedText(key)).toMatch(/stored encrypted/i);
    const clean = [registerForm(), ...registerForm().querySelectorAll("*")];
    expect(clean.filter((el) => el.hasAttribute("style"))).toEqual([]);
    expect(
      clean.flatMap((el) => [...el.classList]).filter((c) => LEGACY.test(c)),
    ).toEqual([]);
  });

  it("Delete opens a dialog naming the credential with Cancel focused; Cancel and Escape send nothing and return focus to Delete", async () => {
    await mount();
    await openCredentials();
    const button = deleteOf("Linux fleet");
    button.focus();
    await click(button);
    await frame();
    const dialog = screen.getByRole("dialog", { name: "Delete credential" });
    expect(squash(dialog)).toContain(
      "Are you sure you want to delete Linux fleet?",
    );
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: "Cancel" }),
    );
    await click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(deleteOf("Linux fleet"));

    deleteOf("Linux fleet").focus();
    await click(deleteOf("Linux fleet"));
    await frame();
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.delete).not.toHaveBeenCalled();
    expect(confirmSpy).not.toHaveBeenCalled();
  });

  it("a deletion in flight is busy, cannot be cancelled or sent twice, and the dialog closes when it settles", async () => {
    const pending = deferred();
    deleteReply = () => pending.promise;
    await mount();
    await openCredentials();
    await click(deleteOf("Linux fleet"));
    const dialog = screen.getByRole("dialog", { name: "Delete credential" });
    const confirm = within(dialog).getByRole("button", {
      name: "Delete credential",
    });
    await click(confirm);
    await click(confirm);
    expect(api.delete).toHaveBeenCalledTimes(1);
    expect(confirm).toBeDisabled();
    expect(confirm).toHaveAttribute("aria-busy", "true");
    expect(
      within(dialog).getByRole("button", { name: "Cancel" }),
    ).toBeDisabled();
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await act(async () => pending.resolve({ data: {} }));
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(bodyText()).toContain("Credential deleted successfully.");
    expect(confirmSpy).not.toHaveBeenCalled();
  });

  it("Save is busy and disabled while the credential is sent, and a second submit sends nothing", async () => {
    const pending = deferred();
    postReply = () => pending.promise;
    await mount();
    await openCredentials();
    const form = registerForm();
    await fill(form, { name: "Busy", username: "a", secret: PASS });
    await click(saveButton(form));
    expect(saveButton(form)).toBeDisabled();
    expect(saveButton(form)).toHaveAttribute("aria-busy", "true");
    fireEvent.submit(form);
    await flush();
    expect(api.post).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve({ data: {} }));
    await flush();
    expect(saveButton(registerForm())).toBeEnabled();
  });

  it("the migrated source uses design-system parts, never the browser's confirm, and its stylesheet is token-only", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-credentials\.css["']/,
    );
    const at = (needle) => {
      const i = source.indexOf(needle);
      expect(i).toBeGreaterThan(-1);
      return i;
    };
    const block = source.slice(
      at('{activeTab === "credentials" && ('),
      at('{activeTab === "approvals" && ('),
    );
    expect(block).not.toMatch(/style=\{/);
    expect(block.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(block).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
    expect(block).not.toMatch(
      /className=["{`][^"}`]*\b(db-|compliance-form|mono\b)/,
    );
    expect(block).not.toMatch(/<(button|input|select|label|table)\b/);
    expect(block).not.toMatch(/window\.confirm/);
    expect(block).toMatch(/<CcurePasswordField\b/);
    expect(block).toMatch(/autoComplete="new-password"/);
    expect(block).toMatch(/<CcureConfirmDialog\b/);
    expect(block).toMatch(/<CcureTable\b/);
    // The one native control left is the key field, which has no primitive.
    expect(block.match(/<textarea\b/g) || []).toHaveLength(1);

    const cssPath = path.join(AUDIT_SRC, "styles/compliance-credentials.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)[a-z0-9-]+/g) || []).toEqual([]);
    expect(css).not.toMatch(/prefers-color-scheme|ux4g|!important/i);
    expect(css).toMatch(/@media \(max-width: 640px\)/);
    const selectors = css
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .split("{")
      .slice(0, -1)
      .map((s) => s.split("}").pop().trim())
      .filter((s) => s && !s.startsWith("@"));
    for (const s of selectors) expect(s).toMatch(/\.cwc-/);
  });
});
