/**
 * ScanCredentials — Checkpoint 3C batch 9 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── The contract this page exists to hold ──────────────────────────────────
 * This is the platform credential store. `api/credentials.js` states the rule
 * in its own header: "A secret goes in and never comes back out." The page
 * enforces the client half of that, and three properties carry it:
 *
 *   * **Editing shows an EMPTY secret field, and empty means "leave
 *     unchanged".** `toPayload` omits `password` / `private_key` unless the
 *     user typed something, so changing a port cannot silently blank the
 *     secret. A masked field that round-tripped the real value is how a
 *     password reaches the DOM and the browser's autofill store.
 *   * **There is no reveal control, and there must not be one.** Nothing is
 *     there to reveal — the server never returns the secret.
 *   * **Validation is a real authentication attempt** against a named target,
 *     and its six reasons stay distinct because they need six different
 *     actions.
 *
 * axiosInstance is mocked rather than `api/credentials`, so the real
 * `toPayload` runs and these assertions pin the bytes that leave the browser.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ScanCredentials from "../../../pages/scan/ScanCredentials";
import axiosInstance from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div data-testid="app-layout">{children}</div>,
}));

const CREDS = [
  {
    id: "c-1",
    name: "Windows admin",
    credential_type: "windows",
    principal: "CORP\\svc_scan",
    username: "svc_scan",
    domain: "CORP",
    auth_method: "ntlm",
    transport: "winrm",
    port: 5985,
    has_secret: true,
    options: {},
  },
  {
    id: "c-2",
    name: "Linux key",
    credential_type: "ssh",
    principal: "root",
    username: "root",
    domain: null,
    auth_method: "key",
    transport: "ssh",
    port: 22,
    has_secret: false,
    options: {},
  },
];

const TYPES = [
  {
    value: "windows",
    label: "Windows",
    auth_methods: ["ntlm", "password"],
    available: true,
  },
  {
    value: "ssh",
    label: "SSH",
    auth_methods: ["password", "key"],
    available: true,
  },
];

const routeGet = (url) => {
  if (url === "/credentials")
    return Promise.resolve({ data: { credentials: CREDS } });
  if (url === "/credentials/types")
    return Promise.resolve({ data: { types: TYPES } });
  return Promise.resolve({ data: {} });
};

const renderPage = async () => {
  const r = render(<ScanCredentials />);
  await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
  return r;
};

/* The credential form is a real dialog now, rendered through a portal into
   document.body — so `container` (the render root) no longer contains it.
   These helpers address the form where it actually lives. That is a change of
   scope, not of assertion: every property checked below is the same one. */
const pwField = () => document.querySelector('input[type="password"]');
const formRoot = () =>
  document.querySelector('[role="dialog"]') || document.body;

const field = (container, labelText, selector = "input") => {
  const byLabel = screen.queryByLabelText(new RegExp(labelText, "i"));
  if (byLabel) return byLabel;
  const lab = [...formRoot().querySelectorAll("label")].find((l) =>
    new RegExp(labelText, "i").test(l.textContent),
  );
  return lab?.querySelector(selector);
};

beforeEach(() => {
  vi.clearAllMocks();
  axiosInstance.get.mockImplementation(routeGet);
  axiosInstance.post.mockResolvedValue({ data: {} });
  axiosInstance.patch.mockResolvedValue({ data: {} });
  axiosInstance.delete.mockResolvedValue({ data: {} });
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — functional", () => {
  it("loads the credential list and the available types", async () => {
    await renderPage();
    await waitFor(() =>
      expect(axiosInstance.get).toHaveBeenCalledWith("/credentials", {
        params: {},
      }),
    );
    expect(axiosInstance.get).toHaveBeenCalledWith("/credentials/types");
  });

  it("renders one row per credential", async () => {
    await renderPage();
    expect(await screen.findByText("Windows admin")).toBeInTheDocument();
    expect(screen.getByText("Linux key")).toBeInTheDocument();
  });

  it("shows the principal, transport and port", async () => {
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    expect(within(row).getByText("CORP\\svc_scan")).toBeInTheDocument();
    expect(within(row).getByText("winrm")).toBeInTheDocument();
    expect(within(row).getByText("5985")).toBeInTheDocument();
  });

  it("marks a credential that has no stored secret", async () => {
    await renderPage();
    const row = (await screen.findByText("Linux key")).closest("tr");
    expect(row.textContent).toMatch(/no secret stored/i);
  });

  it("shows an empty state when there are no credentials", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/credentials"
        ? Promise.resolve({ data: { credentials: [] } })
        : routeGet(url),
    );
    await renderPage();
    expect(await screen.findByText(/no credentials yet/i)).toBeInTheDocument();
  });

  it("opens the create form", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    expect(await screen.findByText(/^username$/i)).toBeInTheDocument();
  });

  it("opens the validate panel for the chosen credential", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /validate/i }));
    expect(container.textContent).toMatch(/validate "Windows admin"/i);
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<ScanCredentials />);
      await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
      const before = axiosInstance.get.mock.calls.length;
      await vi.advanceTimersByTimeAsync(120000);
      expect(axiosInstance.get.mock.calls.length).toBe(before);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECRET HANDLING — the contract
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — secret handling", () => {
  it("offers no control to reveal a secret", async () => {
    /* Deliberately pinned. The server never returns credential material, so
       there is nothing to reveal, and a masked field that round-tripped the
       real value is how a password reaches the DOM. `CcurePasswordField` owns
       a reveal toggle and is therefore the WRONG primitive for this page. */
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    expect(
      screen.queryByRole("button", { name: /show|reveal|toggle|eye/i }),
    ).not.toBeInTheDocument();
  });

  it("renders the secret field as a password control with new-password autocomplete", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    const pw = pwField();
    expect(pw).toBeInTheDocument();
    expect(pw).toHaveAttribute("autoComplete", "new-password");
  });

  it("opens the edit form with an EMPTY secret field", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));
    const pw = pwField();
    expect(pw).toHaveValue("");
  });

  it("omits the password entirely when editing without typing one", async () => {
    /* The whole point of the empty field: changing a port must not blank the
       stored secret. */
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalled());
    const body = axiosInstance.patch.mock.calls[0][1];
    expect(body).not.toHaveProperty("password");
    expect(body).not.toHaveProperty("private_key");
  });

  it("sends the password only when one was typed", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));
    await user.type(pwField(), "s3cret");
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalled());
    expect(axiosInstance.patch.mock.calls[0][1].password).toBe("s3cret");
  });

  it("never puts a secret in the DOM text, an accessible name or a title", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    await user.type(pwField(), "s3cret");
    expect(document.body.textContent).not.toMatch(/s3cret/);
    for (const el of document.body.querySelectorAll("*")) {
      expect(el.getAttribute("aria-label") || "").not.toMatch(/s3cret/);
      expect(el.getAttribute("title") || "").not.toMatch(/s3cret/);
      expect(el.getAttribute("placeholder") || "").not.toMatch(/s3cret/);
    }
  });

  it("does not log a secret when saving fails", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    axiosInstance.post.mockRejectedValue({
      response: { data: { detail: "Name already used." } },
    });
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    await user.type(pwField(), "s3cret");
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const written = errSpy.mock.calls
      .flat()
      .map((a) => (typeof a === "string" ? a : JSON.stringify(a ?? "")))
      .join(" ");
    expect(written).not.toMatch(/s3cret/);
    errSpy.mockRestore();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   API CONTRACT
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — API contract", () => {
  it("creates with POST /credentials and the documented payload shape", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    await user.type(field(container, "^name"), "New cred");
    await user.type(field(container, "^username"), "svc");
    await user.type(pwField(), "pw");
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][0]).toBe("/credentials");
    const body = axiosInstance.post.mock.calls[0][1];
    expect(Object.keys(body).sort()).toEqual([
      "auth_method",
      "credential_type",
      "domain",
      "name",
      "options",
      "password",
      "port",
      "username",
    ]);
  });

  it("updates with PATCH and never sends credential_type", async () => {
    // create-only: it decides the transport.
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalled());
    expect(axiosInstance.patch.mock.calls[0][0]).toBe("/credentials/c-1");
    expect(axiosInstance.patch.mock.calls[0][1]).not.toHaveProperty(
      "credential_type",
    );
  });

  it("sends a blank domain as null rather than an empty string", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    await user.type(field(container, "^name"), "N");
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].domain).toBeNull();
  });

  it("validates against a named target with POST /credentials/:id/validate", async () => {
    axiosInstance.post.mockResolvedValue({
      data: { reason: "authenticated", target: "10.0.0.5" },
    });
    const user = userEvent.setup();
    const { container } = await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /validate/i }));
    const input = container.querySelector('input[placeholder*="Host"]');
    await user.type(input, "10.0.0.5");
    await user.click(screen.getByRole("button", { name: /test now/i }));
    await waitFor(() =>
      expect(axiosInstance.post).toHaveBeenCalledWith(
        "/credentials/c-1/validate",
        { target: "10.0.0.5" },
      ),
    );
  });

  it("will not validate without a target", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /validate/i }));
    expect(screen.getByRole("button", { name: /test now/i })).toBeDisabled();
  });

  it("deletes with DELETE /credentials/:id after confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete|confirm/i }),
    );
    await waitFor(() =>
      expect(axiosInstance.delete).toHaveBeenCalledWith("/credentials/c-1"),
    );
  });

  it("sends no delete when the confirmation is refused", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   VALIDATION RESULT SEMANTICS
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — validation result semantics", () => {
  const runValidate = async (user, container, result) => {
    axiosInstance.post.mockResolvedValue({ data: result });
    const row = screen.getByText("Windows admin").closest("tr");
    await user.click(within(row).getByRole("button", { name: /validate/i }));
    await user.type(container.querySelector('input[placeholder*="Host"]'), "h");
    await user.click(screen.getByRole("button", { name: /test now/i }));
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
  };

  /* Scoped with a leading anchor: the page's own intro text says "used by
     authenticated scans", so a bare /authenticated/i matched twice and failed
     against a page that reports the reason correctly. A wrong assertion, not a
     defect. */
  it.each([
    ["authenticated", /^Authenticated/],
    ["authentication_failed", /authentication failed/i],
    ["insufficient_privileges", /insufficient privileges/i],
    ["unreachable", /unreachable/i],
    ["configuration_error", /configuration problem/i],
  ])("keeps %s distinct", async (reason, expected) => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    await runValidate(user, container, { reason, target: "h" });
    const hits = await screen.findAllByText(expected);
    expect(hits.length).toBeGreaterThanOrEqual(1);
  });

  it("gives an actionable hint for insufficient privileges", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    await runValidate(user, container, {
      reason: "insufficient_privileges",
      target: "h",
    });
    expect(
      await screen.findByText(/Administrators or Remote Management Users/i),
    ).toBeInTheDocument();
  });

  it("does not present a failed validation as success", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    await runValidate(user, container, {
      reason: "authentication_failed",
      target: "h",
    });
    await screen.findByText(/authentication failed/i);
    expect(screen.queryByText(/^Authenticated$/)).not.toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — accessibility", () => {
  it("gives the credential table an accessible name", async () => {
    await renderPage();
    await screen.findByText("Windows admin");
    expect(screen.getByRole("table")).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    await screen.findByText("Windows admin");
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) expect(th.getAttribute("scope")).toBe("col");
  });

  it("marks the credential name as its row's header", async () => {
    await renderPage();
    await screen.findByText("Windows admin");
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(2);
  });

  it("disambiguates each row's action controls", async () => {
    await renderPage();
    await screen.findByText("Windows admin");
    for (const verb of [/validate/i, /edit/i, /delete/i]) {
      const names = screen
        .getAllByRole("button", { name: verb })
        .map((b) => b.getAttribute("aria-label") || b.textContent.trim());
      expect(new Set(names).size).toBe(names.length);
    }
  });

  it("announces the validation result", async () => {
    axiosInstance.post.mockResolvedValue({
      data: { reason: "authentication_failed", target: "h" },
    });
    const user = userEvent.setup();
    const { container } = await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /validate/i }));
    await user.type(container.querySelector('input[placeholder*="Host"]'), "h");
    await user.click(screen.getByRole("button", { name: /test now/i }));
    const live = await screen.findByRole("alert");
    expect(live).toHaveTextContent(/authentication failed/i);
  });

  it("announces the loading state", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/credentials" ? new Promise(() => {}) : routeGet(url),
    );
    render(<ScanCredentials />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|credential/i);
  });

  it("announces a save error rather than only colouring it", async () => {
    axiosInstance.post.mockRejectedValue({
      response: { data: { detail: "Name already used." } },
    });
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    await user.type(field(container, "^name"), "dupe");
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/name already used/i);
  });

  it("names every form control", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    const root = formRoot();
    const controls = root.querySelectorAll(
      "input:not([type=hidden]), select, textarea",
    );
    expect(controls.length).toBeGreaterThan(0);
    for (const el of controls) {
      const named =
        el.getAttribute("aria-label") ||
        el.getAttribute("aria-labelledby") ||
        (el.id && root.querySelector(`label[for="${CSS.escape(el.id)}"]`)) ||
        el.closest("label");
      expect(named).toBeTruthy();
    }
  });

  it("does not skip a heading level", async () => {
    await renderPage();
    await screen.findByText("Windows admin");
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("presents the credential form in a dialog with focus management", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    expect(
      [...container.querySelectorAll("[style]")].map((e) =>
        e.getAttribute("style"),
      ),
    ).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("Windows admin");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   TOAST FEEDBACK — the defect batch 9 found and classified, now fixed
   ──────────────────────────────────────────────────────────────────────────
   `useToasts()` returns { toasts, push, dismiss }. This page destructured
   `addToast`/`removeToast`, so both were undefined and every toast call threw.

   The failure was NOT "a toast is missing". Two of the five call sites sit
   inside their handler's `try`, so the throw was caught by the handler's own
   `catch`:

     * a credential that SAVED SUCCESSFULLY rendered "Could not save the
       credential", left the modal open, and never refreshed the list — so the
       operator retried and created a duplicate;
     * a credential that WAS DELETED left the confirmation dialog open;
     * a failed list load produced no message at all while `finally` cleared
       the loading flag, so a fetch failure rendered as "no credentials".

   Every assertion below is about that observable behaviour, not about the
   presence of a toast element, because the observable behaviour is what a
   regression would break again.
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanCredentials — toast feedback", () => {
  /* An unhandled rejection is reported by vitest at the END of a run and
     attributed to a FILE rather than to a test — which is exactly how this
     defect survived a green 1,002-test suite: 1,002 passed, 1 error, and
     nothing tying the error to the code that caused it. Capturing rejections
     around the action under test turns one into a failing assertion in the
     test that produced it.

     The watcher has to outlive the action by at least one macrotask, because
     Node decides a rejection is unhandled on a later tick. */
  const rejectionsDuring = async (fn) => {
    const seen = [];
    const onReject = (err) => seen.push(err);
    process.on("unhandledRejection", onReject);
    try {
      await fn();
      await new Promise((r) => setTimeout(r, 10));
    } finally {
      process.off("unhandledRejection", onReject);
    }
    return seen.map((e) => String((e && e.message) || e));
  };

  const getsFor = (url) =>
    axiosInstance.get.mock.calls.filter((c) => c[0] === url).length;

  const openCreateForm = async (user, container) => {
    await screen.findByText("Windows admin");
    await user.click(screen.getByRole("button", { name: /new credential/i }));
    await user.type(field(container, "^name"), "New cred");
    await user.type(field(container, "^username"), "svc");
    await user.type(pwField(), "pw");
  };

  const confirmDeleteOf = async (user, name) => {
    const row = (await screen.findByText(name)).closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete|confirm/i }),
    );
  };

  /* ── SAVE ──────────────────────────────────────────────────────────────── */

  it("reports a successful save as a success, not as a failure", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await openCreateForm(user, container);
    const before = getsFor("/credentials");

    const rejections = await rejectionsDuring(async () => {
      await user.click(screen.getByRole("button", { name: /^save$/i }));
      await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    });

    // Exactly one mutation — a false failure is what invites the retry that
    // creates a duplicate, so "one POST" is the property that matters.
    expect(axiosInstance.post).toHaveBeenCalledTimes(1);
    expect(axiosInstance.post.mock.calls[0][0]).toBe("/credentials");

    // The success is announced.
    expect(await screen.findByText(/created\./i)).toBeInTheDocument();

    // The error path is NOT entered.
    expect(screen.queryByText(/could not save/i)).not.toBeInTheDocument();

    // The modal closes and the list is refreshed.
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await waitFor(() =>
      expect(getsFor("/credentials")).toBeGreaterThan(before),
    );

    expect(rejections).toEqual([]);
  });

  it("reports an update as an update", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Windows admin")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));

    const rejections = await rejectionsDuring(async () => {
      await user.click(screen.getByRole("button", { name: /^save$/i }));
      await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalled());
    });

    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/updated\./i)).toBeInTheDocument();
    expect(screen.queryByText(/could not save/i)).not.toBeInTheDocument();
    expect(rejections).toEqual([]);
  });

  it("reports a failed save as a failure and keeps the form open", async () => {
    axiosInstance.post.mockRejectedValue({
      response: { data: { detail: "A credential with that name exists." } },
    });
    const user = userEvent.setup();
    const { container } = await renderPage();
    await openCreateForm(user, container);

    const rejections = await rejectionsDuring(async () => {
      await user.click(screen.getByRole("button", { name: /^save$/i }));
      await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    });

    expect(
      await screen.findByText(/a credential with that name exists/i),
    ).toBeInTheDocument();
    // No false success: the create toast must not appear.
    expect(screen.queryByText(/created\./i)).not.toBeInTheDocument();
    // The form stays open so the operator can correct it.
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(rejections).toEqual([]);
  });

  /* ── DELETE ────────────────────────────────────────────────────────────── */

  it("reports a successful delete and closes the confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const before = getsFor("/credentials");

    const rejections = await rejectionsDuring(async () => {
      await confirmDeleteOf(user, "Windows admin");
      await waitFor(() => expect(axiosInstance.delete).toHaveBeenCalled());
    });

    expect(axiosInstance.delete).toHaveBeenCalledTimes(1);
    expect(axiosInstance.delete.mock.calls[0][0]).toBe("/credentials/c-1");
    expect(await screen.findByText(/deleted\./i)).toBeInTheDocument();

    // The dialog must close — leaving it open on a credential that IS gone is
    // how the operator is invited to delete it a second time.
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await waitFor(() =>
      expect(getsFor("/credentials")).toBeGreaterThan(before),
    );
    expect(rejections).toEqual([]);
  });

  it("surfaces the warning a delete returns rather than a bare success", async () => {
    /* The API answers a delete that orphans a schedule with a note. It is the
       one sentence that tells the operator a scheduled scan will now fail
       rather than silently running unauthenticated, so it must reach them. */
    axiosInstance.delete.mockResolvedValue({
      data: {
        note: "2 schedules now have no credential.",
        schedules_affected: 2,
      },
    });
    const user = userEvent.setup();
    await renderPage();

    const rejections = await rejectionsDuring(async () => {
      await confirmDeleteOf(user, "Windows admin");
      await waitFor(() => expect(axiosInstance.delete).toHaveBeenCalled());
    });

    expect(
      await screen.findByText(/2 schedules now have no credential/i),
    ).toBeInTheDocument();
    expect(rejections).toEqual([]);
  });

  it("reports a failed delete as a failure", async () => {
    axiosInstance.delete.mockRejectedValue({
      response: { data: { detail: "Credential is in use by a running scan." } },
    });
    const user = userEvent.setup();
    await renderPage();

    const rejections = await rejectionsDuring(async () => {
      await confirmDeleteOf(user, "Windows admin");
      await waitFor(() => expect(axiosInstance.delete).toHaveBeenCalled());
    });

    expect(
      await screen.findByText(/in use by a running scan/i),
    ).toBeInTheDocument();
    // The credential is still listed — it was not deleted.
    expect(screen.getByText("Windows admin")).toBeInTheDocument();
    expect(rejections).toEqual([]);
  });

  /* ── LOAD ──────────────────────────────────────────────────────────────── */

  it("does not present a failed list load as an empty credential list", async () => {
    /* The dangerous shape: `finally` clears the loading flag whatever happened,
       so a fetch failure renders the empty state. "You have no credentials" and
       "we could not read your credentials" are different facts, and only one of
       them should make an operator create a second credential. */
    axiosInstance.get.mockImplementation((url) => {
      if (url === "/credentials")
        return Promise.reject({
          response: { data: { detail: "Credential service unavailable." } },
        });
      if (url === "/credentials/types")
        return Promise.resolve({ data: { types: TYPES } });
      return Promise.resolve({ data: {} });
    });

    const rejections = await rejectionsDuring(async () => {
      render(<ScanCredentials />);
      await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
    });

    expect(
      await screen.findByText(/credential service unavailable/i),
    ).toBeInTheDocument();
    expect(rejections).toEqual([]);
  });

  /* ── THE CONTAINER ─────────────────────────────────────────────────────── */

  it("wires the toast container's dismiss handler", async () => {
    /* `ToastContainer({ toasts, dismiss })`. The page passed `removeToast=`,
       which React silently ignored, so `dismiss` was undefined and clicking a
       toast threw. Asserted by clicking one. */
    const user = userEvent.setup();
    const { container } = await renderPage();
    await openCreateForm(user, container);
    await user.click(screen.getByRole("button", { name: /^save$/i }));
    const toast = await screen.findByText(/created\./i);

    const rejections = await rejectionsDuring(async () => {
      await user.click(toast);
    });

    expect(rejections).toEqual([]);
  });
});
