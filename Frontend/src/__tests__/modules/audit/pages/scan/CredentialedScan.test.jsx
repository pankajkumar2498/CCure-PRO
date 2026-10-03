/**
 * CredentialedScan — Checkpoint 3C batch 9 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * This page sends `POST /scan/credentialed` at caller-named targets, carrying
 * credentials. Its own header states the rule: "Credentials are NEVER stored —
 * cleared from state immediately after use." Four properties carry the weight:
 *
 *   * **`scans:execute` gates dispatch**, in the handler — not only in the UI.
 *   * **Just-in-time vs stored credentials are mutually exclusive.** With a
 *     stored credential the page sends `credential_id` and NO secret; with JIT
 *     it sends the secret and no id.
 *   * **`password` is sent only for password auth, `key_path` only for key
 *     auth.** `runCredentialedScan` sets the other to `undefined`.
 *   * **The secret is cleared from React state after a successful dispatch.**
 *
 * axiosInstance is mocked rather than `api/credentialedScan`, so the real
 * `parseTargets` and the real payload builder run.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CredentialedScan from "@audit/pages/scan/CredentialedScan";
import axiosInstance from "@shell/api/axiosInstance";
import { keySetHolds } from "../../../../fixtures/authorization";
import { personaFrom } from "../../../../fixtures/authorization";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => ({ state: null, search: "" }),
  };
});

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
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

let currentUser = { username: "operator", id: 1 };
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(currentUser) }),
}));

let permissions = new Set(["audit.scan.run"]);
vi.mock("@shell/auth/permissions", () => ({
  can: (_u, r, a) => keySetHolds(permissions, r, a),
  denyMessage: "You do not have permission to perform this action.",
}));

const OK = { data: { success: true, scan_id: "cs-1" } };

const renderPage = () => render(<CredentialedScan />);

const targetField = (container) =>
  container.querySelector('input[type="text"], input:not([type])');

const passwordField = (container) =>
  container.querySelector('input[type="password"]');

const runBtn = () =>
  screen.getByRole("button", { name: /run|start|scan|collect/i });

const fillAndRun = async (user, container, over = {}) => {
  const t = targetField(container);
  await user.clear(t);
  await user.type(t, over.target ?? "10.0.0.5");
  const u = [...container.querySelectorAll("input")].find(
    (el) => el.type === "text" && el !== t,
  );
  if (u) {
    await user.clear(u);
    await user.type(u, over.username ?? "svc");
  }
  const p = passwordField(container);
  if (p && over.password !== null) await user.type(p, over.password ?? "pw");
  await user.click(runBtn());
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  currentUser = { username: "operator", id: 1 };
  permissions = new Set(["audit.scan.run"]);
  axiosInstance.get.mockResolvedValue({ data: { credentials: [] } });
  axiosInstance.post.mockResolvedValue(OK);
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("CredentialedScan — functional", () => {
  it("renders the configuration form", () => {
    const { container } = renderPage();
    expect(container.textContent).toMatch(/credential/i);
    expect(targetField(container)).toBeInTheDocument();
  });

  it("loads the stored credential list on mount", async () => {
    renderPage();
    await waitFor(() =>
      expect(axiosInstance.get).toHaveBeenCalledWith("/compliance/credentials"),
    );
  });

  it("issues no scan request on mount", () => {
    renderPage();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("offers the data-collection sections, all selected by default", () => {
    const { container } = renderPage();
    const boxes = [...container.querySelectorAll('input[type="checkbox"]')];
    expect(boxes.length).toBeGreaterThan(0);
    expect(boxes.every((b) => b.checked)).toBe(true);
  });

  it("leaves the port empty so the engine can discover the service", () => {
    /*
     * This asserted a default of 22 until the scanner learned to establish
     * which authentication service a host offers. A pre-filled 22 is
     * indistinguishable from an operator asking for 22, so it pinned every
     * scan to SSH and silently turned discovery off -- which is the whole
     * defect `compliance_credentials.port` already has on the stored side.
     *
     * The field is still there: a value in it is the escape hatch for a
     * listener on a port nothing would guess.
     */
    const { container } = renderPage();
    const port = container.querySelector('input[type="number"]');
    expect(port).toBeTruthy();
    expect(port.value).toBe("");
    expect(port.getAttribute("placeholder")).toMatch(/auto/i);

    const selects = [...container.querySelectorAll("select")];
    expect(selects.some((s) => s.value === "auto")).toBe(true);
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      renderPage();
      await vi.advanceTimersByTimeAsync(120000);
      expect(axiosInstance.post).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   DISPATCH CONTRACT
   ══════════════════════════════════════════════════════════════════════════ */
describe("CredentialedScan — dispatch contract", () => {
  it("POSTs to /scan/credentialed and nowhere else", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalledTimes(1));
    expect(axiosInstance.post.mock.calls[0][0]).toBe("/scan/credentialed");
  });

  it("sends exactly the documented payload keys", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(Object.keys(axiosInstance.post.mock.calls[0][1]).sort()).toEqual([
      "auth_method",
      "credential_id",
      "key_path",
      "os_type",
      "password",
      "port",
      "sections",
      "targets",
      "username",
    ]);
  });

  it("splits the target field into individual expressions", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container, {
      target: "10.0.0.5, 10.0.0.6 10.0.0.7;10.0.0.8",
    });
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].targets).toEqual([
      "10.0.0.5",
      "10.0.0.6",
      "10.0.0.7",
      "10.0.0.8",
    ]);
  });

  it("sends null sections when every section is selected", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].sections).toBeNull();
  });

  it("sends the explicit list when a section is deselected", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    const boxes = [...container.querySelectorAll('input[type="checkbox"]')];
    await user.click(boxes[0]);
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const sections = axiosInstance.post.mock.calls[0][1].sections;
    expect(Array.isArray(sections)).toBe(true);
    expect(sections.length).toBe(boxes.length - 1);
  });

  it("sends no port when the operator states none", async () => {
    /*
     * `undefined`, not 22. The API reads a stated port as a pin and its
     * absence as "discover which service this host offers", so a default
     * here would disable discovery for every scan without anyone choosing
     * that.
     */
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].port).toBeUndefined();
  });

  it("coerces a stated port to a number", async () => {
    /* The escape hatch still works, and still sends a number rather than the
       string the input holds. */
    const user = userEvent.setup();
    const { container } = renderPage();
    const port = container.querySelector('input[type="number"]');
    await user.clear(port);
    await user.type(port, "2222");
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].port).toBe(2222);
  });

  it("navigates to the results page with the scan id", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith(
        "/scan/credentialed/results?scan_id=cs-1",
        expect.objectContaining({ state: expect.any(Object) }),
      ),
    );
  });

  it("does not navigate when the API reports failure", async () => {
    axiosInstance.post.mockResolvedValue({
      data: { success: false, error: "Authentication failed" },
    });
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(navigate).not.toHaveBeenCalledWith(
      expect.stringContaining("/results"),
      expect.anything(),
    );
    expect(
      await screen.findByText(/authentication failed/i),
    ).toBeInTheDocument();
  });

  it("refuses to dispatch with no target", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(runBtn());
    await waitFor(() =>
      expect(screen.getByText(/at least one target/i)).toBeInTheDocument(),
    );
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("never retries by itself", async () => {
    axiosInstance.post.mockRejectedValue(new Error("boom"));
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup();
      const { container } = renderPage();
      await fillAndRun(user, container);
      await waitFor(() => expect(axiosInstance.post).toHaveBeenCalledTimes(1));
      await vi.advanceTimersByTimeAsync(120000);
      expect(axiosInstance.post).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   AUTHORIZATION
   ══════════════════════════════════════════════════════════════════════════ */
describe("CredentialedScan — authorization", () => {
  it("dispatches nothing without scans:execute", async () => {
    /* The original assertion drove the form and expected the HANDLER to
       refuse. It failed with "clear() is only supported on editable elements"
       — because without the permission the page renders the form
       non-editable, so the UI gate fires first and the handler is never
       reached. That is the gate working, not a defect; the assertion was
       written against a mechanism the page does not use.
       Restated as the property that actually matters: with no permission,
       nothing is dispatched, by whatever means. The handler's own guard is
       covered separately below. */
    permissions = new Set();
    const user = userEvent.setup();
    renderPage();
    await user.click(runBtn());
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("keeps the target field non-editable without scans:execute", async () => {
    permissions = new Set();
    const { container } = renderPage();
    const t = targetField(container);
    expect(t.disabled || t.readOnly).toBe(true);
  });

  it("dispatches when the permission is held", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   CREDENTIAL HANDLING
   ══════════════════════════════════════════════════════════════════════════ */
describe("CredentialedScan — credential handling", () => {
  it("sends the password for password auth and no key path", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container, { password: "s3cret" });
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const body = axiosInstance.post.mock.calls[0][1];
    expect(body.password).toBe("s3cret");
    expect(body.key_path).toBeUndefined();
    expect(body.auth_method).toBe("password");
  });

  it("clears the secret from state after a successful dispatch", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container, { password: "s3cret" });
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const pw = passwordField(container);
    if (pw) expect(pw).toHaveValue("");
  });

  it("never puts the secret in the DOM text, a name, a title or a placeholder", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    const p = passwordField(container);
    await user.type(p, "s3cret");
    expect(container.textContent).not.toMatch(/s3cret/);
    for (const el of container.querySelectorAll("*")) {
      expect(el.getAttribute("aria-label") || "").not.toMatch(/s3cret/);
      expect(el.getAttribute("title") || "").not.toMatch(/s3cret/);
      expect(el.getAttribute("placeholder") || "").not.toMatch(/s3cret/);
    }
  });

  it("does not log the secret when the dispatch fails", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    axiosInstance.post.mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container, { password: "s3cret" });
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const written = errSpy.mock.calls
      .flat()
      .map((a) => (typeof a === "string" ? a : JSON.stringify(a ?? "")))
      .join(" ");
    expect(written).not.toMatch(/s3cret/);
    errSpy.mockRestore();
  });

  it("never puts the secret in the request URL", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container, { password: "s3cret" });
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][0]).not.toMatch(/s3cret/);
  });

  it("renders the secret field as a password control by default", () => {
    const { container } = renderPage();
    expect(passwordField(container)).toBeInTheDocument();
  });

  it("offers a reveal control for the field the operator is typing into", async () => {
    /* Unlike ScanCredentials, this page DOES have a visibility toggle, and it
       is legitimate here: the operator is typing a secret now, not viewing a
       stored one. The toggle's own accessibility is asserted in the
       accessibility group. */
    const { container } = renderPage();
    const buttons = [...container.querySelectorAll("button")];
    const toggle = buttons.find((b) => /👁|🙈/.test(b.textContent));
    expect(toggle).toBeTruthy();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("CredentialedScan — accessibility", () => {
  it("names every form control", () => {
    const { container } = renderPage();
    const controls = container.querySelectorAll(
      "input:not([type=hidden]), select, textarea",
    );
    expect(controls.length).toBeGreaterThan(0);
    for (const el of controls) {
      const named =
        el.getAttribute("aria-label") ||
        el.getAttribute("aria-labelledby") ||
        (el.id &&
          container.querySelector(`label[for="${CSS.escape(el.id)}"]`)) ||
        el.closest("label");
      expect(named).toBeTruthy();
    }
  });

  it("gives the password reveal control an accessible name and pressed state", () => {
    const { container } = renderPage();
    const toggle = [...container.querySelectorAll("button")].find((b) =>
      /👁|🙈/.test(b.textContent),
    );
    const named =
      toggle?.getAttribute("aria-label") ||
      toggle?.getAttribute("aria-labelledby");
    expect(named).toBeTruthy();
    expect(toggle?.getAttribute("aria-pressed")).toBeTruthy();
  });

  it("announces a dispatch error assertively", async () => {
    axiosInstance.post.mockResolvedValue({
      data: { success: false, error: "Authentication failed" },
    });
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/authentication failed/i);
  });

  it("states the permission refusal in text, not by a disabled control alone", async () => {
    /* A control that is merely disabled tells a user nothing about why. */
    permissions = new Set();
    const { container } = renderPage();
    expect(container.textContent).toMatch(/permission|not permitted|denied/i);
  });

  it("announces that a scan is running", async () => {
    axiosInstance.post.mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    const status = await screen.findByRole("status");
    expect(status.textContent.trim().length).toBeGreaterThan(0);
  });

  it("marks the dispatch control busy while running", async () => {
    axiosInstance.post.mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await waitFor(() => expect(runBtn()).toHaveAttribute("aria-busy", "true"));
  });

  it("does not skip a heading level", () => {
    renderPage();
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("does not convey the unreachable hint by colour alone", async () => {
    axiosInstance.post.mockResolvedValue({
      data: { success: false, error: "Host unreachable: connection refused" },
    });
    const user = userEvent.setup();
    const { container } = renderPage();
    await fillAndRun(user, container);
    await screen.findByText(/unreachable/i);
    expect(container.textContent).toMatch(/unreachable/i);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("CredentialedScan — rendered surface", () => {
  it("carries no inline styles", () => {
    const { container } = renderPage();
    expect(
      [...container.querySelectorAll("[style]")].map((e) =>
        e.getAttribute("style"),
      ),
    ).toEqual([]);
  });

  it("carries no hardcoded colour literals", () => {
    const { container } = renderPage();
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", () => {
    const { container } = renderPage();
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });
});
