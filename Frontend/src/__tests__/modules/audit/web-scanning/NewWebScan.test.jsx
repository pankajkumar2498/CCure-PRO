/**
 * NewWebScan — Checkpoint 3C batch 7 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Why this page gets its own batch ────────────────────────────────────────
 * This is the web-scanning dispatch surface. CLAUDE.md records what sits behind
 * it: `POST /web-scans` sends ffuf and nuclei at a **caller-named target**, and
 * "an unbounded loop there is an unbounded outbound attack wearing this host's
 * address". Everything on this form decides what this host does to somebody
 * else's machine.
 *
 * ── Why axiosInstance is mocked, not webScansApi ────────────────────────────
 * Mocking `webScansApi` would only prove what the page hands the API module.
 * The things that actually matter here — the endpoint, the wire payload shape,
 * the `Idempotency-Key` header, and above all the `btoa` credential encoding —
 * all live inside `normalizeStartPayload` / `normalizeAuthConfig`. Mocking one
 * layer lower lets the real ones run, so these assertions pin the bytes that
 * leave the browser rather than an intermediate object.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import NewWebScan from "@audit/web-scanning/pages/NewWebScan";
import axiosInstance from "@shell/api/axiosInstance";
import { personaFrom } from "../../../fixtures/authorization";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    post: vi.fn(),
    get: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

/* ── Permissions (Phase 1, finding F2) ───────────────────────────────────────
   The API now requires scans:execute to launch or cancel a web scan,
   findings:update to triage and findings:accept_risk to accept a risk, and the
   page no longer offers what the API would refuse. Every test runs as a user
   holding all of them unless it swaps `authState.user` — the deny-path tests
   at the end of this file do, and restore it afterwards. */
const FULL_PERMISSION_USER = {
  role: { name: "analyst" },
  permissionKeys: [
    "audit.scan.read",
    "audit.scan.run",
    "audit.finding.read",
    "audit.finding.update",
    "audit.finding.accept_risk",
  ],
};
const VIEWER_USER = {
  role: { name: "viewer" },
  permissionKeys: ["audit.scan.read", "audit.finding.read"],
};
const authState = vi.hoisted(() => ({ user: null }));
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(authState.user) }),
}));
authState.user = FULL_PERMISSION_USER;

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

/* ── Field accessors ────────────────────────────────────────────────────────
   Anchored by accessible name where the migration provides one, and by a
   structural fallback while it does not. The pre-migration page renders ten
   `<label>` elements and **not one carries `htmlFor`**, and every input is the
   label's *sibling* rather than its child — so none of the text fields has an
   accessible name at all. That is asserted directly in the accessibility group;
   these helpers exist so the functional and security groups can still address
   the fields on both sides of the migration. */
const byLabelOrOrder = (container, labelText, selector, index) => {
  const named = screen.queryByLabelText(new RegExp(labelText, "i"));
  if (named) return named;
  return container.querySelectorAll(selector)[index];
};

const fields = (container) => ({
  scanName: byLabelOrOrder(container, "^scan name", "input[type='text']", 0),
  targetUrl: byLabelOrOrder(container, "^target url", "input[type='url']", 0),
  depth: byLabelOrOrder(container, "crawl depth", "input[type='number']", 0),
  concurrency: byLabelOrOrder(
    container,
    "concurrency",
    "input[type='number']",
    1,
  ),
  subdomains: byLabelOrOrder(
    container,
    "subdomain",
    "input[type='checkbox']",
    0,
  ),
  authType: screen.getByRole("combobox"),
  authorization: byLabelOrOrder(
    container,
    "authorization",
    "input[type='checkbox']",
    1,
  ),
});

/* The submit control's TEXT changes to "Starting Scan..." while a launch is in
   flight, so a name-anchored query stops finding it exactly when the loading
   assertions need it. Anchored on the submit role instead, which is stable on
   both sides of the migration. */
const launch = () =>
  screen.getByRole("button", { name: /launch scan|starting scan/i });
const cancel = () => screen.getByRole("button", { name: /cancel/i });

/** Fill the two required fields and tick the authorization agreement. */
const fillMinimum = async (user, container, over = {}) => {
  const f = fields(container);
  await user.clear(f.scanName);
  await user.type(f.scanName, over.scan_name ?? "Production API Audit");
  await user.clear(f.targetUrl);
  await user.type(f.targetUrl, over.target_url ?? "https://example.test");
  if (over.authorize !== false) await user.click(f.authorization);
  return f;
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  axiosInstance.post.mockResolvedValue({ data: { id: "ws-new-1" } });
  // Deterministic idempotency key so the header can be asserted exactly.
  vi.stubGlobal("crypto", { randomUUID: () => "fixed-uuid-0001" });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("NewWebScan — functional", () => {
  it("renders the three configuration sections", async () => {
    render(<NewWebScan />);
    expect(screen.getByText(/target details/i)).toBeInTheDocument();
    expect(screen.getByText(/crawler options/i)).toBeInTheDocument();
    expect(screen.getByText(/^authentication$/i)).toBeInTheDocument();
  });

  it("starts with authentication set to none", () => {
    render(<NewWebScan />);
    expect(screen.getByRole("combobox")).toHaveValue("none");
  });

  it("offers exactly the four authentication modes", () => {
    render(<NewWebScan />);
    const values = [...screen.getByRole("combobox").options].map(
      (o) => o.value,
    );
    expect(values).toEqual(["none", "bearer", "cookie", "basic"]);
  });

  it("shows no credential fields for the none mode", () => {
    const { container } = render(<NewWebScan />);
    expect(container.querySelectorAll("input[type='password']").length).toBe(0);
    expect(screen.queryByText(/^token$/i)).not.toBeInTheDocument();
  });

  it("reveals a single token field for bearer", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "bearer");
    expect(screen.getByText(/^token$/i)).toBeInTheDocument();
    expect(container.querySelectorAll("input[type='password']").length).toBe(0);
  });

  it("reveals a cookie-string field for cookie", async () => {
    const user = userEvent.setup();
    render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "cookie");
    expect(screen.getByText(/cookie string/i)).toBeInTheDocument();
  });

  it("reveals username and password fields for basic", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    expect(screen.getByText(/^username$/i)).toBeInTheDocument();
    expect(screen.getByText(/^password$/i)).toBeInTheDocument();
    expect(container.querySelectorAll("input[type='password']").length).toBe(1);
  });

  it("defaults crawl depth to 3 and concurrency to 10", () => {
    const { container } = render(<NewWebScan />);
    const f = fields(container);
    expect(f.depth).toHaveValue(3);
    expect(f.concurrency).toHaveValue(10);
  });

  it("bounds crawl depth and concurrency", () => {
    const { container } = render(<NewWebScan />);
    const f = fields(container);
    expect(f.depth).toHaveAttribute("min", "1");
    expect(f.depth).toHaveAttribute("max", "10");
    expect(f.concurrency).toHaveAttribute("min", "1");
    expect(f.concurrency).toHaveAttribute("max", "50");
  });

  it("marks scan name and target URL required", () => {
    const { container } = render(<NewWebScan />);
    const f = fields(container);
    expect(f.scanName).toBeRequired();
    expect(f.targetUrl).toBeRequired();
  });

  it("uses a url-typed control for the target", () => {
    const { container } = render(<NewWebScan />);
    expect(fields(container).targetUrl).toHaveAttribute("type", "url");
  });

  it("keeps the launch button disabled until authorization is confirmed", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    expect(launch()).toBeDisabled();
    await user.click(fields(container).authorization);
    expect(launch()).toBeEnabled();
  });

  it("navigates back when cancelled", async () => {
    const user = userEvent.setup();
    render(<NewWebScan />);
    await user.click(cancel());
    expect(navigate).toHaveBeenCalledWith(-1);
  });

  it("navigates to the created scan on success, replacing history", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/web-scans/ws-new-1", {
        replace: true,
      }),
    );
  });

  it("accepts web_scan_id as the returned identifier", async () => {
    axiosInstance.post.mockResolvedValue({ data: { web_scan_id: "ws-alt" } });
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/web-scans/ws-alt", {
        replace: true,
      }),
    );
  });

  it("accepts a nested data.id as the returned identifier", async () => {
    axiosInstance.post.mockResolvedValue({ data: { data: { id: "ws-nest" } } });
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/web-scans/ws-nest", {
        replace: true,
      }),
    );
  });

  it("announces progress while the scan is being created", async () => {
    let settle;
    axiosInstance.post.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ data: { id: "ws-new-1" } });
        }),
    );
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    expect(
      await screen.findByText(/creating the scan record/i),
    ).toBeInTheDocument();
    settle();
  });

  it("disables the launch button while a scan is being created", async () => {
    axiosInstance.post.mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(launch()).toBeDisabled());
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<NewWebScan />);
      await vi.advanceTimersByTimeAsync(120000);
      expect(axiosInstance.post).not.toHaveBeenCalled();
      expect(axiosInstance.get).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("issues no network request on mount", () => {
    render(<NewWebScan />);
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.get).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY — dispatch contract
   ══════════════════════════════════════════════════════════════════════════ */
describe("NewWebScan — dispatch contract", () => {
  it("POSTs to /web-scans and nowhere else", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalledTimes(1));
    expect(axiosInstance.post.mock.calls[0][0]).toBe("/web-scans");
  });

  it("sends exactly the documented payload keys", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const body = axiosInstance.post.mock.calls[0][1];
    expect(Object.keys(body).sort()).toEqual([
      "auth",
      "authorization_confirmed",
      "options",
      "scan_name",
      "scan_scope",
      "target_url",
    ]);
    expect(Object.keys(body.scan_scope).sort()).toEqual([
      "exclude_paths",
      "include_subdomains",
      "max_depth",
    ]);
    expect(Object.keys(body.options).sort()).toEqual([
      "enable_sqli",
      "enable_xss",
      "nuclei_severity",
      "rate_limit",
    ]);
  });

  it("sends the target exactly as typed", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container, {
      target_url: "https://portal.example.test/app",
    });
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].target_url).toBe(
      "https://portal.example.test/app",
    );
  });

  it("sends authorization_confirmed true once the agreement is ticked", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].authorization_confirmed).toBe(
      true,
    );
  });

  it("sends the scan defaults the API expects", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const body = axiosInstance.post.mock.calls[0][1];
    expect(body.scan_scope).toEqual({
      include_subdomains: false,
      exclude_paths: [],
      max_depth: 3,
    });
    expect(body.options).toEqual({
      enable_sqli: true,
      enable_xss: true,
      nuclei_severity: ["medium", "high", "critical"],
      rate_limit: 10,
    });
  });

  it("carries crawl depth into max_depth and concurrency into rate_limit", async () => {
    /* `fireEvent.change` rather than clear()+type(). Measured on the
       unmigrated page: clearing the field fires onChange with "", the handler's
       `parseInt("") || 3` snaps the value back to 3, and the subsequent
       keystroke appends — so clear()+type("7") yields **37**, which fails
       checkValidity() against max="10" and silently blocks submission. That is
       a real defect in the page (recorded under out-of-scope findings, since
       fixing it would change validation behaviour), but it made this assertion
       wrong: it was testing my typing technique, not the payload mapping. A
       single change event is what selecting-all-and-typing actually produces. */
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    const f = await fillMinimum(user, container);
    fireEvent.change(f.depth, { target: { value: "7" } });
    fireEvent.change(f.concurrency, { target: { value: "25" } });
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const body = axiosInstance.post.mock.calls[0][1];
    expect(body.scan_scope.max_depth).toBe(7);
    expect(body.options.rate_limit).toBe(25);
  });

  it("carries the subdomain choice into scan_scope", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    const f = await fillMinimum(user, container);
    await user.click(f.subdomains);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(
      axiosInstance.post.mock.calls[0][1].scan_scope.include_subdomains,
    ).toBe(true);
  });

  it("sends an Idempotency-Key header", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][2]).toEqual({
      headers: { "Idempotency-Key": "fixed-uuid-0001" },
    });
  });

  it("refuses to dispatch without the authorization agreement", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container, { authorize: false });
    // The control is disabled, so the form cannot even be submitted.
    expect(launch()).toBeDisabled();
    await user.click(launch());
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("dispatches at most once per click, even on a double click", async () => {
    axiosInstance.post.mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.dblClick(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalledTimes(1));
  });

  it("does not dispatch again after a successful launch", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    await user.click(launch());
    expect(axiosInstance.post).toHaveBeenCalledTimes(1);
  });

  it("issues a fresh idempotency key after a failed attempt", async () => {
    /* Recorded as the existing behaviour, not endorsed: `launchKeyRef` is
       cleared in the catch, so a retry is a NEW logical request rather than a
       replay of the failed one. That is right when the request never reached
       the API and wrong when it did and the response was lost. It is listed
       under out-of-scope findings; the assertion pins today's behaviour so the
       migration cannot change it silently. */
    const keys = [];
    let n = 0;
    vi.stubGlobal("crypto", { randomUUID: () => `uuid-${++n}` });
    axiosInstance.post.mockImplementation((_url, _body, cfg) => {
      keys.push(cfg.headers["Idempotency-Key"]);
      return Promise.reject(new Error("boom"));
    });
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(keys.length).toBe(1));
    await user.click(launch());
    await waitFor(() => expect(keys.length).toBe(2));
    expect(keys[0]).not.toBe(keys[1]);
  });

  it("adds no query parameter to the dispatch", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][0]).not.toMatch(/[?&]/);
    expect(axiosInstance.post.mock.calls[0][2]?.params).toBeUndefined();
  });

  it("makes no other network call while launching", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.get).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY — credential handling
   ══════════════════════════════════════════════════════════════════════════ */
describe("NewWebScan — credential handling", () => {
  it("sends type none with no credential material when unauthenticated", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].auth).toEqual({ type: "none" });
  });

  it("maps bearer onto bearer_token, carrying the token verbatim", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "bearer");
    const token = container.querySelectorAll("input[type='text']")[1];
    await user.type(token, "eyJhbGciOi.SECRET.sig");
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].auth).toEqual({
      type: "bearer_token",
      token: "eyJhbGciOi.SECRET.sig",
    });
  });

  it("parses a cookie string into a map", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "cookie");
    const token = container.querySelectorAll("input[type='text']")[1];
    await user.type(token, "session=abc123; csrf=def456");
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].auth).toEqual({
      type: "cookie",
      cookies: { session: "abc123", csrf: "def456" },
    });
  });

  it("encodes basic credentials with btoa, unchanged", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    const texts = container.querySelectorAll("input[type='text']");
    await user.type(texts[texts.length - 1], "scanuser");
    await user.type(
      container.querySelector("input[type='password']"),
      "hunter2",
    );
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][1].auth).toEqual({
      type: "custom_header",
      headers: { Authorization: `Basic ${btoa("scanuser:hunter2")}` },
    });
  });

  it("renders the password field as a password control", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    const pw = container.querySelector("input[type='password']");
    expect(pw).toBeInTheDocument();
    await user.type(pw, "hunter2");
    expect(pw).toHaveAttribute("type", "password");
  });

  it("offers no way to reveal the password", async () => {
    /* Pinning the CURRENT behaviour deliberately. The brief for this batch
       requires password visibility behaviour to remain identical, so
       CcurePasswordField — which owns a visibility toggle, a caps-lock warning
       and a strength meter — is the wrong primitive here and must not be
       introduced. */
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    expect(
      screen.queryByRole("button", { name: /show|reveal|toggle/i }),
    ).not.toBeInTheDocument();
    expect(container.querySelector("input[type='password']")).toBeTruthy();
  });

  it("never puts a credential in the request URL", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    const texts = container.querySelectorAll("input[type='text']");
    await user.type(texts[texts.length - 1], "scanuser");
    await user.type(
      container.querySelector("input[type='password']"),
      "hunter2",
    );
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    expect(axiosInstance.post.mock.calls[0][0]).not.toMatch(/hunter2|scanuser/);
  });

  it("never puts a credential in an accessible name or visible text", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    await user.type(
      container.querySelector("input[type='password']"),
      "hunter2",
    );
    // Not in any rendered text.
    expect(container.textContent).not.toMatch(/hunter2/);
    // Not in any element's accessible-name source.
    for (const el of container.querySelectorAll("*")) {
      expect(el.getAttribute("aria-label") || "").not.toMatch(/hunter2/);
      expect(el.getAttribute("title") || "").not.toMatch(/hunter2/);
      expect(el.getAttribute("placeholder") || "").not.toMatch(/hunter2/);
    }
  });

  it("does not log a credential", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    axiosInstance.post.mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    await user.type(
      container.querySelector("input[type='password']"),
      "hunter2",
    );
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const written = [...errSpy.mock.calls, ...logSpy.mock.calls]
      .flat()
      .map((a) => (typeof a === "string" ? a : JSON.stringify(a ?? "")))
      .join(" ");
    expect(written).not.toMatch(/hunter2/);
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("drops credential material when the mode is switched back to none", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    await user.type(
      container.querySelector("input[type='password']"),
      "hunter2",
    );
    await user.selectOptions(screen.getByRole("combobox"), "none");
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const sent = JSON.stringify(axiosInstance.post.mock.calls[0][1]);
    expect(sent).not.toMatch(/hunter2/);
    expect(axiosInstance.post.mock.calls[0][1].auth).toEqual({ type: "none" });
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ERROR BEHAVIOUR
   ══════════════════════════════════════════════════════════════════════════ */
describe("NewWebScan — error behaviour", () => {
  it("surfaces the API's detail message", async () => {
    axiosInstance.post.mockRejectedValue({
      response: { data: { detail: "Target is outside the permitted scope." } },
    });
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    expect(
      await screen.findByText(/outside the permitted scope/i),
    ).toBeInTheDocument();
  });

  it("falls back to the error message, then to a generic string", async () => {
    axiosInstance.post.mockRejectedValue(new Error("Network Error"));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    expect(await screen.findByText(/network error/i)).toBeInTheDocument();
  });

  it("treats a response with no scan id as a failure", async () => {
    axiosInstance.post.mockResolvedValue({ data: { queued: true } });
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    expect(
      await screen.findByText(/did not return a scan id/i),
    ).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalledWith(
      expect.stringContaining("/web-scans/"),
      expect.anything(),
    );
  });

  it("clears the progress message when the launch fails", async () => {
    axiosInstance.post.mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() =>
      expect(
        screen.queryByText(/creating the scan record/i),
      ).not.toBeInTheDocument(),
    );
  });

  it("allows a retry after a failure", async () => {
    axiosInstance.post
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce({ data: { id: "ws-retry" } });
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await screen.findByText(/boom/i);
    await user.click(launch());
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/web-scans/ws-retry", {
        replace: true,
      }),
    );
  });

  it("never retries by itself", async () => {
    axiosInstance.post.mockRejectedValue(new Error("boom"));
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup();
      const { container } = render(<NewWebScan />);
      await fillMinimum(user, container);
      await user.click(launch());
      await waitFor(() => expect(axiosInstance.post).toHaveBeenCalledTimes(1));
      await vi.advanceTimersByTimeAsync(120000);
      expect(axiosInstance.post).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("NewWebScan — accessibility", () => {
  it("gives every text, url and number field an accessible name", async () => {
    /* The pre-migration page renders ten `<label>` elements and not one of them
       carries `htmlFor`; every input is the label's SIBLING rather than its
       child. So none of these fields has an accessible name, on the form that
       decides what this host does to somebody else's machine. */
    const { container } = render(<NewWebScan />);
    const controls = container.querySelectorAll(
      "input[type='text'],input[type='url'],input[type='number'],select",
    );
    expect(controls.length).toBeGreaterThan(0);
    for (const el of controls) {
      const labelled =
        el.getAttribute("aria-label") ||
        el.getAttribute("aria-labelledby") ||
        (el.id && container.querySelector(`label[for="${CSS.escape(el.id)}"]`));
      expect(labelled).toBeTruthy();
    }
  });

  it("names the scan name and target fields specifically", () => {
    render(<NewWebScan />);
    expect(screen.getByLabelText(/scan name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/target url/i)).toBeInTheDocument();
  });

  it("names the credential fields when basic auth is selected", async () => {
    const user = userEvent.setup();
    render(<NewWebScan />);
    await user.selectOptions(screen.getByRole("combobox"), "basic");
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
  });

  it("names the auth-type control", () => {
    render(<NewWebScan />);
    expect(screen.getByRole("combobox")).toHaveAccessibleName();
  });

  it("marks the required fields as required to assistive technology", () => {
    render(<NewWebScan />);
    expect(screen.getByLabelText(/scan name/i)).toBeRequired();
    expect(screen.getByLabelText(/target url/i)).toBeRequired();
  });

  it("announces a launch failure assertively", async () => {
    axiosInstance.post.mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/boom/i);
  });

  it("announces launch progress politely", async () => {
    let settle;
    axiosInstance.post.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ data: { id: "ws-new-1" } });
        }),
    );
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/creating the scan record/i);
    settle();
  });

  it("does not convey the authorization warning by colour alone", async () => {
    const { container } = render(<NewWebScan />);
    const agreement = screen.getByText(/authorization agreement/i);
    expect(agreement).toBeInTheDocument();
    // The panel must carry a word, not merely an amber border.
    const panel = agreement.closest("div");
    expect(panel.textContent).toMatch(/authorized|authorised/i);
    expect(container.textContent).toMatch(/performance degradation/i);
  });

  it("describes the authorization checkbox with the agreement text", async () => {
    render(<NewWebScan />);
    const box = screen.getByRole("checkbox", { name: /authoriz/i });
    expect(box).toBeInTheDocument();
  });

  it("does not skip a heading level", () => {
    render(<NewWebScan />);
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("reports the submit control as busy while launching", async () => {
    axiosInstance.post.mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    await fillMinimum(user, container);
    await user.click(launch());
    await waitFor(() => expect(launch()).toHaveAttribute("aria-busy", "true"));
  });

  it("can be completed with the keyboard alone", async () => {
    const user = userEvent.setup();
    const { container } = render(<NewWebScan />);
    const f = fields(container);
    f.scanName.focus();
    await user.keyboard("Keyboard Audit");
    f.targetUrl.focus();
    await user.keyboard("https://kb.example.test");
    f.authorization.focus();
    await user.keyboard(" ");
    expect(launch()).toBeEnabled();
    launch().focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("NewWebScan — rendered surface", () => {
  it("carries no inline styles", () => {
    const { container } = render(<NewWebScan />);
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no hardcoded colour literals", () => {
    const { container } = render(<NewWebScan />);
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("builds no colour value by concatenating onto a CSS variable", () => {
    const { container } = render(<NewWebScan />);
    expect(container.innerHTML).not.toMatch(/var\(--[a-z-]+\)[0-9a-f]{2}/i);
  });

  it("uses no ux4g-* class in application markup", () => {
    const { container } = render(<NewWebScan />);
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("injects no <style> element into the document", () => {
    const { container } = render(<NewWebScan />);
    expect(container.querySelectorAll("style").length).toBe(0);
  });

  it("keeps exactly one page heading", () => {
    render(<NewWebScan />);
    const h1s = screen
      .getAllByRole("heading")
      .filter((h) => h.tagName === "H1");
    expect(h1s.length).toBe(1);
  });
});

describe("NewWebScan — permission (F2)", () => {
  afterEach(() => {
    authState.user = FULL_PERMISSION_USER;
  });

  it("renders no launch form for a role without scans:execute, and says why", () => {
    authState.user = VIEWER_USER;
    const { container } = render(<NewWebScan />);
    expect(screen.getByText(/cannot launch web scans/i)).toBeInTheDocument();
    expect(screen.getByText("Run scans")).toBeInTheDocument();
    expect(container.querySelector("input[type='url']")).toBeNull();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });
});
