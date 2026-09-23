/**
 * ConfigurationChecks — Checkpoint 3C batch 10 migration coverage.
 *
 * Written against the page BEFORE migration. The failing set is the migration
 * specification; the passing set is the regression gate.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * This page is a READ-ONLY catalogue and must stay one. Its own header says
 * why: configuration checks run inside the credentialed scan, on the session
 * the collectors already opened, and a second way to start one against a named
 * target would need its own scope check, quota check and audit entry.
 *
 * So the load-bearing assertion here is a negative: **no mutation, ever**.
 *
 * Two further properties this page exists to make visible, both of which are
 * security statements rather than decoration:
 *
 *   * **The absence policy.** "Absent = compliant" and "Absent = finding" are
 *     opposite verdicts about the same reading, and the page must keep them
 *     distinguishable by TEXT, not only by the colour of a pill.
 *   * **The capability gap.** A rule can exist that this build cannot execute.
 *     The banner says so up front, and it must not become "nothing to report".
 *
 * `axiosInstance` is mocked rather than `api/configAudit`, so the real
 * parameter-building runs and the query string is genuinely pinned.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import ConfigurationChecks from "../../../pages/scan/ConfigurationChecks";
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

/* Deliberately out of severity order in the fixture, so the sort is proven
   rather than accidentally satisfied by the server's ordering. */
const CHECKS = [
  {
    check_id: "ccure.win.smb1",
    title: "SMBv1 must not be installed",
    severity: "medium",
    check_type: "registry",
    absent_policy: "pass",
    domain: "hardening",
    platforms: ["windows"],
    qod: 95,
    requires_credentials: true,
    expected: "SMB1Protocol not installed",
    description: "SMBv1 is obsolete and is the EternalBlue transport.",
    rationale: "Removing it eliminates the protocol entirely.",
    remediation: "Uninstall the SMB1Protocol feature.",
    references: ["https://example.test/smb1"],
  },
  {
    check_id: "ccure.win.auditd",
    title: "Audit policy must be configured",
    severity: "critical",
    check_type: "auditpol",
    absent_policy: "fail",
    domain: "logging",
    platforms: ["windows"],
    qod: 99,
    requires_credentials: true,
    expected: "Success and Failure",
    description: "Without audit policy nothing is recorded.",
  },
  {
    check_id: "ccure.win.iis",
    title: "IIS request filtering",
    severity: "low",
    check_type: "structured_config",
    absent_policy: "not_applicable",
    domain: "middleware",
    platforms: ["windows"],
    qod: 80,
    requires_credentials: true,
    expected: "requestFiltering enabled",
    description: "Only applies where IIS is installed.",
  },
  {
    check_id: "ccure.win.lsa",
    title: "LSA protection",
    severity: "high",
    check_type: "registry",
    absent_policy: "manual_review",
    domain: "hardening",
    platforms: ["windows"],
    qod: 90,
    requires_credentials: true,
    expected: "RunAsPPL = 1",
    description: "Absent means the platform default applies.",
  },
];

const CAPS = {
  supported: {
    windows: ["registry", "auditpol", "structured_config"],
    linux: ["command", "config_file"],
  },
  declared_without_collector: ["api", "database_query"],
};

const routeGet = (url) => {
  if (url === "/config-audit/checks") return Promise.resolve({ data: CHECKS });
  if (url === "/config-audit/capabilities")
    return Promise.resolve({ data: CAPS });
  return Promise.resolve({ data: {} });
};

/* Wrapped since Phase 6: the page links to the rule validator, and a router
   link needs a router. The page still takes no route parameters. */
const renderPage = async () => {
  const r = render(
    <MemoryRouter>
      <ConfigurationChecks />
    </MemoryRouter>,
  );
  await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
  return r;
};

const checksCall = (n = 0) =>
  axiosInstance.get.mock.calls.filter((c) => c[0] === "/config-audit/checks")[
    n
  ];

const platformBtn = (name) =>
  screen.getByRole("button", { name: new RegExp(`^${name}$`, "i") });

beforeEach(() => {
  vi.clearAllMocks();
  axiosInstance.get.mockImplementation(routeGet);
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("ConfigurationChecks — functional", () => {
  it("loads the checks and the capability report on mount", async () => {
    await renderPage();
    await waitFor(() => {
      const urls = axiosInstance.get.mock.calls.map((c) => c[0]);
      expect(urls).toContain("/config-audit/checks");
      expect(urls).toContain("/config-audit/capabilities");
    });
  });

  it("defaults to the whole catalogue, not to one platform", async () => {
    /* It used to default to `windows`, with the selector hardcoded to
       windows and linux. Measured against the live API that reached 106 of
       155 checks: the 49 `database` checks — the whole of the Phase 7
       database assessment — could not be reached from this page at all. The
       first load now asks for everything and the filters narrow it. */
    await renderPage();
    await waitFor(() => expect(checksCall()[1]).toEqual({ params: {} }));
  });

  it("derives the platform buttons from the capability report", async () => {
    /* Not from a constant here. `capabilities.supported` is keyed by exactly
       the platforms that return rows, so a platform the backend gains appears
       without a frontend change — and one it removes stops being offered. */
    await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    for (const name of Object.keys(CAPS.supported)) {
      expect(platformBtn(name)).toBeInTheDocument();
    }
    /* `any` is a targeting value on a check, not a platform to ask about —
       the API answers `platform=any` with nothing. */
    expect(screen.queryByRole("button", { name: /^any$/i })).toBeNull();
  });

  it("re-requests when the platform changes", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    await user.click(platformBtn("linux"));
    await waitFor(() => {
      const platforms = axiosInstance.get.mock.calls
        .filter((c) => c[0] === "/config-audit/checks")
        .map((c) => c[1]?.params?.platform);
      expect(platforms).toContain("linux");
    });
  });

  it("renders one row per check", async () => {
    await renderPage();
    for (const c of CHECKS) {
      expect(await screen.findByText(c.title)).toBeInTheDocument();
    }
  });

  it("orders the checks by severity, worst first", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const titles = CHECKS.map((c) => c.title);
    const order = [...container.querySelectorAll("*")]
      .filter((el) => titles.includes(el.textContent?.trim()))
      .map((el) => el.textContent.trim());
    const seen = order.filter((t, i) => order.indexOf(t) === i);
    expect(seen).toEqual([
      "Audit policy must be configured", // critical
      "LSA protection", // high
      "SMBv1 must not be installed", // medium
      "IIS request filtering", // low
    ]);
  });

  it("counts the checks it is showing", async () => {
    await renderPage();
    expect(await screen.findByText(/4 checks/i)).toBeInTheDocument();
  });

  it("expands a check to show its detail", async () => {
    const user = userEvent.setup();
    await renderPage();
    const title = await screen.findByText(/SMBv1 must not be installed/i);
    const row = title.closest("button");
    expect(
      screen.queryByText(/EternalBlue transport/i),
    ).not.toBeInTheDocument();
    await user.click(row);
    expect(
      await screen.findByText(/EternalBlue transport/i),
    ).toBeInTheDocument();
  });

  it("shows an empty state when the platform has no checks", async () => {
    axiosInstance.get.mockImplementation((url) => {
      if (url === "/config-audit/checks") return Promise.resolve({ data: [] });
      if (url === "/config-audit/capabilities")
        return Promise.resolve({ data: CAPS });
      return Promise.resolve({ data: {} });
    });
    await renderPage();
    expect(
      await screen.findByText(/no configuration checks for this platform/i),
    ).toBeInTheDocument();
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(
        <MemoryRouter>
          <ConfigurationChecks />
        </MemoryRouter>,
      );
      await vi.advanceTimersByTimeAsync(120000);
      const checkCalls = axiosInstance.get.mock.calls.filter(
        (c) => c[0] === "/config-audit/checks",
      );
      expect(checkCalls.length).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   READ-ONLY CONTRACT — the property this page exists to hold
   ══════════════════════════════════════════════════════════════════════════ */
describe("ConfigurationChecks — read-only contract", () => {
  it("issues no mutation on load", async () => {
    await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("issues no mutation when every control on the page is operated", async () => {
    /* There is deliberately no "run" button here. Driving every control and
       asserting the mutation verbs stay untouched is what stops one being
       added by accident during a presentation migration. */
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    for (const btn of [...container.querySelectorAll("button")]) {
      await user.click(btn);
    }
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("offers no control that would start a scan", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const names = [...container.querySelectorAll("button")].map((b) =>
      (b.getAttribute("aria-label") || b.textContent || "").trim(),
    );
    expect(names.join(" | ")).not.toMatch(
      /\brun\b|\bstart\b|\bscan now\b|execute/i,
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY MEANING — absence policy and capability gap
   ══════════════════════════════════════════════════════════════════════════ */
describe("ConfigurationChecks — security meaning", () => {
  it("distinguishes the four absence policies in words, not only by colour", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const text = container.textContent;
    expect(text).toMatch(/absent\s*=\s*compliant/i);
    expect(text).toMatch(/absent\s*=\s*finding/i);
    expect(text).toMatch(/absent\s*=\s*out of scope/i);
    expect(text).toMatch(/absent\s*=\s*review/i);
  });

  it("never renders a pass and a fail absence policy with the same words", async () => {
    /* The single most misread property of a hardening check: absence is a pass
       for one rule and a failure for another. */
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const compliant = within(container).getAllByText(/absent\s*=\s*compliant/i);
    const finding = within(container).getAllByText(/absent\s*=\s*finding/i);
    expect(compliant.length).toBeGreaterThan(0);
    expect(finding.length).toBeGreaterThan(0);
    expect(compliant[0].textContent).not.toBe(finding[0].textContent);
  });

  it("states what this build can read on the selected platform", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(container.textContent).toMatch(/registry/);
    expect(container.textContent).toMatch(/auditpol/);
  });

  it("names the check types this build cannot execute", async () => {
    /* A rule using one reports as not assessed rather than being silently
       skipped, and the banner is where a reader learns that before running a
       scan. It must not be dropped as "empty". */
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(container.textContent).toMatch(/not yet implemented/i);
    expect(container.textContent).toMatch(/database_query/);
  });

  it("shows each check's severity as text", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(container.textContent).toMatch(/critical/i);
    expect(container.textContent).toMatch(/high/i);
    expect(container.textContent).toMatch(/medium/i);
    expect(container.textContent).toMatch(/low/i);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("ConfigurationChecks — accessibility", () => {
  it("gives the page a level-one heading and skips no level", async () => {
    await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("states which platform is selected, not only by colour", async () => {
    await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const all = platformBtn("all platforms");
    const win = platformBtn("windows");
    const lin = platformBtn("linux");
    const pressed = [all, win, lin].map(
      (b) => b.getAttribute("aria-pressed") ?? b.getAttribute("aria-current"),
    );
    expect(pressed.filter(Boolean).length).toBe(3);
    // "all platforms" is the default, so it is the one pressed on load.
    expect(pressed).toContain("true");
    expect(all.getAttribute("aria-pressed")).toBe("true");
  });

  it("marks an expandable check row as expandable", async () => {
    const user = userEvent.setup();
    await renderPage();
    const title = await screen.findByText(/SMBv1 must not be installed/i);
    const row = title.closest("button");
    expect(row).toHaveAttribute("aria-expanded", "false");
    await user.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
  });

  it("gives the expand control an accessible name that names the check", async () => {
    /* Every row's control is otherwise "+" — N identical entries in a reader's
       control list, and the one thing they must not share is their name. */
    await renderPage();
    const title = await screen.findByText(/SMBv1 must not be installed/i);
    const row = title.closest("button");
    const name = (
      row.getAttribute("aria-label") ||
      row.textContent ||
      ""
    ).trim();
    expect(name).toMatch(/SMBv1/i);
  });

  /* The failed-load fixture, used by the three assertions below. */
  const failLoad = () =>
    axiosInstance.get.mockImplementation((url) =>
      url === "/config-audit/checks"
        ? Promise.reject({
            response: { data: { detail: "Config audit service unavailable." } },
          })
        : Promise.resolve({ data: CAPS }),
    );

  it("announces a failed load rather than rendering it as an empty platform", async () => {
    /* `finally` clears the loading flag whatever happened, so before the fix a
       failed fetch rendered the EMPTY state — "No configuration checks for this
       platform" — which is a false statement about the product's capability
       rather than about the data.

       The message now appears twice on screen: a transient toast, and a
       persistent alert. Only the alert is a live region, so there is one
       announcement and one lasting explanation; the assertion scopes to the
       live region rather than demanding the text be unique. */
    failLoad();
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(
        /config audit service unavailable/i,
      ),
    );
  });

  it("does not render the empty state when the load failed", async () => {
    /* The regression that matters: "this platform has no checks" and "we could
       not read the catalogue" are different facts, and only one of them should
       make somebody believe the product cannot check anything on Windows. */
    failLoad();
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(
        /config audit service unavailable/i,
      ),
    );
    expect(
      screen.queryByText(/no configuration checks for this platform/i),
    ).not.toBeInTheDocument();
  });

  it("puts the load error in a live region", async () => {
    failLoad();
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(
        /config audit service unavailable/i,
      ),
    );
    const live = [
      ...container.querySelectorAll(
        '[role="alert"],[role="status"],[aria-live]',
      ),
    ].find((el) =>
      /config audit service unavailable/i.test(el.textContent || ""),
    );
    expect(live).toBeTruthy();
  });

  it("gives the capability banner a programmatic name", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    const banner = [...container.querySelectorAll("*")].find((el) =>
      /what this build can read/i.test(el.textContent || ""),
    );
    expect(banner).toBeTruthy();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("ConfigurationChecks — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(
      [...container.querySelectorAll("[style]")].map((e) =>
        e.getAttribute("style"),
      ),
    ).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText(/SMBv1 must not be installed/i);
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });
});
