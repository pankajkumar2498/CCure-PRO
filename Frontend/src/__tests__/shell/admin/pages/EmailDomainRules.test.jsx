import { assertUx4gAdapters } from "../../../helpers/assertUx4gAdapters";
/**
 * EmailDomainRules — Checkpoint 3C batch 5 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * These rules are platform-wide: one row here decides whether a domain may
 * register on every tenant in the deployment. CLAUDE.md records three
 * properties this page's UI is the only visible expression of:
 *
 *   * **ALLOW always wins** — over a DENY rule *and* over the 75k-entry
 *     disposable blocklist. The page has to say so, because the consequence of
 *     removing an ALLOW is counter-intuitive: the domain does not become
 *     neutral, it starts being blocked.
 *   * **The guard fails open, silently.** An empty corpus screens nothing and
 *     registration keeps working. This page is the one place that is visible,
 *     which is why the corpus banner leads and why it must be *announced*, not
 *     merely coloured red.
 *   * **The lookup is advisory.** In `flag` mode a domain can be "blocked" by
 *     the guard and still register; the two must not be conflated.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import EmailDomainRules from "@shell/admin/pages/EmailDomainRules";
import {
  listEmailDomainRules,
  getEmailDomainStats,
  lookupEmailDomain,
  createEmailDomainRule,
  updateEmailDomainRule,
  deleteEmailDomainRule,
} from "@shell/api/emailDomains";

vi.mock("@shell/api/emailDomains", () => ({
  listEmailDomainRules: vi.fn(),
  getEmailDomainStats: vi.fn(),
  lookupEmailDomain: vi.fn(),
  createEmailDomainRule: vi.fn(),
  updateEmailDomainRule: vi.fn(),
  deleteEmailDomainRule: vi.fn(),
}));

vi.mock("@shell/layout/ProductFrame", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const RULES = [
  {
    id: 1,
    domain: "test.com",
    verdict: "allow",
    source: "seed",
    reason: "Used by the test suite",
  },
  {
    id: 2,
    domain: "hutdot.com",
    verdict: "deny",
    source: "admin",
    reason: "Disposable mailbox provider",
  },
  {
    id: 3,
    domain: "radiant-flow.org",
    verdict: "allow",
    source: "approval",
    reason: "",
  },
];

const HEALTHY = {
  mode: "enforce",
  corpus_size: 75170,
  corpus_healthy: true,
  allow_rules: 2,
  deny_rules: 1,
  flagged_users: 4,
};

/* Row-scoped accessors. The migration gives each row's controls a distinct
   accessible name ("Change test.com to DENY", "Remove the rule for test.com"),
   which is what the two "disambiguates" assertions below demand — so a
   page-wide query on the bare verb stops matching. Scoping to the row is what
   makes a short pattern unambiguous, and page-wide uniqueness is still
   asserted separately. */
const flipBtn = (row) =>
  within(row).getByRole("button", { name: /change|set (deny|allow)/i });
const removeBtn = (row) => within(row).getByRole("button", { name: /remove/i });

const renderPage = async () => {
  const result = render(<EmailDomainRules />);
  await waitFor(() => expect(listEmailDomainRules).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  listEmailDomainRules.mockResolvedValue({
    rules: RULES,
    total: RULES.length,
    counts: { allow: 2, deny: 1 },
  });
  getEmailDomainStats.mockResolvedValue(HEALTHY);
  lookupEmailDomain.mockResolvedValue({
    domain: "company.com",
    blocked: false,
    would_block_registration: false,
    reason: "No rule matched",
    flags: [],
  });
  createEmailDomainRule.mockResolvedValue({
    domain: "acme.com",
    verdict: "deny",
  });
  updateEmailDomainRule.mockResolvedValue({});
  deleteEmailDomainRule.mockResolvedValue({
    domain: "test.com",
    now: { blocked: false },
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("EmailDomainRules — functional", () => {
  it("loads rules and stats on mount", async () => {
    await renderPage();
    expect(listEmailDomainRules).toHaveBeenCalledWith({
      q: undefined,
      verdict: undefined,
      skip: 0,
      limit: 25,
    });
    expect(getEmailDomainStats).toHaveBeenCalled();
  });

  it("renders one row per rule", async () => {
    await renderPage();
    expect(await screen.findByText("test.com")).toBeInTheDocument();
    expect(screen.getByText("hutdot.com")).toBeInTheDocument();
    expect(screen.getByText("radiant-flow.org")).toBeInTheDocument();
  });

  it("renders each rule's verdict", async () => {
    await renderPage();
    await screen.findByText("test.com");
    expect(screen.getAllByText("ALLOW").length).toBe(2);
    expect(screen.getAllByText("DENY").length).toBe(1);
  });

  it("renders each rule's source", async () => {
    await renderPage();
    await screen.findByText("test.com");
    expect(screen.getByText("seed")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("approval")).toBeInTheDocument();
  });

  it("renders the corpus size and mode", async () => {
    await renderPage();
    expect(await screen.findByText(/75,170/)).toBeInTheDocument();
    expect(screen.getByText("enforce")).toBeInTheDocument();
  });

  it("shows an empty state when nothing matches", async () => {
    listEmailDomainRules.mockResolvedValue({
      rules: [],
      total: 0,
      counts: { allow: 0, deny: 0 },
    });
    await renderPage();
    expect(await screen.findByText(/no rules match/i)).toBeInTheDocument();
  });

  it("debounces the search before requesting", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(screen.getByLabelText(/search rules/i), "hut");
    await waitFor(
      () =>
        expect(listEmailDomainRules).toHaveBeenCalledWith(
          expect.objectContaining({ q: "hut" }),
        ),
      { timeout: 3000 },
    );
  });

  it("filters by verdict", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.selectOptions(
      screen.getByLabelText(/filter by verdict/i),
      "deny",
    );
    await waitFor(() =>
      expect(listEmailDomainRules).toHaveBeenCalledWith(
        expect.objectContaining({ verdict: "deny" }),
      ),
    );
  });

  it("creates a rule with the entered values", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(screen.getByLabelText(/^domain\b/i), "acme.com");
    await user.type(screen.getByLabelText(/^reason/i), "Competitor");
    await user.click(screen.getByRole("button", { name: /add rule/i }));
    await waitFor(() =>
      expect(createEmailDomainRule).toHaveBeenCalledWith({
        domain: "acme.com",
        verdict: "deny",
        reason: "Competitor",
      }),
    );
  });

  it("omits an empty reason rather than sending a blank string", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(screen.getByLabelText(/^domain\b/i), "acme.com");
    await user.click(screen.getByRole("button", { name: /add rule/i }));
    await waitFor(() =>
      expect(createEmailDomainRule).toHaveBeenCalledWith({
        domain: "acme.com",
        verdict: "deny",
        reason: undefined,
      }),
    );
  });

  it("reloads rules and stats after a create", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    const before = listEmailDomainRules.mock.calls.length;
    await user.type(screen.getByLabelText(/^domain\b/i), "acme.com");
    await user.click(screen.getByRole("button", { name: /add rule/i }));
    await waitFor(() =>
      expect(listEmailDomainRules.mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("runs a lookup against the live guard", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(
      screen.getByLabelText(/address or domain to test/i),
      "someone@company.com",
    );
    await user.click(screen.getByRole("button", { name: /^check$/i }));
    await waitFor(() =>
      expect(lookupEmailDomain).toHaveBeenCalledWith("someone@company.com"),
    );
    expect(await screen.findByText(/would be accepted/i)).toBeInTheDocument();
  });

  it("reports a domain the guard would block", async () => {
    lookupEmailDomain.mockResolvedValue({
      domain: "hutdot.com",
      blocked: true,
      would_block_registration: true,
      reason: "On the disposable blocklist",
      matched_domain: "hutdot.com",
      matched_source: "corpus",
      flags: [],
    });
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(
      screen.getByLabelText(/address or domain to test/i),
      "a@hutdot.com",
    );
    await user.click(screen.getByRole("button", { name: /^check$/i }));
    expect(await screen.findByText(/would be BLOCKED/i)).toBeInTheDocument();
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<EmailDomainRules />);
      await waitFor(() =>
        expect(listEmailDomainRules).toHaveBeenCalledTimes(1),
      );
      await vi.advanceTimersByTimeAsync(120000);
      expect(listEmailDomainRules).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("EmailDomainRules — security", () => {
  it("states that ALLOW overrides both a DENY and the blocklist", async () => {
    await renderPage();
    expect(await screen.findByText(/ALLOW always wins/i)).toBeInTheDocument();
  });

  it("warns loudly when the blocklist is empty", async () => {
    getEmailDomainStats.mockResolvedValue({
      ...HEALTHY,
      corpus_size: 0,
      corpus_healthy: false,
    });
    await renderPage();
    expect(
      await screen.findByText(/nothing is being screened/i),
    ).toBeInTheDocument();
  });

  it("flips a rule's verdict to the opposite value", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(flipBtn(row));
    await waitFor(() =>
      expect(updateEmailDomainRule).toHaveBeenCalledWith(1, {
        verdict: "deny",
      }),
    );
  });

  it("flips a deny rule to allow", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("hutdot.com")).closest("tr");
    await user.click(flipBtn(row));
    await waitFor(() =>
      expect(updateEmailDomainRule).toHaveBeenCalledWith(2, {
        verdict: "allow",
      }),
    );
  });

  it("never removes a rule without an explicit confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(deleteEmailDomainRule).not.toHaveBeenCalled();
  });

  it("removes only after the confirmation is accepted", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /remove rule/i }),
    );
    await waitFor(() => expect(deleteEmailDomainRule).toHaveBeenCalledWith(1));
  });

  it("warns that removing an ALLOW can start blocking the domain", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/will start blocking/i),
    ).toBeInTheDocument();
  });

  it("gives a DENY removal the opposite warning", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("hutdot.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/lets the domain register again/i),
    ).toBeInTheDocument();
  });

  it("sends nothing when the removal is cancelled", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(deleteEmailDomainRule).not.toHaveBeenCalled();
  });

  it("says what the domain does now after a removal that starts blocking", async () => {
    deleteEmailDomainRule.mockResolvedValue({
      domain: "test.com",
      now: { blocked: true, reason: "on the disposable blocklist" },
    });
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /remove rule/i }),
    );
    expect(await screen.findByText(/is now BLOCKED/i)).toBeInTheDocument();
  });

  it("distinguishes a flag-mode block from a refusal", async () => {
    getEmailDomainStats.mockResolvedValue({ ...HEALTHY, mode: "flag" });
    lookupEmailDomain.mockResolvedValue({
      domain: "hutdot.com",
      blocked: true,
      would_block_registration: false,
      reason: "On the disposable blocklist",
      flags: [],
    });
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(
      screen.getByLabelText(/address or domain to test/i),
      "a@hutdot.com",
    );
    await user.click(screen.getByRole("button", { name: /^check$/i }));
    expect(
      await screen.findByText(/recorded but not enforced/i),
    ).toBeInTheDocument();
  });

  it("surfaces a create failure rather than reporting success", async () => {
    createEmailDomainRule.mockRejectedValue({
      response: { data: { detail: "A rule already exists for acme.com." } },
    });
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(screen.getByLabelText(/^domain\b/i), "acme.com");
    await user.click(screen.getByRole("button", { name: /add rule/i }));
    expect(
      await screen.findByText(/a rule already exists for acme\.com/i),
    ).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("EmailDomainRules — accessibility", () => {
  it("gives the table an accessible name", async () => {
    await renderPage();
    await screen.findByText("test.com");
    expect(screen.getByRole("table")).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    await screen.findByText("test.com");
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th.getAttribute("scope")).toBe("col");
    }
  });

  it("marks the domain as its row's header", async () => {
    await renderPage();
    await screen.findByText("test.com");
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(3);
  });

  it("disambiguates the flip control per row", async () => {
    await renderPage();
    await screen.findByText("test.com");
    const buttons = screen.getAllByRole("button", {
      name: /change|set (deny|allow)/i,
    });
    expect(buttons.length).toBe(3);
    const names = buttons.map(
      (b) => b.getAttribute("aria-label") || b.textContent.trim(),
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("disambiguates the remove control per row", async () => {
    await renderPage();
    await screen.findByText("test.com");
    const buttons = screen.getAllByRole("button", { name: /remove/i });
    expect(buttons.length).toBe(3);
    const names = buttons.map(
      (b) => b.getAttribute("aria-label") || b.textContent.trim(),
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("announces the empty-corpus warning, not only colours it", async () => {
    getEmailDomainStats.mockResolvedValue({
      ...HEALTHY,
      corpus_size: 0,
      corpus_healthy: false,
    });
    await renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/nothing is being screened/i);
  });

  it("announces the lookup result", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("test.com");
    await user.type(
      screen.getByLabelText(/address or domain to test/i),
      "someone@company.com",
    );
    await user.click(screen.getByRole("button", { name: /^check$/i }));
    await screen.findByText(/would be accepted/i);
    const live = [...document.querySelectorAll('[role="status"],[aria-live]')];
    expect(live.some((e) => /would be accepted/i.test(e.textContent))).toBe(
      true,
    );
  });

  it("announces the loading state", async () => {
    let settle;
    listEmailDomainRules.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () =>
            r({ rules: [], total: 0, counts: { allow: 0, deny: 0 } });
        }),
    );
    render(<EmailDomainRules />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading/i);
    settle();
  });

  it("names the rule-creation form", async () => {
    await renderPage();
    await screen.findByText("test.com");
    const forms = document.querySelectorAll("form");
    expect(forms.length).toBeGreaterThan(0);
    for (const form of forms) {
      const named =
        form.getAttribute("aria-label") || form.getAttribute("aria-labelledby");
      expect(named).toBeTruthy();
    }
  });

  it("traps focus inside the confirmation dialog", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("describes the confirmation dialog, not only labels it", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("test.com")).closest("tr");
    await user.click(removeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAccessibleDescription();
  });

  it("keeps exactly one top-level heading", async () => {
    await renderPage();
    await screen.findByText("test.com");
    expect(
      screen.getAllByRole("heading", { name: /email domain rules/i }).length,
    ).toBe(1);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   VISUAL / REGRESSION SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("EmailDomainRules — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("test.com");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("test.com");
    const html = container.innerHTML;
    expect(html).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(html).not.toMatch(/rgba?\(/i);
  });

  it("confines official UX4G classes to shared adapters", async () => {
    const { container } = await renderPage();
    await screen.findByText("test.com");
    assertUx4gAdapters(container);
  });

  it("renders one row per rule and no more", async () => {
    await renderPage();
    await screen.findByText("test.com");
    expect(document.querySelectorAll("tbody tr").length).toBe(3);
  });
});
