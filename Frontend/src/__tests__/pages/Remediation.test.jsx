/**
 * The Remediation workspace.
 *
 * The fixtures are the live deployment's own answers. The summary is the real
 * one — 7,763 open, 156 overdue and 5,791 findings with no deadline at all —
 * which is why the "no deadline applies" figure is asserted separately: it is
 * two-thirds of this installation's findings, and folding it into "within
 * SLA" would report an organisation as comfortably compliant on findings that
 * carry no obligation in either direction.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import summary from "../fixtures/remediationSummary.real.json";
import overdue from "../fixtures/remediationOverdue.real.json";
import Remediation from "../../pages/Remediation";
import api from "../../api/axiosInstance";

vi.mock("../../api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn() },
}));

vi.mock("../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

const ROLE_PERMS = {
  viewer: [{ resource: "findings", action: "read" }],
  analyst: [
    { resource: "findings", action: "read" },
    { resource: "findings", action: "update" },
    { resource: "findings", action: "accept_risk" },
    { resource: "assets", action: "read" },
  ],
  org_admin: [
    { resource: "findings", action: "read" },
    { resource: "findings", action: "update" },
    { resource: "findings", action: "accept_risk" },
    { resource: "settings", action: "update" },
    { resource: "users", action: "read" },
  ],
  scanner: [{ resource: "scans", action: "execute" }],
};

let currentUser = null;
vi.mock("../../context/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

const asRole = (name) => {
  currentUser = {
    id: "usr_me",
    organization_id: "org_default",
    role: { name, permissions: ROLE_PERMS[name] || [] },
  };
};

const people = {
  total: 2,
  users: [
    {
      id: "usr_a",
      full_name: "Asha Rao",
      username: "asha",
      organization_id: "org_default",
    },
    {
      id: "usr_other",
      full_name: "Other Tenant",
      username: "other",
      organization_id: "org_elsewhere",
    },
  ],
};

const assets = {
  total: 1,
  assets: [
    {
      id: overdue.findings[0].asset_id,
      ip_address: "10.180.6.45",
      hostname: "superusr-HP3",
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
  asRole("org_admin");
  api.get.mockImplementation((url) => {
    if (url.includes("/remediation/summary"))
      return Promise.resolve({ data: summary });
    if (url.includes("/remediation/overdue"))
      return Promise.resolve({ data: overdue });
    if (url.includes("/remediation/pending-verification"))
      return Promise.resolve({ data: { total: 0, count: 0, findings: [] } });
    if (url.includes("/remediation/sla-policy"))
      return Promise.resolve({
        data: {
          days_by_severity: { critical: 15 },
          defaults: { critical: 15 },
          due_soon_window_days: 7,
          honour_kev_due_date: true,
          unit: "calendar days",
        },
      });
    if (url.startsWith("/assets")) return Promise.resolve({ data: assets });
    if (url.includes("/admin/users")) return Promise.resolve({ data: people });
    return Promise.resolve({ data: {} });
  });
});

const mount = () =>
  render(
    <MemoryRouter>
      <Remediation />
    </MemoryRouter>,
  );

describe("permission", () => {
  it("refuses the page without findings:read and names the permission", async () => {
    asRole("scanner");
    mount();
    expect(screen.getByText(/findings:read/)).toBeInTheDocument();
    // Nothing is fetched for somebody who may not see it.
    expect(api.get).not.toHaveBeenCalled();
  });

  it("opens for a viewer, who holds read alone", async () => {
    asRole("viewer");
    mount();
    await screen.findByText(summary.summary_line);
    // No write controls anywhere.
    expect(screen.queryByRole("button", { name: /^Assign/ })).toBeNull();
  });
});

describe("the summary", () => {
  it("prints the backend's own line verbatim", async () => {
    mount();
    // Assembled once, server-side, so a report and a dashboard cannot render
    // it two different ways.
    await screen.findByText(summary.summary_line);
  });

  it("shows a count for every state, including the empty ones", async () => {
    mount();
    await screen.findByText(summary.summary_line);
    for (const label of [
      "Open",
      "Assigned",
      "In remediation",
      "Pending verification",
      "Verified fixed",
      "Reopened",
      "Risk accepted",
    ]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
  });

  it("keeps 'no deadline applies' out of 'within SLA'", async () => {
    mount();
    await screen.findByText("No deadline applies");
    expect(screen.getByText(String(summary.no_sla))).toBeInTheDocument();
    expect(screen.getByText(String(summary.within_sla))).toBeInTheDocument();
    expect(summary.no_sla).toBeGreaterThan(summary.within_sla);
  });

  it("says plainly which states have no list behind them", async () => {
    mount();
    await screen.findByText(summary.summary_line);
    expect(
      screen.getByText(/Only Overdue and Pending verification have a listing/i),
    ).toBeInTheDocument();
  });
});

describe("the queues", () => {
  it("lists overdue findings and resolves the host from one assets read", async () => {
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);
    expect(
      screen.getAllByText("10.180.6.45 (superusr-HP3)").length,
    ).toBeGreaterThan(0);
  });

  it("reports the API's own total rather than the page length", async () => {
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);
    // 3 rows returned, 156 matched. A bounded count is a wrong number.
    expect(overdue.count).toBe(3);
    expect(overdue.total).toBe(156);
    expect(screen.getByText(/156 findings/)).toBeInTheDocument();
  });

  it("switches to the pending-verification queue", async () => {
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: /Pending verification/ }));

    await waitFor(() =>
      expect(
        api.get.mock.calls.some(([u]) =>
          u.includes("/remediation/pending-verification"),
        ),
      ).toBe(true),
    );
    await screen.findByText(/Nothing is waiting on a verification scan/);
  });

  it("says a finding stays pending until a scan agrees", async () => {
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: /Pending verification/ }));
    expect(
      await screen.findByText(
        /no action on this screen can move it to verified fixed/i,
      ),
    ).toBeInTheDocument();
  });
});

describe("assignment", () => {
  it("offers only people inside the caller's organisation", async () => {
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);

    const user = userEvent.setup();
    await user.click(
      screen.getByLabelText(`Select ${overdue.findings[0].vuln_id}`),
    );
    await user.click(screen.getByRole("button", { name: /^Assign/ }));

    const dialog = await screen.findByRole("dialog");
    const select = within(dialog).getByLabelText("Owner");
    expect(within(select).getByText("Asha Rao")).toBeInTheDocument();
    // The API refuses an owner from another tenant; the picker never offers one.
    expect(within(select).queryByText("Other Tenant")).toBeNull();
  });

  it("sends the selected ids and reports what actually changed", async () => {
    api.post.mockResolvedValue({
      data: { success: true, requested: 1, matched: 1, changed: 1 },
    });
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);

    const user = userEvent.setup();
    await user.click(
      screen.getByLabelText(`Select ${overdue.findings[0].vuln_id}`),
    );
    await user.click(screen.getByRole("button", { name: /^Assign/ }));
    const dialog = await screen.findByRole("dialog");
    await user.selectOptions(within(dialog).getByLabelText("Owner"), "usr_a");
    await user.click(within(dialog).getByRole("button", { name: "Assign" }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    const [url, body] = api.post.mock.calls[0];
    expect(url).toBe("/remediation/assign");
    expect(body.finding_ids).toEqual([overdue.findings[0].finding_id]);
    expect(body.owner_id).toBe("usr_a");

    await screen.findByText(/1 of 1 findings changed/);
  });

  it("does not offer bulk assignment without findings:update", async () => {
    asRole("viewer");
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);
    expect(
      screen.queryByLabelText(`Select ${overdue.findings[0].vuln_id}`),
    ).toBeNull();
  });
});

describe("the SLA policy section", () => {
  it("is editable for an org admin", async () => {
    mount();
    await screen.findByLabelText("Critical");
    expect(screen.getByLabelText("Critical")).not.toBeDisabled();
  });

  it("is read-only for an analyst, who holds findings:update but not settings:update", async () => {
    asRole("analyst");
    mount();
    await screen.findByLabelText("Critical");
    expect(screen.getByLabelText("Critical")).toBeDisabled();
    expect(screen.getByText("settings:update")).toBeInTheDocument();
  });

  it("falls back to an id field when the caller cannot list people", async () => {
    asRole("analyst");
    mount();
    await screen.findByText(overdue.findings[0].vuln_id);
    // users:read is org_admin and above; an analyst can still assign, so the
    // control degrades rather than disappearing.
    expect(screen.getByLabelText("Owner id")).toBeInTheDocument();
    expect(api.get.mock.calls.some(([u]) => u.includes("/admin/users"))).toBe(
      false,
    );
  });
});

describe("failure", () => {
  it("surfaces a queue failure without losing the summary", async () => {
    api.get.mockImplementation((url) => {
      if (url.includes("/remediation/summary"))
        return Promise.resolve({ data: summary });
      if (url.includes("/remediation/overdue"))
        return Promise.reject({
          response: { data: { message: "Rate limit exceeded." } },
        });
      return Promise.resolve({ data: {} });
    });
    mount();
    await screen.findByText("Rate limit exceeded.");
    expect(screen.getByText(summary.summary_line)).toBeInTheDocument();
  });
});
