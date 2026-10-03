/**
 * OrganizationManagement — Checkpoint 3C batch 5 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This page operates on *tenants*. Deleting an organisation is the widest
 * destructive action in the product — CLAUDE.md records that it may remove
 * users, assets and scans — and deactivating one cuts off everybody inside it.
 * Four authorisation properties, and they are deliberately not the same test:
 *
 *   * create  → `organizations:create`
 *   * update  → `organizations:update`
 *   * delete  → superadmin **and** `organizations:delete`. The conjunction is
 *     the point: a permission alone is not enough, because an org_admin who
 *     somehow held it could delete a different tenant.
 *   * an org_admin may manage only their OWN organisation (`canManageOrg`),
 *     while a superadmin may manage any.
 *
 * ── Scope note ──────────────────────────────────────────────────────────────
 * `components/admin/OrganizationForm` and `components/layout/Modal` are shared
 * components and are NOT migrated in this batch — the form carries admin
 * password provisioning, which is credential-handling surface of its own. The
 * assertions below therefore treat the create/edit dialogs as a black box:
 * they check that the right one opens and that the page's own handler sends
 * the right payload.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import OrganizationManagement from "@shell/admin/pages/OrganizationManagement";
import {
  listOrganizations,
  createOrganization,
  updateOrganization,
  changeOrganizationStatus,
  deleteOrganization,
} from "@shell/api/admin";
import { personaFrom } from "../../../fixtures/authorization";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("@shell/api/admin", () => ({
  listOrganizations: vi.fn(),
  createOrganization: vi.fn(),
  updateOrganization: vi.fn(),
  changeOrganizationStatus: vi.fn(),
  deleteOrganization: vi.fn(),
}));

vi.mock("@shell/layout/ProductFrame", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

// The form is out of this batch's scope; stubbed so the page's own handler
// contract can be asserted without depending on the form's internals.
vi.mock("@shell/admin/components/OrganizationForm", () => ({
  default: ({ mode, organization, onSubmit, onCancel }) => (
    <div data-testid="org-form" data-mode={mode}>
      <span data-testid="org-form-name">{organization?.name || ""}</span>
      <button
        type="button"
        onClick={() =>
          onSubmit({
            name: "Submitted Co",
            slug: "submitted-co",
            plan: "business",
            max_assets: 900,
            max_users: 40,
          })
        }
      >
        Submit form
      </button>
      <button type="button" onClick={onCancel}>
        Cancel form
      </button>
    </div>
  ),
}));

let currentUser = {
  username: "root",
  id: 1,
  org_id: 7,
  role: { name: "superadmin" },
};
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(currentUser) }),
}));

let permissions = new Set([
  "organizations:create",
  "organizations:update",
  "organizations:delete",
]);
let superadmin = true;
// RBAC-7: the pages ask for permission keys; these tests list capabilities as the
// legacy atoms they were written with, so a key is read as the atom it replaced.
const KEY_ATOM = vi.hoisted(() => ({
  "platform.user.read": "users:read",
  "platform.user.create": "users:create",
  "platform.user.update": "users:update",
  "platform.user.delete": "users:delete",
  "platform.role.read": "roles:read",
  "platform.organization.read": "organizations:read",
  "platform.organization.create": "organizations:create",
  "platform.organization.update": "organizations:update",
  "platform.organization.archive": "organizations:delete",
  "platform.audit_log.read": "audit:read",
  "platform.audit_log.export": "audit:export",
}));
vi.mock("@shell/auth/permissions", () => ({
  can: (_user, key) => permissions.has(KEY_ATOM[key] || key),
  canSwitchOrganisation: () => superadmin,
  denyMessage: "You do not have permission to perform this action.",
}));

const ORGS = [
  {
    id: 7,
    name: "Acme Corp",
    slug: "acme",
    plan: "enterprise",
    max_assets: 5000,
    max_users: 100,
    is_active: true,
    created_at: "2026-01-15T10:00:00Z",
  },
  {
    id: 8,
    name: "Other Ltd",
    slug: "other",
    plan: "community",
    max_assets: 500,
    max_users: 10,
    is_active: false,
    created_at: "2026-02-20T10:00:00Z",
  },
];

const renderPage = async () => {
  const result = render(<OrganizationManagement />);
  await waitFor(() => expect(listOrganizations).toHaveBeenCalled());
  await screen.findByText("Acme Corp");
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  currentUser = {
    username: "root",
    id: 1,
    org_id: 7,
    role: { name: "superadmin" },
  };
  permissions = new Set([
    "organizations:create",
    "organizations:update",
    "organizations:delete",
  ]);
  superadmin = true;
  listOrganizations.mockResolvedValue({ organizations: ORGS });
  createOrganization.mockResolvedValue({});
  updateOrganization.mockResolvedValue({});
  changeOrganizationStatus.mockResolvedValue({});
  deleteOrganization.mockResolvedValue({});
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("OrganizationManagement — functional", () => {
  it("loads the organisation list on mount", async () => {
    await renderPage();
    expect(listOrganizations).toHaveBeenCalledTimes(1);
  });

  it("renders one row per organisation", async () => {
    await renderPage();
    expect(screen.getByText("Acme Corp")).toBeInTheDocument();
    expect(screen.getByText("Other Ltd")).toBeInTheDocument();
  });

  it("renders the slug, plan and quotas", async () => {
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    expect(within(row).getByText("acme")).toBeInTheDocument();
    expect(within(row).getByText("enterprise")).toBeInTheDocument();
    expect(within(row).getByText("5000")).toBeInTheDocument();
    expect(within(row).getByText("100")).toBeInTheDocument();
  });

  it("distinguishes an active organisation from an inactive one", async () => {
    await renderPage();
    const active = screen.getByText("Acme Corp").closest("tr");
    const inactive = screen.getByText("Other Ltd").closest("tr");
    expect(within(active).getByText("Active")).toBeInTheDocument();
    expect(within(inactive).getByText("Inactive")).toBeInTheDocument();
  });

  it("shows an empty message when there are no organisations", async () => {
    listOrganizations.mockResolvedValue({ organizations: [] });
    render(<OrganizationManagement />);
    expect(
      await screen.findByText(/no organizations are available yet/i),
    ).toBeInTheDocument();
  });

  it("shows an error when the load fails", async () => {
    listOrganizations.mockRejectedValue(new Error("forbidden"));
    render(<OrganizationManagement />);
    expect(
      await screen.findByText(/failed to load organizations/i),
    ).toBeInTheDocument();
  });

  it("refreshes on demand", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /refresh/i }));
    await waitFor(() => expect(listOrganizations).toHaveBeenCalledTimes(2));
  });

  it("opens the create dialog", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /new organization/i }));
    const form = await screen.findByTestId("org-form");
    expect(form).toHaveAttribute("data-mode", "create");
  });

  it("opens the edit dialog seeded with the chosen organisation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));
    const form = await screen.findByTestId("org-form");
    expect(form).toHaveAttribute("data-mode", "edit");
    expect(screen.getByTestId("org-form-name")).toHaveTextContent("Acme Corp");
  });

  it("sends the create payload unchanged", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /new organization/i }));
    await user.click(
      await screen.findByRole("button", { name: /submit form/i }),
    );
    await waitFor(() =>
      expect(createOrganization).toHaveBeenCalledWith({
        name: "Submitted Co",
        slug: "submitted-co",
        plan: "business",
        max_assets: 900,
        max_users: 40,
      }),
    );
  });

  it("sends the update payload against the selected organisation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /edit/i }));
    await user.click(
      await screen.findByRole("button", { name: /submit form/i }),
    );
    await waitFor(() =>
      expect(updateOrganization).toHaveBeenCalledWith(7, {
        name: "Submitted Co",
        slug: "submitted-co",
        plan: "business",
        max_assets: 900,
        max_users: 40,
      }),
    );
  });

  it("reloads quietly after a successful create", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /new organization/i }));
    await user.click(
      await screen.findByRole("button", { name: /submit form/i }),
    );
    await waitFor(() => expect(listOrganizations).toHaveBeenCalledTimes(2));
  });

  it("navigates to the users of an organisation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /users/i }));
    expect(navigate).toHaveBeenCalledWith("/admin/users?org_id=7");
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<OrganizationManagement />);
      await waitFor(() => expect(listOrganizations).toHaveBeenCalledTimes(1));
      await vi.advanceTimersByTimeAsync(120000);
      expect(listOrganizations).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("OrganizationManagement — security", () => {
  it("hides the create control without organizations:create", async () => {
    permissions = new Set(["organizations:update"]);
    await renderPage();
    expect(
      screen.queryByRole("button", { name: /new organization/i }),
    ).not.toBeInTheDocument();
  });

  it("requires superadmin as well as the permission to delete", async () => {
    // The permission alone must not be enough: an org_admin holding it could
    // otherwise delete another tenant.
    superadmin = false;
    await renderPage();
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
  });

  it("hides delete when superadmin lacks organizations:delete", async () => {
    permissions = new Set(["organizations:create", "organizations:update"]);
    await renderPage();
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
  });

  it("lets an org_admin manage only their own organisation", async () => {
    superadmin = false;
    permissions = new Set(["organizations:update"]);
    currentUser = { ...currentUser, org_id: 7, role: { name: "org_admin" } };
    await renderPage();
    const own = screen.getByText("Acme Corp").closest("tr");
    const other = screen.getByText("Other Ltd").closest("tr");
    expect(
      within(own).getByRole("button", { name: /edit/i }),
    ).toBeInTheDocument();
    expect(
      within(other).queryByRole("button", { name: /edit/i }),
    ).not.toBeInTheDocument();
  });

  it("never deletes without an explicit confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(deleteOrganization).not.toHaveBeenCalled();
  });

  it("deletes only after the confirmation is accepted", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete organization/i }),
    );
    await waitFor(() => expect(deleteOrganization).toHaveBeenCalledWith(7));
  });

  it("warns that deletion reaches tenant data", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/users, assets, scans/i),
    ).toBeInTheDocument();
  });

  it("sends nothing when the delete confirmation is cancelled", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(deleteOrganization).not.toHaveBeenCalled();
  });

  it("never changes status without an explicit confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /deactivate/i }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(changeOrganizationStatus).not.toHaveBeenCalled();
  });

  it("sends the inverted status when a deactivation is confirmed", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /deactivate/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getAllByRole("button", { name: /deactivate/i })[0],
    );
    await waitFor(() =>
      expect(changeOrganizationStatus).toHaveBeenCalledWith(7, {
        is_active: false,
      }),
    );
  });

  it("sends the inverted status when an activation is confirmed", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Other Ltd").closest("tr");
    await user.click(within(row).getByRole("button", { name: /activate/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getAllByRole("button", { name: /^activate$/i })[0],
    );
    await waitFor(() =>
      expect(changeOrganizationStatus).toHaveBeenCalledWith(8, {
        is_active: true,
      }),
    );
  });

  it("warns that deactivating cuts off the tenant's users", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /deactivate/i }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/may lose access/i)).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("OrganizationManagement — accessibility", () => {
  it("gives the table an accessible name", async () => {
    await renderPage();
    expect(screen.getByRole("table")).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th.getAttribute("scope")).toBe("col");
    }
  });

  it("marks the identifying cell as its row's header", async () => {
    await renderPage();
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(2);
  });

  it("disambiguates the edit control per row", async () => {
    await renderPage();
    const names = screen
      .getAllByRole("button", { name: /edit/i })
      .map((b) => b.getAttribute("aria-label") || b.textContent.trim());
    expect(new Set(names).size).toBe(names.length);
  });

  it("disambiguates the delete control per row", async () => {
    await renderPage();
    const names = screen
      .getAllByRole("button", { name: /delete/i })
      .map((b) => b.getAttribute("aria-label") || b.textContent.trim());
    expect(new Set(names).size).toBe(names.length);
  });

  it("does not rely on an emoji alone to name a control", async () => {
    await renderPage();
    for (const btn of screen.getAllByRole("button")) {
      const name = (
        btn.getAttribute("aria-label") ||
        btn.textContent ||
        ""
      ).trim();
      // At least one word character — an emoji-only name announces as nothing
      // useful.
      expect(name).toMatch(/[a-z]/i);
    }
  });

  it("announces the loading state", async () => {
    let settle;
    listOrganizations.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ organizations: [] });
        }),
    );
    render(<OrganizationManagement />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|organization/i);
    settle();
  });

  it("announces a load failure assertively", async () => {
    listOrganizations.mockRejectedValue(new Error("forbidden"));
    render(<OrganizationManagement />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/failed to load organizations/i);
  });

  it("traps focus inside the confirmation dialog", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("describes the confirmation dialog, not only labels it", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAccessibleDescription();
  });

  it("closes the confirmation on Escape", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = screen.getByText("Acme Corp").closest("tr");
    await user.click(within(row).getByRole("button", { name: /delete/i }));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("keeps a single page heading", async () => {
    await renderPage();
    expect(
      screen.getByRole("heading", { name: /^organizations$/i }),
    ).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   VISUAL / REGRESSION SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("OrganizationManagement — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    const html = container.innerHTML;
    expect(html).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(html).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("renders one row per organisation and no more", async () => {
    await renderPage();
    expect(document.querySelectorAll("tbody tr").length).toBe(2);
  });
});
