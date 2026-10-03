/**
 * RoleManagement — Platform RBAC administration (RBAC-7).
 *
 * Every control is driven by the backend: what the signed-in account may do (the
 * authorization payload) and what each role reports (kind, state, blockers). A role's
 * display name is a label — the tests rename roles and show nothing else changes.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import RoleManagement from "@shell/admin/pages/RoleManagement";
import AuthContext from "@shell/auth/AuthContext";
import { PreferencesProvider } from "@shell/preferences/PreferencesContext";
import * as rbac from "@shell/api/rbac";
import { payload } from "../../../fixtures/authorization";

vi.mock("@shell/api/rbac", async (importOriginal) => ({
  ...(await importOriginal()),
  listRbacRoles: vi.fn(),
  getRbacRole: vi.fn(),
  listPermissionCatalogue: vi.fn(),
  createRbacRole: vi.fn(),
  updateRbacRole: vi.fn(),
  setRbacRolePermissions: vi.fn(),
  transitionRbacRole: vi.fn(),
  replaceRbacRole: vi.fn(),
}));
vi.mock("@shell/api/user", () => ({
  getPreferences: vi.fn().mockResolvedValue({ theme: "light" }),
}));
vi.mock("@shell/layout/ProductFrame", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const CATALOGUE = [
  {
    key: "audit.scan.read",
    module: "audit",
    resource: "scan",
    action: "read",
    description: "Read scans",
    scope: "organization",
    sensitivity: "normal",
    delegable: true,
    status: "active",
  },
  {
    key: "audit.scan.run",
    module: "audit",
    resource: "scan",
    action: "run",
    description: "Start scans",
    scope: "organization",
    sensitivity: "normal",
    delegable: true,
    status: "active",
  },
  {
    key: "platform.organization.switch",
    module: "platform",
    resource: "organization",
    action: "switch",
    description: "Enter another organisation",
    scope: "platform",
    sensitivity: "privileged",
    delegable: false,
    status: "active",
  },
  {
    key: "audit.old.thing",
    module: "audit",
    resource: "old",
    action: "thing",
    description: "Gone",
    scope: "organization",
    sensitivity: "normal",
    delegable: true,
    status: "retired",
  },
];

const summary = (over) => ({
  id: "r1",
  key: "custom.o.reader",
  display_name: "Reader",
  description: null,
  kind: "custom",
  assignable_scope: "organization",
  org_id: "o",
  state: "active",
  revision: 1,
  permission_count: 1,
  assignment_count: 0,
  ...over,
});
const detail = (over) => ({
  ...summary(),
  permissions: ["audit.scan.read"],
  history: [
    {
      revision: 1,
      change_kind: "created",
      display_name: "Reader",
      state: "active",
    },
  ],
  retirement_blockers: [],
  sensitive: false,
  ...over,
});

const ALL = [
  "platform.role.read",
  "platform.role.create",
  "platform.role.update",
  "platform.role.retire",
  "audit.scan.read",
  "audit.scan.run",
];

function renderPage(keys = ALL, extra = {}) {
  const user = {
    id: "u1",
    org_id: "o",
    role: { name: "Whatever", permissions: [] },
    authorization: payload({ keys, active: "o", home: "o", ...extra }),
  };
  return render(
    <AuthContext.Provider
      value={{
        user,
        loading: false,
        authState: "authenticated",
        isAuthenticated: true,
      }}
    >
      <PreferencesProvider>
        <MemoryRouter>
          <RoleManagement />
        </MemoryRouter>
      </PreferencesProvider>
    </AuthContext.Provider>,
  );
}

let current;
beforeEach(() => {
  vi.clearAllMocks();
  current = detail();
  rbac.listRbacRoles.mockImplementation(async () => ({
    roles: [
      summary({
        id: current.id,
        display_name: current.display_name,
        state: current.state,
      }),
      summary({
        id: "sys",
        key: "platform.viewer",
        display_name: "Viewer",
        kind: "system",
        assignable_scope: "organization",
        org_id: null,
        assignment_count: 3,
      }),
    ],
  }));
  rbac.listPermissionCatalogue.mockResolvedValue({ permissions: CATALOGUE });
  rbac.getRbacRole.mockImplementation(async (id) =>
    id === "sys"
      ? detail({
          id: "sys",
          key: "platform.viewer",
          display_name: "Viewer",
          kind: "system",
          org_id: null,
          assignment_count: 3,
        })
      : current,
  );
  rbac.updateRbacRole.mockResolvedValue({});
  rbac.setRbacRolePermissions.mockResolvedValue({});
  rbac.transitionRbacRole.mockResolvedValue({});
  rbac.createRbacRole.mockResolvedValue({});
  rbac.replaceRbacRole.mockResolvedValue({});
});

describe("catalogue-driven permissions", () => {
  it("lists the backend's catalogue and nothing else, with scope and sensitivity", async () => {
    renderPage();
    expect(
      await screen.findByRole("checkbox", { name: "audit.scan.read" }),
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", { name: "audit.scan.run" }),
    ).not.toBeChecked();
    expect(screen.getByText("privileged")).toBeInTheDocument();
    expect(screen.getByText("not delegable")).toBeInTheDocument();
  });

  it("does not allow a retired, platform-scope or non-delegable permission to be added", async () => {
    renderPage();
    await screen.findByRole("checkbox", { name: "audit.scan.read" });
    expect(
      screen.getByRole("checkbox", { name: "audit.old.thing" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "platform.organization.switch" }),
    ).toBeDisabled();
  });

  it("disables what is beyond the administrator's own delegation", async () => {
    renderPage([
      "platform.role.read",
      "platform.role.update",
      "audit.scan.read",
    ]);
    await screen.findByRole("checkbox", { name: "audit.scan.read" });
    expect(
      screen.getByRole("checkbox", { name: "audit.scan.run" }),
    ).toBeDisabled();
  });

  it("saves the chosen keys through the API and reports success", async () => {
    const u = userEvent.setup();
    renderPage();
    await u.click(
      await screen.findByRole("checkbox", { name: "audit.scan.run" }),
    );
    await u.click(screen.getByRole("button", { name: "Save permissions" }));
    await waitFor(() =>
      expect(rbac.setRbacRolePermissions).toHaveBeenCalledWith(
        "r1",
        ["audit.scan.read", "audit.scan.run"],
        {},
      ),
    );
  });

  it("a system role's permissions are read-only", async () => {
    const u = userEvent.setup();
    renderPage();
    await u.click(await screen.findByRole("button", { name: /Viewer/ }));
    await screen.findByText(/change with a catalogue release/);
    expect(
      screen.getByRole("checkbox", { name: "audit.scan.read" }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Save permissions" }),
    ).toBeNull();
  });
});

describe("display names are labels", () => {
  it("a role named Superadmin gets no extra controls", async () => {
    current = detail({ display_name: "Superadmin" });
    renderPage(["platform.role.read"]);
    await screen.findByRole("heading", { name: "Superadmin" });
    expect(
      screen.queryByRole("button", { name: "New custom role" }),
    ).toBeNull();
    expect(screen.queryByRole("button", { name: "Save name" })).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "audit.scan.read" }),
    ).toBeDisabled();
  });

  it("renaming sends only the new label", async () => {
    const u = userEvent.setup();
    renderPage();
    const field = await screen.findByLabelText("Display name");
    await u.clear(field);
    await u.type(field, "CISO");
    await u.click(screen.getByRole("button", { name: "Save name" }));
    await waitFor(() =>
      expect(rbac.updateRbacRole).toHaveBeenCalledWith(
        "r1",
        { display_name: "CISO" },
        {},
      ),
    );
  });

  it("renaming a system role is offered only with the system-rename permission", async () => {
    const u = userEvent.setup();
    renderPage();
    await u.click(await screen.findByRole("button", { name: /Viewer/ }));
    await screen.findByRole("heading", { name: "Viewer" });
    expect(screen.getByLabelText("Display name")).toBeDisabled();
  });
});

describe("permission-driven controls", () => {
  it("shows create only to an account that may create roles", async () => {
    renderPage();
    expect(
      await screen.findByRole("button", { name: "New custom role" }),
    ).toBeInTheDocument();
  });

  it("hides create without the permission", async () => {
    renderPage(["platform.role.read"]);
    await screen.findByRole("heading", { name: "Reader" });
    expect(
      screen.queryByRole("button", { name: "New custom role" }),
    ).toBeNull();
  });

  it("creates a role from the catalogue", async () => {
    const u = userEvent.setup();
    renderPage();
    await u.click(
      await screen.findByRole("button", { name: "New custom role" }),
    );
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByLabelText("Display name"), "Auditor");
    await u.click(
      within(dialog).getByRole("checkbox", { name: "audit.scan.read" }),
    );
    await u.click(within(dialog).getByRole("button", { name: "Create role" }));
    await waitFor(() =>
      expect(rbac.createRbacRole).toHaveBeenCalledWith(
        { display_name: "Auditor", permission_keys: ["audit.scan.read"] },
        {},
      ),
    );
  });
});

describe("lifecycle", () => {
  it("shows the retirement blockers and offers replacement when holders exist", async () => {
    current = detail({
      assignment_count: 2,
      state: "retiring",
      retirement_blockers: ["active_assignments"],
    });
    renderPage();
    expect(await screen.findByText(/active_assignments/)).toBeInTheDocument();
    expect(screen.getByLabelText("Move holders to")).toBeInTheDocument();
  });

  it("moves assignments to the chosen replacement", async () => {
    const u = userEvent.setup();
    current = detail({ assignment_count: 2, state: "retiring" });
    renderPage();
    const select = await screen.findByLabelText("Move holders to");
    await u.selectOptions(select, "sys");
    await u.click(screen.getByRole("button", { name: "Move assignments" }));
    await waitFor(() =>
      expect(rbac.replaceRbacRole).toHaveBeenCalledWith("r1", "sys", {}),
    );
  });

  it("walks active → retiring → retired and reactivates", async () => {
    const u = userEvent.setup();
    renderPage();
    await u.click(
      await screen.findByRole("button", { name: "Start retiring" }),
    );
    await waitFor(() =>
      expect(rbac.transitionRbacRole).toHaveBeenCalledWith(
        "r1",
        { target: "retiring" },
        {},
      ),
    );
  });

  it("offers reactivation for a retired role", async () => {
    current = detail({ state: "retired" });
    renderPage();
    expect(
      await screen.findByRole("button", { name: "Reactivate" }),
    ).toBeInTheDocument();
  });

  it("without the retire permission there is no lifecycle control", async () => {
    renderPage([
      "platform.role.read",
      "platform.role.update",
      "audit.scan.read",
    ]);
    await screen.findByRole("heading", { name: "Reader" });
    expect(screen.queryByRole("button", { name: "Start retiring" })).toBeNull();
  });
});

describe("backend refusals and step-up", () => {
  it("shows the backend's own reasons for a refused change", async () => {
    const u = userEvent.setup();
    rbac.setRbacRolePermissions.mockRejectedValue({
      response: {
        status: 403,
        data: {
          detail: {
            code: "governance_refused",
            violations: [
              {
                code: "escalation_ceiling",
                message: "the actor does not hold audit.scan.run",
              },
            ],
          },
        },
      },
    });
    renderPage();
    await u.click(
      await screen.findByRole("checkbox", { name: "audit.scan.run" }),
    );
    await u.click(screen.getByRole("button", { name: "Save permissions" }));
    expect(
      await screen.findByText(/does not hold audit.scan.run/),
    ).toBeInTheDocument();
  });

  it("asks for an authenticator code on reauth_required and retries with it", async () => {
    const u = userEvent.setup();
    rbac.updateRbacRole
      .mockRejectedValueOnce({
        response: {
          status: 403,
          data: { detail: { code: "reauth_required" } },
        },
      })
      .mockResolvedValueOnce({});
    renderPage();
    const field = await screen.findByLabelText("Display name");
    await u.clear(field);
    await u.type(field, "Manager");
    await u.click(screen.getByRole("button", { name: "Save name" }));
    const dialog = await screen.findByRole("dialog", {
      name: /authenticator/i,
    });
    await u.type(within(dialog).getByLabelText("Authenticator code"), "123456");
    await u.click(within(dialog).getByRole("button", { name: "Confirm" }));
    await waitFor(() =>
      expect(rbac.updateRbacRole).toHaveBeenLastCalledWith(
        "r1",
        { display_name: "Manager" },
        { reauthCode: "123456" },
      ),
    );
  });
});
