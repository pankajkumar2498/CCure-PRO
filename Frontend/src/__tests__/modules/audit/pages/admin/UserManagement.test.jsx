/**
 * UserManagement — Checkpoint 3C batch 13 migration coverage.
 *
 * Written against the page BEFORE migration, with the REAL UserTable,
 * UserForm and RoleSelector (they migrate in the same batch) and the REAL
 * auth/permissions module, so the three personas below exercise the page's
 * own gating rather than a mocked answer.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 *   * create → users:create; edit/reset/deactivate/unlock → users:update;
 *     delete → users:delete. A viewer with none of them sees a read-only table.
 *   * superadmin only: the organization filter, the organization field in the
 *     form, the org_admin note absent, and the superadmin role offered.
 *   * delete, deactivate and MFA reset are CONFIRMATION-GATED: the API is not
 *     called until the confirm control is used, and never when cancelled.
 *   * a password typed into the create form or the reset dialog reaches the
 *     API and NOTHING else: no attribute, accessible name or visible text.
 *   * the current user cannot deactivate, delete or MFA-reset themselves.
 *
 * ── Dual-path helpers ───────────────────────────────────────────────────────
 * Controls are found by accessible name, which the migration keeps; the
 * dialogs by role="dialog" (legacy Modal and CcureModal both expose it).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import UserManagement from "@audit/pages/admin/UserManagement";
import * as adminApi from "@audit/api/admin";
import { checkUsername, checkEmail } from "@shell/api/auth";

const navigate = vi.fn();
let searchParams = new URLSearchParams();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useSearchParams: () => [searchParams],
  };
});

vi.mock("@audit/api/admin", () => ({
  listUsers: vi.fn(),
  listRoles: vi.fn(),
  listOrganizations: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  changeUserRole: vi.fn(),
  changeUserStatus: vi.fn(),
  deleteUser: vi.fn(),
  moveUserOrganization: vi.fn(),
  resetUserPassword: vi.fn(),
  resetUserMfa: vi.fn(),
  listPendingUsers: vi.fn(),
  approveUser: vi.fn(),
}));

vi.mock("@shell/api/auth", () => ({
  checkUsername: vi.fn(),
  checkEmail: vi.fn(),
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

/* Personas, shaped exactly as AuthContext hands them out: `role` is an object
   with `name` and `permissions`. */
const SUPERADMIN = {
  id: 1,
  username: "root",
  org_id: 7,
  role: { name: "superadmin", permissions: [] },
};
const ORG_ADMIN = {
  id: 2,
  username: "orgadmin",
  org_id: 7,
  role: {
    name: "org_admin",
    permissions: [
      { resource: "users", action: "read" },
      { resource: "users", action: "create" },
      { resource: "users", action: "update" },
      { resource: "users", action: "delete" },
    ],
  },
};
const VIEWER = {
  id: 3,
  username: "viewer",
  org_id: 7,
  role: {
    name: "viewer",
    permissions: [{ resource: "users", action: "read" }],
  },
};

let currentUser = SUPERADMIN;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

const ROLES = [
  { id: 1, name: "superadmin" },
  { id: 2, name: "org_admin" },
  { id: 3, name: "analyst" },
  { id: 4, name: "viewer" },
];
const ORGS = [
  { id: 7, name: "Acme Corp", slug: "acme" },
  { id: 8, name: "Other Ltd", slug: "other" },
];
const USERS = [
  {
    id: 1,
    username: "root",
    email: "root@example.test",
    full_name: "Root Admin",
    role_id: 1,
    organization_id: 7,
    is_active: true,
    mfa_enabled: true,
    last_login_at: "2026-09-10T08:00:00Z",
  },
  {
    id: 10,
    username: "alice",
    email: "alice@example.test",
    full_name: "Alice Analyst",
    role_id: 3,
    organization_id: 7,
    is_active: true,
    mfa_enabled: true,
    last_login_at: "2026-09-11T08:00:00Z",
  },
  {
    id: 11,
    username: "bob",
    email: "bob@example.test",
    full_name: "Bob Builder",
    role_id: 4,
    organization_id: 8,
    is_active: false,
    mfa_enabled: false,
    last_login_at: null,
  },
  {
    id: 12,
    username: "carol",
    email: "carol@example.test",
    full_name: "Carol Locked",
    role_id: 4,
    organization_id: 7,
    is_active: true,
    mfa_enabled: false,
    locked_until: "2099-01-01T00:00:00Z",
    last_login_at: null,
  },
];

const dialog = () => screen.getByRole("dialog");

/* Dual-path: the legacy RoleSelector and the Organization FormField render a
   <label> with no `for`, so getByLabelText cannot find the select before the
   migration. Fall back to the select that follows the label text; the
   migrated form associates them and the first path is taken. */
const selectFor = (root, re) => {
  const byLabel = within(root)
    .queryAllByLabelText(re)
    .find((el) => el.tagName === "SELECT");
  if (byLabel) return byLabel;
  const label = within(root).getAllByText(re, { selector: "label" })[0];
  const sel = label.closest(".field, .cc-field")?.querySelector("select");
  if (!sel) throw new Error(`no select for ${re}`);
  return sel;
};
const rowOf = (username) =>
  screen.getByText(username, { selector: "span, th, td, div" }).closest("tr");
const rowButton = (username, name) =>
  within(rowOf(username)).getByRole("button", { name });

const renderPage = async () => {
  const utils = render(<UserManagement />);
  await waitFor(() => expect(adminApi.listUsers).toHaveBeenCalled());
  await screen.findByText("alice");
  return utils;
};

/* The password must reach the API and nothing else. Every attribute on every
   element is inspected except the password control's own `value`, and the
   whole visible text. */
const assertSecretNotLeaked = (secret) => {
  expect(document.body.textContent).not.toContain(secret);
  for (const el of document.body.querySelectorAll("*")) {
    for (const attr of el.attributes) {
      if (attr.name === "value" && el.getAttribute("type") === "password")
        continue;
      expect(
        attr.value,
        `${el.tagName}[${attr.name}] carries the password`,
      ).not.toContain(secret);
    }
  }
};

beforeEach(() => {
  vi.clearAllMocks();
  currentUser = SUPERADMIN;
  searchParams = new URLSearchParams();
  adminApi.listUsers.mockResolvedValue({ users: USERS, total: USERS.length });
  adminApi.listRoles.mockResolvedValue({ roles: ROLES });
  adminApi.listOrganizations.mockResolvedValue({ organizations: ORGS });
  adminApi.listPendingUsers.mockResolvedValue([]);
  adminApi.createUser.mockResolvedValue({});
  adminApi.updateUser.mockResolvedValue({});
  adminApi.changeUserRole.mockResolvedValue({});
  adminApi.changeUserStatus.mockResolvedValue({});
  adminApi.deleteUser.mockResolvedValue({});
  adminApi.moveUserOrganization.mockResolvedValue({});
  adminApi.resetUserPassword.mockResolvedValue({});
  adminApi.resetUserMfa.mockResolvedValue({});
  adminApi.approveUser.mockResolvedValue({});
  checkUsername.mockResolvedValue({ available: true });
  checkEmail.mockResolvedValue({ available: true });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("UserManagement — reads and personas", () => {
  it("loads the first page server-side with the page size and no filters", async () => {
    await renderPage();
    expect(adminApi.listUsers).toHaveBeenCalledWith({
      skip: 0,
      limit: 10,
      q: undefined,
      organization_id: undefined,
    });
    expect(screen.getByText("alice@example.test")).toBeInTheDocument();
    expect(screen.getAllByText("Acme Corp", { selector: "td" })).toHaveLength(
      3,
    );
  });

  it("superadmin: fetches roles AND organizations, shows the organization filter, no org_admin note", async () => {
    await renderPage();
    expect(adminApi.listRoles).toHaveBeenCalled();
    expect(adminApi.listOrganizations).toHaveBeenCalled();
    expect(screen.getByDisplayValue("All Organizations")).toBeInTheDocument();
    expect(
      screen.queryByText(/Org admins can only manage users/),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/4 total users across all organizations/),
    ).toBeInTheDocument();
  });

  it("superadmin: an org_id in the URL pre-filters the list", async () => {
    searchParams = new URLSearchParams("org_id=8");
    await renderPage();
    expect(adminApi.listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ organization_id: "8" }),
    );
  });

  it("org_admin: roles only, no organization filter, own-organization note, no Organization column", async () => {
    currentUser = ORG_ADMIN;
    await renderPage();
    expect(adminApi.listRoles).toHaveBeenCalled();
    expect(adminApi.listOrganizations).not.toHaveBeenCalled();
    expect(
      screen.queryByDisplayValue("All Organizations"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Org admins can only manage users/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("columnheader", { name: "Organization" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/4 users in your organization/),
    ).toBeInTheDocument();
  });

  it("viewer: no create / deleted-users controls and every row is read only", async () => {
    currentUser = VIEWER;
    await renderPage();
    expect(
      screen.queryByRole("button", { name: /create user/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /deleted users/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /edit/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
    expect(screen.getAllByText("Read only")).toHaveLength(USERS.length);
  });

  it("the Deleted users control navigates to the recycle list (users:delete only)", async () => {
    await renderPage();
    await userEvent.click(
      screen.getByRole("button", { name: /deleted users/i }),
    );
    expect(navigate).toHaveBeenCalledWith("/admin/users/deleted");
  });

  it("search is debounced and resets to page 1; paging sends the next skip", async () => {
    await renderPage();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const search = screen.getByPlaceholderText(/search by username/i);
    await userEvent.type(search, "ali");
    expect(adminApi.listUsers).toHaveBeenCalledTimes(1);
    await act(async () => {
      vi.advanceTimersByTime(400);
    });
    await waitFor(() =>
      expect(adminApi.listUsers).toHaveBeenLastCalledWith(
        expect.objectContaining({ q: "ali", skip: 0 }),
      ),
    );
    vi.useRealTimers();
  });

  it("paging requests the next slice", async () => {
    adminApi.listUsers.mockResolvedValue({ users: USERS, total: 25 });
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: /^next$/i }));
    await waitFor(() =>
      expect(adminApi.listUsers).toHaveBeenLastCalledWith(
        expect.objectContaining({ skip: 10, limit: 10 }),
      ),
    );
    expect(screen.getByText(/Page 2 of 3/)).toBeInTheDocument();
  });

  it("shows the load error", async () => {
    adminApi.listUsers.mockRejectedValue(new Error("boom"));
    render(<UserManagement />);
    expect(await screen.findByText(/Unable to load users/)).toBeInTheDocument();
  });

  it("row status: active, inactive and locked are told apart; last login 'Never' when null", async () => {
    await renderPage();
    expect(within(rowOf("alice")).getByText("Active")).toBeInTheDocument();
    expect(within(rowOf("bob")).getByText("Inactive")).toBeInTheDocument();
    expect(within(rowOf("carol")).getByText("Locked")).toBeInTheDocument();
    expect(within(rowOf("bob")).getByText("Never")).toBeInTheDocument();
  });
});

describe("UserManagement — create and edit", () => {
  it("creates a user with the form's own field names; the password reaches the API only", async () => {
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: /create user/i }));
    const dlg = dialog();
    expect(dlg).toHaveAccessibleName(/create new user/i);

    const secret = "Xy9!secretPass";
    await userEvent.type(within(dlg).getByLabelText(/^username/i), "dave");
    await userEvent.type(within(dlg).getByLabelText(/full name/i), "Dave Dev");
    await userEvent.type(
      within(dlg).getByLabelText(/email address/i),
      "Dave@Example.TEST",
    );
    const pw = within(dlg).getByLabelText(/^password/i);
    expect(pw).toHaveAttribute("type", "password");
    await userEvent.type(pw, secret);
    await userEvent.selectOptions(selectFor(dlg, /^role/i), "3");
    await userEvent.selectOptions(selectFor(dlg, /^organization/i), "8");

    assertSecretNotLeaked(secret);

    await userEvent.click(
      within(dlg).getByRole("button", { name: /^create user$/i }),
    );
    await waitFor(() => expect(adminApi.createUser).toHaveBeenCalledTimes(1));
    expect(adminApi.createUser).toHaveBeenCalledWith({
      username: "dave",
      full_name: "Dave Dev",
      email: "dave@example.test",
      password: secret,
      role_id: 3,
      organization_id: "8",
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    // Quiet reload after the write.
    expect(adminApi.listUsers).toHaveBeenCalledTimes(2);
  });

  it("the create form refuses to submit until username, email, password, role and organization are set", async () => {
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: /create user/i }));
    const dlg = dialog();
    const submit = within(dlg).getByRole("button", { name: /^create user$/i });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dlg).getByLabelText(/^username/i), "dave");
    await userEvent.type(
      within(dlg).getByLabelText(/email address/i),
      "dave@example.test",
    );
    await userEvent.type(
      within(dlg).getByLabelText(/^password/i),
      "Xy9!secretPass",
    );
    await userEvent.selectOptions(selectFor(dlg, /^role/i), "3");
    expect(submit).toBeDisabled(); // organization still unset for a superadmin
    await userEvent.selectOptions(selectFor(dlg, /^organization/i), "7");
    expect(submit).toBeEnabled();
  });

  it("a taken username is reported after the debounced availability check and blocks submit", async () => {
    checkUsername.mockResolvedValue({ available: false });
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: /create user/i }));
    const dlg = dialog();
    await userEvent.type(within(dlg).getByLabelText(/^username/i), "alice");
    await waitFor(() => expect(checkUsername).toHaveBeenCalledWith("alice"), {
      timeout: 2000,
    });
    expect(
      await within(dlg).findAllByText(/username is already taken/i),
    ).not.toHaveLength(0);
    await userEvent.type(
      within(dlg).getByLabelText(/email address/i),
      "a@example.test",
    );
    await userEvent.type(
      within(dlg).getByLabelText(/^password/i),
      "Xy9!secretPass",
    );
    await userEvent.selectOptions(selectFor(dlg, /^role/i), "3");
    await userEvent.selectOptions(selectFor(dlg, /^organization/i), "7");
    expect(
      within(dlg).getByRole("button", { name: /^create user$/i }),
    ).toBeDisabled();
  });

  it("org_admin: the create form has no organization field and does not offer the superadmin role", async () => {
    currentUser = ORG_ADMIN;
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: /create user/i }));
    const dlg = dialog();
    expect(
      within(dlg).queryAllByText(/^organization/i, { selector: "label" })[0] ??
        null,
    ).not.toBeInTheDocument();
    const roleOptions = within(selectFor(dlg, /^role/i)).getAllByRole("option");
    expect(roleOptions.map((o) => o.textContent)).not.toContain("superadmin");
    expect(roleOptions.map((o) => o.textContent)).toContain("analyst");
  });

  it("org_admin: a created user is filed under the admin's own organization", async () => {
    currentUser = ORG_ADMIN;
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: /create user/i }));
    const dlg = dialog();
    await userEvent.type(within(dlg).getByLabelText(/^username/i), "dave");
    await userEvent.type(
      within(dlg).getByLabelText(/email address/i),
      "dave@example.test",
    );
    await userEvent.type(
      within(dlg).getByLabelText(/^password/i),
      "Xy9!secretPass",
    );
    await userEvent.selectOptions(selectFor(dlg, /^role/i), "3");
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^create user$/i }),
    );
    await waitFor(() =>
      expect(adminApi.createUser).toHaveBeenCalledWith(
        expect.objectContaining({ organization_id: 7, role_id: 3 }),
      ),
    );
  });

  it("edit: prefilled, and only the changed facets are written (profile, then role, then organization)", async () => {
    await renderPage();
    await userEvent.click(rowButton("alice", /edit/i));
    const dlg = dialog();
    expect(dlg).toHaveAccessibleName(/edit alice/i);
    expect(within(dlg).queryByLabelText(/^username/i)).not.toBeInTheDocument();
    expect(within(dlg).queryByLabelText(/^password/i)).not.toBeInTheDocument();
    expect(within(dlg).getByLabelText(/full name/i)).toHaveValue(
      "Alice Analyst",
    );
    expect(selectFor(dlg, /^role/i)).toHaveValue("3");
    expect(selectFor(dlg, /^organization/i)).toHaveValue("7");

    await userEvent.clear(within(dlg).getByLabelText(/full name/i));
    await userEvent.type(within(dlg).getByLabelText(/full name/i), "Alice A.");
    await userEvent.selectOptions(selectFor(dlg, /^role/i), "2");
    await userEvent.selectOptions(selectFor(dlg, /^organization/i), "8");
    await userEvent.click(
      within(dlg).getByRole("button", { name: /save changes/i }),
    );

    await waitFor(() => expect(adminApi.updateUser).toHaveBeenCalledTimes(1));
    expect(adminApi.updateUser).toHaveBeenCalledWith(10, {
      full_name: "Alice A.",
      email: "alice@example.test",
    });
    expect(adminApi.changeUserRole).toHaveBeenCalledWith(10, 2);
    expect(adminApi.moveUserOrganization).toHaveBeenCalledWith(10, "8");
  });

  it("edit without a role or organization change writes the profile only", async () => {
    await renderPage();
    await userEvent.click(rowButton("alice", /edit/i));
    const dlg = dialog();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /save changes/i }),
    );
    await waitFor(() => expect(adminApi.updateUser).toHaveBeenCalledTimes(1));
    expect(adminApi.changeUserRole).not.toHaveBeenCalled();
    expect(adminApi.moveUserOrganization).not.toHaveBeenCalled();
  });

  it("cancel closes the form without writing", async () => {
    await renderPage();
    await userEvent.click(rowButton("alice", /edit/i));
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(adminApi.updateUser).not.toHaveBeenCalled();
  });
});

describe("UserManagement — confirmation-gated and self-protected actions", () => {
  it("delete asks first, cancels without a write, and deletes only on confirm", async () => {
    await renderPage();
    await userEvent.click(rowButton("alice", /delete/i));
    let dlg = dialog();
    expect(dlg).toHaveAccessibleName(/move alice to deleted users/i);
    expect(adminApi.deleteUser).not.toHaveBeenCalled();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(adminApi.deleteUser).not.toHaveBeenCalled();

    await userEvent.click(rowButton("alice", /delete/i));
    dlg = dialog();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /move to deleted users/i }),
    );
    await waitFor(() => expect(adminApi.deleteUser).toHaveBeenCalledWith(10));
    await waitFor(() =>
      expect(screen.queryByText("alice")).not.toBeInTheDocument(),
    );
  });

  it("deactivate is confirmation-gated and sends the inverted flag", async () => {
    await renderPage();
    await userEvent.click(rowButton("alice", /deactivate/i));
    const dlg = dialog();
    expect(dlg).toHaveAccessibleName(/deactivate user/i);
    expect(adminApi.changeUserStatus).not.toHaveBeenCalled();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^deactivate$/i }),
    );
    await waitFor(() =>
      expect(adminApi.changeUserStatus).toHaveBeenCalledWith(10, {
        is_active: false,
      }),
    );
    expect(within(rowOf("alice")).getByText("Inactive")).toBeInTheDocument();
  });

  it("activate an inactive user sends is_active: true", async () => {
    await renderPage();
    await userEvent.click(rowButton("bob", /activate/i));
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /^activate$/i }),
    );
    await waitFor(() =>
      expect(adminApi.changeUserStatus).toHaveBeenCalledWith(11, {
        is_active: true,
      }),
    );
  });

  it("MFA reset is offered only for MFA-enabled others, is confirmation-gated, and clears the flag", async () => {
    await renderPage();
    expect(
      within(rowOf("bob")).queryByRole("button", { name: /reset mfa/i }),
    ).not.toBeInTheDocument();
    expect(
      within(rowOf("root")).queryByRole("button", { name: /reset mfa/i }),
    ).not.toBeInTheDocument();
    await userEvent.click(rowButton("alice", /reset mfa/i));
    const dlg = dialog();
    expect(dlg).toHaveAccessibleName(/reset mfa for alice/i);
    expect(adminApi.resetUserMfa).not.toHaveBeenCalled();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^reset mfa$/i }),
    );
    await waitFor(() => expect(adminApi.resetUserMfa).toHaveBeenCalledWith(10));
    await waitFor(() =>
      expect(
        within(rowOf("alice")).queryByRole("button", { name: /reset mfa/i }),
      ).not.toBeInTheDocument(),
    );
  });

  it("unlock is offered on a locked row only and clears locked_until", async () => {
    await renderPage();
    expect(
      within(rowOf("alice")).queryByRole("button", { name: /unlock/i }),
    ).not.toBeInTheDocument();
    await userEvent.click(rowButton("carol", /unlock/i));
    await waitFor(() =>
      expect(adminApi.changeUserStatus).toHaveBeenCalledWith(12, {
        locked_until: null,
      }),
    );
    await waitFor(() =>
      expect(within(rowOf("carol")).getByText("Active")).toBeInTheDocument(),
    );
  });

  it("the current user's own row carries no deactivate or delete control", async () => {
    await renderPage();
    const self = rowOf("root");
    expect(
      within(self).queryByRole("button", { name: /deactivate/i }),
    ).not.toBeInTheDocument();
    expect(
      within(self).queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
    expect(
      within(self).getByRole("button", { name: /edit/i }),
    ).toBeInTheDocument();
  });

  it("password reset: the new password reaches the API only, and the dialog closes", async () => {
    await renderPage();
    await userEvent.click(rowButton("alice", /reset password|^🔑 reset$/i));
    const dlg = dialog();
    expect(dlg).toHaveAccessibleName(/reset password for alice/i);
    const secret = "N3w!Passw0rdXyz";
    const pw = within(dlg).getByLabelText(/new password/i, {
      selector: "input",
    });
    expect(pw).toHaveAttribute("type", "password");
    const submit = within(dlg).getByRole("button", {
      name: /^reset password$/i,
    });
    expect(submit).toBeDisabled();
    await userEvent.type(pw, secret);
    assertSecretNotLeaked(secret);
    await userEvent.click(submit);
    await waitFor(() =>
      expect(adminApi.resetUserPassword).toHaveBeenCalledWith(10, secret),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("password reset failure keeps the dialog open and reports the server's detail", async () => {
    adminApi.resetUserPassword.mockRejectedValue({
      response: { data: { detail: [{ msg: "Password too weak" }] } },
    });
    await renderPage();
    await userEvent.click(rowButton("alice", /reset password|^🔑 reset$/i));
    const dlg = dialog();
    await userEvent.type(
      within(dlg).getByLabelText(/new password/i, { selector: "input" }),
      "weak",
    );
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^reset password$/i }),
    );
    expect(await screen.findByText(/Password too weak/)).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});

describe("UserManagement — approval queue", () => {
  const PENDING = [
    {
      id: 20,
      username: "newbie",
      email: "newbie@radiant-flow.org",
      full_name: "New Person",
      is_verified: true,
      is_email_flagged: true,
      email_risk: {
        reason: "young_domain",
        flags: ["no_mx"],
        domain: "radiant-flow.org",
        signals: { domain_age_days: 513, mx_status: "no_mx" },
      },
      created_at: "2026-09-10T09:00:00Z",
    },
    {
      id: 21,
      username: "unverified",
      email: "unverified@example.test",
      is_verified: false,
      is_email_flagged: false,
      email_risk: null,
    },
  ];

  it("lists pending accounts with their domain facts; approve-only sends allowlistDomain false", async () => {
    adminApi.listPendingUsers.mockResolvedValue(PENDING);
    await renderPage();
    expect(
      await screen.findByText(/2 accounts awaiting approval/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /domain registered recently · domain publishes no mail exchanger/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /radiant-flow\.org · registered 513 days ago · no mail exchanger/,
      ),
    ).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: /^approve only$/i }),
    );
    await waitFor(() =>
      expect(adminApi.approveUser).toHaveBeenCalledWith(20, {
        allowlistDomain: false,
      }),
    );
    expect(adminApi.listPendingUsers).toHaveBeenCalledTimes(2);
  });

  it("an unverified account cannot be approved; a flagged one offers the allow-domain path behind a confirmation dialog", async () => {
    adminApi.listPendingUsers.mockResolvedValue(PENDING);
    await renderPage();
    await screen.findByText(/2 accounts awaiting approval/);
    const approveButtons = screen.getAllByRole("button", {
      name: /^approve$/i,
    });
    expect(approveButtons.some((b) => b.disabled)).toBe(true);
    expect(
      screen.getAllByRole("button", { name: /allow domain/i }),
    ).toHaveLength(1);
    await userEvent.click(
      screen.getByRole("button", { name: /allow domain/i }),
    );

    /* The platform-wide list is not touched until the dialog is answered, and
       the dialog carries the sentence the native prompt used to. */
    const dlg = await screen.findByRole("dialog");
    expect(
      within(dlg).getByText(/adds radiant-flow\.org to the/i),
    ).toBeInTheDocument();
    expect(adminApi.approveUser).not.toHaveBeenCalled();

    await userEvent.click(
      within(dlg).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(adminApi.approveUser).not.toHaveBeenCalled();

    // Confirming is what sends the allow-list flag.
    await userEvent.click(
      screen.getByRole("button", { name: /allow domain/i }),
    );
    const again = await screen.findByRole("dialog");
    await userEvent.click(
      within(again).getByRole("button", { name: /approve \+ allow domain/i }),
    );
    await waitFor(() =>
      expect(adminApi.approveUser).toHaveBeenCalledWith(20, {
        allowlistDomain: true,
      }),
    );
  });

  it("the queue is not rendered for a user without users:update", async () => {
    adminApi.listPendingUsers.mockResolvedValue(PENDING);
    currentUser = VIEWER;
    await renderPage();
    expect(screen.queryByText(/awaiting approval/)).not.toBeInTheDocument();
  });
});
