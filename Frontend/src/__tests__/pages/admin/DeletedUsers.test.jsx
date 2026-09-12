/**
 * DeletedUsers — Checkpoint 3C batch 5 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * Two state-changing operations on *accounts*: restore and purge. Both are
 * gated on the same permission, `users:delete`, and both are irreversible in
 * different directions — a purge removes the account row, and a restore returns
 * an account somebody deliberately deleted.
 *
 *   * `scope: "deleted"` is load-bearing. `listUsers` without it lists live
 *     accounts on a page whose second button deletes them permanently.
 *   * A restored user must stay INACTIVE. The page says so in the confirmation
 *     and the backend enforces it; the wording is the only thing telling the
 *     admin that restoring is not the same as re-enabling.
 *   * The organisation list is requested only for a superadmin, and the role
 *     name it is decided from is read from `user.role.name` — an object, not a
 *     string.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import DeletedUsers from "../../../pages/admin/DeletedUsers";
import {
  listUsers,
  listRoles,
  listOrganizations,
  restoreUser,
  purgeUser,
} from "../../../api/admin";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("../../../api/admin", () => ({
  listUsers: vi.fn(),
  listRoles: vi.fn(),
  listOrganizations: vi.fn(),
  restoreUser: vi.fn(),
  purgeUser: vi.fn(),
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let currentUser = { username: "admin", id: 1, role: { name: "org_admin" } };
vi.mock("../../../context/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

let permissions = new Set(["users:delete"]);
vi.mock("../../../auth/permissions", () => ({
  can: (_user, resource, action) => permissions.has(`${resource}:${action}`),
  denyMessage: "You do not have permission to perform this action.",
}));

const USERS = [
  {
    id: 101,
    username: "jdoe",
    full_name: "Jane Doe",
    email: "jane@acme.test",
    role_id: 3,
    organization_id: 7,
    deleted_at: "2026-08-01T10:00:00Z",
    last_login_at: "2026-07-30T09:00:00Z",
  },
  {
    id: 102,
    username: "bsmith",
    full_name: "Bob Smith",
    email: "bob@acme.test",
    role_id: 4,
    organization_id: 7,
    deleted_at: "2026-08-02T11:00:00Z",
    last_login_at: null,
  },
  {
    id: 103,
    username: "carol",
    full_name: "",
    email: "carol@other.test",
    role_id: 3,
    organization_id: 8,
    deleted_at: "2026-08-03T12:00:00Z",
    last_login_at: "2026-08-01T08:00:00Z",
  },
];

const ROLES = [
  { id: 3, name: "analyst" },
  { id: 4, name: "viewer" },
];

const ORGS = [
  { id: 7, name: "Acme Corp" },
  { id: 8, name: "Other Ltd" },
];

/* Row-scoped accessors. The migration gives each row's controls a distinct
   accessible name ("Delete jdoe permanently"), which is what the two
   "disambiguates" assertions below demand — so a page-wide query on the bare
   verb phrase stops matching. Scoping to the row is what makes a short pattern
   unambiguous, and it is stricter than the page-wide query it replaces: the
   page-wide uniqueness check is still asserted separately. */
const restoreBtn = (row) =>
  within(row).getByRole("button", { name: /restore/i });
const purgeBtn = (row) => within(row).getByRole("button", { name: /delete/i });

const renderPage = async () => {
  const result = render(<DeletedUsers />);
  await waitFor(() => expect(listUsers).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  currentUser = { username: "admin", id: 1, role: { name: "org_admin" } };
  permissions = new Set(["users:delete"]);
  listUsers.mockResolvedValue({ users: USERS });
  listRoles.mockResolvedValue({ roles: ROLES });
  listOrganizations.mockResolvedValue({ organizations: ORGS });
  restoreUser.mockResolvedValue({});
  purgeUser.mockResolvedValue({});
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("DeletedUsers — functional", () => {
  it("requests the deleted scope", async () => {
    await renderPage();
    expect(listUsers).toHaveBeenCalledWith({
      skip: 0,
      limit: 100,
      scope: "deleted",
    });
  });

  it("requests the role list", async () => {
    await renderPage();
    expect(listRoles).toHaveBeenCalled();
  });

  it("does not request organisations for a non-superadmin", async () => {
    await renderPage();
    expect(listOrganizations).not.toHaveBeenCalled();
  });

  it("requests organisations for a superadmin", async () => {
    currentUser = { username: "root", id: 1, role: { name: "superadmin" } };
    await renderPage();
    await waitFor(() => expect(listOrganizations).toHaveBeenCalled());
  });

  it("reads the role name from user.role.name, not from a bare string", async () => {
    // `role` is an object throughout this application. A page that compared
    // `user.role` to "superadmin" would silently take the non-superadmin path.
    currentUser = { username: "root", id: 1, role: { name: "SuperAdmin" } };
    await renderPage();
    await waitFor(() => expect(listOrganizations).toHaveBeenCalled());
  });

  it("renders one row per deleted user", async () => {
    await renderPage();
    expect(await screen.findByText("jdoe")).toBeInTheDocument();
    expect(screen.getByText("bsmith")).toBeInTheDocument();
    expect(screen.getByText("carol")).toBeInTheDocument();
  });

  it("resolves the role name for each user", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    expect(screen.getAllByText("analyst").length).toBe(2);
    expect(screen.getByText("viewer")).toBeInTheDocument();
  });

  it("resolves the organisation name for a superadmin", async () => {
    currentUser = { username: "root", id: 1, role: { name: "superadmin" } };
    await renderPage();
    // Two of the three fixtures share org 7, so this must be scoped to a row.
    // The first version queried the page and failed on "found multiple" —
    // a wrong assertion, not a page defect.
    const row = (await screen.findByText("jdoe")).closest("tr");
    await waitFor(() =>
      expect(within(row).getByText("Acme Corp")).toBeInTheDocument(),
    );
    const other = screen.getByText("carol").closest("tr");
    expect(within(other).getByText("Other Ltd")).toBeInTheDocument();
  });

  it("renders Never for a user who has never logged in", async () => {
    await renderPage();
    await screen.findByText("bsmith");
    expect(screen.getByText("Never")).toBeInTheDocument();
  });

  it("counts the deleted users in the subtitle", async () => {
    const { container } = await renderPage();
    await screen.findByText("jdoe");
    // The pagination summary also says "of 3 deleted users", so a page-wide
    // text query matches twice. Scoped to the subtitle, which is what this
    // assertion is actually about.
    const subtitle = container.querySelector(".page-subtitle");
    expect(subtitle).toHaveTextContent(/3 deleted users/i);
  });

  it("shows an empty state when nothing is deleted", async () => {
    listUsers.mockResolvedValue({ users: [] });
    await renderPage();
    expect(
      await screen.findByText(/deleted users is empty/i),
    ).toBeInTheDocument();
  });

  it("shows an error message when the load fails", async () => {
    listUsers.mockRejectedValue(new Error("network"));
    await renderPage();
    expect(
      await screen.findByText(/failed to load deleted users/i),
    ).toBeInTheDocument();
  });

  it("filters by username", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("jdoe");
    await user.type(screen.getByLabelText(/search deleted users/i), "bsmith");
    await waitFor(() =>
      expect(screen.queryByText("jdoe")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("bsmith")).toBeInTheDocument();
  });

  it("filters by email", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("jdoe");
    await user.type(
      screen.getByLabelText(/search deleted users/i),
      "other.test",
    );
    await waitFor(() =>
      expect(screen.queryByText("jdoe")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("carol")).toBeInTheDocument();
  });

  it("filters by full name", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("jdoe");
    await user.type(screen.getByLabelText(/search deleted users/i), "Bob");
    await waitFor(() =>
      expect(screen.queryByText("jdoe")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("bsmith")).toBeInTheDocument();
  });

  it("refreshes on demand", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("jdoe");
    await user.click(screen.getByRole("button", { name: /refresh/i }));
    await waitFor(() => expect(listUsers).toHaveBeenCalledTimes(2));
  });

  it("navigates to the active user list", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /active users/i }));
    expect(navigate).toHaveBeenCalledWith("/admin/users");
  });

  it("reports the visible range in the pagination summary", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    expect(screen.getByText(/showing 1.3 of 3/i)).toBeInTheDocument();
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<DeletedUsers />);
      await waitFor(() => expect(listUsers).toHaveBeenCalledTimes(1));
      await vi.advanceTimersByTimeAsync(120000);
      expect(listUsers).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("DeletedUsers — security", () => {
  it("never restores without an explicit confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(restoreBtn(row));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(restoreUser).not.toHaveBeenCalled();
  });

  it("restores only after the confirmation is accepted", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(restoreBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /restore user/i }),
    );
    await waitFor(() => expect(restoreUser).toHaveBeenCalledWith(101));
  });

  it("says a restored account stays inactive", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(restoreBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/stay inactive/i)).toBeInTheDocument();
  });

  it("never purges without an explicit confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(purgeUser).not.toHaveBeenCalled();
  });

  it("purges only after the confirmation is accepted", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete permanently/i }),
    );
    await waitFor(() => expect(purgeUser).toHaveBeenCalledWith(101));
  });

  it("names the account being purged", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/jdoe/)).toBeInTheDocument();
  });

  it("says the purge cannot be undone", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/cannot be undone/i)).toBeInTheDocument();
  });

  it("sends nothing when a purge confirmation is cancelled", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(purgeUser).not.toHaveBeenCalled();
  });

  it("drops the row after a successful purge", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete permanently/i }),
    );
    await waitFor(() =>
      expect(screen.queryByText("jdoe")).not.toBeInTheDocument(),
    );
  });

  it("keeps the row when a purge fails", async () => {
    purgeUser.mockRejectedValue({
      response: { data: { detail: "Account is referenced." } },
    });
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete permanently/i }),
    );
    await waitFor(() => expect(purgeUser).toHaveBeenCalled());
    expect(screen.getByText("jdoe")).toBeInTheDocument();
  });

  it("offers no action controls without users:delete", async () => {
    permissions = new Set();
    await renderPage();
    await screen.findByText("jdoe");
    expect(
      screen.queryByRole("button", { name: /restore/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
    expect(screen.getAllByText(/read only/i).length).toBe(3);
  });

  it("does not leak an organisation name a non-superadmin never fetched", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    expect(screen.queryByText("Acme Corp")).not.toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("DeletedUsers — accessibility", () => {
  it("gives the table an accessible name", async () => {
    await renderPage();
    const table = await screen.findByRole("table");
    expect(table).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th.getAttribute("scope")).toBe("col");
    }
  });

  it("marks the identifying cell as its row's header", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(3);
  });

  it("disambiguates the restore control per row", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    const buttons = screen.getAllByRole("button", { name: /restore/i });
    expect(buttons.length).toBe(3);
    const names = buttons.map(
      (b) => b.getAttribute("aria-label") || b.textContent.trim(),
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("disambiguates the purge control per row", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    const buttons = screen.getAllByRole("button", { name: /delete/i });
    expect(buttons.length).toBe(3);
    const names = buttons.map(
      (b) => b.getAttribute("aria-label") || b.textContent.trim(),
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("announces the loading state", async () => {
    let settle;
    listUsers.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ users: [] });
        }),
    );
    render(<DeletedUsers />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading/i);
    settle();
  });

  it("announces a load failure assertively", async () => {
    listUsers.mockRejectedValue(new Error("network"));
    await renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/failed to load deleted users/i);
  });

  it("labels the search field", async () => {
    await renderPage();
    expect(screen.getByLabelText(/search deleted users/i)).toBeInTheDocument();
  });

  it("announces the page position when paging", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    const live = [...document.querySelectorAll('[role="status"],[aria-live]')];
    expect(live.some((e) => /page \d+ of \d+/i.test(e.textContent))).toBe(true);
  });

  it("labels the pagination landmark", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    const nav = screen.queryByRole("navigation", { name: /pagination/i });
    expect(nav).toBeInTheDocument();
  });

  it("traps focus inside the confirmation dialog", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("describes the confirmation dialog, not only labels it", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAccessibleDescription();
  });

  it("closes the confirmation on Escape", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("jdoe")).closest("tr");
    await user.click(purgeBtn(row));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   VISUAL / REGRESSION SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("DeletedUsers — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("jdoe");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("jdoe");
    const html = container.innerHTML;
    expect(html).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(html).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("jdoe");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("renders one row per user and no more", async () => {
    await renderPage();
    await screen.findByText("jdoe");
    expect(document.querySelectorAll("tbody tr").length).toBe(3);
  });

  it("keeps the page heading", async () => {
    await renderPage();
    expect(
      screen.getByRole("heading", { name: /^deleted users$/i, level: 2 }),
    ).toBeInTheDocument();
  });
});
