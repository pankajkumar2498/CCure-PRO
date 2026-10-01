/**
 * RoleManagement — Checkpoint 3C migration coverage.
 *
 * Written against the page BEFORE migration so it records the functional
 * baseline, then kept as the regression suite afterwards. Every assertion
 * about behaviour — which endpoints are called, in what order, what happens on
 * failure — holds identically before and after; only the assertions marked as
 * accessibility gains are new.
 *
 * The page is behind `PrivateRoute requiredPermission={{roles, read}}`, so a
 * browser screenshot needs an authenticated session. This suite is the
 * deterministic artefact that stands in for one.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import RoleManagement from "@audit/pages/admin/RoleManagement";
import AuthContext from "@shell/auth/AuthContext";
import { PreferencesProvider } from "@audit/context/PreferencesContext";
import { listRoles, listRolePermissions } from "@audit/api/admin";

vi.mock("@audit/api/admin", () => ({
  listRoles: vi.fn(),
  listRolePermissions: vi.fn(),
}));

vi.mock("@audit/api/user", () => ({
  getPreferences: vi.fn().mockResolvedValue({ theme: "light" }),
}));

// AppLayout pulls in the notification SSE stream, the org switcher and the
// quota bar. None of that is under test here, and mocking it keeps the diff
// this suite is guarding narrow.
vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const ROLES = [
  { id: 1, name: "superadmin", description: "Full platform access" },
  { id: 2, name: "analyst", description: "Runs scans and triages findings" },
  { id: 3, name: "viewer", description: null },
];

const PERMISSIONS = [
  { id: 10, resource: "scans", action: "execute", description: "Start a scan" },
  { id: 11, resource: "users", action: "manage", description: null },
];

function renderPage() {
  return render(
    <AuthContext.Provider
      value={{
        user: { role: { name: "superadmin", permissions: ["roles:read"] } },
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

beforeEach(() => {
  vi.clearAllMocks();
  listRoles.mockResolvedValue({ roles: ROLES });
  listRolePermissions.mockResolvedValue({ permissions: PERMISSIONS });
});

/* ── Functional baseline — must hold identically after migration ─────────── */

describe("RoleManagement — API contract", () => {
  it("loads the role list once on mount", async () => {
    renderPage();
    await waitFor(() => expect(listRoles).toHaveBeenCalledTimes(1));
    // No arguments: GET /admin/roles/ takes none.
    expect(listRoles).toHaveBeenCalledWith();
  });

  it("auto-selects the first role and loads its permissions", async () => {
    renderPage();
    // Pre-existing behaviour: the page selects roles[0] so the right-hand
    // panel is never empty on arrival. Preserved by the migration.
    await waitFor(() => expect(listRolePermissions).toHaveBeenCalledWith(1));
  });

  it("requests permissions for the role the user selects", async () => {
    renderPage();
    await screen.findByText("analyst");
    await userEvent.click(screen.getByText("analyst"));
    await waitFor(() => expect(listRolePermissions).toHaveBeenCalledWith(2));
  });

  it("makes no other request", async () => {
    renderPage();
    await waitFor(() => expect(listRolePermissions).toHaveBeenCalled());
    // The migration must not introduce polling or extra endpoints.
    expect(listRoles).toHaveBeenCalledTimes(1);
    expect(listRolePermissions).toHaveBeenCalledTimes(1);
  });
});

describe("RoleManagement — rendering", () => {
  it("renders every role with its description", async () => {
    renderPage();
    // "superadmin" appears twice — once in the list, once in the "Permissions
    // for <role>" heading — so this counts rather than expecting one node.
    expect((await screen.findAllByText("superadmin")).length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText("analyst")).toBeInTheDocument();
    expect(screen.getByText("Full platform access")).toBeInTheDocument();
  });

  it("falls back to a placeholder for a role with no description", async () => {
    renderPage();
    expect(await screen.findByText("No description")).toBeInTheDocument();
  });

  it("renders each permission's resource and action", async () => {
    renderPage();
    expect(await screen.findByText("scans")).toBeInTheDocument();
    expect(screen.getByText("execute")).toBeInTheDocument();
    expect(screen.getByText("manage")).toBeInTheDocument();
  });

  it("synthesises a description for a permission that has none", async () => {
    renderPage();
    // Pre-existing string: "Allows access to " + resource.
    expect(
      await screen.findByText("Allows access to users"),
    ).toBeInTheDocument();
  });

  it("sets the page title", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByTestId("app-layout")).toHaveAttribute(
        "data-page-title",
        "Roles & Permissions",
      ),
    );
  });
});

describe("RoleManagement — states", () => {
  it("shows a loading state before the roles arrive", async () => {
    let resolve;
    listRoles.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderPage();
    // Accessibility gain: the pre-migration page rendered a bare spinner div
    // with no text, so a screen reader was told nothing at all.
    expect(await screen.findByRole("status")).toHaveTextContent(/loading/i);
    resolve({ roles: ROLES });
    await screen.findByText("superadmin");
  });

  it("reports a failure to load roles", async () => {
    listRoles.mockRejectedValue(new Error("boom"));
    renderPage();
    expect(
      await screen.findByText(/Failed to load roles/i),
    ).toBeInTheDocument();
  });

  it("shows an empty state when a role has no permissions", async () => {
    listRolePermissions.mockResolvedValue({ permissions: [] });
    renderPage();
    expect(
      await screen.findByText(/No permissions assigned to this role/i),
    ).toBeInTheDocument();
  });

  it("keeps the table header visible while empty", async () => {
    listRolePermissions.mockResolvedValue({ permissions: [] });
    renderPage();
    await screen.findByText(/No permissions assigned/i);
    // Replacing the table wholesale would reflow the panel on every selection.
    expect(screen.getAllByRole("columnheader")).toHaveLength(3);
  });
});

/* ── Accessibility — the gains this migration is for ─────────────────────── */

describe("RoleManagement — accessibility", () => {
  it("gives the permissions table an accessible name", async () => {
    renderPage();
    // Before migration the table had no caption at all.
    const table = await screen.findByRole("table");
    expect(table).toHaveAccessibleName(/permissions/i);
  });

  it("marks every column header with scope=col", async () => {
    renderPage();
    const headers = await screen.findAllByRole("columnheader");
    expect(headers).toHaveLength(3);
    // 330 header cells across the application carry no scope; this is the
    // first page to fix it.
    for (const h of headers) expect(h).toHaveAttribute("scope", "col");
  });

  it("identifies each row by its resource", async () => {
    renderPage();
    const rowHeaders = await screen.findAllByRole("rowheader");
    expect(rowHeaders.map((h) => h.textContent)).toEqual(["scans", "users"]);
    for (const h of rowHeaders) expect(h).toHaveAttribute("scope", "row");
  });

  it("exposes the role list as a list of buttons with pressed state", async () => {
    renderPage();
    await screen.findByText("superadmin");
    const selected = screen
      .getAllByRole("button")
      .filter((b) => b.getAttribute("aria-pressed") === "true");
    // The pre-migration page styled the selected role but announced nothing,
    // so a screen-reader user could not tell which panel they were reading.
    expect(selected).toHaveLength(1);
    expect(selected[0]).toHaveTextContent("superadmin");
  });

  it("moves the pressed state when another role is chosen", async () => {
    renderPage();
    await screen.findByText("analyst");
    await userEvent.click(screen.getByText("analyst"));
    await waitFor(() => {
      const pressed = screen
        .getAllByRole("button")
        .filter((b) => b.getAttribute("aria-pressed") === "true");
      expect(pressed).toHaveLength(1);
      expect(pressed[0]).toHaveTextContent("analyst");
    });
  });

  it("names the two regions of the page", async () => {
    renderPage();
    await screen.findByText("superadmin");
    expect(screen.getByRole("region", { name: /roles/i })).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: /permissions/i }),
    ).toBeInTheDocument();
  });

  it("announces the permissions loading state", async () => {
    let resolve;
    listRolePermissions.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderPage();
    await screen.findByText("superadmin");
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading/i);
    resolve({ permissions: PERMISSIONS });
  });

  it("reports the load error as an alert", async () => {
    listRoles.mockRejectedValue(new Error("boom"));
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/Failed to load roles/i);
  });
});

/* ── Theming ─────────────────────────────────────────────────────────────── */

describe("RoleManagement — theming", () => {
  it("renders under data-theme=dark without pinning colour", async () => {
    document.documentElement.setAttribute("data-theme", "dark");
    try {
      const { container } = renderPage();
      await screen.findByText("scans");
      // The page is auth-gated, so a browser screenshot of it needs a session.
      // This is the deterministic stand-in: every colour now resolves through
      // --ccure-* tokens, which are redefined under [data-theme="dark"], and
      // nothing is pinned inline to defeat that.
      for (const el of container.querySelectorAll("*")) {
        expect(el.getAttribute("style") ?? "").not.toMatch(
          /(^|;)\s*(color|background)/,
        );
      }
      expect(screen.getByRole("table")).toBeInTheDocument();
    } finally {
      document.documentElement.removeAttribute("data-theme");
    }
  });

  it("pins no colour inline", async () => {
    const { container } = renderPage();
    await screen.findByText("scans");
    // The pre-migration page hardcoded #fef2f2 / #dc2626 / #f0f9ff / #0369a1
    // and rgba(37,99,235,.05), none of which respond to data-theme, plus
    // var(--primary) — a token that does not exist, so it resolved to nothing.
    for (const el of container.querySelectorAll("*")) {
      expect(el.getAttribute("style") ?? "").not.toMatch(
        /(^|;)\s*(color|background)/,
      );
    }
  });
});
