import { everything } from "../../../../fixtures/authorization";
/**
 * AppLayout — Checkpoint 3C batch 12 baseline.
 *
 * Written against the shell BEFORE migration. The passing set is the
 * regression gate; the failing set is the migration specification.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Reads on mount:  GET /dashboard/summary (then every 30 s);
 *                  GET /admin/organizations/ (superadmin only);
 * Writes:          none from the shell itself.
 * Storage:         localStorage activeOrgId, sidebarCollapsed;
 *                  sessionStorage sidebarScrollPos.
 * Navigation:      SIDEBAR_SECTIONS filtered by canSeeNavItem
 *                  (superadminOnly → role gate; permission → canPermission);
 *                  global search Enter → /vulnerabilities?search= for a CVE id,
 *                  /assets?search= otherwise; Ctrl/Cmd+K focuses it.
 * Org switch:      writes activeOrgId and reloads the document.
 *
 * `auth/permissions` is REAL here — the nav gating is the thing under test.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import AppLayout from "@audit/components/layout/AppLayout";
import axiosInstance from "@shell/api/axiosInstance";
import { listOrganizations } from "@shell/api/admin";
import {
  getUnreadCount,
  getNotifications,
  streamNotificationEvents,
} from "@shell/api/notifications";
import { personaFrom } from "../../../../fixtures/authorization";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@shell/api/admin", () => ({ listOrganizations: vi.fn() }));

vi.mock("@shell/api/notifications", () => ({
  getUnreadCount: vi.fn(),
  getNotifications: vi.fn(),
  markAsRead: vi.fn(),
  markAllAsRead: vi.fn(),
  deleteNotification: vi.fn(),
  streamNotificationEvents: vi.fn(),
}));

vi.mock("@shell/api/user", () => ({
  getPreferences: vi.fn(),
  updatePreferences: vi.fn(),
}));

// Excluded from the batch: never rendered for real here.
vi.mock("@shell/account/ProfileModal", () => ({
  default: () => <div data-testid="profile-modal" />,
}));

const navigate = vi.fn();
let location = { pathname: "/scan", search: "" };
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => location,
  };
});

const logout = vi.fn();
let user;
const switchOrganisation = vi.fn();
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(user), logout, switchOrganisation }),
}));

const updateLocalPreferences = vi.fn();
let preferences = {};
vi.mock("@shell/preferences/PreferencesContext", () => ({
  usePreferences: () => ({ preferences, updateLocalPreferences }),
}));

/* ── Personas (real permissions module) ───────────────────────────────────── */
const SUPERADMIN_RAW = {
  id: 1,
  username: "root",
  email: "root@example.test",
  org_id: "o-1",
  role: { name: "superadmin", permissions: [] },
  authorization: everything(),
};
const ORG_ADMIN_RAW = {
  id: 2,
  username: "orgadmin",
  email: "oa@example.test",
  org_id: "o-1",
  role: { name: "org_admin" },
  permissionKeys: [
    "audit.dashboard.read",
    "audit.report.read",
    "audit.scan.run",
    "audit.scan.read",
    "audit.scan_schedule.read",
    "audit.credential.read",
    "audit.asset.read",
    "audit.finding.read",
    "platform.user.read",
    "platform.user.approve",
    "platform.user.assign_role",
    "platform.user.reset_credentials",
    "platform.user.update",
    "platform.organization.read",
    "platform.permission.read",
    "platform.role.read",
    "platform.audit_log.read",
    "audit.compliance.read",
  ],
};
const VIEWER_RAW = {
  id: 3,
  username: "viewer",
  email: "v@example.test",
  org_id: "o-1",
  role: { name: "viewer" },
  permissionKeys: ["audit.dashboard.read", "audit.asset.read"],
};
const SUPERADMIN = personaFrom(SUPERADMIN_RAW);
const ORG_ADMIN = personaFrom(ORG_ADMIN_RAW);
const VIEWER = personaFrom(VIEWER_RAW);

const SUMMARY = {
  scans: { running: 2, last_24h: 7 },
  severity: { critical: 4 },
};
const ORGS = {
  organizations: [
    { id: "o-1", name: "CDAC RTSG Bangalore" },
    { id: "o-2", name: "Acme" },
  ],
};

function wire() {
  axiosInstance.get.mockImplementation((url) => {
    if (url === "/dashboard/summary")
      return Promise.resolve({ status: 200, data: SUMMARY });
    return Promise.reject(new Error("unexpected GET " + url));
  });
  listOrganizations.mockResolvedValue(ORGS);
}

const renderShell = async (props = {}) => {
  const utils = render(
    <AppLayout {...props}>
      <div data-testid="page">page content</div>
    </AppLayout>,
    // The header's CCurePRO Home control is a real router link (Phase 12), so
    // the shell needs a router; navigation itself stays the mocked hooks.
    { wrapper: MemoryRouter },
  );
  await waitFor(() =>
    expect(axiosInstance.get).toHaveBeenCalledWith("/dashboard/summary"),
  );
  return utils;
};

const navButton = (name) =>
  screen.queryByRole("button", { name }) ||
  screen.queryByRole("link", { name });

/* Dual-path helpers: the control as it was (title-named icon button, plain
   button, div) and as the migration makes it (aria-named button, menuitem,
   dialog). The assertion that follows is the same either way. */
const iconButton = (title, nameRe) =>
  screen.queryByRole("button", { name: nameRe }) || screen.getByTitle(title);
const menuItem = (name) =>
  screen.queryByRole("menuitem", { name }) ||
  screen.queryByRole("menuitemradio", { name }) ||
  screen.getByRole("button", { name });
const isCollapsed = (container) => {
  const aside = container.querySelector("aside");
  return (
    /collapsed/.test(aside.className) ||
    aside.getAttribute("data-collapsed") === "true"
  );
};

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  user = SUPERADMIN;
  location = { pathname: "/scan", search: "" };
  preferences = {};
  wire();
});

afterEach(() => {
  vi.useRealTimers();
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — reads on mount", () => {
  it("reads the dashboard summary and renders the page inside .page-main", async () => {
    await renderShell();
    const urls = axiosInstance.get.mock.calls.map((c) => c[0]);
    expect(urls).toEqual(["/dashboard/summary"]);
    expect(screen.getByTestId("page").closest(".page-main")).not.toBeNull();
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.put).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("re-reads summary every 30 seconds", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await renderShell();
    expect(
      axiosInstance.get.mock.calls.filter((c) => c[0] === "/dashboard/summary"),
    ).toHaveLength(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(
      axiosInstance.get.mock.calls.filter((c) => c[0] === "/dashboard/summary"),
    ).toHaveLength(2);
  });

  it("shows running-scan and critical badges from the summary", async () => {
    await renderShell();
    const active = navButton(/Active Scans/);
    expect(within(active).getByText("2")).toBeInTheDocument();
    const vulns = navButton(/Vulnerabilities/);
    expect(within(vulns).getByText("4")).toBeInTheDocument();
  });

  it("leaves notification reads and streams to the Common Platform", async () => {
    await renderShell();
    expect(streamNotificationEvents).not.toHaveBeenCalled();
    expect(getUnreadCount).not.toHaveBeenCalled();
    expect(getNotifications).not.toHaveBeenCalled();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — navigation gating (real permissions)", () => {
  it("shows every section to a superadmin, including the superadmin-only item", async () => {
    await renderShell();
    for (const label of [
      "Audit Dashboard",
      "Scan Templates",
      "Scan Schedules",
      "Vulnerabilities",
      "Security Reports",
      "AMT Integration",
    ]) {
      expect(navButton(new RegExp("^" + label))).toBeTruthy();
    }
  });

  it("carries no platform navigation: no product switcher, no shared administration", async () => {
    await renderShell();
    for (const label of [
      /^Policy Pro/,
      /^Rank/,
      /^IR$/,
      /^Home$/,
      /User Management/,
      /Email Domain Rules/,
      /^Organizations/,
      /Roles & Permissions/,
      /Audit Logs/,
    ]) {
      expect(navButton(label)).toBeNull();
    }
  });

  it("shows a viewer only what their permissions allow", async () => {
    user = VIEWER;
    await renderShell();
    expect(navButton(/Audit Dashboard/)).toBeTruthy();
    expect(navButton(/Asset Registry/)).toBeTruthy();
    expect(navButton(/Scan Templates/)).toBeNull();
    expect(navButton(/AMT Integration/)).toBeNull();
    expect(screen.queryByText("Audit Settings")).not.toBeInTheDocument();
  });

  it("navigates to the item's route on activation", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.click(navButton(/^Vulnerabilities/));
    expect(navigate).toHaveBeenCalledWith("/vulnerabilities");
  });

  it("marks the current route's item as active", async () => {
    location = { pathname: "/assets", search: "?tab=tls" };
    await renderShell();
    const tls = navButton(/TLS \/ Certificates/);
    expect(
      tls.className.includes("--active") ||
        tls.getAttribute("aria-current") === "page",
    ).toBe(true);
    const registry = navButton(/^Asset Registry/);
    expect(
      registry.className.includes("--active") ||
        registry.getAttribute("aria-current") === "page",
    ).toBe(false);
  });

  /* ── Phase 12.2: Audit's dashboard moved to /audit-dashboard, and / is
     CCurePRO Home. Audit's own navigation must stay inside Audit. ── */
  const isActive = (el) =>
    el.className.includes("--active") ||
    el.getAttribute("aria-current") === "page";

  it("Audit Dashboard opens /audit-dashboard, not CCurePRO Home", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.click(navButton(/^Audit Dashboard/));
    expect(navigate).toHaveBeenCalledWith("/audit-dashboard");
    expect(navigate).not.toHaveBeenCalledWith("/");
  });

  it.each(["/audit-dashboard", "/dashboard"])(
    "Audit Dashboard is the active item on %s",
    async (pathname) => {
      location = { pathname, search: "" };
      await renderShell();
      expect(isActive(navButton(/^Audit Dashboard/))).toBe(true);
    },
  );

  it("no Audit item is active on CCurePRO Home's address", async () => {
    location = { pathname: "/", search: "" };
    await renderShell();
    expect(isActive(navButton(/^Audit Dashboard/))).toBe(false);
  });

  it("Executive Report is accessed through Security Reports without an Overview duplicate", async () => {
    location = { pathname: "/reports", search: "?tab=executive" };
    const u = userEvent.setup();
    await renderShell();
    expect(navButton(/^Executive Report/)).toBeNull();
    const reports = navButton(/^Security Reports/);
    expect(isActive(reports)).toBe(true);
    await u.click(reports);
    expect(navigate).toHaveBeenCalledWith("/reports");
  });

  it("the header carries a CCurePRO Home link to /", async () => {
    for (const persona of [SUPERADMIN, ORG_ADMIN, VIEWER]) {
      user = persona;
      const { unmount } = await renderShell();
      const home = screen.getByRole("link", { name: "CCurePRO Home" });
      expect(home).toHaveAttribute("href", "/");
      unmount();
    }
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — header actions", () => {
  it.each([SUPERADMIN, ORG_ADMIN, VIEWER])(
    "omits New Scan, notifications, and Help for persona $username",
    async (persona) => {
      user = persona;
      await renderShell();
      const header = within(screen.getByRole("banner"));
      for (const name of [
        /New Scan/i,
        /Notifications/i,
        /^Help$|Help Center/i,
      ]) {
        expect(header.queryByRole("button", { name })).not.toBeInTheDocument();
      }
      expect(
        header.getByRole("link", { name: "CCurePRO Home" }),
      ).toBeInTheDocument();
      expect(
        header.getByRole("button", { name: "Switch to dark mode" }),
      ).toBeInTheDocument();
    },
  );

  it("reflects saveStatus", async () => {
    const { rerender } = await renderShell({ saveStatus: "saving" });
    expect(screen.getByText("Saving...")).toBeInTheDocument();
    rerender(
      <AppLayout saveStatus="saved">
        <div />
      </AppLayout>,
    );
    expect(screen.getByText("Saved")).toBeInTheDocument();
    rerender(
      <AppLayout saveStatus="error">
        <div />
      </AppLayout>,
    );
    expect(screen.getByText("Save failed")).toBeInTheDocument();
  });

  it("opens the profile dropdown and signs out from it", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.click(screen.getByRole("button", { name: /root/ }));
    await u.click(menuItem("Sign Out"));
    expect(logout).toHaveBeenCalledTimes(1);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — global search (superadmin)", () => {
  const box = () =>
    screen.getByPlaceholderText("Search assets, CVEs, scans...");

  it("sends a CVE id to the vulnerability browser", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.type(box(), "CVE-2026-1111{Enter}");
    expect(navigate).toHaveBeenCalledWith(
      "/vulnerabilities?search=CVE-2026-1111",
    );
  });

  it("sends anything else to the asset registry, encoded", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.type(box(), "ws 01{Enter}");
    expect(navigate).toHaveBeenCalledWith("/assets?search=ws%2001");
  });

  it("ignores an empty query", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.type(box(), "   {Enter}");
    expect(navigate).not.toHaveBeenCalled();
  });

  it("focuses on Ctrl+K", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.keyboard("{Control>}k{/Control}");
    expect(box()).toHaveFocus();
  });

  it("is not rendered for an org_admin", async () => {
    user = ORG_ADMIN;
    await renderShell();
    expect(
      screen.queryByPlaceholderText("Search assets, CVEs, scans..."),
    ).not.toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — organisation switcher (backend-authorized)", () => {
  beforeEach(() => {
    switchOrganisation.mockReset();
  });

  it("lists organisations and labels the organisation the backend reports as active", async () => {
    await renderShell();
    await waitFor(() => expect(listOrganizations).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("CDAC RTSG Bangalore")).toBeInTheDocument();
    // the stored hint is not written by the switcher: the backend's answer is
    // what AuthContext stores
    expect(localStorage.getItem("activeOrgId")).toBeNull();
  });

  it("ignores a stored organisation hint: the active organisation is the backend's", async () => {
    localStorage.setItem("activeOrgId", "o-2");
    await renderShell();
    expect(await screen.findByText("CDAC RTSG Bangalore")).toBeInTheDocument();
    expect(screen.queryByText("Acme")).not.toBeInTheDocument();
    expect(localStorage.getItem("activeOrgId")).toBe("o-2");
  });

  it("switching asks the backend, and reloads only after it accepts", async () => {
    const u = userEvent.setup();
    const reload = vi.fn();
    Object.defineProperty(window, "location", {
      value: { ...window.location, reload },
      writable: true,
    });
    switchOrganisation.mockResolvedValue({});
    await renderShell();
    await screen.findByText("CDAC RTSG Bangalore");
    await u.click(screen.getByText("CDAC RTSG Bangalore"));
    await waitFor(() => expect(menuItem(/Acme/)).toBeInTheDocument());
    await u.click(menuItem(/Acme/));
    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
    expect(switchOrganisation).toHaveBeenCalledWith("o-2");
  });

  it("a refused switch does not reload and changes nothing", async () => {
    const u = userEvent.setup();
    const reload = vi.fn();
    Object.defineProperty(window, "location", {
      value: { ...window.location, reload },
      writable: true,
    });
    switchOrganisation.mockImplementation(async () => {
      throw { response: { status: 403 } };
    });
    await renderShell();
    await screen.findByText("CDAC RTSG Bangalore");
    await u.click(screen.getByText("CDAC RTSG Bangalore"));
    await waitFor(() => expect(menuItem(/Acme/)).toBeInTheDocument());
    await u.click(menuItem(/Acme/));
    await waitFor(() => expect(switchOrganisation).toHaveBeenCalled());
    expect(reload).not.toHaveBeenCalled();
    expect(localStorage.getItem("activeOrgId")).toBeNull();
  });

  it("a role called superadmin without the backend's switch flag gets no switcher", async () => {
    user = personaFrom({
      id: 9,
      org_id: "o-1",
      role: { name: "superadmin", permissions: [] },
      authorization: everything(),
    });
    user.authorization.can_switch_organisation = false;
    await renderShell();
    expect(listOrganizations).not.toHaveBeenCalled();
    expect(screen.queryByText("CDAC RTSG Bangalore")).not.toBeInTheDocument();
  });

  it("does not exist for an org_admin, and no organisations are read", async () => {
    user = ORG_ADMIN;
    await renderShell();
    expect(listOrganizations).not.toHaveBeenCalled();
    expect(screen.queryByText("CDAC RTSG Bangalore")).not.toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — sidebar state", () => {
  it("starts expanded, collapses on the toggle and records it in localStorage", async () => {
    const u = userEvent.setup();
    const { container } = await renderShell();
    expect(isCollapsed(container)).toBe(false);
    await u.click(iconButton("Collapse Sidebar", /collapse sidebar/i));
    expect(isCollapsed(container)).toBe(true);
    expect(localStorage.getItem("sidebarCollapsed")).toBe("true");
    await u.click(iconButton("Expand Sidebar", /expand sidebar/i));
    expect(localStorage.getItem("sidebarCollapsed")).toBe("false");
  });

  it("starts collapsed when localStorage says so", async () => {
    localStorage.setItem("sidebarCollapsed", "true");
    const { container } = await renderShell();
    expect(isCollapsed(container)).toBe(true);
  });

  it("follows the saved preference and mirrors it to localStorage", async () => {
    preferences = { sidebar_collapsed: true };
    const { container } = await renderShell();
    expect(isCollapsed(container)).toBe(true);
    expect(localStorage.getItem("sidebarCollapsed")).toBe("true");
  });

  it("remembers the nav scroll position in sessionStorage", async () => {
    const { container } = await renderShell();
    const nav = container.querySelector("nav");
    nav.scrollTop = 120;
    nav.dispatchEvent(new Event("scroll", { bubbles: true }));
    expect(sessionStorage.getItem("sidebarScrollPos")).toBe("120");
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — panels", () => {
  it("opens the settings drawer from the sidebar and it reads the preferences", async () => {
    const u = userEvent.setup();
    const { getPreferences } = await import("@shell/api/user");
    getPreferences.mockResolvedValue({
      theme: "dark",
      default_rows_per_page: 25,
      sidebar_collapsed: false,
      default_scan_type: "asset",
      email_alerts: true,
      in_app_alerts: true,
    });
    await renderShell();
    await u.click(iconButton("Settings", /^settings$/i));
    expect(
      screen.queryByRole("dialog", { name: "Settings" }) ||
        screen.getByRole("complementary", { name: "Settings" }),
    ).toBeInTheDocument();
    await waitFor(() => expect(getPreferences).toHaveBeenCalledTimes(1));
    // The drawer is the shell's; Audit supplies its own "Scan Defaults"
    // section, which must still render there.
    expect(
      await screen.findByRole("heading", { name: "Scan Defaults" }),
    ).toBeInTheDocument();
  });

  it("never opens the profile modal until asked", async () => {
    await renderShell();
    expect(screen.queryByTestId("profile-modal")).not.toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AppLayout — accessibility and design-system expectations (migration spec)", () => {
  it("offers a skip link as the first tab stop that targets the main landmark", async () => {
    const u = userEvent.setup();
    await renderShell();
    await u.tab();
    const skip = screen.getByRole("link", { name: /skip to main content/i });
    expect(skip).toHaveFocus();
    expect(document.querySelector(skip.getAttribute("href"))).toBe(
      screen.getByRole("main"),
    );
  });

  it("names the navigation and sidebar landmarks", async () => {
    await renderShell();
    expect(
      screen.getByRole("navigation", { name: /sections|primary/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("complementary", { name: /primary|sidebar/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
  });

  it("renders navigation items as links marked aria-current on the active route", async () => {
    location = { pathname: "/vulnerabilities", search: "" };
    await renderShell();
    const link = screen.getByRole("link", { name: /^Vulnerabilities/ });
    expect(link).toHaveAttribute("aria-current", "page");
    expect(
      screen.getByRole("link", { name: /^Asset Registry/ }),
    ).not.toHaveAttribute("aria-current");
  });

  it("names the global search", async () => {
    await renderShell();
    expect(
      screen.getByLabelText(/search assets, cves, scans/i, {
        selector: "input",
      }),
    ).toBeInTheDocument();
  });

  it("exposes the sidebar collapse control with its state", async () => {
    const u = userEvent.setup();
    await renderShell();
    const btn = screen.getByRole("button", { name: /collapse sidebar/i });
    expect(btn).toHaveAttribute("aria-expanded", "true");
    await u.click(btn);
    expect(
      screen.getByRole("button", { name: /expand sidebar/i }),
    ).toHaveAttribute("aria-expanded", "false");
  });

  it("exposes the organisation switcher as a named menu button", async () => {
    const u = userEvent.setup();
    await renderShell();
    await screen.findByText("CDAC RTSG Bangalore");
    const btn = screen.getByRole("button", { name: /switch organi[sz]ation/i });
    expect(btn).toHaveAttribute("aria-expanded", "false");
    await u.click(btn);
    expect(btn).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("menu")).toBeInTheDocument();
    expect(screen.getAllByRole("menuitemradio")).toHaveLength(2);
  });

  it("names every header and sidebar control", async () => {
    await renderShell();
    await screen.findByText("CDAC RTSG Bangalore");
    const unnamed = screen
      .getAllByRole("button")
      .filter((b) => !b.getAttribute("aria-label") && !b.textContent.trim());
    expect(unnamed).toHaveLength(0);
  });

  it("carries no inline styles in the shell chrome", async () => {
    const { container } = await renderShell();
    await screen.findByText("CDAC RTSG Bangalore");
    const styled = [...container.querySelectorAll("[style]")].filter(
      (el) =>
        !el.closest(".page-main") &&
        !el.matches("[data-allow-inline], .cc-progress__bar"),
    );
    expect(styled).toHaveLength(0);
  });
});
