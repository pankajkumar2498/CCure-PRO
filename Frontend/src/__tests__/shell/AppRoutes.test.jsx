/**
 * The Phase 12.2 address map, through the real `App` routes.
 *
 * Every Audit page is a stub naming itself, so this pins *which page an
 * address opens* — the routing decision Phase 12 changes — and nothing about
 * the pages, which have their own suites. CCure Home and the module entry
 * page are real; the product list is the live :443 body recorded at 12.1.
 *
 *   /                  CCure Home
 *   /audit-dashboard   Audit's Security Dashboard (canonical)
 *   /dashboard         redirect to /audit-dashboard, query and fragment kept
 *   /{policy,rank,ir}-dashboard   the module page from the registry
 *   every other Audit address     unchanged
 *
 * And D12-8: authentication and authorisation behave exactly as before — an
 * unauthenticated visit goes to sign-in carrying its address, and a refusal is
 * never turned into a trip to CCure Home.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import real from "../fixtures/platformModules.real.json";
import api from "@shell/api/axiosInstance";
import App from "../../App";
import { personaFrom } from "../fixtures/authorization";

// The platform header composes the shell's shared pieces (Phase 12 platform
// navigation): preferences come from the provider main.jsx mounts, and the
// notification feed opens a stream — both stubbed here, as in AppLayout's suite.
vi.mock("@shell/preferences/PreferencesContext", () => ({
  usePreferences: () => ({ preferences: {}, updateLocalPreferences: vi.fn() }),
}));
vi.mock("@shell/api/notifications", () => ({
  getUnreadCount: vi.fn().mockResolvedValue({ total_unread: 0 }),
  streamNotificationEvents: vi.fn(() => new Promise(() => {})),
  getNotifications: vi.fn().mockResolvedValue([]),
  markAsRead: vi.fn(),
  markAllAsRead: vi.fn(),
  deleteNotification: vi.fn(),
  deleteAllNotifications: vi.fn(),
}));

vi.mock("@shell/api/axiosInstance", () => ({ default: { get: vi.fn() } }));

let auth;
vi.mock("@shell/auth/AuthContext", () => ({
  default: null,
  useAuth: () => auth,
}));

vi.mock("@audit/context/ScanContext", () => ({
  ScanProvider: ({ children }) => children,
}));

vi.mock("@audit/pages/SecurityDashboard", () => ({
  default: () => <div data-testid="page">SecurityDashboard</div>,
}));
vi.mock("@audit/pages/AssetRegistry", () => ({
  default: () => <div data-testid="page">AssetRegistry</div>,
}));
vi.mock("@audit/pages/AssetDetail", () => ({
  default: () => <div data-testid="page">AssetDetail</div>,
}));
vi.mock("@audit/pages/VulnerabilityBrowser", () => ({
  default: () => <div data-testid="page">VulnerabilityBrowser</div>,
}));
vi.mock("@audit/pages/ComplianceWorkspace", () => ({
  default: () => <div data-testid="page">ComplianceWorkspace</div>,
}));
vi.mock("../../pages/Login", () => ({
  default: () => <div data-testid="page">Login</div>,
}));
vi.mock("../../pages/Register", () => ({
  default: () => <div data-testid="page">Register</div>,
}));
vi.mock("../../pages/VerifyEmail", () => ({
  default: () => <div data-testid="page">VerifyEmail</div>,
}));
vi.mock("../../pages/ForgotPassword", () => ({
  default: () => <div data-testid="page">ForgotPassword</div>,
}));
vi.mock("../../pages/ResetPassword", () => ({
  default: () => <div data-testid="page">ResetPassword</div>,
}));
vi.mock("@audit/pages/Dashboard", () => ({
  default: () => <div data-testid="page">Dashboard</div>,
}));
vi.mock("@audit/pages/ScanHistory", () => ({
  default: () => <div data-testid="page">ScanHistory</div>,
}));
vi.mock("@audit/pages/scan/ScanSchedules", () => ({
  default: () => <div data-testid="page">ScanSchedules</div>,
}));
vi.mock("@audit/pages/scan/ConfigurationChecks", () => ({
  default: () => <div data-testid="page">ConfigurationChecks</div>,
}));
vi.mock("@audit/pages/scan/ConfigurationRuleValidator", () => ({
  default: () => <div data-testid="page">ConfigurationRuleValidator</div>,
}));
vi.mock("@audit/pages/scan/ScanCredentials", () => ({
  default: () => <div data-testid="page">ScanCredentials</div>,
}));
vi.mock("@audit/pages/ArchivedScans", () => ({
  default: () => <div data-testid="page">ArchivedScans</div>,
}));
vi.mock("@audit/pages/RecycleBin", () => ({
  default: () => <div data-testid="page">RecycleBin</div>,
}));
vi.mock("@audit/pages/SecurityReports", () => ({
  default: () => <div data-testid="page">SecurityReports</div>,
}));
vi.mock("@audit/pages/scan/NewScan", () => ({
  default: () => <div data-testid="page">NewScan</div>,
}));
vi.mock("@audit/pages/scan/Phase1Results", () => ({
  default: () => <div data-testid="page">Phase1Results</div>,
}));
vi.mock("@audit/pages/scan/Phase2Results", () => ({
  default: () => <div data-testid="page">Phase2Results</div>,
}));
vi.mock("@audit/pages/scan/Phase3Results", () => ({
  default: () => <div data-testid="page">Phase3Results</div>,
}));
vi.mock("@audit/pages/scan/CredentialedScan", () => ({
  default: () => <div data-testid="page">CredentialedScan</div>,
}));
vi.mock("@audit/pages/scan/CredentialedResults", () => ({
  default: () => <div data-testid="page">CredentialedResults</div>,
}));
vi.mock("@audit/pages/scan/ScanComparison", () => ({
  default: () => <div data-testid="page">ScanComparison</div>,
}));
vi.mock("@audit/pages/scan/ScanPolicies", () => ({
  default: () => <div data-testid="page">ScanPolicies</div>,
}));
vi.mock("@audit/pages/Remediation", () => ({
  default: () => <div data-testid="page">Remediation</div>,
}));
vi.mock("@audit/pages/scan/NetworkMap", () => ({
  default: () => <div data-testid="page">NetworkMap</div>,
}));
vi.mock("@audit/web-scanning/WebScanningRoutes", () => ({
  default: () => <div data-testid="page">WebScanningRoutes</div>,
}));
vi.mock("@shell/admin/pages/AuditLogs", () => ({
  default: () => <div data-testid="page">AuditLogs</div>,
}));
vi.mock("@shell/admin/pages/EmailDomainRules", () => ({
  default: () => <div data-testid="page">EmailDomainRules</div>,
}));
vi.mock("@shell/admin/pages/UserManagement", () => ({
  default: () => <div data-testid="page">UserManagement</div>,
}));
vi.mock("@shell/admin/pages/OrganizationManagement", () => ({
  default: () => <div data-testid="page">OrganizationManagement</div>,
}));
vi.mock("@shell/admin/pages/RoleManagement", () => ({
  default: () => <div data-testid="page">RoleManagement</div>,
}));
vi.mock("@shell/admin/pages/DeletedUsers", () => ({
  default: () => <div data-testid="page">DeletedUsers</div>,
}));
vi.mock("@audit/pages/admin/AMTIntegration", () => ({
  default: () => <div data-testid="page">AMTIntegration</div>,
}));
vi.mock("@audit/pages/DesignSystemShowcase", () => ({
  default: () => <div data-testid="page">DesignSystemShowcase</div>,
}));

function Probe() {
  const { pathname, search, hash, state } = useLocation();
  return (
    <output data-testid="where">
      {JSON.stringify({
        pathname,
        search,
        hash,
        from: state?.from?.pathname ?? null,
      })}
    </output>
  );
}
const where = () => JSON.parse(screen.getByTestId("where").textContent);
const page = () => screen.queryByTestId("page")?.textContent ?? null;

const signedIn = (permissions = []) => ({
  user: personaFrom({
    username: "analyst",
    role: { name: "analyst", permissions },
  }),
  loading: false,
  authState: "authenticated",
  authMessage: "",
  logout: vi.fn(),
});
const ANALYST = [
  "dashboard:read",
  "scans:execute",
  "scans:read",
  "reports:read",
  "assets:read",
];

const visit = (path) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <App />
      <Probe />
    </MemoryRouter>,
  );

beforeEach(() => {
  api.get.mockReset();
  api.get.mockResolvedValue({ data: real });
  auth = signedIn(ANALYST);
});

describe("/ is CCure Home", () => {
  it("renders the Product Hub, not Audit's dashboard", async () => {
    visit("/");
    expect(
      await screen.findByRole("heading", { level: 1, name: "CCure Home" }),
    ).toBeInTheDocument();
    expect(await screen.findAllByRole("heading", { level: 2 })).toHaveLength(4);
    expect(page()).toBeNull();
    expect(api.get).toHaveBeenCalledWith("/platform/modules");
  });

  it("Open dashboard on the Audit card opens Audit's dashboard", async () => {
    visit("/");
    await userEvent.setup().click(
      await screen.findByRole("link", {
        name: "Open dashboard, CCure Audit",
      }),
    );
    expect(where().pathname).toBe("/audit-dashboard");
    expect(page()).toBe("SecurityDashboard");
  });

  it("About this product on the Rank card opens its module page", async () => {
    visit("/");
    await userEvent.setup().click(
      await screen.findByRole("link", {
        name: "About this product, CCure Rank",
      }),
    );
    expect(where().pathname).toBe("/rank-dashboard");
    expect(
      await screen.findByRole("heading", { level: 1, name: "CCure Rank" }),
    ).toBeInTheDocument();
  });
});

describe("Audit's dashboard address", () => {
  it("/audit-dashboard is Audit's Security Dashboard", () => {
    visit("/audit-dashboard");
    expect(page()).toBe("SecurityDashboard");
    expect(where().pathname).toBe("/audit-dashboard");
  });

  it("/dashboard redirects to /audit-dashboard", () => {
    visit("/dashboard");
    expect(where().pathname).toBe("/audit-dashboard");
    expect(page()).toBe("SecurityDashboard");
  });

  it("the redirect keeps the query string and the fragment", () => {
    visit("/dashboard?tab=overview#top");
    expect(where()).toMatchObject({
      pathname: "/audit-dashboard",
      search: "?tab=overview",
      hash: "#top",
    });
  });
});

describe("module entry pages from the registry", () => {
  it.each([
    ["/policy-dashboard", "CCure Policy Pro", 0],
    ["/rank-dashboard", "CCure Rank", 2],
    ["/ir-dashboard", "CCure IR", 3],
  ])(
    "%s says %s is not available yet, and nothing more",
    async (path, title, i) => {
      const { container } = visit(path);
      expect(
        await screen.findByRole("heading", { level: 1, name: title }),
      ).toBeInTheDocument();
      expect(screen.getByText(real.modules[i].description)).toBeInTheDocument();
      expect(screen.getByText("Not yet available")).toBeInTheDocument();
      expect(
        screen.getByText(`${title} is not available yet`),
      ).toBeInTheDocument();
      expect(
        screen.getByText(
          `There are no ${title} features, data or settings in this installation.`,
        ),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("link", { name: "Back to CCure Home" }),
      ).toHaveAttribute("href", "/");
      expect(
        container.querySelector("table, canvas, figure, progress"),
      ).toBeNull();
      expect(
        container.querySelector("[disabled], [aria-disabled='true']"),
      ).toBeNull();
      expect(page()).toBeNull();
      expect(where().pathname).toBe(path);
    },
  );

  it("a trailing slash reaches the same page", async () => {
    visit("/ir-dashboard/");
    expect(
      await screen.findByRole("heading", { level: 1, name: "CCure IR" }),
    ).toBeInTheDocument();
  });

  it("an unknown state is said, never rendered as available", async () => {
    const body = JSON.parse(JSON.stringify(real));
    body.modules[2].tile_state = "beta";
    api.get.mockResolvedValue({ data: body });
    visit("/rank-dashboard");
    expect(
      await screen.findByText("The availability of CCure Rank is unknown"),
    ).toBeInTheDocument();
    expect(screen.getByText("Status unknown")).toBeInTheDocument();
    expect(screen.queryByText("Available")).toBeNull();
  });

  it("an available product with no page in this build is said, not blank", async () => {
    const body = JSON.parse(JSON.stringify(real));
    body.modules[0].tile_state = "available";
    api.get.mockResolvedValue({ data: body });
    visit("/policy-dashboard");
    expect(
      await screen.findByText("CCure Policy Pro has no page in this build"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/is not available yet/)).toBeNull();
  });

  it("an address that is no product's entry falls through to /, as before", async () => {
    visit("/no-such-page");
    await waitFor(() => expect(where().pathname).toBe("/"));
    expect(
      await screen.findByRole("heading", { level: 1, name: "CCure Home" }),
    ).toBeInTheDocument();
  });

  it("a deeper unknown address still takes the catch-all to /", async () => {
    visit("/no/such/page");
    await waitFor(() => expect(where().pathname).toBe("/"));
  });

  it("a failed list is an error with a retry, and the address is kept", async () => {
    api.get.mockReset();
    api.get.mockRejectedValueOnce(
      Object.assign(new Error("Forbidden"), { response: { status: 403 } }),
    );
    api.get.mockResolvedValueOnce({ data: real });
    visit("/ir-dashboard");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The CCure product list could not be loaded",
    );
    expect(where().pathname).toBe("/ir-dashboard");
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Retry" }));
    expect(
      await screen.findByRole("heading", { level: 1, name: "CCure IR" }),
    ).toBeInTheDocument();
  });
});

describe("every other Audit address is unchanged", () => {
  it.each([
    ["/scan", "Dashboard"],
    ["/assets", "AssetRegistry"],
    ["/assets/a-1", "AssetDetail"],
    ["/vulnerabilities", "VulnerabilityBrowser"],
    ["/history", "ScanHistory"],
    ["/monitor", "ScanHistory"],
    ["/reports", "SecurityReports"],
    ["/compliance", "ComplianceWorkspace"],
    ["/remediation", "Remediation"],
    ["/scan-policies", "ScanPolicies"],
    ["/scan-schedules", "ScanSchedules"],
    ["/scan-credentials", "ScanCredentials"],
    ["/configuration-checks", "ConfigurationChecks"],
    ["/archived", "ArchivedScans"],
    ["/recycle-bin", "RecycleBin"],
    ["/topology", "NetworkMap"],
    ["/scan/new", "NewScan"],
    ["/scan/42/phase1", "Phase1Results"],
    ["/scan/comparison?base=1&head=2", "ScanComparison"],
    ["/web-scans/dashboard", "WebScanningRoutes"],
  ])("%s opens %s", (path, name) => {
    visit(path);
    expect(page()).toBe(name);
    expect(where().pathname).toBe(path.split("?")[0]);
    expect(api.get).not.toHaveBeenCalledWith("/platform/modules");
  });

  it.each([
    ["/scan-history", "/history"],
    ["/archived-scans", "/archived"],
    ["/scan/advanced-scan", "/scan/vulnerability-audit"],
  ])("the existing redirect %s → %s still holds", (from, to) => {
    visit(from);
    expect(where().pathname).toBe(to);
  });
});

describe("D12-8 — authentication and authorisation are unchanged", () => {
  it.each(["/", "/audit-dashboard", "/rank-dashboard", "/scan/42/phase1"])(
    "signed out, %s goes to sign-in carrying its address",
    (path) => {
      auth = { user: null, loading: false, authState: "anonymous" };
      visit(path);
      expect(where().pathname).toBe("/login");
      expect(where().from).toBe(path);
      expect(page()).toBe("Login");
      expect(api.get).not.toHaveBeenCalled();
    },
  );

  it("/dashboard signed out reaches sign-in carrying its own address", () => {
    // After sign-in the user returns to /dashboard, which then redirects to
    // /audit-dashboard (covered above): the old address survives the trip.
    auth = { user: null, loading: false, authState: "anonymous" };
    visit("/dashboard");
    expect(where().pathname).toBe("/login");
    expect(where().from).toBe("/dashboard");
  });

  it("a refused platform route is refused in place: not CCure Home, not Audit", () => {
    visit("/admin/users");
    expect(where().pathname).toBe("/admin/users");
    expect(screen.getByRole("heading", { name: "Access denied" })).toBeTruthy();
    expect(page()).toBeNull(); // no Audit page rendered
    expect(api.get).not.toHaveBeenCalledWith("/platform/modules/never");
  });

  it("a refused user with nothing else to open is still refused in the platform, not sent to sign-in", () => {
    auth = signedIn([]);
    visit("/admin/roles");
    expect(where().pathname).toBe("/admin/roles");
    expect(screen.getByRole("heading", { name: "Access denied" })).toBeTruthy();
  });

  it("a 403 from the product list is shown on CCure Home, not navigated away from", async () => {
    api.get.mockReset();
    api.get.mockRejectedValue(
      Object.assign(new Error("Forbidden"), { response: { status: 403 } }),
    );
    visit("/");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The server answered HTTP 403.",
    );
    expect(where().pathname).toBe("/");
  });
});

const platformSidebarLists = () =>
  [
    ...document.querySelectorAll(
      'nav[aria-label="Sections"] [id^="cc-navsec-"]',
    ),
  ].map((n) => n.textContent);

describe("a denied platform route stays in the Platform Shell", () => {
  const ADMIN_ROUTES = [
    ["/admin/users", ["users:read"]],
    ["/admin/users/deleted", ["users:read"]],
    ["/admin/roles", ["roles:read"]],
    ["/admin/organizations", ["organizations:read"]],
    ["/admin/audit-logs", ["audit:read"]],
  ];

  it.each(ADMIN_ROUTES)("%s: an authorised user opens it", (path, perms) => {
    auth = signedIn([...ANALYST, ...perms]);
    visit(path);
    expect(where().pathname).toBe(path);
    expect(screen.queryByRole("heading", { name: "Access denied" })).toBeNull();
  });

  it.each(ADMIN_ROUTES)(
    "%s: an authenticated user without the permission is refused in place",
    (path) => {
      auth = signedIn(ANALYST);
      visit(path);
      expect(where().pathname).toBe(path);
      expect(
        screen.getByRole("heading", { name: "Access denied" }),
      ).toBeTruthy();
      expect(where().pathname).not.toBe("/audit-dashboard");
    },
  );

  it("email-domain rules need the platform-wide key: an account without it is refused in place", () => {
    auth = {
      ...signedIn([...ANALYST, "users:read"]),
      user: personaFrom({
        username: "oa",
        role: { name: "org_admin", permissions: [...ANALYST, "users:read"] },
      }),
    };
    visit("/admin/email-domains");
    expect(where().pathname).toBe("/admin/email-domains");
    expect(screen.getByRole("heading", { name: "Access denied" })).toBeTruthy();
  });

  it("the denied page is in the platform's frame and offers no Audit navigation", () => {
    auth = signedIn(ANALYST);
    visit("/admin/users");
    const sections = platformSidebarLists();
    expect(sections).toContain("CCure Platform");
    expect(sections.join("|")).not.toMatch(/Overview|Scanning|Intelligence/);
    expect(
      screen.getByRole("link", { name: "Back to CCure Home" }),
    ).toBeTruthy();
  });

  it("an unauthenticated visitor still goes to sign-in", () => {
    auth = { user: null, loading: false, authState: "anonymous" };
    visit("/admin/users");
    expect(where().pathname).toBe("/login");
    expect(where().from).toBe("/admin/users");
  });
});

describe("Audit's refusals are unchanged: they still fall back to an Audit page", () => {
  it("a refused Audit route (AMT) falls back to the first Audit page the user may open", () => {
    auth = signedIn(ANALYST); // no settings:update
    visit("/admin/amt");
    expect(where().pathname).toBe("/audit-dashboard");
    expect(page()).toBe("SecurityDashboard");
  });
});

describe("AMT Integration: the route and the sidebar share one permission", () => {
  it("settings:update opens the page", () => {
    auth = signedIn([...ANALYST, "settings:update"]);
    visit("/admin/amt");
    expect(where().pathname).toBe("/admin/amt");
    expect(page()).toBe("AMTIntegration");
  });

  it("assets:update alone — what the route used to ask — does not", () => {
    auth = signedIn([...ANALYST, "assets:update"]);
    visit("/admin/amt");
    expect(where().pathname).toBe("/audit-dashboard");
    expect(page()).not.toBe("AMTIntegration");
  });

  it("a user with neither cannot reach it by URL", () => {
    auth = signedIn(ANALYST);
    visit("/admin/amt");
    expect(page()).not.toBe("AMTIntegration");
  });

  it("the sidebar item and the route name the same permission", async () => {
    const { AMT_PERMISSION } = await import("@audit/config/permissions");
    const { readFileSync } = await import("node:fs");
    const path = await import("node:path");
    const { SRC } = await import("../testPaths.js");
    const layout = readFileSync(
      path.join(SRC, "modules/audit/components/layout/AppLayout.jsx"),
      "utf8",
    );
    const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
    expect(AMT_PERMISSION).toBe("audit.asset.import_amt");
    expect(layout).toMatch(
      /route: "\/admin\/amt",\s+permission: AMT_PERMISSION/,
    );
    expect(app).toMatch(
      /<PrivateRoute requiredPermission=\{AMT_PERMISSION\} \/>/,
    );
  });
});
