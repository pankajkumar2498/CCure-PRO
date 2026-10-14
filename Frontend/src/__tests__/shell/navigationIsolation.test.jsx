import { everything } from "../fixtures/authorization";
/**
 * Platform navigation and product navigation are separate levels, decided by
 * the route tree — not by hiding one of two rendered menus.
 *
 *   CCure PRO Home / an entry page / a shared admin screen   → Platform Shell
 *   an Audit address                                     → Audit's own layout
 *
 * Audit's state (ScanProvider) mounts only under Audit's routes, so the
 * platform never loads Audit; and Audit's sidebar carries no product switcher.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import real from "../fixtures/platformModules.real.json";
import api from "@shell/api/axiosInstance";
import App from "../../App";

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
vi.mock("@shell/auth/AuthContext", async () => {
  const { personaFrom } = await import("../fixtures/authorization");
  const user = personaFrom({
    id: 1,
    username: "root",
    email: "root@example.test",
    org_id: "o-1",
    role: { name: "superadmin", permissions: [] },
    authorization: everything(),
  });
  return {
    default: null,
    useAuth: () => ({
      isAuthenticated: true,
      loading: false,
      user: personaFrom(user),
      logout: vi.fn(),
    }),
  };
});

vi.mock("@shell/api/admin", () => ({
  listOrganizations: vi.fn().mockResolvedValue({ organizations: [] }),
}));

// A marker where Audit's state mounts, so its presence is observable.
vi.mock("@audit/context/ScanContext", async (importOriginal) => ({
  ...(await importOriginal()),
  ScanProvider: ({ children }) => (
    <div data-testid="audit-state">{children}</div>
  ),
}));
vi.mock("@audit/pages/SecurityDashboard", async () => {
  const { default: AppLayout } = await import(
    "@audit/components/layout/AppLayout"
  );
  return {
    default: () => (
      <AppLayout>
        <div data-testid="page">SecurityDashboard</div>
      </AppLayout>
    ),
  };
});
vi.mock("@shell/admin/pages/UserManagement", async () => {
  const { default: ProductFrame } = await import("@shell/layout/ProductFrame");
  return {
    default: () => (
      <ProductFrame pageTitle="Users">
        <div data-testid="page">UserManagement</div>
      </ProductFrame>
    ),
  };
});

const open = (path) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
const sidebar = () => screen.getByRole("navigation", { name: "Sections" });
const PLATFORM_LIST = { name: "CCure PRO Platform" };

beforeEach(() => {
  api.get.mockReset();
  api.get.mockImplementation((url) =>
    url === "/platform/modules"
      ? Promise.resolve({ data: real })
      : Promise.resolve({ data: {} }),
  );
});

describe("CCure PRO Home", () => {
  it("is in the Platform Shell, with the product switcher and no Audit", async () => {
    open("/");
    await screen.findByRole("heading", { name: "CCure PRO Home" });
    const list = within(sidebar()).getByRole("list", PLATFORM_LIST);
    expect(
      within(list)
        .getAllByRole("link")
        .map((a) => a.getAttribute("href")),
    ).toEqual(["/", ...real.modules.map((m) => m.entry_path)]);
    expect(screen.queryByTestId("audit-state")).toBeNull();
    expect(
      within(document.querySelector(".cc-header")).getByRole("button", {
        name: /notifications/i,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Scan Templates")).toBeNull();
    expect(screen.queryByText("Audit Dashboard")).toBeNull();
  });

  it("keeps the header and sidebar mounted across platform pages", async () => {
    const u = userEvent.setup();
    open("/");
    await screen.findByRole("heading", { name: "CCure PRO Home" });
    const header = document.querySelector(".cc-header");
    const nav = sidebar();
    const sidebarFrame = document.querySelector(".cc-sidebar");
    sidebarFrame.scrollTop = 72;
    for (const [link, content] of [
      ["CCure Rank", "CCure Rank"],
      ["User Management", "UserManagement"],
      ["Home", "CCure PRO Home"],
    ]) {
      await u.click(
        within(sidebar()).getByRole("link", { name: link, exact: true }),
      );
      if (content === "UserManagement") await screen.findByTestId("page");
      else await screen.findByRole("heading", { name: content, exact: true });
      expect(document.querySelector(".cc-header")).toBe(header);
      expect(sidebar()).toBe(nav);
      expect(document.querySelector(".cc-sidebar")).toBe(sidebarFrame);
      expect(sidebarFrame.scrollTop).toBe(72);
      expect(
        within(nav).getByRole("link", { name: link, exact: true }),
      ).toHaveAttribute("aria-current", "page");
      expect(document.querySelectorAll(".cc-shell")).toHaveLength(1);
    }
    expect(
      api.get.mock.calls.filter(([url]) => url === "/platform/modules"),
    ).toHaveLength(1);
  });
});

describe("a shared administration screen", () => {
  it("renders in the Platform Shell, not Audit's layout", async () => {
    open("/admin/users");
    await screen.findByTestId("page");
    expect(within(sidebar()).getByRole("list", PLATFORM_LIST)).toBeTruthy();
    expect(screen.queryByTestId("audit-state")).toBeNull();
    expect(
      within(document.querySelector(".cc-header")).getByRole("button", {
        name: /notifications/i,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Scan Templates")).toBeNull();
  });
});

describe("a product entry page for a product not built yet", () => {
  it("stays in the Platform Shell and loads no Audit", async () => {
    open("/rank-dashboard");
    await screen.findByRole("heading", { name: /Rank/ });
    expect(within(sidebar()).getByRole("list", PLATFORM_LIST)).toBeTruthy();
    expect(screen.queryByTestId("audit-state")).toBeNull();
    expect(
      within(document.querySelector(".cc-header")).getByRole("button", {
        name: /notifications/i,
      }),
    ).toBeInTheDocument();
  });
});

describe("Audit", () => {
  it("opens with Audit's state and Audit's own sidebar only", async () => {
    open("/audit-dashboard");
    await screen.findByTestId("page");
    expect(screen.getByTestId("audit-state")).toBeTruthy();
    expect(
      within(document.querySelector(".cc-header")).queryByRole("button", {
        name: /notifications/i,
      }),
    ).toBeNull();
    const nav = sidebar();
    expect(within(nav).getByText("Scan Templates")).toBeTruthy();
    // No platform product switcher, no shared administration.
    expect(within(nav).queryByRole("list", PLATFORM_LIST)).toBeNull();
    for (const label of [
      /^Policy Pro/,
      /^Rank/,
      /^IR$/,
      /^Home$/,
      /User Management/,
    ]) {
      expect(within(nav).queryByText(label)).toBeNull();
    }
  });
});
