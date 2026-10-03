/**
 * The platform header (PlatformLayout) — the shared CCure Platform navigation a
 * person sees the moment they sign in, before entering any product.
 *
 * Every control is the shell's own shared component; these pin that each is
 * present, works, and is gated exactly as it is in Audit's layout:
 *   CCure Home · Administration (by permission) · organisation switcher
 *   (superadmin) · notifications · settings (platform preferences only) ·
 *   account menu (My Account, Sign Out) · Sign out.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import PlatformLayout from "@shell/layout/PlatformLayout";
import real from "./../fixtures/platformModules.real.json";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn() },
}));
import api from "@shell/api/axiosInstance";

let user;
const logout = vi.fn();
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user, logout }),
}));
const updateLocalPreferences = vi.fn();
vi.mock("@shell/preferences/PreferencesContext", () => ({
  usePreferences: () => ({ preferences: {}, updateLocalPreferences }),
}));

let streamHandler;
vi.mock("@shell/api/notifications", () => ({
  getUnreadCount: vi.fn().mockResolvedValue({ total_unread: 0 }),
  streamNotificationEvents: vi.fn(({ onEvent }) => {
    streamHandler = onEvent;
    return new Promise(() => {});
  }),
  getNotifications: vi.fn().mockResolvedValue([]),
  markAsRead: vi.fn(),
  markAllAsRead: vi.fn(),
  deleteNotification: vi.fn(),
  deleteAllNotifications: vi.fn(),
}));
vi.mock("@shell/api/admin", () => ({
  listOrganizations: vi.fn().mockResolvedValue({
    organizations: [
      { id: "o-1", name: "Org One" },
      { id: "o-2", name: "Org Two" },
    ],
  }),
}));
vi.mock("@shell/api/user", () => ({
  getPreferences: vi.fn().mockResolvedValue({
    theme: "light",
    default_rows_per_page: 10,
    sidebar_collapsed: false,
    default_scan_type: "asset",
    email_alerts: true,
    in_app_alerts: true,
  }),
  updatePreferences: vi.fn(),
}));
vi.mock("@shell/account/ProfileModal", () => ({
  default: () => <div role="dialog" aria-label="My Account" />,
}));

import { listOrganizations } from "@shell/api/admin";
import { personaFrom } from "../fixtures/authorization";

const persona = (roleName, permissions = []) =>
  personaFrom({
    id: 7,
    username: "pat",
    email: "pat@example.test",
    org_id: "o-1",
    role: { name: roleName, permissions },
  });
const SUPERADMIN = persona("superadmin");
const ORG_ADMIN = persona("org_admin", ["users:read", "audit:read"]);
const VIEWER = persona("viewer", ["dashboard:read"]);

const renderLayout = () =>
  render(
    <MemoryRouter>
      <PlatformLayout>
        <p>hub</p>
      </PlatformLayout>
    </MemoryRouter>,
  );

beforeEach(() => {
  api.get.mockReset();
  api.get.mockResolvedValue({ data: real });
  logout.mockReset();
  listOrganizations.mockClear();
  localStorage.clear();
  user = ORG_ADMIN;
});

describe("the shared platform navigation", () => {
  it("carries a platform sidebar, notifications, settings, the account menu and Sign out", async () => {
    renderLayout();
    const nav = screen.getByRole("navigation", { name: "Sections" });
    expect(within(nav).getByRole("link", { name: "Home" })).toHaveAttribute(
      "href",
      "/",
    );
    expect(
      screen.getByRole("button", { name: /^Notifications/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Settings" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Account menu for pat" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign out" }),
    ).toBeInTheDocument();
    expect(screen.getByText("hub")).toBeInTheDocument();
  });

  it("Sign out signs out", async () => {
    renderLayout();
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Sign out" }));
    expect(logout).toHaveBeenCalledTimes(1);
  });
});

describe("Administration — the same gates as Audit's sidebar", () => {
  const adminLinks = () => {
    const nav = screen.getByRole("navigation", { name: "Sections" });
    const list = within(nav).getByRole("list", { name: "Administration" });
    return within(list)
      .getAllByRole("link")
      .map((a) => [
        a.querySelector(".cc-sidebar__label").textContent,
        a.getAttribute("href"),
      ]);
  };

  it("is absent for a user who may see none of the screens", () => {
    user = VIEWER;
    renderLayout();
    expect(screen.queryByText("Administration")).toBeNull();
  });

  it("shows an org admin only what their permissions allow", async () => {
    user = ORG_ADMIN;
    renderLayout();
    expect(adminLinks()).toEqual([
      ["User Management", "/admin/users"],
      ["Deleted Users", "/admin/users/deleted"],
      ["Audit Logs", "/admin/audit-logs"],
    ]);
  });

  it("shows a superadmin every screen, Email Domain Rules included", async () => {
    user = SUPERADMIN;
    renderLayout();
    expect(adminLinks()).toEqual([
      ["User Management", "/admin/users"],
      ["Deleted Users", "/admin/users/deleted"],
      ["Email Domain Rules", "/admin/email-domains"],
      ["Organizations", "/admin/organizations"],
      ["Roles & Permissions", "/admin/roles"],
      ["Audit Logs", "/admin/audit-logs"],
    ]);
  });
});

describe("organisation switcher", () => {
  it("is offered to a superadmin and lists the organisations", async () => {
    user = SUPERADMIN;
    renderLayout();
    const btn = await screen.findByRole("button", {
      name: /Switch organization\. Current: Org One/,
    });
    await userEvent.setup().click(btn);
    const menu = screen.getByRole("menu", { name: "Switch Organization" });
    expect(
      within(menu)
        .getAllByRole("menuitem")
        .map((m) => m.textContent.replace("✓", "").trim()),
    ).toEqual(["Org One", "Org Two"]);
  });

  it("is not offered to anyone else, and no organisations are read", () => {
    user = ORG_ADMIN;
    renderLayout();
    expect(
      screen.queryByRole("button", { name: /Switch organization/ }),
    ).toBeNull();
    expect(listOrganizations).not.toHaveBeenCalled();
  });
});

describe("notifications", () => {
  it("shows the live unread count and opens the panel", async () => {
    renderLayout();
    await waitFor(() => expect(streamHandler).toBeTypeOf("function"));
    streamHandler({
      event: "connected",
      data: { summary: { total_unread: 3 } },
    });
    const bell = await screen.findByRole("button", {
      name: "Notifications, 3 unread",
    });
    await userEvent.setup().click(bell);
    expect(bell).toHaveAttribute("aria-expanded", "true");
    expect(document.getElementById("sh-notifications")).toBeInTheDocument();
  });
});

describe("account menu", () => {
  it("opens My Account and signs out", async () => {
    const u = userEvent.setup();
    renderLayout();
    await u.click(screen.getByRole("button", { name: "Account menu for pat" }));
    await u.click(screen.getByRole("menuitem", { name: "My Account" }));
    expect(
      screen.getByRole("dialog", { name: "My Account" }),
    ).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Account menu for pat" }));
    await u.click(screen.getByRole("menuitem", { name: "Sign Out" }));
    expect(logout).toHaveBeenCalledTimes(1);
  });
});

describe("settings", () => {
  it("opens the drawer with the platform's preferences only — no product section", async () => {
    renderLayout();
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Settings" }));
    await screen.findByText("Theme");
    expect(
      screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent),
    ).toEqual(["Display", "Notifications"]);
    expect(screen.queryByText("Default scan type")).toBeNull();
  });
});

describe("the platform sidebar is a product switcher", () => {
  it("lists every product from the registry, in its order, and nothing of Audit's", async () => {
    renderLayout();
    const nav = screen.getByRole("navigation", { name: "Sections" });
    const list = within(nav).getByRole("list", { name: "CCure Platform" });
    await waitFor(() =>
      expect(within(list).getAllByRole("link")).toHaveLength(
        1 + real.modules.length,
      ),
    );
    expect(
      within(list)
        .getAllByRole("link")
        .map((a) => [
          a.querySelector(".cc-sidebar__label").textContent,
          a.getAttribute("href"),
        ]),
    ).toEqual([
      ["Home", "/"],
      ...real.modules.map((m) => [m.title, m.entry_path]),
    ]);
    for (const auditItem of [
      /Scan Templates/,
      /Asset Registry/,
      /Compliance/,
    ]) {
      expect(screen.queryByText(auditItem)).toBeNull();
    }
  });

  it("fetches the product list once for the sidebar and the page", async () => {
    renderLayout();
    await waitFor(() => expect(api.get).toHaveBeenCalledTimes(1));
  });

  it("says when the products could not be loaded, rather than listing none", async () => {
    api.get.mockRejectedValue(new Error("boom"));
    renderLayout();
    expect(
      await screen.findByText("Products could not be loaded"),
    ).toBeInTheDocument();
  });
});
