/**
 * The two seams the navigation refactor added to the shell:
 *
 *   ProductFrame      a shared screen renders in the layout the composition
 *                     root supplies, and in the platform's own without one;
 *   productSettings   the shared settings drawer carries a product's section
 *                     at the place it always rendered, and none otherwise.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import ProductFrame, { ProductFrameProvider } from "@shell/layout/ProductFrame";
import SettingsDrawer from "@shell/account/SettingsDrawer";
import renderAuditSettings from "@audit/components/layout/auditSettings";

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

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: { username: "analyst" }, logout: vi.fn() }),
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

describe("ProductFrame", () => {
  it("with no frame supplied, renders the platform's own layout", () => {
    render(
      <MemoryRouter>
        <ProductFrame pageTitle="Users">
          <p>page body</p>
        </ProductFrame>
      </MemoryRouter>,
    );
    expect(screen.getByText("page body")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "CCure Home" }),
    ).toBeInTheDocument();
  });

  it("renders in the frame the composition root supplies, passing props through", () => {
    const Frame = ({ pageTitle, children }) => (
      <div data-testid="product-frame" data-title={pageTitle}>
        {children}
      </div>
    );
    render(
      <ProductFrameProvider frame={Frame}>
        <ProductFrame pageTitle="Users">
          <p>page body</p>
        </ProductFrame>
      </ProductFrameProvider>,
    );
    const frame = screen.getByTestId("product-frame");
    expect(frame).toHaveAttribute("data-title", "Users");
    expect(within(frame).getByText("page body")).toBeInTheDocument();
  });
});

describe("SettingsDrawer productSettings", () => {
  const titles = () =>
    screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);

  it("holds only the platform's settings without a product section", async () => {
    render(<SettingsDrawer onClose={() => {}} />);
    await screen.findByText("Theme");
    expect(titles()).toEqual(["Display", "Notifications"]);
    expect(screen.queryByText("Default scan type")).toBeNull();
  });

  it("renders Audit's section between Display and Notifications", async () => {
    render(
      <SettingsDrawer
        onClose={() => {}}
        productSettings={renderAuditSettings}
      />,
    );
    await screen.findByText("Theme");
    expect(titles()).toEqual(["Display", "Scan Defaults", "Notifications"]);
    expect(screen.getByText("Default scan type")).toBeInTheDocument();
  });
});
