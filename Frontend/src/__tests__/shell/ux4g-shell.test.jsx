import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CcureAppShell } from "../../design-system";
import AccountMenu from "@shell/navigation/AccountMenu";
import OrgSwitcher from "@shell/navigation/OrgSwitcher";
import SettingsDrawer from "@shell/account/SettingsDrawer";
import { updatePreferences } from "@shell/api/user";
vi.mock("@shell/api/user", () => ({
  getPreferences: vi.fn().mockResolvedValue({
    theme: "light",
    default_rows_per_page: 25,
    sidebar_collapsed: false,
    email_alerts: true,
    in_app_alerts: true,
    products: { audit: { default_scan_type: "credentialed" } },
  }),
  updatePreferences: vi.fn().mockResolvedValue({ theme: "light" }),
}));

const sections = [
  {
    label: "Platform",
    items: [
      { label: "Home", route: "/" },
      { label: "Users", route: "/admin/users" },
    ],
  },
];
afterEach(() => vi.unstubAllGlobals());

function mobileViewport() {
  vi.stubGlobal("matchMedia", () => ({
    matches: true,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
}

describe("shared shell navigation", () => {
  it("removes closed mobile navigation from keyboard and accessibility trees, then traps and restores focus", async () => {
    mobileViewport();
    const u = userEvent.setup();
    render(
      <CcureAppShell sections={sections}>
        <button>Page action</button>
      </CcureAppShell>,
    );
    expect(screen.queryByRole("navigation", { name: "Sections" })).toBeNull();
    const opener = screen.getByRole("button", { name: "Open navigation" });
    await u.click(opener);
    const drawer = screen.getByRole("dialog", { name: "Navigation" });
    expect(drawer).toHaveAttribute("aria-modal", "true");
    expect(screen.queryByRole("button", { name: "Page action" })).toBeNull();
    await waitFor(() =>
      expect(drawer.contains(document.activeElement)).toBe(true),
    );
    for (let i = 0; i < 8; i++) {
      await u.tab();
      expect(drawer.contains(document.activeElement)).toBe(true);
    }
    await u.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(opener).toHaveFocus();
    expect(
      screen.getByRole("button", { name: "Page action" }),
    ).toBeInTheDocument();
  });

  it("keeps the host's current route and invokes navigation once before closing its mobile drawer", async () => {
    mobileViewport();
    const navigate = vi.fn();
    const u = userEvent.setup();
    render(
      <CcureAppShell
        sections={sections}
        currentPath="/admin/users"
        onNavigate={navigate}
      />,
    );
    await u.click(screen.getByRole("button", { name: "Open navigation" }));
    const users = screen.getByRole("link", { name: "Users" });
    expect(users).toHaveAttribute("aria-current", "page");
    await u.click(users);
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith("/admin/users", sections[0].items[1]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("preserves native modified-link gestures while ordinary activation uses the host", () => {
    const navigate = vi.fn();
    render(<CcureAppShell sections={sections} onNavigate={navigate} />);
    const link = screen.getByRole("link", { name: "Users" });
    // Cancel the browser's actual navigation after the component sees the gesture.
    const cancel = (event) => event.preventDefault();
    document.addEventListener("click", cancel);
    fireEvent.click(link, { ctrlKey: true, button: 0 });
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.click(link, { button: 0 });
    expect(navigate).toHaveBeenCalledTimes(1);
    document.removeEventListener("click", cancel);
  });

  it("moves skip-link focus to the main landmark", async () => {
    render(
      <CcureAppShell sections={sections}>
        <button>Page action</button>
      </CcureAppShell>,
    );
    await userEvent
      .setup()
      .click(screen.getByRole("link", { name: "Skip to main content" }));
    expect(screen.getByRole("main")).toHaveFocus();
  });
});

describe("shell menu adapters", () => {
  it("operates the account menu by arrows and Escape, then invokes its action once", async () => {
    const u = userEvent.setup();
    const profile = vi.fn(),
      logout = vi.fn();
    render(
      <AccountMenu
        user={{ username: "pat" }}
        onOpenProfile={profile}
        onLogout={logout}
      />,
    );
    const trigger = screen.getByRole("button", {
      name: "Account menu for pat",
    });
    trigger.focus();
    await u.keyboard("{ArrowDown}");
    await waitFor(() =>
      expect(
        screen.getByRole("menuitem", { name: "My Account" }),
      ).toHaveFocus(),
    );
    await u.keyboard("{End}");
    expect(screen.getByRole("menuitem", { name: "Sign Out" })).toHaveFocus();
    await u.keyboard("{Escape}");
    expect(trigger).toHaveFocus();
    expect(screen.queryByRole("menu")).toBeNull();
    await u.keyboard("{ArrowDown}{Enter}");
    expect(profile).toHaveBeenCalledTimes(1);
    expect(logout).not.toHaveBeenCalled();
  });

  it("retains organization selection and calls the host exactly once using the keyboard", async () => {
    const switchOrg = vi.fn();
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <OrgSwitcher
          selectedOrg="Org One"
          orgs={[
            { id: "1", name: "Org One" },
            { id: "2", name: "Org Two" },
          ]}
          open={open}
          onToggle={() => setOpen(true)}
          onClose={() => setOpen(false)}
          onSwitch={switchOrg}
        />
      );
    }
    render(<Harness />);
    const u = userEvent.setup();
    const trigger = screen.getByRole("button", { name: /Switch organization/ });
    trigger.focus();
    await u.keyboard("{ArrowDown}");
    await waitFor(() =>
      expect(
        within(screen.getByRole("menu")).getAllByRole("menuitemradio")[0],
      ).toHaveFocus(),
    );
    expect(
      screen.getByRole("menuitemradio", { name: /Org One/ }),
    ).toHaveAttribute("aria-checked", "true");
    await u.keyboard("{End}{Enter}");
    expect(switchOrg).toHaveBeenCalledExactlyOnceWith({
      id: "2",
      name: "Org Two",
    });
    expect(trigger).toHaveFocus();
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

it("saves native Switch values without overwriting the header theme preference", async () => {
  const u = userEvent.setup();
  render(<SettingsDrawer onClose={() => {}} />);
  const email = await screen.findByRole("switch", { name: "Email alerts" });
  expect(email).toHaveAccessibleDescription(
    "Receive scan results and alerts via email",
  );
  email.focus();
  await u.keyboard(" ");
  expect(email).not.toBeChecked();
  await u.click(screen.getByRole("button", { name: "Save Settings" }));
  await waitFor(() =>
    expect(updatePreferences).toHaveBeenCalledExactlyOnceWith({
      default_rows_per_page: 25,
      sidebar_collapsed: false,
      email_alerts: false,
      in_app_alerts: true,
      products: { audit: { default_scan_type: "credentialed" } },
    }),
  );
});
