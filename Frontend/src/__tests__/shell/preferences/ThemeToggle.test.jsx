import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { PreferencesProvider } from "@shell/preferences/PreferencesContext";
import {
  applyTheme,
  readTheme,
  THEME_STORAGE_KEY,
} from "@shell/preferences/theme";
import ThemeToggle from "@shell/navigation/ThemeToggle";
import { getPreferences, updatePreferences } from "@shell/api/user";

let authenticated = true;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ isAuthenticated: authenticated }),
}));
vi.mock("@shell/api/user", () => ({
  getPreferences: vi.fn(),
  updatePreferences: vi.fn(),
}));

const preferences = {
  theme: "light",
  email_alerts: true,
  sidebar_collapsed: false,
  products: { audit: { default_scan_type: "credentialed" } },
};
const mount = () =>
  render(
    <PreferencesProvider>
      <ThemeToggle />
    </PreferencesProvider>,
  );
const ready = async (name = "Switch to dark mode") => {
  const button = screen.getByRole("button", { name });
  await waitFor(() => expect(button).toBeEnabled());
  return button;
};

beforeEach(() => {
  vi.resetAllMocks();
  authenticated = true;
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  getPreferences.mockResolvedValue(preferences);
  updatePreferences.mockImplementation(async (change) => ({
    ...preferences,
    ...change,
  }));
});
afterEach(() => {
  vi.restoreAllMocks();
  document.documentElement.removeAttribute("data-theme");
  localStorage.clear();
});

describe("header theme preference", () => {
  it("switches with one keyboard activation, saves only theme, and restores it on reload", async () => {
    const view = mount();
    const button = await ready();
    expect(button.querySelector('[data-icon="moon"]')).toBeInTheDocument();
    button.focus();
    await userEvent.setup().keyboard("{Enter}");
    expect(updatePreferences).toHaveBeenCalledExactlyOnceWith({
      theme: "dark",
    });
    const lightButton = await ready("Switch to light mode");
    expect(lightButton.querySelector('[data-icon="sun"]')).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");

    view.unmount();
    getPreferences.mockResolvedValue({ ...preferences, theme: "dark" });
    applyTheme(readTheme());
    mount();
    await userEvent.setup().click(await ready("Switch to light mode"));
    expect(updatePreferences).toHaveBeenLastCalledWith({ theme: "light" });
    await ready();
    expect(document.documentElement).not.toHaveAttribute("data-theme");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
  });

  it("keeps the cached theme during startup, then uses the account preference", async () => {
    let finishLoad;
    getPreferences.mockReturnValue(
      new Promise((resolve) => {
        finishLoad = resolve;
      }),
    );
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    applyTheme(readTheme());
    mount();
    expect(
      screen.getByRole("button", { name: "Switch to light mode" }),
    ).toBeDisabled();
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    await act(async () => finishLoad(preferences));
    await ready();
    expect(document.documentElement).not.toHaveAttribute("data-theme");
  });

  it("serializes repeated clicks and keeps the confirmed theme when saving fails", async () => {
    let rejectSave;
    updatePreferences.mockReturnValue(
      new Promise((_resolve, reject) => {
        rejectSave = reject;
      }),
    );
    mount();
    const button = await ready();
    await userEvent.setup().dblClick(button);
    expect(updatePreferences).toHaveBeenCalledTimes(1);
    expect(button).toBeDisabled();
    expect(document.documentElement).not.toHaveAttribute("data-theme");
    await act(async () => rejectSave(new Error("offline")));
    expect(
      await screen.findByText(
        "Could not save the theme preference. Please try again.",
      ),
    ).toBeInTheDocument();
    await ready();
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
  });

  it("still persists to the account when browser storage is blocked", async () => {
    mount();
    const button = await ready();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    updatePreferences.mockResolvedValue({ ...preferences, theme: "dark" });
    await userEvent.setup().click(button);
    await ready("Switch to light mode");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(screen.queryByText(/Could not save/)).toBeNull();
  });

  it("ignores a preference response from a session that has signed out", async () => {
    let finishLoad;
    getPreferences.mockReturnValue(
      new Promise((resolve) => {
        finishLoad = resolve;
      }),
    );
    const view = mount();
    authenticated = false;
    view.rerender(
      <PreferencesProvider>
        <ThemeToggle />
      </PreferencesProvider>,
    );
    await act(async () => finishLoad({ ...preferences, theme: "dark" }));
    expect(document.documentElement).not.toHaveAttribute("data-theme");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Switch to dark mode" }));
    expect(updatePreferences).not.toHaveBeenCalled();
  });
});

describe("applying the theme", () => {
  // WebKit leaves a freshly built subtree holding a <select> on the old theme
  // if the theme changes before that subtree is first styled (cr-report in the
  // webkit browser matrix). Settling style first is half of the fix; the other
  // half, applying it from the commit, is covered by the browser suite.
  it("settles pending style before the change, and does nothing without one", () => {
    const themeWhenSettled = [];
    vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockImplementation(
      () => {
        themeWhenSettled.push(
          document.documentElement.getAttribute("data-theme"),
        );
        return 0;
      },
    );
    applyTheme("dark");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    applyTheme("dark");
    applyTheme("light");
    expect(document.documentElement).not.toHaveAttribute("data-theme");
    expect(themeWhenSettled).toEqual([null, "dark"]);
  });
});
