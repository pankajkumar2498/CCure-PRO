/**
 * NotificationsPanel, HelpPanel, SettingsDrawer — Checkpoint 3C batch 12
 * baseline. Written against the panels BEFORE migration.
 *
 * ── Contracts ──────────────────────────────────────────────────────────────
 * NotificationsPanel: GET /notifications {unread_only:false, limit:50, offset:0
 *   [, category]} on open and on every category change; PATCH
 *   /notifications/{id}/read; PATCH /notifications/read-all; DELETE
 *   /notifications/{id}; GET /notifications/summary after read/delete to
 *   refresh the badge; a live `created` event is inserted at the top when it
 *   matches the category; click outside closes (the bell is exempt).
 * HelpPanel: no request at all — the support form is client-side only.
 * SettingsDrawer: GET /user/preferences on open; PUT /user/preferences with
 *   the full preferences object on Save; onPreferencesUpdated(response);
 *   Cancel closes without a write.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import NotificationsPanel, {
  NotificationBell,
} from "../../../components/layout/NotificationsPanel";
import HelpPanel from "../../../components/layout/HelpPanel";
import SettingsDrawer from "../../../components/layout/SettingsDrawer";
import axiosInstance from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

/* Dual-path helpers — see AppLayout.test.jsx. */
const tabOrButton = (name) =>
  screen.queryByRole("tab", { name }) || screen.getByRole("button", { name });
const radioOrButton = (name) =>
  screen.queryByRole("radio", { name }) || screen.getByRole("button", { name });
const findRadioOrButton = async (name) => {
  let el;
  await waitFor(() => {
    el = radioOrButton(name);
    expect(el).toBeInTheDocument();
  });
  return el;
};
const settingsDialog = () =>
  screen.queryByRole("dialog", { name: "Settings" }) ||
  screen.getByRole("complementary", { name: "Settings" });

const NOTIFS = [
  {
    id: "n-1",
    type: "scan_completed",
    category: "scan",
    title: "Scan #41 complete",
    message: "12 hosts",
    is_read: false,
    created_at: new Date(Date.now() - 120000).toISOString(),
  },
  {
    id: "n-2",
    type: "vulnerability_found",
    category: "security",
    title: "Critical finding",
    message: "CVE-2026-1111",
    is_read: true,
    created_at: new Date(Date.now() - 7200000).toISOString(),
  },
];
const PREFS = {
  theme: "light",
  default_rows_per_page: 25,
  sidebar_collapsed: false,
  default_scan_type: "asset",
  email_alerts: true,
  in_app_alerts: false,
};

beforeEach(() => {
  vi.clearAllMocks();
  axiosInstance.get.mockImplementation((url) => {
    if (url === "/notifications") return Promise.resolve({ data: NOTIFS });
    if (url === "/notifications/summary")
      return Promise.resolve({ data: { total_unread: 1 } });
    if (url === "/user/preferences") return Promise.resolve({ data: PREFS });
    return Promise.reject(new Error("unexpected GET " + url));
  });
  axiosInstance.patch.mockResolvedValue({ data: {} });
  axiosInstance.delete.mockResolvedValue({ data: {} });
  axiosInstance.put.mockImplementation((_u, body) =>
    Promise.resolve({ data: { ...body, saved: true } }),
  );
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("NotificationsPanel", () => {
  const open = async (props = {}) => {
    const onClose = vi.fn();
    const onUnreadChange = vi.fn();
    render(
      <>
        <button type="button" id="header-notifications-btn">
          bell
        </button>
        <button type="button">elsewhere</button>
        <NotificationsPanel
          onClose={onClose}
          onUnreadChange={onUnreadChange}
          {...props}
        />
      </>,
    );
    await screen.findByText("Scan #41 complete");
    return { onClose, onUnreadChange };
  };

  it("reads the first page of all categories on open", async () => {
    await open();
    expect(axiosInstance.get).toHaveBeenCalledWith("/notifications", {
      params: { unread_only: false, limit: 50, offset: 0 },
    });
    expect(
      screen.getByRole("dialog", { name: "Notifications" }),
    ).toBeInTheDocument();
    expect(screen.getByText("12 hosts")).toBeInTheDocument();
    expect(screen.getByText("2m ago")).toBeInTheDocument();
  });

  it("re-reads with the category when a tab is chosen", async () => {
    const u = userEvent.setup();
    await open();
    await u.click(tabOrButton("Security"));
    await waitFor(() =>
      expect(axiosInstance.get).toHaveBeenCalledWith("/notifications", {
        params: {
          unread_only: false,
          limit: 50,
          offset: 0,
          category: "security",
        },
      }),
    );
  });

  it("marks one as read: PATCH then a badge refresh", async () => {
    const u = userEvent.setup();
    const { onUnreadChange } = await open();
    await u.click(screen.getByTitle("Mark as read"));
    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith(
        "/notifications/n-1/read",
      ),
    );
    await waitFor(() => expect(onUnreadChange).toHaveBeenCalledWith(1));
    expect(screen.queryByTitle("Mark as read")).not.toBeInTheDocument();
  });

  it("marks all read: PATCH read-all and the badge goes to zero", async () => {
    const u = userEvent.setup();
    const { onUnreadChange } = await open();
    await u.click(screen.getByTitle("Mark all as read"));
    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith(
        "/notifications/read-all",
      ),
    );
    expect(onUnreadChange).toHaveBeenCalledWith(0);
  });

  it("deletes one: DELETE then a badge refresh, row removed", async () => {
    const u = userEvent.setup();
    await open();
    await u.click(screen.getAllByTitle("Delete")[0]);
    await waitFor(() =>
      expect(axiosInstance.delete).toHaveBeenCalledWith("/notifications/n-1"),
    );
    await waitFor(() =>
      expect(screen.queryByText("Scan #41 complete")).not.toBeInTheDocument(),
    );
    expect(axiosInstance.get).toHaveBeenCalledWith("/notifications/summary");
  });

  it("inserts a matching live event at the top, once, while open", async () => {
    const live = {
      type: "created",
      notification: {
        id: "n-3",
        type: "scan_failed",
        category: "scan",
        title: "Scan #42 failed",
        message: "x",
        is_read: false,
        created_at: new Date().toISOString(),
      },
    };
    const { rerender } = render(
      <NotificationsPanel onClose={() => {}} liveEvent={null} />,
    );
    await screen.findByText("Scan #41 complete");
    rerender(<NotificationsPanel onClose={() => {}} liveEvent={live} />);
    await screen.findByText("Scan #42 failed");
    const titles = screen.getAllByText(/Scan #4/).map((e) => e.textContent);
    expect(titles[0]).toBe("Scan #42 failed");
    expect(screen.getAllByText("Scan #42 failed")).toHaveLength(1);
  });

  it("closes on a click outside, but not on the bell", async () => {
    const u = userEvent.setup();
    const { onClose } = await open();
    await u.click(screen.getByText("bell"));
    expect(onClose).not.toHaveBeenCalled();
    await u.click(screen.getByText("elsewhere"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("shows the category-specific empty message and the load error", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/notifications"
        ? Promise.resolve({ data: [] })
        : Promise.reject(new Error("x")),
    );
    const u = userEvent.setup();
    render(<NotificationsPanel onClose={() => {}} />);
    expect(
      await screen.findByText("No notifications available."),
    ).toBeInTheDocument();
    await u.click(tabOrButton("Scans"));
    expect(
      await screen.findByText("No Scan notifications found."),
    ).toBeInTheDocument();
  });

  it("renders the bell badge and caps it at 99+", () => {
    const { rerender } = render(
      <NotificationBell unreadCount={3} onClick={() => {}} />,
    );
    expect(screen.getByText("3")).toBeInTheDocument();
    rerender(<NotificationBell unreadCount={250} onClick={() => {}} />);
    expect(screen.getByText("99+")).toBeInTheDocument();
    rerender(<NotificationBell unreadCount={0} onClick={() => {}} />);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("HelpPanel", () => {
  it("is a named dialog that issues no request", () => {
    render(<HelpPanel onClose={() => {}} />);
    expect(
      screen.getByRole("dialog", { name: "Help Center" }),
    ).toBeInTheDocument();
    expect(axiosInstance.get).not.toHaveBeenCalled();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("filters FAQs by question, answer and tag, and expands an answer", async () => {
    const u = userEvent.setup();
    render(<HelpPanel onClose={() => {}} />);
    await u.type(screen.getByPlaceholderText("Search FAQs…"), "new scan");
    const q = screen.getByRole("button", { name: /How do I start a new scan/ });
    expect(q).toBeInTheDocument();
    await u.click(q);
    expect(screen.getByText(/New Scan' button/)).toBeInTheDocument();
    await u.clear(screen.getByPlaceholderText("Search FAQs…"));
    await u.type(screen.getByPlaceholderText("Search FAQs…"), "zzzz");
    expect(
      screen.getByText("No matching questions found."),
    ).toBeInTheDocument();
  });

  it("switches sections and the support form sends nothing over the wire", async () => {
    const u = userEvent.setup();
    render(<HelpPanel onClose={() => {}} />);
    await u.click(tabOrButton("Quick Links"));
    expect(screen.getByText("Getting Started Guide")).toBeInTheDocument();
    await u.click(tabOrButton("What's New"));
    await u.click(tabOrButton("Support"));
    const send = screen.getByRole("button", { name: "Send Message" });
    expect(send).toBeDisabled();
    await u.type(screen.getByPlaceholderText(/Describe your issue/), "hello");
    await u.click(send);
    expect(screen.getByText(/Message sent/)).toBeInTheDocument();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("closes from its close control and on a click outside (help button exempt)", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <>
        <button type="button" id="header-help-btn">
          help
        </button>
        <button type="button">elsewhere</button>
        <HelpPanel onClose={onClose} />
      </>,
    );
    await u.click(screen.getByText("help"));
    expect(onClose).not.toHaveBeenCalled();
    await u.click(screen.getByText("elsewhere"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("SettingsDrawer", () => {
  it("reads the preferences on open and renders them", async () => {
    render(
      <SettingsDrawer onClose={() => {}} onPreferencesUpdated={() => {}} />,
    );
    expect(settingsDialog()).toBeInTheDocument();
    await waitFor(() =>
      expect(axiosInstance.get).toHaveBeenCalledWith("/user/preferences"),
    );
    expect(await findRadioOrButton(/Light/)).toBeInTheDocument();
    expect(radioOrButton("25")).toBeInTheDocument();
    // The toggles had no accessible name before the migration (the label
    // element was empty); by id then, by name now.
    const inapp =
      screen.queryByLabelText(/In-app notifications/) ||
      document.getElementById("sd-inapp");
    const email =
      screen.queryByLabelText(/Email alerts/) ||
      document.getElementById("sd-email");
    expect(inapp).not.toBeChecked();
    expect(email).toBeChecked();
  });

  it("saves the whole preferences object with PUT and reports it upward", async () => {
    const u = userEvent.setup();
    const onPreferencesUpdated = vi.fn();
    render(
      <SettingsDrawer
        onClose={() => {}}
        onPreferencesUpdated={onPreferencesUpdated}
      />,
    );
    await findRadioOrButton(/Dark/);
    await u.click(radioOrButton(/Dark/));
    await u.click(radioOrButton("50"));
    await u.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() =>
      expect(axiosInstance.put).toHaveBeenCalledWith("/user/preferences", {
        ...PREFS,
        theme: "dark",
        default_rows_per_page: 50,
      }),
    );
    expect(onPreferencesUpdated).toHaveBeenCalledWith(
      expect.objectContaining({ theme: "dark", saved: true }),
    );
    expect(await screen.findByText("Saved")).toBeInTheDocument();
  });

  it("Cancel closes without a write; a failed save is reported", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <SettingsDrawer onClose={onClose} onPreferencesUpdated={() => {}} />,
    );
    await findRadioOrButton(/Dark/);
    await u.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(axiosInstance.put).not.toHaveBeenCalled();
    axiosInstance.put.mockRejectedValueOnce({
      response: { data: { detail: "Nope" } },
    });
    await u.click(screen.getByRole("button", { name: "Save Settings" }));
    expect(await screen.findByText("Nope")).toBeInTheDocument();
  });

  it("reports a failed load", async () => {
    axiosInstance.get.mockRejectedValue(new Error("x"));
    render(<SettingsDrawer onClose={() => {}} />);
    expect(
      await screen.findByText("Failed to load preferences"),
    ).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("Shell panels — accessibility expectations (migration spec)", () => {
  it("notifications: category tabs announce selection; item actions are named; Escape closes", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<NotificationsPanel onClose={onClose} />);
    await screen.findByText("Scan #41 complete");
    expect(screen.getByRole("tab", { name: "All" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      screen.getByRole("button", {
        name: /mark .*scan #41 complete.* as read/i,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /delete .*scan #41 complete/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /close notifications/i }),
    ).toBeInTheDocument();
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("help: FAQ toggles state, the search is labelled, Escape closes", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<HelpPanel onClose={onClose} />);
    expect(
      screen.getByLabelText(/search faqs/i, { selector: "input" }),
    ).toBeInTheDocument();
    const q = screen.getByRole("button", { name: /How do I start a new scan/ });
    expect(q).toHaveAttribute("aria-expanded", "false");
    await u.click(q);
    expect(q).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tab", { name: "FAQ" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("settings: a named dialog that traps focus, whose option groups announce selection, and whose save result is announced", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <>
        <button type="button">outside</button>
        <SettingsDrawer onClose={onClose} onPreferencesUpdated={() => {}} />
      </>,
    );
    const dlg = screen.getByRole("dialog", { name: "Settings" });
    expect(dlg).toHaveAttribute("aria-modal", "true");
    await screen.findByRole("radio", { name: /Light/ });
    await waitFor(() =>
      expect(dlg.contains(document.activeElement)).toBe(true),
    );
    for (let i = 0; i < 20; i += 1) {
      await u.tab();
      expect(dlg.contains(document.activeElement)).toBe(true);
    }
    expect(screen.getByLabelText(/In-app notifications/)).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /Light/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Dark/ })).not.toBeChecked();
    await u.click(screen.getByRole("button", { name: "Save Settings" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Saved");
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });

  it("panels carry no inline styles", async () => {
    const { container } = render(
      <>
        <NotificationsPanel onClose={() => {}} />
        <HelpPanel onClose={() => {}} />
        <SettingsDrawer onClose={() => {}} />
      </>,
    );
    await screen.findByText("Scan #41 complete");
    await findRadioOrButton(/Dark/);
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
  });
});
