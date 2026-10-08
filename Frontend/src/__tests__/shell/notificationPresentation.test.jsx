/**
 * The shared notification panel is generic; a product describes its own
 * notifications through the presentation context.
 *
 *   - without a product, the panel knows the platform's types and categories
 *     only, and renders anything else with a neutral icon — never an error;
 *   - with Audit's presentation (what the composition root provides) Audit's
 *     types and its Scans tab look exactly as they always did, in the original
 *     tab order;
 *   - a product cannot restyle the platform's own notifications;
 *   - no shell notification source names Audit's vocabulary.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { SHELL_SRC } from "../testPaths";
import NotificationsPanel from "@shell/notifications/NotificationsPanel";
import { NotificationPresentationProvider } from "@shell/notifications/notificationPresentation";
import {
  AUDIT_NOTIFICATION_CATEGORIES,
  AUDIT_NOTIFICATION_TYPES,
} from "@audit/config/notificationPresentation";
import axiosInstance from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

const note = (id, type, extra = {}) => ({
  id,
  type,
  category: "scan",
  title: `title ${type}`,
  message: "m",
  is_read: false,
  created_at: new Date().toISOString(),
  ...extra,
});

const ALL_TYPES = [
  note("1", "scan_completed"),
  note("2", "scan_failed"),
  note("3", "scan_paused"),
  note("4", "vulnerability_found", { category: "security" }),
  note("5", "system_message", { category: "system" }),
  note("6", "admin_notice", { category: "admin" }),
  note("7", "something_from_a_future_product", { category: "other" }),
];

beforeEach(() => {
  axiosInstance.get.mockReset();
  axiosInstance.get.mockImplementation((url) =>
    url === "/notifications"
      ? Promise.resolve({ data: ALL_TYPES })
      : Promise.resolve({ data: { total_unread: 7, by_category: {} } }),
  );
});

const iconOf = (type) =>
  screen
    .getByText(`title ${type}`)
    .closest(".shn-item")
    .querySelector(".shn-item-icon");
// B.13: the panel draws CcureIcon; the icon's name is what was the emoji.
const glyph = (type) => iconOf(type).querySelector("svg")?.dataset.icon;
const tabs = () => screen.getAllByRole("tab").map((t) => t.textContent);

const withAudit = (ui) =>
  render(
    <NotificationPresentationProvider
      types={AUDIT_NOTIFICATION_TYPES}
      categories={AUDIT_NOTIFICATION_CATEGORIES}
    >
      {ui}
    </NotificationPresentationProvider>,
  );

describe("without a product's presentation (the platform alone)", () => {
  it("knows its own types and shows everything else neutrally", async () => {
    render(<NotificationsPanel onClose={() => {}} />);
    await screen.findByText("title system_message");
    expect(glyph("system_message")).toBe("info");
    expect(glyph("admin_notice")).toBe("bell");
    for (const t of ["scan_completed", "scan_failed", "vulnerability_found"]) {
      expect(glyph(t)).toBe("message-square");
      expect(iconOf(t).className).toContain("shn-item-icon--neutral");
    }
    expect(glyph("something_from_a_future_product")).toBe("message-square");
  });

  it("offers only the platform's category tabs", async () => {
    render(<NotificationsPanel onClose={() => {}} />);
    await screen.findByText("title system_message");
    expect(tabs()).toEqual(["All", "Security", "System", "Admin"]);
  });
});

describe("with Audit's presentation, as the composition root provides it", () => {
  it("renders Audit's types exactly as before", async () => {
    withAudit(<NotificationsPanel onClose={() => {}} />);
    await screen.findByText("title scan_completed");
    expect(glyph("scan_completed")).toBe("check-circle");
    expect(iconOf("scan_completed").className).toContain("--success");
    expect(glyph("scan_failed")).toBe("x-circle");
    expect(iconOf("scan_failed").className).toContain("--danger");
    expect(glyph("scan_paused")).toBe("pause-circle");
    expect(iconOf("scan_paused").className).toContain("--warning");
    expect(glyph("vulnerability_found")).toBe("alert-octagon");
    expect(iconOf("vulnerability_found").className).toContain("--danger");
    expect(glyph("system_message")).toBe("info");
    expect(glyph("admin_notice")).toBe("bell");
  });

  it("keeps the original tab order, with Scans after All", async () => {
    withAudit(<NotificationsPanel onClose={() => {}} />);
    await screen.findByText("title scan_completed");
    expect(tabs()).toEqual(["All", "Scans", "Security", "System", "Admin"]);
  });

  it("still renders a type nobody described, safely", async () => {
    withAudit(<NotificationsPanel onClose={() => {}} />);
    await screen.findByText("title something_from_a_future_product");
    expect(glyph("something_from_a_future_product")).toBe("message-square");
  });

  it("cannot restyle the platform's own notifications", async () => {
    render(
      <NotificationPresentationProvider
        types={{ admin_notice: { icon: "zap", tone: "danger" } }}
        categories={[{ id: "admin", label: "Hijacked" }]}
      >
        <NotificationsPanel onClose={() => {}} />
      </NotificationPresentationProvider>,
    );
    await screen.findByText("title admin_notice");
    expect(glyph("admin_notice")).toBe("bell");
    expect(tabs()).toEqual(["All", "Security", "System", "Admin"]);
  });
});

describe("the shared notification code holds no Audit vocabulary", () => {
  const files = readdirSync(path.join(SHELL_SRC, "notifications")).filter((f) =>
    /\.(jsx?|css)$/.test(f),
  );
  const WORDS =
    /scan_completed|scan_failed|scan_paused|vulnerability_found|related_scan|["']scan["']|Scans\b/;

  it.each(files)("%s", (file) => {
    const source = readFileSync(
      path.join(SHELL_SRC, "notifications", file),
      "utf8",
    );
    // comments may name the example; code must not
    const code = source
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
    expect(code).not.toMatch(WORDS);
  });
});
