/**
 * AuditTimeline — Checkpoint 3C batch 11.
 *
 * The component reads `/assets/{id}/changelog` data handed to it by
 * AssetDetail (its only consumer). It issues no request of its own. These
 * tests pin the grouping, filtering, the two views and their empty states,
 * and the semantics the migration added: a tab list for the views, pressed
 * state on the category filters, expanded state on group headers and the
 * technical-details toggle, and a text equivalent for the new-discovery dot.
 */

import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AuditTimeline from "../../components/assets/AuditTimeline";

const DAY = 86400000;
const iso = (daysAgo) => new Date(Date.now() - daysAgo * DAY).toISOString();

const DATA = {
  timeline: [
    {
      group_id: "g-1",
      scan_id: "scan-77",
      group_icon: "🔬",
      summary_title: "Scan #77 — 2 changes",
      summary_subtitle: "Vulnerability audit",
      highest_severity: "high",
      detected_at: iso(1),
      events: [
        {
          id: "ev-1",
          category: "services",
          event_title: "Port 443 opened",
          event_description: "A new HTTPS listener was discovered.",
          severity: "high",
          icon: "🔓",
          is_new_discovery: true,
        },
        {
          id: "ev-2",
          category: "identity",
          event_title: "Hostname changed",
          change_type: "field_update",
          old_value_display: "ws-01",
          new_value_display: "ws-01b",
          severity: "low",
          icon: "🏷️",
          is_new_discovery: false,
        },
      ],
    },
  ],
  raw_changelog: [
    { id: "ev-1", field: "services", old: null, new: "443/tcp" },
    { id: "ev-2", field: "hostname", old: "ws-01", new: "ws-01b" },
  ],
  admin_logs: [
    {
      id: "al-1",
      created_at: iso(2),
      action: "asset_owner_update",
      status: "success",
      user_email: "alice@example.test",
      changes: { owner: ["bob", "alice"] },
    },
    {
      id: "al-2",
      created_at: iso(3),
      action: "tag_remove",
      status: "failed",
      user_email: "mallory@example.test",
      changes: {},
    },
  ],
  category_meta: {
    services: { icon: "🔌", label: "Services" },
    identity: { icon: "🪪", label: "Identity" },
  },
  categories: ["services", "identity"],
  stats: { total_events: 2 },
};

const groupButton = () => screen.getByRole("button", { name: /Scan #77/ });

describe("AuditTimeline — states", () => {
  it("shows a loading placeholder without data", () => {
    render(<AuditTimeline changelogData={null} />);
    expect(screen.getByText("Loading Timeline...")).toBeInTheDocument();
  });

  it("shows the empty state when there is no history at all", () => {
    render(
      <AuditTimeline changelogData={{ timeline: [], raw_changelog: [] }} />,
    );
    expect(screen.getByText("No Audit Logs")).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("renders the heading at the level the host asks for", () => {
    render(<AuditTimeline changelogData={DATA} headingLevel={2} />);
    expect(
      screen.getByRole("heading", {
        level: 2,
        name: "Asset Activity Timeline",
      }),
    ).toBeInTheDocument();
  });
});

describe("AuditTimeline — activity view", () => {
  it("offers the two views as tabs and opens on the timeline", () => {
    render(<AuditTimeline changelogData={DATA} />);
    const list = screen.getByRole("tablist", { name: "Audit views" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual([
      "Activity Timeline",
      "Administrative Audit",
    ]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(groupButton()).toBeInTheDocument();
  });

  it("renders the category filters as pressed toggles, All Events first", () => {
    render(<AuditTimeline changelogData={DATA} />);
    const group = screen.getByRole("group", {
      name: /filter events by category/i,
    });
    const pills = within(group).getAllByRole("button");
    // Accessible names, not textContent: the icons are aria-hidden, so the
    // name is the label alone.
    for (const name of ["All Events", "Services", "Identity"]) {
      expect(within(group).getByRole("button", { name })).toBeInTheDocument();
    }
    expect(pills).toHaveLength(3);
    expect(pills[0]).toHaveAttribute("aria-pressed", "true");
    expect(pills[1]).toHaveAttribute("aria-pressed", "false");
  });

  it("collapses groups by default and expands them from a button that says so", async () => {
    const user = userEvent.setup();
    render(<AuditTimeline changelogData={DATA} />);
    const btn = groupButton();
    expect(btn).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Port 443 opened")).not.toBeInTheDocument();

    await user.click(btn);
    expect(btn).toHaveAttribute("aria-expanded", "true");
    expect(btn).toHaveAttribute("aria-controls");
    expect(
      document.getElementById(btn.getAttribute("aria-controls")),
    ).toHaveTextContent("Port 443 opened");
    expect(screen.getByText("Hostname changed")).toBeInTheDocument();
  });

  it("renders a new discovery with a text equivalent, and a field update as old → new", async () => {
    const user = userEvent.setup();
    render(<AuditTimeline changelogData={DATA} />);
    await user.click(groupButton());
    expect(screen.getByText("New discovery")).toBeInTheDocument();
    expect(
      screen.getByText("A new HTTPS listener was discovered."),
    ).toBeInTheDocument();
    expect(screen.getByText("ws-01")).toBeInTheDocument();
    expect(screen.getByText("ws-01b")).toBeInTheDocument();
    expect(screen.getByText("Previous value:")).toBeInTheDocument();
    expect(screen.getByText("New value:")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
  });

  it("filters events by category and clears back to all", async () => {
    const user = userEvent.setup();
    render(<AuditTimeline changelogData={DATA} />);
    await user.click(groupButton());
    await user.click(screen.getByRole("button", { name: "Identity" }));
    expect(screen.getByRole("button", { name: "Identity" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    // The group stays (it has an identity event); the services event is gone.
    expect(groupButton()).toHaveAttribute("aria-expanded", "true");
    expect(screen.queryByText("Port 443 opened")).not.toBeInTheDocument();
    expect(screen.getByText("Hostname changed")).toBeInTheDocument();
  });

  it("shows the filtered-empty state with a Clear Filters action", async () => {
    const user = userEvent.setup();
    const data = {
      ...DATA,
      timeline: [{ ...DATA.timeline[0], events: [DATA.timeline[0].events[0]] }],
    };
    render(<AuditTimeline changelogData={data} />);
    await user.click(screen.getByRole("button", { name: "Identity" }));
    expect(screen.getByText("No events match filter")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear Filters" }));
    expect(screen.getByRole("button", { name: "All Events" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(groupButton()).toBeInTheDocument();
  });

  it("toggles technical details with an expanded state", async () => {
    const user = userEvent.setup();
    render(<AuditTimeline changelogData={DATA} />);
    await user.click(groupButton());
    const toggles = screen.getAllByRole("button", {
      name: "View Technical Details",
    });
    expect(toggles[0]).toHaveAttribute("aria-expanded", "false");
    await user.click(toggles[0]);
    expect(
      screen.getByRole("button", { name: "Hide Technical Details" }),
    ).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/"new": "443\/tcp"/)).toBeInTheDocument();
  });
});

describe("AuditTimeline — administrative view", () => {
  it("lists administrative actions with their outcome", async () => {
    const user = userEvent.setup();
    render(<AuditTimeline changelogData={DATA} />);
    await user.click(screen.getByRole("tab", { name: "Administrative Audit" }));
    expect(screen.getByText("Asset Owner Update")).toBeInTheDocument();
    expect(screen.getByText("Tag Remove")).toBeInTheDocument();
    expect(screen.getByText("success")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getByText("alice@example.test")).toBeInTheDocument();
    expect(screen.getByText(/"owner"/)).toBeInTheDocument();
    expect(screen.getAllByText("Changes:")).toHaveLength(1);
  });

  it("shows the administrative empty state", async () => {
    const user = userEvent.setup();
    render(<AuditTimeline changelogData={{ ...DATA, admin_logs: [] }} />);
    await user.click(screen.getByRole("tab", { name: "Administrative Audit" }));
    expect(screen.getByText("No Administrative Actions")).toBeInTheDocument();
  });
});

describe("AuditTimeline — design-system expectations", () => {
  it("renders no inline styles in either view", async () => {
    const user = userEvent.setup();
    const { container } = render(<AuditTimeline changelogData={DATA} />);
    await user.click(groupButton());
    await user.click(
      screen.getAllByRole("button", { name: "View Technical Details" })[0],
    );
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
    await user.click(screen.getByRole("tab", { name: "Administrative Audit" }));
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
  });

  it("uses no dashboard.css classes", () => {
    const { container } = render(<AuditTimeline changelogData={DATA} />);
    expect(
      container.querySelectorAll('[class^="db-"], [class*=" db-"]'),
    ).toHaveLength(0);
  });
});
