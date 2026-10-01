/**
 * P3-2 — recurring compliance scans.
 *
 * Four operations that have existed since the first compliance migration, with
 * beat polling `compliance_scan_schedules` every sixty seconds and no frontend
 * reference to any of them. Phase 7 recorded it as the largest single UI
 * coverage gap in the product.
 *
 * The assertions below are about the lifecycle, because that is what a single
 * "status" column would have destroyed: `is_active`, `last_run_at` and
 * `next_run_at` are three facts.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ComplianceSchedules from "@audit/components/compliance/ComplianceSchedules";
import { scheduleState } from "@audit/api/complianceSchedules";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

/* The live response shape of GET /compliance/schedules. */
const ROWS = [
  {
    id: "csch_1",
    framework_id: "cfw_iso27001_2022",
    policy_id: "pol_1",
    frequency: "weekly",
    notify_on: "always",
    is_active: true,
    last_run_at: "2026-09-20T02:00:00Z",
    next_run_at: "2026-09-27T02:00:00Z",
  },
  {
    id: "csch_2",
    framework_id: "cfw_nist_csf_v2",
    policy_id: "pol_2",
    frequency: "daily",
    notify_on: "on_failure_only",
    is_active: false,
    last_run_at: null,
    next_run_at: null,
  },
];

beforeEach(() => {
  vi.clearAllMocks();
  api.get.mockResolvedValue({ data: { data: ROWS } });
  api.patch.mockResolvedValue({ data: {} });
  api.delete.mockResolvedValue({ data: {} });
  api.post.mockResolvedValue({ data: {} });
});

const mount = async (props = {}) => {
  const r = render(<ComplianceSchedules {...props} />);
  await screen.findByText("cfw_iso27001_2022");
  return r;
};

describe("the lifecycle is three facts, not one status", () => {
  it("shows an active schedule with its next run", async () => {
    await mount();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(
      screen.getAllByText(/27\/09\/2026|9\/27\/2026|2026/).length,
    ).toBeGreaterThan(0);
  });

  it("shows a paused schedule as paused, not as failed or finished", async () => {
    await mount();
    const badge = screen.getByText("Paused");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute(
      "title",
      expect.stringMatching(/will not run until it is resumed/i),
    );
  });

  it("says a schedule has never run rather than leaving the cell blank", async () => {
    await mount();
    // `last_run_at: null` is an event that has not happened, not a missing
    // value.
    expect(screen.getAllByText("never").length).toBe(2);
  });

  it("names the state an active schedule with no next run is really in", () => {
    // The compliance scheduler treats a null next run as due on the very next
    // tick, which is worth saying rather than hiding behind "Active".
    const st = scheduleState({ is_active: true, next_run_at: null });
    expect(st.label).toMatch(/no next run/i);
    expect(st.detail).toMatch(/due on the next tick/i);
  });
});

describe("permission", () => {
  it("offers no write control without compliance:manage_schedules", async () => {
    await mount({ canManage: false });
    expect(screen.queryByRole("button", { name: "New schedule" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Pause" })).toBeNull();
    expect(screen.getByText("compliance:manage_schedules")).toBeInTheDocument();
  });

  it("offers them with it", async () => {
    await mount({ canManage: true });
    expect(
      screen.getByRole("button", { name: "New schedule" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resume" })).toBeInTheDocument();
  });
});

describe("writes go through the backend's own contract", () => {
  it("pauses by patching is_active, and re-reads rather than patching a row", async () => {
    await mount({ canManage: true });
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(api.patch).toHaveBeenCalled());
    const [url, body] = api.patch.mock.calls[0];
    expect(url).toBe("/compliance/schedules/csch_1");
    expect(body).toEqual({ is_active: false });
    // Two reads: the mount and the reload. What is shown is what the server
    // stored, not what this page assumed.
    expect(api.get.mock.calls.length).toBeGreaterThan(1);
  });

  it("changes frequency through the same patch", async () => {
    await mount({ canManage: true });
    await userEvent
      .setup()
      .selectOptions(
        screen.getByLabelText("Frequency for cfw_iso27001_2022"),
        "monthly",
      );
    await waitFor(() => expect(api.patch).toHaveBeenCalled());
    expect(api.patch.mock.calls[0][1]).toEqual({ frequency: "monthly" });
  });

  it("deletes by id", async () => {
    await mount({ canManage: true });
    const row = screen.getByText("cfw_iso27001_2022").closest("tr");
    await userEvent
      .setup()
      .click(within(row).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(api.delete).toHaveBeenCalled());
    expect(api.delete.mock.calls[0][0]).toBe("/compliance/schedules/csch_1");
  });

  it("creates with the framework, policy, frequency and notification the API requires", async () => {
    await mount({
      canManage: true,
      frameworks: [{ id: "cfw_iso27001_2022", name: "ISO 27001" }],
      policies: [{ id: "pol_1", name: "Baseline" }],
    });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "New schedule" }));
    await user.selectOptions(
      await screen.findByLabelText(/^Framework/),
      "cfw_iso27001_2022",
    );
    await user.selectOptions(screen.getByLabelText(/^Policy/), "pol_1");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    const [url, body] = api.post.mock.calls[0];
    expect(url).toBe("/compliance/schedules");
    expect(body).toMatchObject({
      framework_id: "cfw_iso27001_2022",
      policy_id: "pol_1",
      frequency: "weekly",
      notify_on: "always",
    });
  });

  it("shows the backend's own refusal", async () => {
    api.patch.mockRejectedValue({
      response: { data: { detail: "Schedule not found" } },
    });
    await mount({ canManage: true });
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Pause" }));
    expect(await screen.findByText("Schedule not found")).toBeInTheDocument();
  });
});

describe("empty and failed reads", () => {
  it("says no schedule is configured rather than showing an empty table", async () => {
    api.get.mockResolvedValue({ data: { data: [] } });
    render(<ComplianceSchedules />);
    expect(
      await screen.findByText("No recurring compliance scan is configured."),
    ).toBeInTheDocument();
  });

  it("surfaces a read failure", async () => {
    api.get.mockRejectedValue({
      response: { data: { message: "Forbidden" } },
    });
    render(<ComplianceSchedules />);
    expect(await screen.findByText("Forbidden")).toBeInTheDocument();
  });
});
