/**
 * ScanSchedules — Checkpoint 3C batch 13 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── What is preserved ───────────────────────────────────────────────────────
 *   * the reads: listScanSchedules with the two filters, listTimezones,
 *     listScheduleCredentials, listScanScheduleRuns on demand;
 *   * the writes and their arguments: createScanSchedule(form),
 *     updateScanSchedule(id, form), setScanScheduleEnabled(id, !enabled),
 *     runScanScheduleNow(id), deleteScanSchedule(id);
 *   * run-now is an EXPLICIT user action: never called on render, never
 *     called by opening any other control;
 *   * delete is confirmation-gated;
 *   * there is no password field anywhere on the page — a credentialed
 *     schedule picks a stored credential by name.
 *
 * ── Baseline defect, recorded not hidden ────────────────────────────────────
 * The page destructures `{ addToast, removeToast }` from `useToasts()`, which
 * exports `{ push, dismiss }`. Every success and failure path therefore throws
 * TypeError AFTER the API call has been made: save reports "Could not save the
 * schedule." on success and leaves the form open; enable/run/delete perform
 * the write and never refresh the list. The tests in the "feedback and
 * refresh" block describe the intended behaviour and FAIL on the baseline;
 * the rest pass on both sides.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ScanSchedules from "@audit/pages/scan/ScanSchedules";
import * as api from "@audit/api/scanSchedules";

vi.mock("@audit/api/scanSchedules", () => ({
  listScanSchedules: vi.fn(),
  listTimezones: vi.fn(),
  listScheduleCredentials: vi.fn(),
  listScanScheduleRuns: vi.fn(),
  createScanSchedule: vi.fn(),
  updateScanSchedule: vi.fn(),
  setScanScheduleEnabled: vi.fn(),
  runScanScheduleNow: vi.fn(),
  deleteScanSchedule: vi.fn(),
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const SCHEDULES = [
  {
    id: "sch-1",
    name: "Nightly DMZ",
    description: "Every night",
    scan_kind: "network",
    targets: ["10.180.5.0/24", "10.180.6.14"],
    credential_id: null,
    credential_name: null,
    recurrence: "daily",
    timezone: "Asia/Kolkata",
    run_at: "02:00",
    day_of_week: null,
    day_of_month: null,
    cron_expression: null,
    starts_at: null,
    is_enabled: true,
    scan_options: {},
    summary: "Daily at 02:00 Asia/Kolkata",
    next_run_at: "2026-09-13T20:30:00Z",
    last_run_at: "2026-09-12T20:30:00Z",
    last_status: "dispatched",
    last_error: null,
    consecutive_failures: 0,
  },
  {
    id: "sch-2",
    name: "Weekly Windows audit",
    description: "",
    scan_kind: "credentialed",
    targets: ["10.180.6.14"],
    credential_id: "cred-9",
    credential_name: "DC admin",
    recurrence: "weekly",
    timezone: "UTC",
    run_at: "03:30",
    day_of_week: 6,
    day_of_month: null,
    cron_expression: null,
    starts_at: null,
    is_enabled: false,
    scan_options: {},
    summary: "Weekly on Sunday at 03:30 UTC",
    next_run_at: null,
    last_run_at: "2026-09-06T03:30:00Z",
    last_status: "failed",
    last_error: "credential refused",
    consecutive_failures: 3,
  },
];

const CREDENTIALS = [
  { id: "cred-9", name: "DC admin", username: "CORP\\svc-audit" },
  { id: "cred-10", name: "Linux ro", username: "audit" },
];

const rowOf = (name) => screen.getByText(name).closest("tr");
/* Dual-path: the legacy row buttons are named by their visible text ("Edit");
   the migrated ones carry the schedule name in the accessible name ("Edit
   Nightly DMZ") so ten rows do not produce ten identical names. Matching on
   the leading verb inside the row satisfies both. */
const rowButton = (name, label) =>
  within(rowOf(name)).getByRole("button", { name: label });

const renderPage = async () => {
  const utils = render(<ScanSchedules />);
  await waitFor(() => expect(api.listScanSchedules).toHaveBeenCalled());
  await screen.findByText("Nightly DMZ");
  return utils;
};

beforeEach(() => {
  vi.clearAllMocks();
  api.listScanSchedules.mockResolvedValue({ schedules: SCHEDULES });
  api.listTimezones.mockResolvedValue(["UTC", "Asia/Kolkata", "Europe/London"]);
  api.listScheduleCredentials.mockResolvedValue(CREDENTIALS);
  api.listScanScheduleRuns.mockResolvedValue({ runs: [] });
  api.createScanSchedule.mockResolvedValue({ id: "sch-3" });
  api.updateScanSchedule.mockResolvedValue({});
  api.setScanScheduleEnabled.mockResolvedValue({});
  api.runScanScheduleNow.mockResolvedValue({
    run: { status: "dispatched", scan_id: 41 },
  });
  api.deleteScanSchedule.mockResolvedValue({});
});

describe("ScanSchedules — reads, filters and list", () => {
  it("lists schedules with kind, recurrence summary, targets count and credential name", async () => {
    await renderPage();
    expect(api.listScanSchedules).toHaveBeenCalledWith({
      scanKind: undefined,
      enabled: undefined,
    });
    expect(api.listTimezones).toHaveBeenCalled();
    expect(api.listScheduleCredentials).toHaveBeenCalled();
    expect(screen.getByText("Daily at 02:00 Asia/Kolkata")).toBeInTheDocument();
    expect(screen.getByText(/2 targets/)).toBeInTheDocument();
    expect(screen.getByText(/1 target · DC admin/)).toBeInTheDocument();
    expect(screen.getByText("DISPATCHED")).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
    expect(screen.getByText("credential refused")).toBeInTheDocument();
    expect(
      within(rowOf("Weekly Windows audit")).getByText("disabled"),
    ).toBeInTheDocument();
  });

  it("run-now is never called on render or by loading the page", async () => {
    await renderPage();
    expect(api.runScanScheduleNow).not.toHaveBeenCalled();
    expect(api.createScanSchedule).not.toHaveBeenCalled();
    expect(api.setScanScheduleEnabled).not.toHaveBeenCalled();
    expect(api.deleteScanSchedule).not.toHaveBeenCalled();
  });

  it("filters re-query the server by kind and enabled state", async () => {
    await renderPage();
    const selects = screen.getAllByRole("combobox");
    await userEvent.selectOptions(selects[0], "credentialed");
    await waitFor(() =>
      expect(api.listScanSchedules).toHaveBeenLastCalledWith({
        scanKind: "credentialed",
        enabled: undefined,
      }),
    );
    await userEvent.selectOptions(selects[1], "false");
    await waitFor(() =>
      expect(api.listScanSchedules).toHaveBeenLastCalledWith({
        scanKind: "credentialed",
        enabled: false,
      }),
    );
  });

  it("warns about schedules switched off after repeated failures", async () => {
    await renderPage();
    expect(
      screen.getByText(/1 schedule switched off after repeated failures/),
    ).toBeInTheDocument();
  });

  it("shows the empty state when there are no schedules", async () => {
    api.listScanSchedules.mockResolvedValue({ schedules: [] });
    render(<ScanSchedules />);
    expect(
      await screen.findByText(/No scan schedules yet/),
    ).toBeInTheDocument();
  });

  it("there is no password field anywhere on the page, including the credentialed form", async () => {
    await renderPage();
    await userEvent.click(
      screen.getByRole("button", { name: /new schedule/i }),
    );
    await userEvent.selectOptions(
      screen.getByLabelText(/scan kind/i),
      "credentialed",
    );
    expect(document.querySelectorAll('input[type="password"]')).toHaveLength(0);
    expect(
      screen.queryAllByText(/^password/i, { selector: "label" }),
    ).toHaveLength(0);
    const cred = screen.getByLabelText(/^credential/i);
    expect(
      within(cred).getByRole("option", {
        name: /DC admin \(CORP\\svc-audit\)/,
      }),
    ).toBeInTheDocument();
  });
});

describe("ScanSchedules — form", () => {
  it("new schedule: defaults, recurrence-dependent fields, and the create payload", async () => {
    await renderPage();
    await userEvent.click(
      screen.getByRole("button", { name: /new schedule/i }),
    );
    expect(
      screen.getByRole("heading", { name: /new schedule/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/scan kind/i)).toBeEnabled();

    await userEvent.type(screen.getByLabelText(/^name/i), "Quarterly");
    await userEvent.type(
      screen.getByLabelText(/targets/i),
      "10.0.0.1, 10.0.0.2",
    );

    await userEvent.selectOptions(
      screen.getByLabelText(/recurrence/i),
      "weekly",
    );
    expect(screen.getByLabelText(/day of week/i)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText(/day of week/i), "4");

    await userEvent.selectOptions(
      screen.getByLabelText(/recurrence/i),
      "monthly",
    );
    expect(screen.queryByLabelText(/day of week/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/day of month/i)).toBeInTheDocument();

    await userEvent.selectOptions(
      screen.getByLabelText(/recurrence/i),
      "custom",
    );
    expect(screen.getByLabelText(/cron expression/i)).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText(/recurrence/i), "once");
    expect(screen.getByLabelText(/^run at/i)).toHaveAttribute(
      "type",
      "datetime-local",
    );
    expect(screen.queryByLabelText(/time of day/i)).not.toBeInTheDocument();

    await userEvent.selectOptions(
      screen.getByLabelText(/recurrence/i),
      "daily",
    );
    expect(screen.getByLabelText(/time of day/i)).toHaveAttribute(
      "type",
      "time",
    );
    await userEvent.selectOptions(
      screen.getByLabelText(/time zone/i),
      "Europe/London",
    );

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.createScanSchedule).toHaveBeenCalledTimes(1),
    );
    expect(api.createScanSchedule).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Quarterly",
        scanKind: "network",
        targets: "10.0.0.1, 10.0.0.2",
        recurrence: "daily",
        timezone: "Europe/London",
        runAt: "02:00",
        dayOfWeek: "4",
        credentialId: "",
        isEnabled: true,
      }),
    );
  });

  it("edit: prefilled from the schedule, kind locked, and the update payload carries the id", async () => {
    await renderPage();
    await userEvent.click(rowButton("Weekly Windows audit", /^edit/i));
    expect(
      screen.getByRole("heading", { name: /edit schedule/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/^name/i)).toHaveValue("Weekly Windows audit");
    expect(screen.getByLabelText(/scan kind/i)).toBeDisabled();
    expect(screen.getByText(/The kind cannot be changed/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^credential/i)).toHaveValue("cred-9");
    expect(screen.getByLabelText(/day of week/i)).toHaveValue("6");
    await userEvent.clear(screen.getByLabelText(/^name/i));
    await userEvent.type(screen.getByLabelText(/^name/i), "Weekly DC audit");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.updateScanSchedule).toHaveBeenCalledWith(
        "sch-2",
        expect.objectContaining({
          name: "Weekly DC audit",
          scanKind: "credentialed",
          credentialId: "cred-9",
        }),
      ),
    );
  });

  it("a 422 body's field errors are shown in the form", async () => {
    api.createScanSchedule.mockRejectedValue({
      response: {
        data: {
          detail: [
            { msg: "targets: at least one target" },
            { msg: "name: required" },
          ],
        },
      },
    });
    await renderPage();
    await userEvent.click(
      screen.getByRole("button", { name: /new schedule/i }),
    );
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    expect(
      await screen.findByText(/targets: at least one target; name: required/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /new schedule/i }),
    ).toBeInTheDocument();
  });

  it("cancel closes the form without writing", async () => {
    await renderPage();
    await userEvent.click(
      screen.getByRole("button", { name: /new schedule/i }),
    );
    await userEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
    expect(
      screen.queryByRole("heading", { name: /new schedule/i }),
    ).not.toBeInTheDocument();
    expect(api.createScanSchedule).not.toHaveBeenCalled();
  });
});

describe("ScanSchedules — row actions", () => {
  it("history loads the runs for that schedule on demand and links a dispatched scan", async () => {
    api.listScanScheduleRuns.mockResolvedValue({
      runs: [
        {
          id: "r-1",
          triggered_at: "2026-09-12T20:30:00Z",
          trigger: "beat",
          status: "dispatched",
          scan_id: 41,
          detail: "",
        },
        {
          id: "r-2",
          triggered_at: "2026-09-11T20:30:00Z",
          trigger: "manual",
          status: "skipped",
          scan_id: null,
          detail: "quota exhausted",
        },
      ],
    });
    await renderPage();
    expect(api.listScanScheduleRuns).not.toHaveBeenCalled();
    await userEvent.click(rowButton("Nightly DMZ", /^history/i));
    await waitFor(() =>
      expect(api.listScanScheduleRuns).toHaveBeenCalledWith("sch-1"),
    );
    expect(
      await screen.findByRole("heading", {
        name: /Execution history — Nightly DMZ/,
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "41" })).toHaveAttribute(
      "href",
      "/history?scan=41",
    );
    expect(screen.getByText("no scan was created")).toBeInTheDocument();
    expect(screen.getByText("quota exhausted")).toBeInTheDocument();
    expect(screen.getByText("SKIPPED")).toBeInTheDocument();
  });

  it("delete asks first and writes nothing on cancel", async () => {
    await renderPage();
    await userEvent.click(rowButton("Nightly DMZ", /^delete/i));
    const dlg = screen.getByRole("dialog");
    expect(dlg).toHaveAccessibleName(/Delete "Nightly DMZ"\?/);
    expect(api.deleteScanSchedule).not.toHaveBeenCalled();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(api.deleteScanSchedule).not.toHaveBeenCalled();
  });
});

/* These describe the behaviour the page's own code INTENDS and fail on the
   baseline for the reason given in the header. They are the migration spec. */
describe("ScanSchedules — feedback and refresh after a write", () => {
  it("save closes the form, reports success and reloads the list", async () => {
    await renderPage();
    await userEvent.click(
      screen.getByRole("button", { name: /new schedule/i }),
    );
    await userEvent.type(screen.getByLabelText(/^name/i), "Quarterly");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(api.createScanSchedule).toHaveBeenCalled());
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: /new schedule/i }),
      ).not.toBeInTheDocument(),
    );
    expect(
      await screen.findByText(/Schedule "Quarterly" created\./),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Could not save the schedule/),
    ).not.toBeInTheDocument();
    expect(api.listScanSchedules).toHaveBeenCalledTimes(2);
  });

  it("enable/disable sends the inverted flag and reloads", async () => {
    await renderPage();
    await userEvent.click(rowButton("Weekly Windows audit", /^enable/i));
    await waitFor(() =>
      expect(api.setScanScheduleEnabled).toHaveBeenCalledWith("sch-2", true),
    );
    expect(
      await screen.findByText(/"Weekly Windows audit" enabled\./),
    ).toBeInTheDocument();
    await waitFor(() => expect(api.listScanSchedules).toHaveBeenCalledTimes(2));
  });

  it("run-now dispatches only on the explicit control, reports the scan number and reloads", async () => {
    await renderPage();
    await userEvent.click(rowButton("Nightly DMZ", /^run/i));
    await waitFor(() =>
      expect(api.runScanScheduleNow).toHaveBeenCalledWith("sch-1"),
    );
    expect(api.runScanScheduleNow).toHaveBeenCalledTimes(1);
    expect(
      await screen.findByText(/"Nightly DMZ" started — scan 41\./),
    ).toBeInTheDocument();
    await waitFor(() => expect(api.listScanSchedules).toHaveBeenCalledTimes(2));
  });

  it("run-now refusal is reported, not swallowed", async () => {
    api.runScanScheduleNow.mockResolvedValue({
      run: { status: "skipped", detail: "outside authorised scope" },
    });
    await renderPage();
    await userEvent.click(rowButton("Nightly DMZ", /^run/i));
    expect(
      await screen.findByText(
        /"Nightly DMZ" did not run: outside authorised scope/,
      ),
    ).toBeInTheDocument();
  });

  it("delete on confirm removes the schedule, reports it and reloads", async () => {
    await renderPage();
    await userEvent.click(rowButton("Nightly DMZ", /^delete/i));
    const dlg = screen.getByRole("dialog");
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^delete$/i }),
    );
    await waitFor(() =>
      expect(api.deleteScanSchedule).toHaveBeenCalledWith("sch-1"),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(
      await screen.findByText(/Schedule "Nightly DMZ" deleted\./),
    ).toBeInTheDocument();
    await waitFor(() => expect(api.listScanSchedules).toHaveBeenCalledTimes(2));
  });

  it("a failed load is reported", async () => {
    api.listScanSchedules.mockRejectedValue({
      response: { data: { detail: "Scheduler unavailable" } },
    });
    render(<ScanSchedules />);
    expect(
      await screen.findByText(/Scheduler unavailable/),
    ).toBeInTheDocument();
  });
});
