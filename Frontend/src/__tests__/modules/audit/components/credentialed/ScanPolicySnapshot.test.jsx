/**
 * The per-scan policy snapshot.
 *
 * This is the component the phase's acceptance criterion names: a policy
 * already associated with a completed scan must display as **the historical
 * snapshot used for that scan**, not the current edited version.
 *
 * The real fixture is the case that makes it matter. Scan 69 ran under a
 * policy that is *now archived and disabled*, while `matches_snapshot` is
 * true — so the lifecycle moved and the configuration did not. Both a UI that
 * showed the live policy and one that announced "the policy has changed" would
 * be wrong, in opposite directions.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import real from "../../../../fixtures/scanPolicySnapshot.real.json";
import ScanPolicySnapshot from "@audit/components/credentialed/ScanPolicySnapshot";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn() },
}));

beforeEach(() => vi.clearAllMocks());

const renderWith = (data) => {
  api.get.mockResolvedValue({ data });
  return render(<ScanPolicySnapshot scanId="scn_1" />);
};

describe("ScanPolicySnapshot — the snapshot is authoritative", () => {
  it("reads the scan's own record, not the policy row", async () => {
    renderWith(real);
    await screen.findByText(/This is the configuration this scan used/);

    expect(api.get).toHaveBeenCalledWith("/scans/scn_1/policy");
    expect(
      screen.getByText(/not from the policy as it stands now/i),
    ).toBeInTheDocument();
  });

  it("shows the snapshot's own identity", async () => {
    renderWith(real);
    await screen.findByText(/This is the configuration this scan used/);
    expect(screen.getAllByText(real.policy.policy_name).length).toBeGreaterThan(
      0,
    );
    expect(
      screen.getByText(real.policy.fingerprint.slice(0, 16)),
    ).toBeInTheDocument();
  });

  it("renders every effective configuration field the API returned", async () => {
    renderWith(real);
    await screen.findByText(/Effective configuration/);

    // Identity fields live in the header; the rest are the config grid.
    const identity = new Set([
      "policy_id",
      "policy_name",
      "policy_family_code",
      "version_number",
      "fingerprint",
      "source",
      "scan_kind",
    ]);
    const expected = Object.keys(real.effective).filter(
      (k) => !identity.has(k),
    );
    expect(expected.length).toBeGreaterThan(10);
    for (const key of expected) {
      expect(
        screen.getAllByText(key.replace(/_/g, " ")).length,
      ).toBeGreaterThan(0);
    }
  });

  it("does not claim the configuration changed when only the lifecycle did", async () => {
    // The real case: archived and disabled, but matches_snapshot is true.
    expect(real.policy_current_state.status).toBe("archived");
    expect(real.policy_current_state.is_enabled).toBe(false);
    expect(real.policy_current_state.matches_snapshot).toBe(true);

    renderWith(real);
    await screen.findByText(/The policy today/);

    expect(screen.getByText(/unchanged since this scan/)).toBeInTheDocument();
    expect(screen.queryByText(/edited since this scan/)).toBeNull();
    expect(
      screen.getByText(/affects future scans, not\s+this one/i),
    ).toBeInTheDocument();
  });
});

describe("ScanPolicySnapshot — divergence", () => {
  it("warns with the backend's own note when the policy was edited", async () => {
    renderWith({
      ...real,
      policy_current_state: {
        ...real.policy_current_state,
        matches_snapshot: false,
        note: "The policy has been edited since this scan ran. The configuration above is what this scan used.",
      },
    });
    await screen.findByText(/The policy today/);
    // The phrase appears twice on purpose: once as the field value and once
    // inside the backend's note.
    expect(
      screen.getAllByText(/edited since this scan/).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText(/The configuration above is what this scan used/),
    ).toBeInTheDocument();
  });

  it("says so when the policy was deleted, without losing the record", async () => {
    renderWith({
      ...real,
      policy_current_state: {
        exists: false,
        matches_snapshot: false,
        note: "The policy that produced this scan has since been deleted. The configuration above is unaffected.",
      },
    });
    await screen.findByText(/Policy deleted/);
    expect(screen.getByText(/is unaffected/)).toBeInTheDocument();
    // The snapshot is still rendered in full.
    expect(screen.getByText(/Effective configuration/)).toBeInTheDocument();
  });
});

describe("ScanPolicySnapshot — empty-state semantics", () => {
  it("reports an unrecorded policy as such, never as a default", async () => {
    renderWith({
      scan_id: "scn_1",
      scan_no: 84,
      policy: { recorded: false },
    });
    await screen.findByText(/No policy record/);

    expect(
      screen.getByText(/not a statement that no policy applied/i),
    ).toBeInTheDocument();
    // Nothing invented in place of the missing record.
    expect(screen.queryByText(/Effective configuration/)).toBeNull();
  });

  it("names a request-built snapshot as what it is", async () => {
    renderWith({
      ...real,
      policy: { ...real.policy, source: "request", policy_name: null },
    });
    await screen.findByText(/Effective configuration/);
    expect(
      screen.getByText("the scan's own request parameters"),
    ).toBeInTheDocument();
  });

  it("surfaces a read failure rather than rendering an empty record", async () => {
    api.get.mockRejectedValue({
      response: { status: 403, data: { message: "Forbidden" } },
    });
    render(<ScanPolicySnapshot scanId="scn_1" />);
    await waitFor(() =>
      expect(screen.getByText("Forbidden")).toBeInTheDocument(),
    );
  });
});
