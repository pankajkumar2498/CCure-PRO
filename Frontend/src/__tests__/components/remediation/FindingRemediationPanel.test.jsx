/**
 * The shared per-finding remediation record.
 *
 * The fixtures are the live API's own answers, captured while driving the
 * whole workflow against the running deployment — including the one that
 * matters most: a finding whose acceptance was withdrawn, which comes back
 * `open` while still carrying the reason, the approver and the acceptance
 * timestamp. A panel that reads those as a live exception labels an open
 * finding as one the organisation decided to carry.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import withdrawn from "../../fixtures/remediationFindingWithdrawn.real.json";
import accepted from "../../fixtures/remediationFindingAccepted.real.json";
import history from "../../fixtures/remediationHistory.real.json";
import FindingRemediationPanel from "../../../components/remediation/FindingRemediationPanel";
import api from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn() },
}));

const mountWith = (finding, events = history.events, props = {}) => {
  api.get.mockImplementation((url) =>
    url.endsWith("/history")
      ? Promise.resolve({ data: { events } })
      : Promise.resolve({ data: finding }),
  );
  return render(
    <FindingRemediationPanel findingId={finding.finding_id} {...props} />,
  );
};

beforeEach(() => vi.clearAllMocks());

describe("what the record says", () => {
  it("renders every field the API's serialiser returns", async () => {
    mountWith(withdrawn);
    await screen.findByText("Detection");

    // Identity and detection
    expect(screen.getAllByText(withdrawn.vuln_id).length).toBeGreaterThan(0);
    expect(screen.getAllByText(withdrawn.asset_id).length).toBeGreaterThan(0);
    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getByText("First found")).toBeInTheDocument();
    expect(screen.getByText("Last found")).toBeInTheDocument();

    // Ownership
    for (const label of [
      "Owner",
      "Assigned at",
      "Assigned by",
      "Latest note",
      "Times reopened",
      "Reopened at",
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }

    // Deadline, verification, exception
    for (const label of [
      "Due",
      "Position",
      "Basis",
      "Unit",
      "Verified at",
      "Verified by scan",
      "Reason",
      "Accepted by",
      "Accepted at",
      "Expires",
      "Indefinite",
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("keeps the detection status beside the workflow state, not merged", async () => {
    mountWith(withdrawn);
    await screen.findByText("Detection");
    // `status` is "open" (detection) and `remediation.state` is "open"
    // (workflow) — the same word for two different facts, so both are shown.
    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getAllByText("Open").length).toBeGreaterThan(0);
  });
});

describe("a withdrawn acceptance is history, not a live exception", () => {
  it("labels it as withdrawn and says the record is kept deliberately", async () => {
    expect(withdrawn.remediation.state).toBe("open");
    expect(withdrawn.exception.reason).toBeTruthy();

    mountWith(withdrawn);
    await screen.findByText("Accepted risk (withdrawn)");
    expect(screen.getByText(/no longer in force/i)).toBeInTheDocument();
    expect(screen.queryByText(/^Accepted risk$/)).toBeNull();
  });

  it("offers Accept risk rather than Withdraw on such a finding", async () => {
    mountWith(withdrawn, history.events, { canAcceptRisk: true });
    await screen.findByText("Remediation actions");
    expect(
      screen.getByRole("button", { name: /accept risk/i }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /withdraw/i })).toBeNull();
  });

  it("offers Withdraw on a finding whose acceptance is in force", async () => {
    expect(accepted.remediation.state).toBe("risk_accepted");
    mountWith(accepted, history.events, { canAcceptRisk: true });
    await screen.findByText("Accepted risk");
    expect(
      screen.getByRole("button", { name: /withdraw acceptance/i }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^accept risk$/i })).toBeNull();
  });
});

describe("the states a person may ask for", () => {
  it("offers only the four the backend's human table can reach", async () => {
    mountWith(withdrawn, history.events, { canUpdate: true });
    await screen.findByText("Remediation actions");

    const select = screen.getByLabelText("Move to");
    const values = [...select.querySelectorAll("option")]
      .map((o) => o.value)
      .filter(Boolean);

    expect(values).toContain("in_remediation");
    expect(values).toContain("pending_verification");
    expect(values).toContain("assigned");
    expect(values).not.toContain("verified_fixed");
    expect(values).not.toContain("reopened");
    expect(values).not.toContain("risk_accepted");
    // The state it is already in is not offered either.
    expect(values).not.toContain("open");
  });

  it("names the three it cannot offer, with the reason", async () => {
    mountWith(withdrawn, history.events, { canUpdate: true });
    await screen.findByText("Remediation actions");

    expect(screen.getByText("Verified fixed")).toBeInTheDocument();
    expect(screen.getByText("Reopened")).toBeInTheDocument();
    // "Risk accepted" is also an event label in the trail below, so this
    // asserts presence rather than uniqueness.
    expect(screen.getAllByText("Risk accepted").length).toBeGreaterThan(0);
    expect(
      screen.getByText(/A scan establishes this, not a person/),
    ).toBeInTheDocument();
  });

  it("says a scan is what makes a finding verified", async () => {
    mountWith(withdrawn);
    await screen.findByText("Verification");
    expect(
      screen.getByText(/stops detecting it. No action on this screen/i),
    ).toBeInTheDocument();
  });
});

describe("permissions decide which controls exist", () => {
  it("shows no actions at all to a reader", async () => {
    mountWith(withdrawn);
    await screen.findByText("Detection");
    expect(screen.queryByText("Remediation actions")).toBeNull();
    expect(screen.queryByLabelText("Move to")).toBeNull();
  });

  it("separates findings:update from findings:accept_risk", async () => {
    mountWith(withdrawn, history.events, { canUpdate: true });
    await screen.findByText("Remediation actions");
    expect(screen.getByLabelText("Move to")).toBeInTheDocument();
    // Accepting a risk is a different authorisation and is absent without it.
    expect(screen.queryByRole("button", { name: /accept risk/i })).toBeNull();
  });
});

describe("what the API refuses is what the operator is told", () => {
  it("shows the backend's own sentence rather than 'failed'", async () => {
    mountWith(withdrawn, history.events, { canUpdate: true });
    await screen.findByText("Remediation actions");

    api.patch.mockRejectedValue({
      response: {
        data: {
          message:
            "A finding cannot be marked verified fixed by hand. It becomes verified when a subsequent scan stops detecting it.",
        },
      },
    });

    const user = userEvent.setup();
    await user.selectOptions(
      screen.getByLabelText("Move to"),
      "in_remediation",
    );
    await user.click(screen.getByRole("button", { name: /change state/i }));

    await waitFor(() =>
      expect(
        screen.getByText(/cannot be marked verified fixed by hand/i),
      ).toBeInTheDocument(),
    );
  });
});

describe("the event trail", () => {
  it("renders every event in the order the API returned it", async () => {
    mountWith(withdrawn);
    await screen.findByText("History");

    const items = document.querySelectorAll(".rm-timeline__item");
    expect(items.length).toBe(history.events.length);
    // Not re-sorted here: the API orders by occurred_at then id, and the id
    // carries a random tail, so re-deriving an order would be this UI
    // inventing a sequence.
    expect(items[0].textContent).toContain("SLA set");
  });

  it("tells a system event from a person's decision", async () => {
    mountWith(withdrawn);
    await screen.findByText("History");
    // `actor_label` is set on a system event and `actor_id` on a human one;
    // exactly one of the two is ever present.
    expect(screen.getByText("system:sla")).toBeInTheDocument();
  });

  it("shows the transition each state change recorded", async () => {
    mountWith(withdrawn);
    await screen.findByText("History");
    expect(
      screen.getAllByText(/Assigned → In remediation/).length,
    ).toBeGreaterThan(0);
  });

  it("says so when a finding has no events rather than rendering nothing", async () => {
    mountWith(withdrawn, []);
    await screen.findByText("History");
    expect(
      screen.getByText(/No remediation events recorded/i),
    ).toBeInTheDocument();
  });
});

describe("failure", () => {
  it("surfaces a read failure rather than an empty record", async () => {
    api.get.mockRejectedValue({
      response: { status: 404, data: { message: "Finding not found." } },
    });
    render(<FindingRemediationPanel findingId="nope" />);
    await waitFor(() =>
      expect(screen.getByText("Finding not found.")).toBeInTheDocument(),
    );
  });
});
