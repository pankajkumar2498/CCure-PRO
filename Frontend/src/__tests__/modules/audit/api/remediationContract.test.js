/**
 * The remediation contract, asserted against payloads captured verbatim from
 * the running API.
 *
 * Two of these assertions exist because the live API disagreed with what the
 * obvious implementation would assume:
 *
 * * withdrawing an acceptance leaves `reason`, `accepted_by` and `accepted_at`
 *   on the finding, so a UI testing "is there a reason" labels an open finding
 *   as an accepted risk;
 * * `sla.days_remaining` keeps counting while a risk is accepted, so a UI
 *   reading the number rather than the state reports a deadline on a finding
 *   that has none.
 */

import { describe, it, expect } from "vitest";

import withdrawn from "../../../fixtures/remediationFindingWithdrawn.real.json";
import accepted from "../../../fixtures/remediationFindingAccepted.real.json";
import summary from "../../../fixtures/remediationSummary.real.json";
import {
  HUMAN_UNREACHABLE_STATES,
  REMEDIATION_STATES,
  REQUESTABLE_STATES,
  SLA_LABELS,
  STATE_LABELS,
  dueDescription,
  hadRiskAccepted,
  isRiskAccepted,
  remediationErrorMessage,
} from "@audit/api/remediation";

describe("the state vocabulary matches the backend's", () => {
  it("names every state the API can return, and labels each one", () => {
    // Read from a live summary rather than transcribed.
    expect(Object.keys(summary.by_state).sort()).toEqual(
      [...REMEDIATION_STATES].sort(),
    );
    for (const s of REMEDIATION_STATES) {
      expect(STATE_LABELS[s]).toBeTruthy();
    }
  });

  it("labels every SLA position the API declares", () => {
    for (const s of summary.sla_states) expect(SLA_LABELS[s]).toBeTruthy();
  });

  it("offers exactly the four states a person may request", () => {
    expect(REQUESTABLE_STATES).toEqual([
      "open",
      "assigned",
      "in_remediation",
      "pending_verification",
    ]);
  });

  it("withholds verified_fixed and reopened, and says why", () => {
    // The two a scan writes. Offering either produces a 400 and nothing else.
    expect(REQUESTABLE_STATES).not.toContain("verified_fixed");
    expect(REQUESTABLE_STATES).not.toContain("reopened");
    expect(HUMAN_UNREACHABLE_STATES.verified_fixed).toMatch(/scan/i);
    expect(HUMAN_UNREACHABLE_STATES.reopened).toMatch(/scan/i);
  });

  it("withholds risk_accepted for its own reason, not the same one", () => {
    expect(REQUESTABLE_STATES).not.toContain("risk_accepted");
    expect(HUMAN_UNREACHABLE_STATES.risk_accepted).toMatch(
      /reason|permission/i,
    );
  });

  it("gives every unreachable state a reason", () => {
    for (const [state, why] of Object.entries(HUMAN_UNREACHABLE_STATES)) {
      expect(REMEDIATION_STATES).toContain(state);
      expect(String(why).length).toBeGreaterThan(20);
    }
  });
});

describe("an acceptance is read from the state, never from the residue", () => {
  it("reports an accepted finding as accepted", () => {
    expect(accepted.remediation.state).toBe("risk_accepted");
    expect(isRiskAccepted(accepted)).toBe(true);
    expect(hadRiskAccepted(accepted)).toBe(false);
  });

  it("does not report a withdrawn acceptance as a live one", () => {
    // The fixture is the live API's answer after a withdrawal: the state
    // moved on and all three exception fields stayed.
    expect(withdrawn.remediation.state).toBe("open");
    expect(withdrawn.exception.reason).toBeTruthy();
    expect(withdrawn.exception.accepted_by).toBeTruthy();
    expect(withdrawn.exception.accepted_at).toBeTruthy();

    expect(isRiskAccepted(withdrawn)).toBe(false);
    expect(hadRiskAccepted(withdrawn)).toBe(true);
  });

  it("is false for a finding that was never accepted", () => {
    expect(isRiskAccepted({ remediation: { state: "open" } })).toBe(false);
    expect(hadRiskAccepted({ remediation: { state: "open" } })).toBe(false);
  });
});

describe("dueDescription", () => {
  it("says no deadline applies rather than leaving a blank", () => {
    expect(dueDescription({ state: "not_applicable", due_at: null })).toBe(
      "No deadline applies",
    );
  });

  it("counts a negative days_remaining as overdue, in the stated unit", () => {
    expect(
      dueDescription({
        state: "overdue",
        due_at: "2026-09-16T00:00:00Z",
        days_remaining: -7,
        unit: "calendar days",
      }),
    ).toBe("7 calendar days overdue");
  });

  it("reads the remaining days for a finding inside its deadline", () => {
    expect(
      dueDescription({
        state: "within_sla",
        due_at: "2026-10-02T00:00:00Z",
        days_remaining: 9,
        unit: "calendar days",
      }),
    ).toBe("9 calendar days remaining");
  });

  it("says today rather than zero days", () => {
    expect(
      dueDescription({ state: "due_soon", due_at: "x", days_remaining: 0 }),
    ).toBe("Due today");
  });
});

describe("remediationErrorMessage", () => {
  it("prefers the backend's own sentence", () => {
    expect(
      remediationErrorMessage(
        {
          response: {
            data: {
              message: "A finding cannot be marked verified fixed by hand.",
            },
          },
        },
        "fallback",
      ),
    ).toMatch(/cannot be marked verified fixed/);
  });

  it("strips Pydantic's own prefix from a field error", () => {
    expect(
      remediationErrorMessage(
        {
          response: {
            data: {
              errors: [
                { loc: ["body", "state"], msg: "Value error, state must be…" },
              ],
            },
          },
        },
        "fallback",
      ),
    ).toBe("state must be…");
  });

  it("falls back only when the response says nothing", () => {
    expect(remediationErrorMessage({}, "fallback")).toBe("fallback");
  });
});
