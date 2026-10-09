/**
 * The SLA policy form.
 *
 * Three properties, each of which is a number or a permission that does not
 * behave the way the form's appearance suggests.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import policy from "../../../../fixtures/remediationSlaPolicy.real.json";
import SlaPolicyPanel from "@audit/components/remediation/SlaPolicyPanel";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), put: vi.fn() },
}));

beforeEach(() => {
  vi.clearAllMocks();
  api.get.mockResolvedValue({ data: policy });
});

describe("what the policy shows", () => {
  it("builds the fields from the API's own severity list", async () => {
    render(<SlaPolicyPanel />);
    await screen.findByLabelText("Critical");

    // Six, from the payload's `defaults` — not from a copy in the frontend.
    for (const key of Object.keys(policy.defaults)) {
      const label = key.charAt(0).toUpperCase() + key.slice(1);
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    expect(screen.getByLabelText("Critical")).toHaveValue(
      policy.days_by_severity.critical,
    );
  });

  it("says zero means no deadline, not due immediately", async () => {
    render(<SlaPolicyPanel />);
    await screen.findByLabelText("Critical");
    expect(
      screen.getByText(/Zero means no deadline applies/),
    ).toBeInTheDocument();
    // Which is why the two unrated severities ship at zero.
    expect(policy.defaults.none).toBe(0);
    expect(policy.defaults.unscored).toBe(0);
  });

  it("states the unit rather than leaving a reader to assume business days", async () => {
    render(<SlaPolicyPanel />);
    await screen.findByLabelText("Critical");
    expect(screen.getByText("calendar days")).toBeInTheDocument();
  });

  it("says a KEV date only ever tightens the deadline", async () => {
    render(<SlaPolicyPanel />);
    await screen.findByLabelText("Critical");
    expect(screen.getByText(/never where it is later/i)).toBeInTheDocument();
  });
});

describe("permission", () => {
  it("is read-only without settings:update, and names the permission", async () => {
    render(<SlaPolicyPanel canEdit={false} />);
    await screen.findByLabelText("Critical");
    expect(screen.getByLabelText("Critical")).toBeDisabled();
    expect(
      screen.getByText("Manage remediation SLA policy"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /save deadlines/i }),
    ).toBeNull();
  });

  it("is editable with it", async () => {
    render(<SlaPolicyPanel canEdit />);
    await screen.findByLabelText("Critical");
    expect(screen.getByLabelText("Critical")).not.toBeDisabled();
    expect(
      screen.getByRole("button", { name: /save deadlines/i }),
    ).toBeDisabled(); // nothing changed yet
  });
});

describe("saving", () => {
  it("sends only what changed, because the backend merges", async () => {
    api.put.mockResolvedValue({
      data: {
        ...policy,
        note: "Existing findings keep their recorded due dates.",
      },
    });
    render(<SlaPolicyPanel canEdit />);
    await screen.findByLabelText("Critical");

    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Critical"));
    await user.type(screen.getByLabelText("Critical"), "7");
    await user.click(screen.getByRole("button", { name: /save deadlines/i }));

    await waitFor(() => expect(api.put).toHaveBeenCalled());
    const [, body] = api.put.mock.calls[0];
    // Only `critical`. Sending the whole map would overwrite a value somebody
    // else had just set.
    expect(body).toEqual({ days_by_severity: { critical: 7 } });
    expect(body.due_soon_window_days).toBeUndefined();
    expect(body.honour_kev_due_date).toBeUndefined();
  });

  it("renders the backend's note verbatim rather than paraphrasing it", async () => {
    const note =
      "Existing findings keep their recorded due dates; the new policy applies from the next scan that syncs them.";
    api.put.mockResolvedValue({ data: { ...policy, note } });
    render(<SlaPolicyPanel canEdit />);
    await screen.findByLabelText("Critical");

    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("High"));
    await user.type(screen.getByLabelText("High"), "14");
    await user.click(screen.getByRole("button", { name: /save deadlines/i }));

    await waitFor(() => expect(screen.getByText(note)).toBeInTheDocument());
  });

  it("shows the backend's refusal rather than a generic failure", async () => {
    api.put.mockRejectedValue({
      response: {
        data: {
          errors: [
            {
              loc: ["body", "days_by_severity"],
              msg: "Value error, 'urgent' is not a severity this build recognises",
            },
          ],
        },
      },
    });
    render(<SlaPolicyPanel canEdit />);
    await screen.findByLabelText("Critical");

    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Low"));
    await user.type(screen.getByLabelText("Low"), "5");
    await user.click(screen.getByRole("button", { name: /save deadlines/i }));

    await waitFor(() =>
      expect(
        screen.getByText(/is not a severity this build recognises/),
      ).toBeInTheDocument(),
    );
  });
});

describe("failure", () => {
  it("surfaces a read failure rather than an empty form", async () => {
    api.get.mockRejectedValue({
      response: { data: { message: "Forbidden" } },
    });
    render(<SlaPolicyPanel />);
    await waitFor(() =>
      expect(screen.getByText("Forbidden")).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText("Critical")).toBeNull();
  });
});
