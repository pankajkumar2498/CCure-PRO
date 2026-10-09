import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import UserRolesPanel from "@shell/admin/components/UserRolesPanel";
import * as rbac from "@shell/api/rbac";
import { payload } from "../../../fixtures/authorization";

vi.mock("@shell/api/rbac", async (importOriginal) => ({
  ...(await importOriginal()),
  getUserAssignments: vi.fn(),
  listAssignableRoles: vi.fn(),
  assignRbacRole: vi.fn(),
  revokeRbacAssignment: vi.fn(),
}));

const target = { id: "t1", username: "tess", org_id: "o" };
const admin = (keys) => ({
  id: "a1",
  org_id: "o",
  role: { name: "Org Admin", permissions: [] },
  authorization: payload({ keys, active: "o", home: "o" }),
});

const assignment = (over) => ({
  id: "as1",
  role: {
    id: "viewer",
    display_name: "Viewer",
    kind: "system",
    state: "active",
  },
  scope_type: "organization",
  scope_org_id: "o",
  status: "active",
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  rbac.getUserAssignments.mockResolvedValue({ assignments: [assignment()] });
  rbac.listAssignableRoles.mockResolvedValue({
    roles: [
      { id: "viewer", display_name: "Viewer", assignable: true, reasons: [] },
      { id: "analyst", display_name: "Analyst", assignable: true, reasons: [] },
      {
        id: "boss",
        display_name: "Superadmin",
        assignable: false,
        reasons: ["escalation_ceiling"],
      },
    ],
    delegation: {},
  });
  rbac.assignRbacRole.mockResolvedValue({});
  rbac.revokeRbacAssignment.mockResolvedValue({});
});

describe("UserRolesPanel", () => {
  it("shows each assignment with its display name, kind, scope and status", async () => {
    render(
      <UserRolesPanel
        user={target}
        currentUser={admin(["platform.user.assign_role"])}
      />,
    );
    expect(await screen.findByText("Viewer")).toBeInTheDocument();
    expect(screen.getByText("organisation o")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
  });

  it("offers only the roles the backend marks assignable, and explains the rest", async () => {
    render(
      <UserRolesPanel
        user={target}
        currentUser={admin(["platform.user.assign_role"])}
      />,
    );
    const select = await screen.findByLabelText("Assign a role");
    const options = [...select.querySelectorAll("option")].map(
      (o) => o.textContent,
    );
    expect(options).toEqual(["Choose a role", "Analyst"]); // Viewer is already held
    expect(
      screen.getByText(/Superadmin \(escalation_ceiling\)/),
    ).toBeInTheDocument();
  });

  it("a role called Superadmin is not offered just because of its label — the backend decides", async () => {
    rbac.listAssignableRoles.mockResolvedValue({
      roles: [
        {
          id: "boss",
          display_name: "Superadmin",
          assignable: true,
          reasons: [],
        },
      ],
      delegation: {},
    });
    render(
      <UserRolesPanel
        user={target}
        currentUser={admin(["platform.user.assign_role"])}
      />,
    );
    const select = await screen.findByLabelText("Assign a role");
    expect(
      [...select.querySelectorAll("option")].map((o) => o.textContent),
    ).toContain("Superadmin");
  });

  it("assigns and removes through the API", async () => {
    const u = userEvent.setup();
    render(
      <UserRolesPanel
        user={target}
        currentUser={admin(["platform.user.assign_role"])}
      />,
    );
    await u.selectOptions(
      await screen.findByLabelText("Assign a role"),
      "analyst",
    );
    await u.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() =>
      expect(rbac.assignRbacRole).toHaveBeenCalledWith("t1", "analyst", {}),
    );
    await u.click(
      screen.getByRole("button", { name: "Remove Viewer from tess" }),
    );
    await waitFor(() =>
      expect(rbac.revokeRbacAssignment).toHaveBeenCalledWith("as1", {}),
    );
  });

  it("an account without assign authority sees the roles but no controls", async () => {
    render(<UserRolesPanel user={target} currentUser={admin([])} />);
    await screen.findByText("Viewer");
    expect(screen.queryByLabelText("Assign a role")).toBeNull();
    expect(screen.queryByRole("button", { name: /Remove/ })).toBeNull();
  });

  it("shows the backend's refusal when an escalation is attempted", async () => {
    const u = userEvent.setup();
    rbac.assignRbacRole.mockRejectedValue({
      response: {
        status: 403,
        data: {
          detail: {
            code: "governance_refused",
            violations: [
              {
                code: "self_assignment",
                message: "an account cannot assign its own roles",
              },
            ],
          },
        },
      },
    });
    render(
      <UserRolesPanel
        user={target}
        currentUser={admin(["platform.user.assign_role"])}
      />,
    );
    await u.selectOptions(
      await screen.findByLabelText("Assign a role"),
      "analyst",
    );
    await u.click(screen.getByRole("button", { name: "Assign" }));
    expect(
      await screen.findByText(/cannot assign its own roles/),
    ).toBeInTheDocument();
  });

  it("revoked and expired assignments are shown as history, not removable", async () => {
    rbac.getUserAssignments.mockResolvedValue({
      assignments: [
        assignment({ status: "revoked" }),
        assignment({
          id: "as2",
          status: "expired",
          role: {
            id: "x",
            display_name: "Old",
            kind: "custom",
            state: "retired",
          },
        }),
      ],
    });
    render(
      <UserRolesPanel
        user={target}
        currentUser={admin(["platform.user.assign_role"])}
      />,
    );
    await screen.findByText("Old");
    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.getByText("retired")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Remove/ })).toBeNull();
  });
});
