/**
 * Scan policy management.
 *
 * Ten of the eleven operations live here (the eleventh, the per-scan snapshot,
 * has its own component and test). What these defend is mostly the difference
 * between two operations that look alike and are not, and the four RBAC atoms
 * the backend keeps separate.
 *
 * * **Versioning is not editing.** An edit changes what schedules pointing at
 *   the policy will assess next; a version supersedes and archives, leaving
 *   the old row for the scans that cite it. Sending one for the other silently
 *   rewrites history or silently fails to.
 *
 * * **`is_usable` is the backend's.** Recomputing "active and enabled" here
 *   would be a second rule that agrees until it does not.
 *
 * * **The vocabulary is fetched.** A hardcoded list omits a check family the
 *   backend added and offers one it removed.
 *
 * * **delete is org_admin and above.** Measured on the live role grants:
 *   analyst holds create and update but not delete.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ScanPolicies from "@audit/pages/scan/ScanPolicies";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

let currentUser = { id: "u1", role: { name: "superadmin" } };
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

/** The live /settings payload, verbatim. */
const SETTINGS = {
  scan_kinds: ["network", "credentialed", "any"],
  statuses: ["draft", "active", "archived"],
  config_keys: [
    "allow_intrusive",
    "check_families",
    "framework_ids",
    "include_builtin_checks",
    "min_severity",
  ],
  check_families: ["network_service", "host_configuration", "container"],
  severities: ["info", "low", "medium", "high", "critical"],
};

function policy(overrides = {}) {
  return {
    id: "spol_1",
    org_id: "org_default",
    name: "Ubuntu 24.04 STIG, medium and above",
    description: "Validation policy.",
    policy_family_code: "rt_export_validation",
    version_number: 1,
    scan_kind: "credentialed",
    status: "archived",
    is_enabled: false,
    is_usable: false,
    superseded_by_policy_id: null,
    use_count: 2,
    config: { min_severity: "medium", include_builtin_checks: true },
    fingerprint: "4bd5a15f949b36e2",
    summary: { Policy: "Ubuntu 24.04 STIG, medium and above" },
    schedule_count: 0,
    ...overrides,
  };
}

function wire({
  policies = [policy()],
  usage = { use_count: 2, scan_count: 2, schedules: [] },
} = {}) {
  api.get.mockImplementation((url) => {
    if (url.endsWith("/settings")) return Promise.resolve({ data: SETTINGS });
    if (url.includes("/usage")) return Promise.resolve({ data: usage });
    if (url === "/scan-policies")
      return Promise.resolve({ data: { policies, total: policies.length } });
    return Promise.resolve({ data: {} });
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  currentUser = { id: "u1", role: { name: "superadmin" } };
});

const open = async () => {
  render(<ScanPolicies />);
  await screen.findByText("Ubuntu 24.04 STIG, medium and above");
};

describe("ScanPolicies — listing", () => {
  it("builds its filters from the API's vocabulary", async () => {
    wire();
    await open();

    const kind = screen.getByLabelText("Scan kind");
    const values = [...kind.querySelectorAll("option")].map((o) => o.value);
    expect(values).toEqual(["", ...SETTINGS.scan_kinds]);
  });

  it("shows the backend's is_usable rather than recomputing it", async () => {
    wire({
      policies: [
        policy({
          id: "a",
          name: "A",
          status: "active",
          is_enabled: true,
          is_usable: true,
        }),
        // Deliberately inconsistent: active+enabled but the API says not
        // usable. The table must report what the API said.
        policy({
          id: "b",
          name: "B",
          status: "active",
          is_enabled: true,
          is_usable: false,
        }),
      ],
    });
    render(<ScanPolicies />);
    await screen.findByText("A");

    const rowB = screen.getByText("B").closest("tr");
    expect(within(rowB).queryByText("yes")).toBeNull();
  });

  it("filters server-side, not in the browser", async () => {
    wire();
    const user = userEvent.setup();
    await open();

    api.get.mockClear();
    await user.selectOptions(screen.getByLabelText("Status"), "active");
    await waitFor(() => {
      const call = api.get.mock.calls.find((c) => c[0] === "/scan-policies");
      expect(call[1].params.status).toBe("active");
    });
  });

  it("asks for usable-only when requested", async () => {
    wire();
    const user = userEvent.setup();
    await open();

    api.get.mockClear();
    await user.click(
      screen.getByRole("checkbox", { name: /a scan may use now/i }),
    );
    await waitFor(() => {
      const call = api.get.mock.calls.find((c) => c[0] === "/scan-policies");
      expect(call[1].params.usable_only).toBe(true);
    });
  });
});

describe("ScanPolicies — detail and usage", () => {
  it("loads usage when a policy is opened", async () => {
    wire();
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "Open" }));
    await waitFor(() =>
      expect(
        api.get.mock.calls.some((c) => String(c[0]).includes("/usage")),
      ).toBe(true),
    );
    expect(screen.getByText("Schedules")).toBeInTheDocument();
  });

  it("names what supersedes a policy when it has been versioned", async () => {
    wire({ policies: [policy({ superseded_by_policy_id: "spol_2" })] });
    const user = userEvent.setup();
    await open();
    await user.click(screen.getByRole("button", { name: "Open" }));
    expect(screen.getByText("spol_2")).toBeInTheDocument();
  });
});

describe("ScanPolicies — create, validate, edit, version", () => {
  it("validates a configuration without saving it", async () => {
    wire();
    api.post.mockResolvedValue({
      data: {
        valid: false,
        errors: [
          "a policy that excludes the built-in checks must name at least one framework",
        ],
        warnings: [],
      },
    });
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "New policy" }));
    await user.click(
      screen.getByRole("button", { name: "Check configuration" }),
    );

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        "/scan-policies/validate",
        expect.objectContaining({ scan_kind: "any" }),
      ),
    );
    // The backend's own wording, which explains the consequence.
    expect(
      await screen.findByText(/must name at least one framework/),
    ).toBeInTheDocument();
  });

  it("refuses to offer 'archived' as an initial status", async () => {
    // The API rejects it at creation: a policy created already retired is a
    // mistake every time.
    wire();
    const user = userEvent.setup();
    await open();
    await user.click(screen.getByRole("button", { name: "New policy" }));

    const status = screen.getByLabelText("Initial status");
    const values = [...status.querySelectorAll("option")].map((o) => o.value);
    expect(values).toEqual(["draft", "active"]);
  });

  it("puts a 422's field message on the field it belongs to", async () => {
    wire();
    api.post.mockRejectedValue({
      response: {
        status: 422,
        data: {
          message: "Request validation failed.",
          errors: [
            {
              loc: ["body", "name"],
              msg: "Value error, name must not be blank",
            },
          ],
        },
      },
    });
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "New policy" }));
    await user.click(screen.getByRole("button", { name: "Create policy" }));

    // "Value error, " is Pydantic's prefix and is stripped.
    expect(
      await screen.findByText("name must not be blank"),
    ).toBeInTheDocument();
  });

  it("sends a version to the version endpoint, not as an edit", async () => {
    wire();
    api.post.mockResolvedValue({
      data: policy({ id: "spol_2", version_number: 2 }),
    });
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.click(screen.getByRole("button", { name: "New version" }));
    expect(
      screen.getByText(/This supersedes, it does not edit/),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Create version" }));
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        "/scan-policies/spol_1/version",
        expect.objectContaining({ activate: true }),
      ),
    );
    expect(api.patch).not.toHaveBeenCalled();
  });

  it("sends an edit to PATCH, not as a version", async () => {
    wire();
    api.patch.mockResolvedValue({ data: policy() });
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(api.patch).toHaveBeenCalledWith(
        "/scan-policies/spol_1",
        expect.objectContaining({ name: expect.any(String) }),
      ),
    );
  });
});

describe("ScanPolicies — lifecycle controls", () => {
  it("toggles enablement through its own endpoint", async () => {
    wire();
    api.post.mockResolvedValue({ data: policy({ is_enabled: true }) });
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.click(screen.getByRole("button", { name: "Enable" }));

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith("/scan-policies/spol_1/enable", {
        is_enabled: true,
      }),
    );
  });

  it("offers every status except the one it already has", async () => {
    wire();
    const user = userEvent.setup();
    await open();
    await user.click(screen.getByRole("button", { name: "Open" }));

    expect(screen.getByRole("button", { name: "Mark draft" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Mark active" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Mark archived" })).toBeNull();
  });
});

describe("ScanPolicies — deletion", () => {
  it("keeps the 409 visible so force is a deliberate choice", async () => {
    wire();
    api.delete.mockRejectedValue({
      response: {
        status: 409,
        data: {
          message: "2 schedule(s) reference this policy: Nightly, Weekly.",
        },
      },
    });
    const user = userEvent.setup();
    await open();

    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByText(/Completed scans are unaffected/);
    const panel = dialog.closest("div");
    await user.click(within(panel).getByRole("button", { name: /^Delete$/ }));

    expect(
      await screen.findByText(/2 schedule\(s\) reference this policy/),
    ).toBeInTheDocument();
    // The dialog stays open with force still available.
    expect(
      screen.getByRole("checkbox", { name: /Delete anyway/ }),
    ).toBeTruthy();
  });

  it("says completed scans are unaffected", async () => {
    wire();
    const user = userEvent.setup();
    await open();
    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(
      screen.getByText(/Completed scans are unaffected/),
    ).toBeInTheDocument();
  });
});

describe("ScanPolicies — RBAC", () => {
  it("refuses the page without scan_policies:read", async () => {
    currentUser = { id: "u1", role: { name: "nobody", permissions: [] } };
    render(<ScanPolicies />);
    expect(
      await screen.findByText(/Scan policies unavailable/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New policy" })).toBeNull();
  });

  it("hides delete from a role that may create and update but not delete", async () => {
    // Measured on the live grants: analyst holds create and update, not delete.
    // `can()` reads user.role.permissions — not a top-level list.
    currentUser = {
      id: "u1",
      role: {
        name: "analyst",
        permissions: [
          { resource: "scan_policies", action: "read" },
          { resource: "scan_policies", action: "create" },
          { resource: "scan_policies", action: "update" },
        ],
      },
    };
    wire();
    const user = userEvent.setup();
    await open();
    await user.click(screen.getByRole("button", { name: "Open" }));

    expect(screen.getByRole("button", { name: "Edit" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "New version" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  });

  it("hides create from a read-only role", async () => {
    currentUser = {
      id: "u1",
      role: {
        name: "viewer",
        permissions: [{ resource: "scan_policies", action: "read" }],
      },
    };
    wire();
    await open();
    expect(screen.queryByRole("button", { name: "New policy" })).toBeNull();
  });
});
