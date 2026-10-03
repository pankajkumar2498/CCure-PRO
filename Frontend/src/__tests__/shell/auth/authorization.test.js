import { describe, it, expect } from "vitest";
import {
  can,
  canAny,
  canAll,
  canSwitchOrganisation,
  activeOrganisationId,
  assignmentLabels,
  authorizationOf,
} from "@shell/auth/authorization";
import { canSeeNavItem } from "@shell/auth/navVisibility";

// What the backend sends (`/auth/me` → `authorization`); the UI invents none of it.
const authz = (over = {}) => ({
  contract: 1,
  source: "platform",
  home_org_id: "org_a",
  active_org_id: "org_a",
  permissions: {
    platform: ["platform.organization.switch", "platform.email_domain.read"],
    organization: ["audit.scan.read", "audit.scan.run"],
  },
  can_switch_organisation: true,
  assignments: [
    {
      display_name: "Chief Information Security Officer",
      scope_type: "platform",
    },
  ],
  atoms: {
    "scans:read": ["audit.scan.read"],
    "scans:execute": ["audit.scan.run"],
    "scans:purge": ["audit.scan.purge"],
    "settings:update": [
      "audit.asset.import_amt",
      "audit.remediation.manage_sla",
    ],
  },
  ...over,
});
const userWith = (a, role) => ({
  id: "u1",
  org_id: "org_a",
  role,
  authorization: a,
});

describe("permission-based can()", () => {
  const u = userWith(authz());

  it("answers from the permission keys the backend listed", () => {
    expect(can(u, "audit.scan.read")).toBe(true);
    expect(can(u, "audit.scan.purge")).toBe(false);
    expect(can(u, "platform.email_domain.read")).toBe(true);
  });

  it("resolves legacy atoms through the backend's vocabulary", () => {
    expect(can(u, "scans", "read")).toBe(true);
    expect(can(u, { resource: "scans", action: "execute" })).toBe(true);
    expect(can(u, "scans:purge")).toBe(false);
    expect(can(u, "nonsense", "atom")).toBe(false);
  });

  it("a multi-key atom needs every key", () => {
    expect(can(u, "settings", "update")).toBe(false);
    const both = authz({
      permissions: {
        platform: [],
        organization: [
          "audit.asset.import_amt",
          "audit.remediation.manage_sla",
        ],
      },
    });
    expect(can(userWith(both), "settings", "update")).toBe(true);
  });

  it("never invents a permission: no wildcard, no role, no payload", () => {
    const wildcard = userWith(
      authz({
        permissions: { platform: [], organization: ["audit.scan.manage"] },
      }),
    );
    expect(can(wildcard, "audit.scan.read")).toBe(false);
    expect(
      can(
        userWith(null, { name: "superadmin", permissions: [] }),
        "audit.scan.read",
      ),
    ).toBe(false);
    expect(can(userWith(authz({ contract: 2 })), "audit.scan.read")).toBe(
      false,
    );
    expect(
      can(userWith(authz({ permissions: undefined })), "audit.scan.read"),
    ).toBe(false);
    expect(can(null, "audit.scan.read")).toBe(false);
    expect(can(u, "")).toBe(false);
  });

  it("canAny / canAll", () => {
    expect(canAny(u, ["audit.scan.purge", "audit.scan.read"])).toBe(true);
    expect(canAll(u, ["audit.scan.purge", "audit.scan.read"])).toBe(false);
  });
});

describe("scope-aware", () => {
  const u = userWith(authz());
  it("an organisation key is known for the active organisation only", () => {
    expect(
      can(u, "audit.scan.read", { scope: "organization", orgId: "org_a" }),
    ).toBe(true);
    expect(
      can(u, "audit.scan.read", { scope: "organization", orgId: "org_b" }),
    ).toBe(false);
  });
  it("a platform-scope request is satisfied only by a platform key", () => {
    expect(can(u, "platform.email_domain.read", { scope: "platform" })).toBe(
      true,
    );
    expect(can(u, "audit.scan.read", { scope: "platform" })).toBe(false);
  });
  it("the active organisation is the backend's, not the stored hint", () => {
    localStorage.setItem("activeOrgId", "org_forged");
    expect(activeOrganisationId(u)).toBe("org_a");
    expect(
      can(u, "audit.scan.read", { orgId: localStorage.getItem("activeOrgId") }),
    ).toBe(false);
    localStorage.removeItem("activeOrgId");
  });
  it("switching capability is the backend's flag, never a role", () => {
    expect(canSwitchOrganisation(u)).toBe(true);
    expect(
      canSwitchOrganisation(
        userWith(authz({ can_switch_organisation: false }), {
          name: "superadmin",
        }),
      ),
    ).toBe(false);
    expect(canSwitchOrganisation(userWith(null, { name: "superadmin" }))).toBe(
      false,
    );
  });
});

describe("role display names are presentation only", () => {
  it("renaming Superadmin to CISO changes nothing", () => {
    const before = userWith(authz(), { name: "Superadmin" });
    const after = userWith(authz(), { name: "CISO" });
    for (const k of [
      "audit.scan.read",
      "audit.scan.purge",
      "platform.email_domain.read",
    ]) {
      expect(can(before, k)).toBe(can(after, k));
    }
    expect(canSwitchOrganisation(before)).toBe(canSwitchOrganisation(after));
  });
  it("a role value on the client cannot grant access", () => {
    const viewer = userWith(
      authz({
        permissions: { platform: [], organization: ["audit.scan.read"] },
        can_switch_organisation: false,
      }),
    );
    viewer.role = {
      name: "superadmin",
      permissions: [{ resource: "scans", action: "purge" }],
    };
    expect(can(viewer, "audit.scan.purge")).toBe(false);
    expect(can(viewer, "scans", "purge")).toBe(false);
    expect(canSwitchOrganisation(viewer)).toBe(false);
  });
  it("labels come from assignments, for display", () => {
    expect(assignmentLabels(userWith(authz()))).toEqual([
      "Chief Information Security Officer",
    ]);
  });
});

describe("multiple roles, revoked and retired assignments", () => {
  it("the backend's union is what is shown; a dropped role drops its keys", () => {
    const union = userWith(
      authz({
        permissions: {
          platform: [],
          organization: ["audit.scan.read", "audit.scan.purge"],
        },
      }),
    );
    expect(can(union, "audit.scan.purge")).toBe(true);
    const revoked = userWith(
      authz({
        permissions: { platform: [], organization: ["audit.scan.read"] },
      }),
    );
    expect(can(revoked, "audit.scan.purge")).toBe(false);
  });
});

describe("older backend (no authorization payload)", () => {
  it("honours the listed atoms exactly, with no wildcard and no role rule", () => {
    const old = {
      role: {
        name: "superadmin",
        permissions: [{ resource: "scans", action: "read" }],
      },
    };
    expect(can(old, "scans", "read")).toBe(true);
    expect(can(old, "scans", "purge")).toBe(false); // superadmin is not everything
    expect(can(old, "audit.scan.read")).toBe(false); // keys are never guessed
    const manage = { role: { name: "x", permissions: ["scans:manage"] } };
    expect(can(manage, "scans", "read")).toBe(false); // `:manage` is not a wildcard
  });
});

describe("navigation uses permissions, not roles", () => {
  it("an item naming a platform key is visible only to a holder", () => {
    const item = { permission: "platform.email_domain.read" };
    expect(canSeeNavItem(userWith(authz()), item)).toBe(true);
    expect(
      canSeeNavItem(
        userWith(authz({ permissions: { platform: [], organization: [] } }), {
          name: "superadmin",
        }),
        item,
      ),
    ).toBe(false);
  });
  it("requiredAny passes on one held permission", () => {
    expect(
      canSeeNavItem(userWith(authz()), {
        requiredAny: ["audit.scan.purge", "audit.scan.run"],
      }),
    ).toBe(true);
  });
});

describe("authorizationOf", () => {
  it("rejects an unknown contract version and a non-object", () => {
    expect(authorizationOf({ authorization: "x" })).toBeNull();
    expect(
      authorizationOf({ authorization: authz({ contract: 99 }) }),
    ).toBeNull();
    expect(authorizationOf({ authorization: authz() })).not.toBeNull();
  });
});
