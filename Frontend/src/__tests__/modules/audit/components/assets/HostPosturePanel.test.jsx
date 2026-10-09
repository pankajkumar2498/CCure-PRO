/**
 * P1-4 — what an authenticated scan established about a host.
 *
 * `AssetDetail` referenced none of this: zero occurrences of
 * `registry_hardening`, `credentialed_status`, `password_policy`,
 * `running_services` and `local_groups`.
 *
 * The fixture is a live `custom_attributes` block, including its measured
 * `firewall_active: false` and `audit_configured: false` — which are findings,
 * not absences, and must not print the same as a key the scan never read.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import HostPosturePanel from "@audit/components/assets/HostPosturePanel";

const LIVE = {
  credentialed_status: "success",
  registry_hardening: {
    uac_enabled: true,
    rdp_disabled: true,
    smbv1_disabled: true,
    firewall_active: false,
    telnet_disabled: true,
    audit_configured: false,
    netbios_disabled: true,
    rdp_nla_enforced: true,
    legacy_tls_disabled: true,
  },
  password_policy: { max_age_days: 99999 },
  credentialed_system_info: {
    detected_os: "linux",
    os_version_id: "24.04",
    synced_at: "2026-09-04T13:55:36.632904+00:00",
    source_scan_id: "scn_defa_c522b539_04sep26_77zr",
    running_services: [],
    local_groups: new Array(45).fill({ name: "g" }),
    suspicious_scheduled_tasks: [],
  },
};

describe("the hardening switches keep three states apart", () => {
  it("shows a measured true as hardened", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    expect(screen.getAllByText("Hardened").length).toBe(7);
  });

  it("shows a measured false as NOT hardened, which is a finding", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    // firewall_active and audit_configured are both false on the live host.
    expect(screen.getAllByText("Not hardened").length).toBe(2);
    expect(screen.getByText("Firewall active")).toBeInTheDocument();
    expect(screen.getByText("Audit policy configured")).toBeInTheDocument();
  });

  it("shows an absent key as not assessed, never as false", () => {
    // CLAUDE.md: "Do not restore a `False` default anywhere on that path:
    // `False` asserts the insecure state, which is the same defect pointing
    // at a FAIL."
    render(
      <HostPosturePanel
        customAttributes={{
          ...LIVE,
          registry_hardening: { uac_enabled: true },
        }}
      />,
    );
    expect(screen.getAllByText("Not assessed").length).toBe(8);
    expect(screen.queryByText("Not hardened")).toBeNull();
  });
});

describe("credentialed_status has three meanings", () => {
  it("reports success as authenticated", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    expect(screen.getByText("Authenticated")).toBeInTheDocument();
  });

  it("reports a refused credential as a failure", () => {
    render(
      <HostPosturePanel
        customAttributes={{ ...LIVE, credentialed_status: "failed" }}
      />,
    );
    expect(screen.getByText("Authentication failed")).toBeInTheDocument();
  });

  it("reports an unset status as not attempted, not as a failure", () => {
    // "No credential was in scope" and "the credential was refused" are
    // different facts, and the backend leaves the first unset on purpose.
    render(
      <HostPosturePanel
        customAttributes={{ ...LIVE, credentialed_status: undefined }}
      />,
    );
    const badge = screen.getByText("Not attempted");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute(
      "title",
      expect.stringMatching(
        /not the same as a credential having been refused/i,
      ),
    );
    expect(screen.queryByText("Authentication failed")).toBeNull();
  });
});

describe("collected inventories", () => {
  it("names the provenance of the whole block", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    expect(
      screen.getByText(/scan scn_defa_c522b539_04sep26_77zr/),
    ).toBeInTheDocument();
  });

  it("tells an empty collection from one that was never collected", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    // running_services is [] — collected and empty.
    expect(screen.getByText("0 collected")).toBeInTheDocument();
    expect(screen.getByText("45 collected")).toBeInTheDocument();

    render(
      <HostPosturePanel
        customAttributes={{
          ...LIVE,
          credentialed_system_info: { detected_os: "linux" },
        }}
      />,
    );
    expect(screen.getAllByText("not collected").length).toBeGreaterThanOrEqual(
      3,
    );
  });

  it("says none found for an empty suspicious-task list", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    expect(screen.getByText("none found")).toBeInTheDocument();
  });

  it("lists suspicious scheduled tasks when there are any", () => {
    render(
      <HostPosturePanel
        customAttributes={{
          ...LIVE,
          credentialed_system_info: {
            ...LIVE.credentialed_system_info,
            suspicious_scheduled_tasks: ["\\Microsoft\\Windows\\Odd task"],
          },
        }}
      />,
    );
    expect(screen.getByText("1 found")).toBeInTheDocument();
    expect(
      screen.getByText("\\Microsoft\\Windows\\Odd task"),
    ).toBeInTheDocument();
  });

  it("renders the password policy the API supplied", () => {
    render(<HostPosturePanel customAttributes={LIVE} />);
    expect(screen.getByText("max age days")).toBeInTheDocument();
    expect(screen.getByText("99999")).toBeInTheDocument();
  });
});

describe("nothing to show", () => {
  it("renders no panel when the asset carries no authenticated data", () => {
    const { container } = render(<HostPosturePanel customAttributes={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});
