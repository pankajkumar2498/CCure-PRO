/**
 * A vulnerability audit run with credentials, read on the credentialed page.
 *
 * The pipeline stores a host's posture in `credentialed_report` and its
 * findings beside it on the host record; the package list and the per-item
 * security lists are not stored at all. The page defaulted every absent field,
 * so scan #17 (13 Oct 2026, 2,287 findings, 3,677 suppressed) rendered as
 * "0 CVEs", "Installed Software (0)", "Suppressed Findings (0)", "SUID
 * Binaries 0 found" and "NOPASSWD Sudo: No".
 *
 *     UNKNOWN ≠ ZERO      NO DATA ≠ EMPTY RESULT      UNASSESSED ≠ PASS
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

import api from "@shell/api/axiosInstance";
import CredentialedResults from "@audit/pages/scan/CredentialedResults";

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

const navigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => ({
      pathname: "/scan/credentialed/results",
      search: "?scan_id=scn_17",
      state: null,
    }),
  };
});

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, role: { name: "analyst" }, permissionKeys: [] },
  }),
}));

const finding = (id, severity) => ({
  cve_id: id,
  cve: id,
  severity,
  cvss_score: severity === "High" ? 7.5 : 5.0,
  description: `${id} description`,
  package: "openssl",
  installed_ver: "3.0.13-0ubuntu3.5",
  fixed_ver: "3.0.13-0ubuntu3.6",
});

/* The shape GET /scans/{id} returns for a pipeline audit with credentials,
   reduced to what the page reads. Keys the pipeline does not store are left
   out on purpose. */
const SCAN = {
  id: "scn_17",
  scan_no: 17,
  status: "complete",
  results: {
    phase3: {
      data: [
        {
          ip_address: "10.180.6.45",
          credentialed: true,
          cves: [
            finding("CVE-2026-0001", "High"),
            finding("CVE-2026-0002", "Medium"),
          ],
          suppressed_cves: [
            {
              identifier: "CVE-2019-9193",
              host: "10.180.6.45",
              reason:
                "Ruled out: the version detected on this host falls outside the range.",
            },
          ],
          vulnerability_counts: { High: 1, Medium: 1, Unscored: 0 },
          credentialed_report: {
            target: "10.180.6.45",
            system_info: {
              os_name: "Ubuntu 24.04.5 LTS",
              kernel_version: "6.8.0-146-generic",
            },
            package_count: 2943,
            package_coverage: { packages_collected: 2699, coverage_pct: 99.7 },
            security_issues: [
              "50 SUID binaries found — review for privilege escalation risk",
            ],
          },
        },
      ],
    },
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  api.get.mockResolvedValue({ data: SCAN });
});

describe("a pipeline audit's credentialed view", () => {
  it("counts the host's findings, not an absent list", async () => {
    render(<CredentialedResults />);
    await screen.findByText("Suppressed Findings (1)");
    const summary = screen.getByText(/CVEs?$/, { selector: "li" });
    expect(summary).toHaveTextContent("2 CVEs");
    expect(screen.getByText("CVE Findings (2)")).toBeInTheDocument();
  });

  it("shows the host's suppressed candidates", async () => {
    render(<CredentialedResults />);
    expect(
      await screen.findByText("Suppressed Findings (1)"),
    ).toBeInTheDocument();
  });

  it("says the package list was enumerated but not stored, never (0)", async () => {
    render(<CredentialedResults />);
    expect(
      await screen.findByText(
        "Installed Software (2,943 enumerated, not stored)",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Installed Software (0)"),
    ).not.toBeInTheDocument();
  });

  it("marks security fields the scan did not record as not recorded", async () => {
    render(<CredentialedResults />);
    await screen.findByText("Suppressed Findings (1)");
    // NOPASSWD Sudo, SUID Binaries, World-Writable Dirs, Failed Logins.
    expect(screen.getAllByText("Not recorded for this scan")).toHaveLength(4);
    expect(screen.queryByText("0 found")).not.toBeInTheDocument();
  });
});
