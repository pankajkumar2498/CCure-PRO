/**
 * P2-5 — credentialed assessment fidelity.
 *
 * Four readings the credentialed report carries and the page either dropped or
 * replaced with an assumption. Every fixture value below is the live one.
 *
 *     absent field ≠ negative result
 *     NOT CONFIGURED ≠ FALSE
 *     start type ≠ running state
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CredentialedResults from "../../../pages/scan/CredentialedResults";

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

let location;
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => vi.fn(),
    useLocation: () => location,
  };
});

vi.mock("../../../api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), defaults: { baseURL: "/api" } },
}));

vi.mock("../../../context/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, role: { name: "analyst", permissions: [] } },
  }),
}));

const report = (extra = {}) => ({
  target: "10.180.6.30",
  scan_id: "scn_x",
  cves: [],
  system_info: {
    os_name: "Microsoft Windows 11 Pro",
    os_family: "Windows",
    os_confidence: 100,
    mac_vendor: "",
    hostname: "WS-1",
  },
  access: {
    how: "discovered",
    port: 445,
    source: "credential",
    summary: "SMB on 445/tcp [credential]",
    use_tls: null,
    transport: "smb",
    considered: [{ reason: "445/tcp", resolved: true, transport: "smb" }],
  },
  coverage: {
    timing_template: "Not applicable — no network probing performed",
  },
  running_services: [
    { name: "AdobeARMservice", start_type: "Auto", description: "Updater" },
  ],
  ...extra,
});

const mountWith = (result) => {
  location = { pathname: "/scan/credentialed", search: "", state: { result } };
  return render(<CredentialedResults />);
};

beforeEach(() => vi.clearAllMocks());

describe("system information fidelity", () => {
  it("shows the OS family and confidence the collector recorded", async () => {
    mountWith(report());
    await screen.findByText("System Information");
    expect(screen.getByText("OS Family")).toBeInTheDocument();
    expect(screen.getByText("Windows")).toBeInTheDocument();
    // A number here, a word on the discovery phases. Printed as it came.
    expect(screen.getByText("100")).toBeInTheDocument();
  });

  it("says a MAC vendor that did not resolve is not resolved", async () => {
    // The live payload sends `""`, which is not a vendor called "".
    mountWith(report());
    await screen.findByText("System Information");
    expect(screen.getByText("not resolved")).toBeInTheDocument();
  });

  it("says an absent OS confidence is not reported, never 0", async () => {
    mountWith(
      report({
        system_info: { os_name: "Ubuntu", hostname: "h", os_confidence: null },
      }),
    );
    await screen.findByText("System Information");
    expect(screen.getAllByText("not reported").length).toBeGreaterThan(0);
    // Scoped: "0" appears in unrelated counters elsewhere on the page.
    const label = screen.getByText("OS Confidence");
    expect(label.parentElement.textContent).toMatch(/not reported/);
    expect(label.parentElement.textContent).not.toMatch(/\b0\b/);
  });
});

describe("use_tls is three-valued", () => {
  it("reports an unrecorded TLS state as unrecorded, not as no", async () => {
    // The live payload carries `use_tls: null` — 5985 and 5986 are settled by
    // convention and nothing else is, so a guess would be an assertion.
    mountWith(report());
    expect(await screen.findByText(/TLS: not recorded/)).toBeInTheDocument();
    // Anchored: "TLS: no" is a prefix of "TLS: not recorded".
    expect(screen.queryByText(/^TLS: no$/)).toBeNull();
  });

  it("reports a recorded true as yes", async () => {
    mountWith(report({ access: { ...report().access, use_tls: true } }));
    expect(await screen.findByText(/TLS: yes/)).toBeInTheDocument();
  });

  it("reports a recorded false as no, distinct from unrecorded", async () => {
    mountWith(report({ access: { ...report().access, use_tls: false } }));
    expect(await screen.findByText(/^TLS: no$/)).toBeInTheDocument();
    expect(screen.queryByText(/TLS: not recorded/)).toBeNull();
  });
});

describe("running services", () => {
  const openServices = async () => {
    const toggle = await screen.findByRole("button", {
      name: /Running Services/i,
    });
    await userEvent.setup().click(toggle);
  };

  it("does not print a running state the transport never reported", async () => {
    // `svc.sub_state || "running"` printed "running" for all 174 services on
    // the live Windows host, a state nothing established.
    mountWith(report());
    await openServices();
    expect(screen.getByText("not reported")).toBeInTheDocument();
    expect(screen.queryByText("running")).toBeNull();
  });

  it("shows the start type without calling it a running state", async () => {
    mountWith(report());
    await openServices();
    const cell = screen.getByText("Auto");
    expect(cell).toBeInTheDocument();
    expect(cell).toHaveAttribute(
      "title",
      expect.stringMatching(/does not say whether the service is running/i),
    );
    expect(
      screen.getByRole("columnheader", { name: "Start type" }),
    ).toBeInTheDocument();
  });

  it("renders a reported sub_state when the transport gives one", async () => {
    mountWith(
      report({
        running_services: [
          { name: "sshd", sub_state: "running", description: "d" },
        ],
      }),
    );
    await openServices();
    expect(screen.getByText("running")).toBeInTheDocument();
    expect(screen.queryByText("not reported")).toBeNull();
  });
});

describe("assessment coverage", () => {
  it("shows the timing template the report carried", async () => {
    mountWith(report());
    const toggle = await screen.findByRole("button", {
      name: /Assessment coverage — what this scan examined/i,
    });
    await userEvent.setup().click(toggle);
    expect(
      await screen.findByText("Not applicable — no network probing performed"),
    ).toBeInTheDocument();
  });
});
