/**
 * P0-4 — what a transport could not collect is stated, not implied.
 *
 * The credentialed report records an unserved item under an `item:` prefix in
 * `collection_errors`. CLAUDE.md is explicit that they are recorded there
 * "rather than left to look like an empty reading from the host" — but nothing
 * surfaced them per section, so a host whose password policy was never
 * collected rendered exactly like a host with no password-policy finding.
 *
 *     UNASSESSED ≠ PASS
 *     NO DATA    ≠ EMPTY RESULT
 *
 * Also covers `exposure_summary.listeners_undetermined`, which was dropped
 * while exposed, filtered and host-only were all shown: `UNKNOWN ≠ ZERO`.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CredentialedResults from "../../../pages/scan/CredentialedResults";

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

const navigate = vi.fn();
let location;
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => location,
  };
});

vi.mock("../../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../../context/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, role: { name: "analyst", permissions: [] } },
  }),
}));

/* The live `collection_errors` shape: an `item:` prefix and the scanner's own
   sentence as the value. */
const COLLECTION_ERRORS = {
  "item:password_policy": "not served by the SMB transport",
  "item:firewall": "Remote Registry did not answer",
  "item:open_ports": "netstat is not available over this transport",
  "item:scheduled_tasks": "insufficient privilege for the task store",
  // An item with no entry in the section map must still be reported.
  "item:some_future_item": "a reason for something this build cannot place",
  // A non-item error is a different thing and must not be swept in.
  password_policy: "an ordinary section error, not an unserved item",
};

const report = (extra = {}) => ({
  target: "10.180.6.14",
  scan_id: "scn_x",
  system_info: { os_name: "Windows 11", hostname: "WS-1" },
  cves: [],
  collection_errors: COLLECTION_ERRORS,
  ...extra,
});

const mountWith = (result) => {
  location = { pathname: "/scan/credentialed", search: "", state: { result } };
  return render(<CredentialedResults />);
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("items the transport could not collect", () => {
  it("names each one against the section a reader would look in", async () => {
    mountWith(report());
    await screen.findByText(/Not assessed \(5\)/);

    const table = screen.getByRole("table", {
      name: /could not collect/i,
    });
    for (const section of [
      "Password Policy",
      "Firewall",
      "Listening Sockets",
      "Scheduled Tasks",
    ]) {
      expect(within(table).getByText(section)).toBeInTheDocument();
    }
  });

  it("shows the backend's own reason verbatim", async () => {
    mountWith(report());
    await screen.findByText(/Not assessed \(5\)/);
    expect(
      screen.getByText("not served by the SMB transport"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Remote Registry did not answer"),
    ).toBeInTheDocument();
  });

  it("marks the state as Not assessed, never as a pass or a zero", async () => {
    mountWith(report());
    const table = await screen.findByRole("table", {
      name: /could not collect/i,
    });
    // One badge per row, and the word is the carrier of the meaning.
    expect(within(table).getAllByText("Not assessed")).toHaveLength(5);
  });

  it("says in words that these are not findings-free sections", async () => {
    mountWith(report());
    await screen.findByText(/Not assessed \(5\)/);
    expect(
      screen.getByText(/not.*findings-free sections/i),
    ).toBeInTheDocument();
  });

  it("still reports an item it cannot place under a known section", async () => {
    mountWith(report());
    const table = await screen.findByRole("table", {
      name: /could not collect/i,
    });
    // Unmapped, so it falls back to its own key rather than disappearing.
    expect(within(table).getByText("some future item")).toBeInTheDocument();
  });

  it("does not sweep in a non-item collection error", async () => {
    mountWith(report());
    const table = await screen.findByRole("table", {
      name: /could not collect/i,
    });
    expect(
      within(table).queryByText(
        "an ordinary section error, not an unserved item",
      ),
    ).toBeNull();
  });

  it("renders no section at all when everything was collected", async () => {
    mountWith(report({ collection_errors: {} }));
    await screen.findByText("System Information");
    expect(screen.queryByText(/Not assessed \(/)).toBeNull();
  });
});

describe("undetermined listeners", () => {
  const withExposure = (exposure) =>
    report({
      open_ports_credentialed: [
        { port: 22, protocol: "tcp", process: "sshd", state: "LISTEN" },
      ],
      exposure_summary: {
        correlated_with_port_scan: true,
        listeners_exposed: 1,
        listeners_filtered: 2,
        listeners_host_only: 3,
        ...exposure,
      },
    });

  /* The sockets section is collapsed until asked for, as every evidence
     section on this page is. */
  const openSockets = async () => {
    const toggle = await screen.findByRole("button", {
      name: /Listening sockets/i,
    });
    await userEvent.setup().click(toggle);
  };

  it("is shown as its own figure beside exposed and host-only", async () => {
    mountWith(withExposure({ listeners_undetermined: 4 }));
    await openSockets();
    expect(await screen.findByText(/4 undetermined/)).toBeInTheDocument();
    expect(screen.getByText(/1 exposed/)).toBeInTheDocument();
    expect(screen.getByText(/3 host-only/)).toBeInTheDocument();
  });

  it("is absent rather than zero when the API did not send it", async () => {
    // An older payload has no such figure. Printing 0 would assert that none
    // was undetermined, which nothing established.
    mountWith(withExposure({}));
    await openSockets();
    await screen.findByText(/1 exposed/);
    expect(screen.queryByText(/undetermined/)).toBeNull();
  });

  it("renders a genuine zero when the API sends one", async () => {
    mountWith(withExposure({ listeners_undetermined: 0 }));
    await openSockets();
    expect(await screen.findByText(/0 undetermined/)).toBeInTheDocument();
  });
});
