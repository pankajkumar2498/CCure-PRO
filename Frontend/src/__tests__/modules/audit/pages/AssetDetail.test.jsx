/**
 * AssetDetail (`/assets/:id`) — Checkpoint 3C batch 11 baseline.
 *
 * Written against the page BEFORE migration. The passing set is the
 * regression gate; the failing set is the migration specification.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Four reads on mount, in parallel, all keyed on the route id:
 *
 *   GET /assets/{id}   GET /assets/{id}/services
 *   GET /assets/{id}/findings   GET /assets/{id}/changelog
 *
 * One read on demand: GET /findings/{id} when a finding row is opened.
 *
 * Five writes, every one behind `assets:update` (via `canPermission`):
 *
 *   PATCH  /assets/{id}                   { is_managed }  — the toggle
 *   PATCH  /assets/{id}                   { owner }       — owner edit
 *   POST   /assets/{id}/tags              { tag }         — then GET /assets/{id}
 *   DELETE /assets/{id}/tags/{encoded}                    — no confirmation
 *   POST   /assets/{id}/notes             { content }     — then GET /assets/{id}
 *   PATCH  /findings/{id}/status          { status, accepted_risk_reason,
 *                                           remediation_notes } — then GET /findings/{id}
 *
 * The finding-status write is the security-sensitive one: `accepted` records a
 * risk acceptance. The page only ever sends it after an explicit two-step
 * (choose action → Confirm), and the tests assert both the exact body and that
 * nothing short of Confirm sends it.
 *
 * Every write handler on this page swallows its error (`catch {}`), so a
 * failed write is indistinguishable from a successful one to the user. That
 * is recorded as a defect in the batch 11 inventory; these tests assert the
 * CURRENT behaviour (no request retried, no crash) and do not assert feedback
 * that does not exist yet.
 *
 * Fixture field names are taken from the page's own reads. `ago()` compares
 * calendar days against the real clock, so relative dates are built from
 * `Date.now()` rather than pinned strings.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AssetDetail from "@audit/pages/AssetDetail";
import axiosInstance from "@shell/api/axiosInstance";
import { keySetHolds } from "../../../fixtures/authorization";
import { personaFrom } from "../../../fixtures/authorization";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const navigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useParams: () => ({ id: "a-1" }),
  };
});

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({
    user: personaFrom({ username: "operator", id: 1, org_id: "o-1" }),
  }),
}));

let permissions = new Set(["audit.asset.update"]);
vi.mock("@shell/auth/permissions", () => ({
  canPermission: (_u, p) => keySetHolds(permissions, p),
  can: (_u, r, a) => keySetHolds(permissions, r, a),
  denyMessage: "You do not have permission to perform this action.",
}));

/* ── Fixtures ─────────────────────────────────────────────────────────────── */
const DAY = 86400000;
const iso = (daysAgo) => new Date(Date.now() - daysAgo * DAY).toISOString();

const ASSET = {
  id: "a-1",
  ip_address: "10.180.5.10",
  hostname: "ws-01",
  fqdn: "ws-01.corp.test",
  dns_name: "ws-01.dns.test",
  netbios_name: "WS-01",
  mac_address: "AA:BB:CC:DD:EE:01",
  subnet: "10.180.5.0/24",
  vlan_id: 50,
  os_family: "windows",
  os_name: "Windows 11 Pro",
  os_version: "10.0.26100",
  os_confidence: 95,
  device_category: "endpoint",
  vendor: "Dell Inc.",
  manufacturer: "Dell Inc.",
  risk_score: 82,
  risk_level: "critical",
  is_active: true,
  is_managed: false,
  owner: "alice",
  provenance: { owner: { source: "analyst" } },
  custom_attributes: {
    owner_employee_id: "E-1001",
    credentialed_system_info: {
      domain: "CORP",
      os_build: "26100.4770",
      kernel_version: null,
      hardware_model: "Latitude 5540",
      cpu_model: "Intel i7-1365U",
      cpu_count: 12,
      uptime: "3 days",
    },
  },
  discovery_method: "active",
  first_seen_at: iso(30),
  last_seen_at: iso(0),
  response_time_ms: 12,
  last_scan_id: "scan-77",
  tags: ["finance", "dmz/prod"],
  notes: [
    {
      id: "n-1",
      user_id: "user-aaaaaaaa-1111",
      created_at: iso(3),
      content: "Older note",
    },
    {
      id: "n-2",
      user_id: "user-bbbbbbbb-2222",
      created_at: iso(0),
      content: "Newest note",
    },
  ],
};

const SERVICES = {
  services: [
    {
      id: "s-1",
      port: 443,
      protocol: "tcp",
      service_name: "https",
      state: "open",
      service_product: "nginx",
      service_version: "1.27.0",
      banner: "nginx/1.27.0",
      tls: {
        grade: "B",
        protocol_version: "TLSv1.2",
        cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384",
        cert_subject: { common_name: "ws-01.corp.test" },
        cert_not_after: iso(-60),
        cert_is_expired: false,
        cert_is_self_signed: true,
        is_weak_cipher: false,
        issues: ["self-signed"],
      },
      http: {
        status_code: 200,
        security_score: 40,
        has_hsts: false,
        has_csp: true,
        x_frame_options: "DENY",
        x_content_type: null,
        missing_headers: [
          "Strict-Transport-Security",
          "X-Content-Type-Options",
        ],
      },
    },
    {
      id: "s-2",
      port: 22,
      protocol: "tcp",
      service_name: "ssh",
      state: "open",
      service_product: null,
      service_version: null,
      banner: null,
      tls: null,
      http: null,
    },
  ],
};

const BARE_SERVICES = {
  services: [
    {
      id: "s-9",
      port: 135,
      protocol: "tcp",
      service_name: "msrpc",
      state: "open",
    },
  ],
};

const FINDINGS = {
  findings: [
    {
      id: "f-1",
      vuln_id: "CVE-2026-1111",
      title: "Remote code execution in nginx",
      in_kev: true,
      cvss_v3_score: 9.8,
      priority_label: "P0",
      severity: "Critical",
      status: "open",
      last_found_at: iso(3),
    },
    {
      id: "f-2",
      vuln_id: "CCURE-CFG-SSH-ROOT-LOGIN",
      title: "Root login over SSH is permitted",
      in_kev: false,
      cvss_v3_score: null,
      priority_label: "P2",
      severity: "Medium",
      status: "accepted",
      last_found_at: iso(0),
    },
  ],
};

const CHANGELOG_EMPTY = {
  timeline: [],
  raw_changelog: [],
  admin_logs: [],
  category_meta: {},
  categories: [],
  stats: { total_events: 0 },
};

const CHANGELOG = {
  timeline: [
    {
      scan_id: "scan-77",
      group_icon: "🔬",
      summary_title: "Scan #77 — 2 changes",
      summary_subtitle: "Vulnerability audit",
      highest_severity: "high",
      timestamp: iso(1),
      events: [
        {
          id: "ev-1",
          category: "services",
          event_title: "Port 443 opened",
          severity: "high",
          icon: "🔓",
          is_new_discovery: true,
          timestamp: iso(1),
        },
      ],
    },
  ],
  raw_changelog: [{ id: "ev-1", field: "services", old: null, new: "443/tcp" }],
  admin_logs: [],
  category_meta: { services: { icon: "🔌", label: "Services" } },
  categories: ["services"],
  stats: { total_events: 7 },
};

const FINDING_DETAIL = {
  id: "f-1",
  status: "open",
  proof: "Server: nginx/1.27.0",
  plugin_output: null,
  first_found_at: iso(10),
  last_found_at: iso(3),
  fixed_at: null,
  remediation_notes: "",
  vulnerability: {
    id: "CVE-2026-1111",
    title: "Remote code execution in nginx",
    severity: "Critical",
    priority_label: "P0",
    in_kev: true,
    has_exploit: true,
    cvss_v3_score: 9.8,
    epss_score: 0.123,
    priority_score: 97.4,
    description: "A crafted request executes code.",
    cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe_ids: ["CWE-787", "CWE-20"],
    references: [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
      "https://example.test/advisory/1",
      "https://example.test/advisory/2",
      "https://example.test/advisory/3",
      "https://example.test/advisory/4",
      "https://example.test/advisory/5",
      "https://example.test/advisory/6",
    ],
  },
};

/* ── Wiring ───────────────────────────────────────────────────────────────── */
function wire({
  asset = ASSET,
  services = SERVICES,
  findings = FINDINGS,
  changelog = CHANGELOG_EMPTY,
  finding = FINDING_DETAIL,
  fail = null,
} = {}) {
  // `asset` may be swapped by a test to simulate a refreshed read.
  const state = { asset };
  axiosInstance.get.mockImplementation((url) => {
    if (fail && url === fail) return Promise.reject(new Error("boom"));
    if (url === "/assets/a-1") return Promise.resolve({ data: state.asset });
    if (url === "/assets/a-1/services")
      return Promise.resolve({ data: services });
    if (url === "/assets/a-1/findings")
      return Promise.resolve({ data: findings });
    if (url === "/assets/a-1/changelog")
      return Promise.resolve({ data: changelog });
    if (/^\/findings\//.test(url)) return Promise.resolve({ data: finding });
    return Promise.reject(new Error("unexpected GET " + url));
  });
  axiosInstance.patch.mockResolvedValue({ data: {} });
  axiosInstance.post.mockResolvedValue({ data: {} });
  axiosInstance.delete.mockResolvedValue({ data: {} });
  return state;
}

const renderPage = async (opts) => {
  const state = wire(opts);
  const utils = render(<AssetDetail />);
  await waitFor(() =>
    expect(axiosInstance.get).toHaveBeenCalledWith(
      "/assets/a-1/changelog",
      expect.anything(),
    ),
  );
  // Settled: either the header IP or the error state is on screen.
  // The address appears twice once loaded (header and the identity panel),
  // so this uses queryAll — a single-match query throws on duplicates and
  // waitFor would retry it to the timeout.
  await waitFor(() =>
    expect(
      screen.queryAllByText("10.180.5.10").length > 0 ||
        screen.queryAllByText("Failed to Load Asset").length > 0,
    ).toBe(true),
  );
  return { ...utils, state };
};

/* Dual-path: the views were plain buttons before the migration and are
   `role="tab"` after it. Either way the control must carry exactly this name. */
const tab = (name) =>
  screen.queryByRole("tab", { name }) || screen.getByRole("button", { name });
/* The drawer's close control was an unnamed "✕" before the migration and a
   named close button after it. */
const closeDrawer = () =>
  screen.queryByRole("button", { name: /close finding/i }) ||
  screen.getByRole("button", { name: "✕" });
const noWrites = () => {
  expect(axiosInstance.post).not.toHaveBeenCalled();
  expect(axiosInstance.patch).not.toHaveBeenCalled();
  expect(axiosInstance.delete).not.toHaveBeenCalled();
};

/* Dual-path helpers: they find the control as it exists TODAY (a clickable
   row / span) and as the migration will make it (a named button). The
   assertion that follows is the same either way, so the contract does not
   loosen when the control changes shape. */
const openFinding = async (user, vulnId) => {
  const btn = screen.queryByRole("button", {
    name: new RegExp("details for " + vulnId, "i"),
  });
  if (btn) return user.click(btn);
  const cell = screen.getByText(vulnId).closest("td");
  return user.click(cell);
};
const expandService = async (user, port) => {
  const btn = screen
    .queryAllByRole("button")
    .find(
      (b) =>
        b.hasAttribute("aria-expanded") &&
        new RegExp("\\b" + port + "\\b").test(b.textContent),
    );
  if (btn) return user.click(btn);
  return user.click(
    screen.getByText(new RegExp("^" + port + " / tcp$")).closest("tr"),
  );
};
const removeTagControl = (tag) => {
  const chip = screen.getByText(tag, { selector: "span" }).closest("span");
  return (
    within(chip).queryByRole("button", { name: /remove/i }) ||
    within(chip).getByTitle("Remove Tag")
  );
};
/* `selector` restricts the label lookup to the control: a CcureCard is a
   <section aria-labelledby> and "Assignee / Owner" would otherwise match. */
const ownerInput = () =>
  screen.queryByLabelText(/owner name/i, { selector: "input" }) ||
  screen.getByPlaceholderText("Enter owner name…");
const tagInput = () =>
  screen.queryByLabelText(/new tag/i, { selector: "input" }) ||
  screen.getByPlaceholderText(/new tag/i);
const noteInput = () =>
  screen.queryByLabelText(/analyst note/i, { selector: "textarea" }) ||
  screen.getByPlaceholderText(/add comment logs/i);
/* "+" before the migration; a named "Add tag" control after it. */
const addTagButton = () =>
  screen.queryByRole("button", { name: /add tag/i }) ||
  screen.getByRole("button", { name: "+" });

beforeEach(() => {
  vi.clearAllMocks();
  permissions = new Set(["audit.asset.update"]);
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — load contract", () => {
  it("issues exactly the four reads, keyed on the route id, and nothing else", async () => {
    await renderPage();
    const urls = axiosInstance.get.mock.calls.map((c) => c[0]).sort();
    expect(urls).toEqual([
      "/assets/a-1",
      "/assets/a-1/changelog",
      "/assets/a-1/findings",
      "/assets/a-1/services",
    ]);
    // No org_id, no status filter — the page calls the wrappers with id only.
    for (const [, cfg] of axiosInstance.get.mock.calls) {
      expect(cfg).toEqual({ params: {} });
    }
    noWrites();
  });

  it("shows a loading placeholder, not stale content, until the reads settle", async () => {
    let release;
    axiosInstance.get.mockImplementation(
      () =>
        new Promise((r) => {
          release = r;
        }),
    );
    render(<AssetDetail />);
    expect(screen.queryAllByText("10.180.5.10")).toHaveLength(0);
    expect(screen.getByTestId("app-layout")).toHaveAttribute(
      "data-page-title",
      "Asset Details",
    );
    release({ data: {} });
  });

  it("renders the error state with a way back when any read fails", async () => {
    const user = userEvent.setup();
    await renderPage({ fail: "/assets/a-1/services" });
    expect(screen.getByText("Failed to Load Asset")).toBeInTheDocument();
    expect(
      screen.getByText("Failed to load asset details."),
    ).toBeInTheDocument();
    expect(screen.queryAllByText("10.180.5.10")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Back to Registry" }));
    expect(navigate).toHaveBeenCalledWith("/assets");
  });

  it("puts the asset address in the shell title and the header", async () => {
    await renderPage();
    expect(screen.getByTestId("app-layout")).toHaveAttribute(
      "data-page-title",
      "Asset: 10.180.5.10",
    );
    // hostname appears in the header and again in the identity panel
    expect(screen.getAllByText("ws-01").length).toBeGreaterThanOrEqual(1);
    expect(
      screen.getAllByText(/ws-01\.corp\.test/).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it("says when no hostname resolved", async () => {
    await renderPage({ asset: { ...ASSET, hostname: null, fqdn: null } });
    expect(screen.getByText("No Hostname Resolved")).toBeInTheDocument();
  });

  it("shows the risk score, classification and activity state", async () => {
    await renderPage();
    expect(screen.getByText("82")).toBeInTheDocument();
    expect(screen.getByText("RISK")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText(/Online \/ Active/)).toBeInTheDocument();
  });

  it("shows the offline state and the unmanaged label", async () => {
    await renderPage({
      asset: { ...ASSET, is_active: false, is_managed: false },
    });
    expect(screen.getByText(/Offline \/ Inactive/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Unmanaged Asset/ }),
    ).toBeInTheDocument();
  });

  it("returns to the registry from the back control", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(
      screen.getByRole("button", { name: /Back to Asset Registry/ }),
    );
    expect(navigate).toHaveBeenCalledWith("/assets");
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — tabs", () => {
  it("offers four views with live counts and opens on Asset Information", async () => {
    await renderPage({ changelog: CHANGELOG });
    expect(tab("Asset Information")).toBeInTheDocument();
    expect(tab("Services & Ports (2)")).toBeInTheDocument();
    expect(tab("Vulnerabilities (2)")).toBeInTheDocument();
    expect(tab("Audit & Changelog (7)")).toBeInTheDocument();
    expect(screen.getByText("Assignee / Owner")).toBeInTheDocument();
    expect(screen.queryByText("Discovered Findings")).not.toBeInTheDocument();
  });

  it("switches content between the four views without re-reading", async () => {
    const user = userEvent.setup();
    await renderPage({ changelog: CHANGELOG });
    const reads = axiosInstance.get.mock.calls.length;

    await user.click(tab("Vulnerabilities (2)"));
    expect(screen.getByText("Discovered Findings")).toBeInTheDocument();
    expect(screen.queryByText("Assignee / Owner")).not.toBeInTheDocument();

    await user.click(tab("Services & Ports (2)"));
    expect(
      screen.getByText("Open Ports & Running Services"),
    ).toBeInTheDocument();

    await user.click(tab("Audit & Changelog (7)"));
    expect(screen.getByText("Asset Activity Timeline")).toBeInTheDocument();

    await user.click(tab("Asset Information"));
    expect(screen.getByText("Assignee / Owner")).toBeInTheDocument();

    expect(axiosInstance.get.mock.calls.length).toBe(reads);
    noWrites();
  });

  it("counts zero events when the changelog carries no stats", async () => {
    await renderPage({ changelog: { timeline: [], raw_changelog: [] } });
    expect(tab("Audit & Changelog (0)")).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — Asset Information panels", () => {
  it("renders identity fields and hides empty or Unknown ones", async () => {
    await renderPage({
      asset: { ...ASSET, netbios_name: "Unknown", vlan_id: "" },
    });
    expect(screen.getByText("IP Address")).toBeInTheDocument();
    expect(screen.getByText("AA:BB:CC:DD:EE:01")).toBeInTheDocument();
    expect(screen.getByText("10.180.5.0/24")).toBeInTheDocument();
    expect(screen.getByText("CORP")).toBeInTheDocument();
    expect(screen.queryByText("NetBIOS Name")).not.toBeInTheDocument();
    expect(screen.queryByText("VLAN ID")).not.toBeInTheDocument();
  });

  it("shows FQDN and DNS name only when they add information", async () => {
    await renderPage();
    expect(screen.getByText("FQDN")).toBeInTheDocument();
    expect(screen.getByText("DNS Name")).toBeInTheDocument();
    expect(screen.getByText("ws-01.dns.test")).toBeInTheDocument();
  });

  it("suppresses FQDN and DNS name when they repeat the hostname", async () => {
    await renderPage({
      asset: { ...ASSET, fqdn: "ws-01", dns_name: "ws-01" },
    });
    expect(screen.queryByText("FQDN")).not.toBeInTheDocument();
    expect(screen.queryByText("DNS Name")).not.toBeInTheDocument();
  });

  it("renders OS and hardware, labels the category, and drops a duplicate manufacturer", async () => {
    await renderPage();
    expect(screen.getByText("Windows 11 Pro")).toBeInTheDocument();
    expect(screen.getByText("26100.4770")).toBeInTheDocument();
    expect(screen.getByText("95%")).toBeInTheDocument();
    expect(screen.getByText("Endpoint")).toBeInTheDocument();
    expect(screen.getByText("Latitude 5540")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    // manufacturer === vendor after normalisation → not repeated
    expect(screen.queryByText("Manufacturer")).not.toBeInTheDocument();
    expect(screen.queryByText("Kernel Version")).not.toBeInTheDocument();
  });

  it("shows a distinct manufacturer", async () => {
    await renderPage({ asset: { ...ASSET, manufacturer: "Foxconn" } });
    expect(screen.getByText("Manufacturer")).toBeInTheDocument();
    expect(screen.getByText("Foxconn")).toBeInTheDocument();
  });

  it("shows the corporate panel only when AMT data exists", async () => {
    await renderPage();
    expect(
      screen.queryByText(/Corporate \(Assets\) Details/),
    ).not.toBeInTheDocument();
  });

  it("renders the corporate panel from AMT attributes", async () => {
    await renderPage({
      asset: {
        ...ASSET,
        custom_attributes: {
          ...ASSET.custom_attributes,
          amt_asset_name: "LAPTOP-0042",
          serial_number: "SN-XYZ",
          amt_asset_type: "Laptop",
          amt_company_name: "CDAC",
          amt_location: "Bengaluru",
        },
      },
    });
    expect(
      screen.getByText(/Corporate \(Assets\) Details/),
    ).toBeInTheDocument();
    expect(screen.getByText("LAPTOP-0042")).toBeInTheDocument();
    expect(screen.getByText("SN-XYZ")).toBeInTheDocument();
    expect(screen.getByText("Bengaluru")).toBeInTheDocument();
  });

  it("renders discovery metadata with relative and absolute times", async () => {
    await renderPage();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText(/^30d ago \(/)).toBeInTheDocument();
    expect(screen.getByText(/^Today \(/)).toBeInTheDocument();
    expect(screen.getByText("12 ms")).toBeInTheDocument();
    expect(screen.getByText("scan-77")).toBeInTheDocument();
    expect(screen.getByText("a-1")).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — owner", () => {
  it("shows the owner, employee id and the analyst-override provenance badge", async () => {
    await renderPage();
    expect(
      screen.getByText("alice", { selector: ".ad-owner-name" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Employee ID:/)).toHaveTextContent("E-1001");
    expect(screen.getByText("OVERRIDE")).toBeInTheDocument();
  });

  it("shows the AMT-verified provenance badge", async () => {
    await renderPage({
      asset: { ...ASSET, provenance: { owner: { source: "amt_import" } } },
    });
    expect(screen.getByText(/CCure PRO VERIFIED/)).toBeInTheDocument();
    expect(screen.queryByText("OVERRIDE")).not.toBeInTheDocument();
  });

  it("saves a new owner with PATCH /assets/{id} { owner } and leaves edit mode", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: "Edit" }));
    const input = ownerInput();
    expect(input).toHaveValue("alice");
    await user.clear(input);
    await user.type(input, "bob");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith("/assets/a-1", {
        owner: "bob",
      }),
    );
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
    expect(
      screen.getByText("bob", { selector: ".ad-owner-name" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Save" }),
    ).not.toBeInTheDocument();
  });

  it("cancel restores the stored owner and writes nothing", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.clear(ownerInput());
    await user.type(ownerInput(), "mallory");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    noWrites();
    expect(
      screen.getByText("alice", { selector: ".ad-owner-name" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(ownerInput()).toHaveValue("alice");
  });

  it("does not crash when the owner PATCH fails (error is swallowed today)", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.patch.mockRejectedValueOnce(new Error("403"));
    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.clear(ownerInput());
    await user.type(ownerInput(), "bob");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalledTimes(1));
    // Still in edit mode, owner unchanged — and no retry.
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — managed toggle", () => {
  it("PATCHes { is_managed: true } from unmanaged and updates optimistically", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /Unmanaged Asset/ }));
    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith("/assets/a-1", {
        is_managed: true,
      }),
    );
    expect(
      screen.getByRole("button", { name: /^Managed Asset$/ }),
    ).toBeInTheDocument();
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
  });

  it("PATCHes { is_managed: false } from managed", async () => {
    const user = userEvent.setup();
    await renderPage({ asset: { ...ASSET, is_managed: true } });
    await user.click(screen.getByRole("button", { name: /^Managed Asset$/ }));
    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith("/assets/a-1", {
        is_managed: false,
      }),
    );
  });

  it("keeps the previous state when the PATCH fails", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.patch.mockRejectedValueOnce(new Error("403"));
    await user.click(screen.getByRole("button", { name: /Unmanaged Asset/ }));
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalledTimes(1));
    expect(
      screen.getByRole("button", { name: /Unmanaged Asset/ }),
    ).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — tags", () => {
  it("lists the tags and the add form", async () => {
    await renderPage();
    expect(screen.getByText("finance")).toBeInTheDocument();
    expect(screen.getByText("dmz/prod")).toBeInTheDocument();
    expect(tagInput()).toBeInTheDocument();
  });

  it("says so when there are none", async () => {
    await renderPage({ asset: { ...ASSET, tags: [] } });
    expect(screen.getByText("No tags configured")).toBeInTheDocument();
  });

  it("adds a tag with POST /assets/{id}/tags { tag }, then re-reads the asset", async () => {
    const user = userEvent.setup();
    const { state } = await renderPage();
    state.asset = { ...ASSET, tags: [...ASSET.tags, "hr"] };
    await user.type(tagInput(), "  hr  {Enter}");
    await waitFor(() =>
      expect(axiosInstance.post).toHaveBeenCalledWith("/assets/a-1/tags", {
        tag: "hr",
      }),
    );
    await waitFor(() => expect(screen.getByText("hr")).toBeInTheDocument());
    expect(
      axiosInstance.get.mock.calls.filter((c) => c[0] === "/assets/a-1"),
    ).toHaveLength(2);
    expect(tagInput()).toHaveValue("");
  });

  it("ignores an empty or whitespace tag", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.type(tagInput(), "   {Enter}");
    await user.click(addTagButton());
    noWrites();
  });

  it("removes a tag with DELETE /assets/{id}/tags/{encoded} and no confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(removeTagControl("dmz/prod"));
    await waitFor(() =>
      expect(axiosInstance.delete).toHaveBeenCalledWith(
        "/assets/a-1/tags/dmz%2Fprod",
      ),
    );
    expect(screen.queryByText("dmz/prod")).not.toBeInTheDocument();
    expect(screen.getByText("finance")).toBeInTheDocument();
    // There is no confirm step today, and the removal is not preceded by
    // any other request.
    expect(axiosInstance.delete).toHaveBeenCalledTimes(1);
  });

  it("keeps the tag when the DELETE fails", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.delete.mockRejectedValueOnce(new Error("403"));
    await user.click(removeTagControl("finance"));
    await waitFor(() => expect(axiosInstance.delete).toHaveBeenCalledTimes(1));
    expect(screen.getByText("finance")).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — analyst notes", () => {
  it("lists notes newest first with a truncated author id and relative time", async () => {
    await renderPage();
    const items = screen.getAllByText(/User ID:/);
    expect(items[0]).toHaveTextContent("user-bbb");
    expect(items[1]).toHaveTextContent("user-aaa");
    expect(screen.getByText("Newest note")).toBeInTheDocument();
    expect(screen.getByText("3d ago")).toBeInTheDocument();
  });

  it("says so when there are none", async () => {
    await renderPage({ asset: { ...ASSET, notes: [] } });
    expect(
      screen.getByText("No analyst notes logged for this host."),
    ).toBeInTheDocument();
  });

  it("logs a note with POST /assets/{id}/notes { content }, then re-reads the asset", async () => {
    const user = userEvent.setup();
    const { state } = await renderPage();
    state.asset = {
      ...ASSET,
      notes: [
        ...ASSET.notes,
        {
          id: "n-3",
          user_id: "user-c",
          created_at: iso(0),
          content: "Patched",
        },
      ],
    };
    await user.type(noteInput(), "Patched");
    await user.click(screen.getByRole("button", { name: "Log Note" }));
    await waitFor(() =>
      expect(axiosInstance.post).toHaveBeenCalledWith("/assets/a-1/notes", {
        content: "Patched",
      }),
    );
    await waitFor(() =>
      expect(screen.getByText("Patched")).toBeInTheDocument(),
    );
    expect(noteInput()).toHaveValue("");
  });

  it("ignores an empty note", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.type(noteInput(), "   ");
    await user.click(screen.getByRole("button", { name: "Log Note" }));
    noWrites();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — Services & Ports", () => {
  it("renders one row per service with port, name and state", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Services & Ports (2)"));
    expect(screen.getByText("443 / tcp")).toBeInTheDocument();
    expect(screen.getByText("22 / tcp")).toBeInTheDocument();
    expect(screen.getByText("https")).toBeInTheDocument();
    expect(screen.getByText("2 services discovered")).toBeInTheDocument();
  });

  it("shows Product, Banner and Audits columns only when some row has the data", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Services & Ports (2)"));
    expect(
      screen.getByRole("columnheader", { name: "Product & Version" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Banner" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Audits" }),
    ).toBeInTheDocument();
    expect(screen.getByText("nginx 1.27.0")).toBeInTheDocument();
    expect(screen.getByText("nginx/1.27.0")).toBeInTheDocument();
    expect(screen.getByText("TLS")).toBeInTheDocument();
    expect(screen.getByText("HTTP")).toBeInTheDocument();
  });

  it("hides enrichment columns and explains why when no row is enriched", async () => {
    const user = userEvent.setup();
    await renderPage({ services: BARE_SERVICES });
    await user.click(tab("Services & Ports (1)"));
    expect(
      screen.queryByRole("columnheader", { name: "Banner" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("columnheader", { name: "Audits" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Service enrichment data not available for this scan type",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("1 service discovered")).toBeInTheDocument();
  });

  it("renders the empty state with a scan hint", async () => {
    const user = userEvent.setup();
    await renderPage({ services: { services: [] } });
    await user.click(tab("Services & Ports (0)"));
    expect(
      screen.getByText("No open ports detected on this host."),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/enrichment data not available/),
    ).not.toBeInTheDocument();
  });

  it("expands a row with TLS/HTTP detail and collapses it again", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Services & Ports (2)"));
    expect(screen.queryByText(/TLS Details/)).not.toBeInTheDocument();

    await expandService(user, 443);
    expect(screen.getByText(/TLS Details/)).toBeInTheDocument();
    expect(screen.getByText("TLSv1.2")).toBeInTheDocument();
    expect(screen.getByText("ECDHE-RSA-AES256-GCM-SHA384")).toBeInTheDocument();
    expect(screen.getByText("ws-01.corp.test")).toBeInTheDocument();
    expect(screen.getByText(/Self-Signed Certificate/)).toBeInTheDocument();
    expect(screen.queryByText(/Certificate Expired/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Weak Ciphers/)).not.toBeInTheDocument();
    expect(screen.getByText("self-signed")).toBeInTheDocument();

    expect(screen.getByText(/HTTP Details/)).toBeInTheDocument();
    expect(screen.getByText("40/100")).toBeInTheDocument();
    expect(screen.getByText("HSTS:").parentElement).toHaveTextContent(
      "HSTS: Missing",
    );
    expect(screen.getByText("CSP:").parentElement).toHaveTextContent(
      "CSP: Configured",
    );
    expect(screen.getByText("DENY")).toBeInTheDocument();
    expect(screen.getByText("Strict-Transport-Security")).toBeInTheDocument();

    await expandService(user, 443);
    expect(screen.queryByText(/TLS Details/)).not.toBeInTheDocument();
    noWrites();
  });

  it("does not expand a row that has nothing to show", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Services & Ports (2)"));
    await user.click(screen.getByText("22 / tcp").closest("tr"));
    expect(screen.queryByText(/TLS Details/)).not.toBeInTheDocument();
    expect(screen.queryByText(/HTTP Details/)).not.toBeInTheDocument();
  });

  it("flags an expired certificate and weak ciphers", async () => {
    const user = userEvent.setup();
    const svc = SERVICES.services[0];
    await renderPage({
      services: {
        services: [
          {
            ...svc,
            tls: {
              ...svc.tls,
              grade: "F",
              cert_is_expired: true,
              is_weak_cipher: true,
              issues: [],
            },
          },
        ],
      },
    });
    await user.click(tab("Services & Ports (1)"));
    await expandService(user, 443);
    expect(screen.getByText("F")).toBeInTheDocument();
    expect(screen.getByText(/Certificate Expired/)).toBeInTheDocument();
    expect(screen.getByText(/Weak Ciphers Enabled/)).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — Vulnerabilities", () => {
  it("renders a row per finding with CVSS, priority, severity and status", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    expect(screen.getByText("9.8")).toBeInTheDocument();
    expect(screen.getByText("0.0")).toBeInTheDocument(); // null score renders 0.0
    expect(screen.getByText("P0")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
    expect(screen.getByText("accepted")).toBeInTheDocument();
    expect(screen.getByText("KEV")).toBeInTheDocument();
    // The sidebar notes also render relative times, so these are getAll.
    expect(screen.getAllByText("3d ago").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Today").length).toBeGreaterThanOrEqual(1);
  });

  it("links a CVE id to NVD and leaves a CCure identifier plain", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    const link = screen.getByRole("link", { name: "CVE-2026-1111" });
    expect(link).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(
      screen.queryByRole("link", { name: "CCURE-CFG-SSH-ROOT-LOGIN" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("CCURE-CFG-SSH-ROOT-LOGIN")).toBeInTheDocument();
  });

  it("renders the empty state with the audit hint", async () => {
    const user = userEvent.setup();
    await renderPage({ findings: { findings: [] } });
    await user.click(tab("Vulnerabilities (0)"));
    expect(
      screen.getByText("No vulnerabilities identified on this asset."),
    ).toBeInTheDocument();
  });

  it("opens the finding drawer with exactly one GET /findings/{id}", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    await openFinding(user, "CVE-2026-1111");
    await waitFor(() =>
      expect(axiosInstance.get).toHaveBeenCalledWith("/findings/f-1", {
        params: {},
      }),
    );
    expect(await screen.findByText("Finding Detail")).toBeInTheDocument();
    expect(
      screen.getByText("A crafted request executes code."),
    ).toBeInTheDocument();
    expect(
      axiosInstance.get.mock.calls.filter((c) => /^\/findings\//.test(c[0])),
    ).toHaveLength(1);
    noWrites();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — finding drawer", () => {
  const openDrawer = async (user, opts) => {
    await renderPage(opts);
    await user.click(tab("Vulnerabilities (2)"));
    await openFinding(user, "CVE-2026-1111");
    await screen.findByText("A crafted request executes code.");
  };

  it("renders scores, badges, vector, CWEs, evidence and dates", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    expect(screen.getByText("CVSSv3")).toBeInTheDocument();
    expect(screen.getAllByText("9.8").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("12.3%")).toBeInTheDocument(); // EPSS as a percentage
    expect(screen.getByText("97")).toBeInTheDocument(); // priority, no decimals
    expect(screen.getByText("Exploit")).toBeInTheDocument();
    expect(screen.getAllByText("KEV").length).toBeGreaterThanOrEqual(2);
    expect(
      screen.getByText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ).toBeInTheDocument();
    expect(screen.getByText("CWE-787")).toBeInTheDocument();
    expect(screen.getByText("Server: nginx/1.27.0")).toBeInTheDocument();
    expect(screen.getByText("First: 10d ago")).toBeInTheDocument();
    expect(screen.getByText("Last: 3d ago")).toBeInTheDocument();
    expect(screen.queryByText(/^Fixed:/)).not.toBeInTheDocument();
  });

  it("lists at most five references, each opening safely in a new tab", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    const refs = screen
      .getAllByRole("link", { name: /^https:\/\/(nvd|example)/ })
      .filter((a) => a.closest("[class]")?.className !== "cve-id");
    // 5 references + the CVE link in the drawer title + the row's CVE link.
    const refLinks = refs.filter((a) =>
      /advisory|nvd\.nist\.gov\/vuln\/detail\/CVE-2026-1111$/.test(a.href),
    );
    expect(refLinks.length).toBeGreaterThanOrEqual(5);
    expect(
      screen.queryByRole("link", { name: "https://example.test/advisory/5" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "https://example.test/advisory/6" }),
    ).not.toBeInTheDocument();
    for (const a of screen.getAllByRole("link", { name: /advisory/ })) {
      expect(a).toHaveAttribute("target", "_blank");
      expect(a).toHaveAttribute("rel", "noopener noreferrer");
    }
  });

  it("offers Accept Risk and Mark Fixed only for an open finding", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    expect(
      screen.getByRole("button", { name: /Accept Risk/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Mark Fixed/ }),
    ).toBeInTheDocument();
  });

  it("offers no actions for a finding that is not open", async () => {
    const user = userEvent.setup();
    await openDrawer(user, {
      finding: {
        ...FINDING_DETAIL,
        status: "accepted",
        remediation_notes: "Compensating control",
      },
    });
    expect(
      screen.queryByRole("button", { name: /Accept Risk/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Mark Fixed/ }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Compensating control")).toBeInTheDocument();
  });

  it("choosing an action does not write; only Confirm does", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    await user.click(screen.getByRole("button", { name: /Accept Risk/ }));
    expect(
      screen.getByText("Accept Risk — provide reason:"),
    ).toBeInTheDocument();
    await user.type(
      screen.getByPlaceholderText(/Reason for accepting/),
      "Air-gapped",
    );
    noWrites();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    noWrites();
    expect(
      screen.getByRole("button", { name: /Accept Risk/ }),
    ).toBeInTheDocument();
  });

  it("Accept Risk sends PATCH /findings/{id}/status with the exact body, then re-reads", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    await user.click(screen.getByRole("button", { name: /Accept Risk/ }));
    await user.type(
      screen.getByPlaceholderText(/Reason for accepting/),
      "Air-gapped",
    );
    await user.type(
      screen.getByPlaceholderText(/Remediation notes/),
      "Segment",
    );
    await user.click(screen.getByRole("button", { name: "Confirm Accept" }));

    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith("/findings/f-1/status", {
        status: "accepted",
        accepted_risk_reason: "Air-gapped",
        remediation_notes: "Segment",
      }),
    );
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(
        axiosInstance.get.mock.calls.filter((c) => c[0] === "/findings/f-1"),
      ).toHaveLength(2),
    );
    // The action panel closes on success and the result is announced.
    // APPROVED CHANGE (batch 11): before the migration this message was set
    // in state but rendered only inside the panel the same handler closed,
    // so the user never saw it. It now lives in a persistent live region.
    expect(screen.getByRole("status")).toHaveTextContent(
      "Status updated to accepted",
    );
    expect(
      screen.getByRole("button", { name: /Accept Risk/ }),
    ).toBeInTheDocument();
  });

  it("Mark Fixed sends status fixed with an empty reason", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    await user.click(screen.getByRole("button", { name: /Mark Fixed/ }));
    expect(screen.getByText("Mark as Fixed:")).toBeInTheDocument();
    expect(
      screen.queryByPlaceholderText(/Reason for accepting/),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm Fixed" }));
    await waitFor(() =>
      expect(axiosInstance.patch).toHaveBeenCalledWith("/findings/f-1/status", {
        status: "fixed",
        accepted_risk_reason: "",
        remediation_notes: "",
      }),
    );
  });

  it("updates the row's status in the table after a commit", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    await user.click(screen.getByRole("button", { name: /Mark Fixed/ }));
    await user.click(screen.getByRole("button", { name: "Confirm Fixed" }));
    await waitFor(() =>
      expect(
        axiosInstance.get.mock.calls.filter((c) => c[0] === "/findings/f-1"),
      ).toHaveLength(2),
    );
    // Close the drawer and check the table row.
    await user.click(closeDrawer());
    expect(screen.getByText("fixed")).toBeInTheDocument();
    expect(screen.queryByText("open")).not.toBeInTheDocument();
  });

  it("reports a failed status write and keeps the action open", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    axiosInstance.patch.mockRejectedValueOnce(new Error("403"));
    await user.click(screen.getByRole("button", { name: /Mark Fixed/ }));
    await user.click(screen.getByRole("button", { name: "Confirm Fixed" }));
    expect(
      await screen.findByText("Failed to update status"),
    ).toBeInTheDocument();
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "Confirm Fixed" }),
    ).toBeInTheDocument();
  });

  it("closes from the close control", async () => {
    const user = userEvent.setup();
    await openDrawer(user);
    await user.click(closeDrawer());
    expect(screen.queryByText("Finding Detail")).not.toBeInTheDocument();
  });

  it("says when the finding could not be loaded", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    axiosInstance.get.mockImplementationOnce(() =>
      Promise.reject(new Error("404")),
    );
    await openFinding(user, "CVE-2026-1111");
    expect(await screen.findByText("Finding not found")).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
/* APPROVED CHANGE (batch 11): the five writes that used to `catch {}` now
   report their failure. State behaviour is unchanged and asserted alongside:
   nothing retries, the toggle reverts, edit mode stays open, the tag stays. */
describe("AssetDetail — write failures are reported (approved change)", () => {
  const failureAlert = () => screen.getByRole("alert");

  it("owner save failure is announced, edit mode stays, one request only", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.patch.mockRejectedValueOnce(new Error("403"));
    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.clear(ownerInput());
    await user.type(ownerInput(), "bob");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not save the owner/,
    );
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(
      axiosInstance.get.mock.calls.filter((c) => c[0] === "/assets/a-1"),
    ).toHaveLength(1);
  });

  it("managed toggle failure is announced and the state reverts", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.patch.mockRejectedValueOnce(new Error("403"));
    await user.click(screen.getByRole("button", { name: /Unmanaged Asset/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not update the managed state/,
    );
    expect(
      screen.getByRole("button", { name: /Unmanaged Asset/ }),
    ).toBeInTheDocument();
    expect(axiosInstance.patch).toHaveBeenCalledTimes(1);
  });

  it("tag add failure is announced, nothing is re-read", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.post.mockRejectedValueOnce(new Error("403"));
    await user.type(tagInput(), "hr{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not add the tag "hr"/,
    );
    expect(axiosInstance.post).toHaveBeenCalledTimes(1);
    expect(
      axiosInstance.get.mock.calls.filter((c) => c[0] === "/assets/a-1"),
    ).toHaveLength(1);
    expect(tagInput()).toHaveValue("hr");
  });

  it("tag remove failure is announced and the tag stays", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.delete.mockRejectedValueOnce(new Error("403"));
    await user.click(removeTagControl("finance"));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not remove the tag "finance"/,
    );
    expect(screen.getByText("finance")).toBeInTheDocument();
    expect(axiosInstance.delete).toHaveBeenCalledTimes(1);
  });

  it("note failure is announced, nothing is re-read, the draft is kept", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.post.mockRejectedValueOnce(new Error("403"));
    await user.type(noteInput(), "Patched");
    await user.click(screen.getByRole("button", { name: "Log Note" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not log the note/,
    );
    expect(axiosInstance.post).toHaveBeenCalledTimes(1);
    expect(
      axiosInstance.get.mock.calls.filter((c) => c[0] === "/assets/a-1"),
    ).toHaveLength(1);
    expect(noteInput()).toHaveValue("Patched");
  });

  it("a later success clears the failure message", async () => {
    const user = userEvent.setup();
    await renderPage();
    axiosInstance.patch.mockRejectedValueOnce(new Error("503"));
    await user.click(screen.getByRole("button", { name: /Unmanaged Asset/ }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: /Unmanaged Asset/ }));
    await waitFor(() =>
      expect(screen.queryByRole("alert")).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("button", { name: /^Managed Asset$/ }),
    ).toBeInTheDocument();
    expect(axiosInstance.patch).toHaveBeenCalledTimes(2);
    expect(failureAlert).toBeDefined();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — changelog", () => {
  it("renders the timeline empty state", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Audit & Changelog (0)"));
    expect(screen.getByText("No Audit Logs")).toBeInTheDocument();
  });

  it("renders grouped events with the category filter", async () => {
    const user = userEvent.setup();
    await renderPage({ changelog: CHANGELOG });
    await user.click(tab("Audit & Changelog (7)"));
    expect(screen.getByText("Asset Activity Timeline")).toBeInTheDocument();
    expect(screen.getByText("Scan #77 — 2 changes")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /All Events/ }),
    ).toBeInTheDocument();
    // Exact: /Services/ would also match the "Services & Ports" tab. The icon
    // was part of the name before the migration and is decorative after it.
    expect(
      screen.queryByRole("button", { name: "Services" }) ||
        screen.getByRole("button", { name: "🔌 Services" }),
    ).toBeInTheDocument();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — without assets:update", () => {
  beforeEach(() => {
    permissions = new Set();
  });

  it("hides every write control and disables the toggle", async () => {
    const user = userEvent.setup();
    await renderPage();
    expect(
      screen.queryByRole("button", { name: "Edit" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/new tag/i)).not.toBeInTheDocument();
    expect(
      screen.queryByPlaceholderText(/add comment logs/i),
    ).not.toBeInTheDocument();
    expect(screen.queryByTitle("Remove Tag")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /remove/i }),
    ).not.toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: /Unmanaged Asset/ });
    expect(toggle).toBeDisabled();
    await user.click(toggle);
    noWrites();
  });

  it("still reads everything and shows the finding drawer read-only", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    await openFinding(user, "CVE-2026-1111");
    await screen.findByText("A crafted request executes code.");
    expect(
      screen.queryByRole("button", { name: /Accept Risk/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Mark Fixed/ }),
    ).not.toBeInTheDocument();
    noWrites();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════ */
describe("AssetDetail — accessibility and design-system expectations", () => {
  it("has exactly one h1, carrying the asset address", async () => {
    await renderPage();
    const h1s = screen.getAllByRole("heading", { level: 1 });
    expect(h1s).toHaveLength(1);
    expect(h1s[0]).toHaveTextContent("10.180.5.10");
  });

  it("exposes the views as a tab list with a selected tab", async () => {
    const user = userEvent.setup();
    await renderPage();
    const list = screen.getByRole("tablist");
    const tabs = within(list).getAllByRole("tab");
    expect(tabs).toHaveLength(4);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    await user.click(tabs[2]);
    expect(tabs[2]).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveTextContent(
      "Discovered Findings",
    );
  });

  it("captions both tables and scopes every column header", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    const t1 = screen.getByRole("table");
    expect(t1.querySelector("caption")).not.toBeNull();
    for (const th of t1.querySelectorAll("th"))
      expect(th).toHaveAttribute("scope", "col");
    await user.click(tab("Services & Ports (2)"));
    const t2 = screen.getByRole("table");
    expect(t2.querySelector("caption")).not.toBeNull();
    for (const th of t2.querySelectorAll("th"))
      expect(th).toHaveAttribute("scope", "col");
  });

  it("exposes the managed toggle as a pressed/unpressed button", async () => {
    await renderPage();
    expect(
      screen.getByRole("button", { name: /Unmanaged Asset/ }),
    ).toHaveAttribute("aria-pressed", "false");
  });

  it("makes each expandable service row a keyboard-operable control", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Services & Ports (2)"));
    const b = screen.getByRole("button", { name: /443/ });
    expect(b).toHaveAttribute("aria-expanded", "false");
    await user.click(b);
    expect(b).toHaveAttribute("aria-expanded", "true");
  });

  it("makes each finding row reachable through a named control", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    expect(
      screen.getByRole("button", { name: /details for CVE-2026-1111/i }),
    ).toBeInTheDocument();
  });

  it("presents the finding drawer as a named modal dialog that Escape closes", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    await openFinding(user, "CVE-2026-1111");
    const dlg = await screen.findByRole("dialog", { name: /CVE-2026-1111/ });
    expect(dlg).toHaveAttribute("aria-modal", "true");
    expect(
      within(dlg).getByRole("button", { name: /close/i }),
    ).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("names the remove-tag control as a button", async () => {
    await renderPage();
    expect(
      screen.getByRole("button", { name: /remove tag finance/i }),
    ).toBeInTheDocument();
  });

  it("labels the owner, tag, note and drawer inputs", async () => {
    const user = userEvent.setup();
    await renderPage();
    expect(
      screen.getByLabelText(/new tag/i, { selector: "input" }),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(/analyst note/i, { selector: "textarea" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(
      screen.getByLabelText(/owner name/i, { selector: "input" }),
    ).toBeInTheDocument();
  });

  it("announces the status-save result in a live region", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(tab("Vulnerabilities (2)"));
    await openFinding(user, "CVE-2026-1111");
    await screen.findByText("A crafted request executes code.");
    await user.click(screen.getByRole("button", { name: /Mark Fixed/ }));
    await user.click(screen.getByRole("button", { name: "Confirm Fixed" }));
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalledTimes(1));
    // Today the success text is set but never rendered (see the drawer
    // suite). The corrected page announces it where it can be perceived.
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Status updated to fixed",
    );
  });

  it("announces the load failure as an alert", async () => {
    await renderPage({ fail: "/assets/a-1" });
    expect(screen.getByRole("alert")).toHaveTextContent(
      /Failed to load asset details/,
    );
  });

  it("renders no inline styles beyond the data-driven risk ring", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage({ changelog: CHANGELOG });
    /* Allowance: the risk ring (data-driven). CVELink used to be a second
       one — it rendered its own inline colour (batch 10 §11.3) — and batch 15
       retired that, so `.ad-cve-id` and the drawer title are no longer
       excused. */
    const styled = () =>
      [...container.querySelectorAll("[style]")].filter(
        (el) => !el.closest(".ad-riskring, [data-allow-inline]"),
      );
    expect(styled()).toHaveLength(0);
    await user.click(tab("Services & Ports (2)"));
    expect(styled()).toHaveLength(0);
    await user.click(tab("Vulnerabilities (2)"));
    expect(styled()).toHaveLength(0);
    await user.click(tab("Audit & Changelog (7)"));
    expect(styled()).toHaveLength(0);
  });
});
