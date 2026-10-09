import { everything } from "../../../../fixtures/authorization";
/**
 * ExportPanel — Checkpoint 3C batch 15.
 *
 * Written against the legacy panel BEFORE migration. Everything up to the
 * last block holds on both sides; the last block is the migration spec and
 * fails on the baseline.
 *
 * ── Why the contents are pinned byte for byte ───────────────────────────────
 * The panel is small on screen and large in consequence: its CSV and JSON are
 * files an operator hands to somebody else. A presentation migration must not
 * change a cell, so each CSV branch is asserted as exact text, the JSON as a
 * structure, the clipboard summary line by line, and the PDF download as its
 * exact request arguments.
 *
 * ── Dual-path helper ───────────────────────────────────────────────────────
 * Legacy buttons put a glyph into their text ("📄PDFReport") and label the
 * technical PDF "PDF/XML" — it has always produced a PDF; `XML` is the
 * historical name of the technical format. Migrated buttons are named by what
 * they produce. `exportButton(kind)` finds the control as it is, else as it
 * becomes.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  act,
  fireEvent,
  waitFor,
  within,
} from "@testing-library/react";

import ExportPanel from "@audit/components/scan/ExportPanel";
import api from "@shell/api/axiosInstance";
import { personaFrom } from "../../../../fixtures/authorization";

vi.mock("@shell/api/axiosInstance", () => ({ default: { get: vi.fn() } }));

let currentUser;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(currentUser) }),
}));

/* ── Personas ─────────────────────────────────────────────────────────────── */

const ANALYST = personaFrom({
  id: 1,
  role: { name: "analyst" },
  permissionKeys: ["audit.report.read"],
});
const MANAGER = personaFrom({
  id: 2,
  role: { name: "org_admin" },
  permissionKeys: ["audit.report.read", "audit.report.delete"],
});
const SUPERADMIN = personaFrom({
  id: 3,
  role: { name: "superadmin", permissions: [] },
  authorization: everything(),
});
const VIEWER = personaFrom({
  id: 4,
  role: { name: "viewer" },
  permissionKeys: ["audit.scan.read", "audit.asset.read"],
});

/* ── Fixtures ─────────────────────────────────────────────────────────────── */

const TARGET = "10.180.6.0/24";

const P1_HOSTS = [
  {
    ip_address: "10.180.6.14",
    hostname: "ws-14",
    mac_address: "AA:BB:CC:00:00:14",
    vendor: "Dell",
    device_category: "Workstation",
    discovery_method: "ARP",
    netbios_workgroup: "CDAC",
    is_active: true,
  },
  {
    ip_address: "10.180.6.15",
    hostname: "Unknown",
    mac_address: "N/A",
    vendor: 'Acme "Networks"',
    snmp_device_type: "Switch",
    scan_method: "ICMP",
    is_active: true,
  },
  { ip_address: "10.180.6.99", hostname: "gone", is_active: false },
];
const P1_SUMMARY = {
  total_hosts: 3,
  active_hosts: 2,
  inactive_hosts: 1,
  scan_duration: 12.345,
};

const P2_HOSTS = [
  {
    ip_address: "10.180.6.14",
    hostname: "ws-14",
    mac_address: "AA",
    vendor: "Dell",
    device_category: "Workstation",
    is_active: true,
    open_ports: [
      {
        port: 22,
        protocol: "tcp",
        service: "ssh",
        product: "OpenSSH",
        version: "9.6",
        risk: "Low",
      },
      {
        port: 445,
        service: "microsoft-ds",
        product: "unknown",
        risk: "Critical",
      },
      { port: 161, protocol: "UDP", service: "snmp", risk: "High" },
    ],
    udp_services: [{ port: 123, risk: "medium" }],
    cves: [{}, {}],
  },
  { ip_address: "10.180.6.20", is_active: true },
  { ip_address: "10.180.6.21", is_active: false, open_ports: [{ port: 80 }] },
];
const P2_SUMMARY = {
  total_hosts: 3,
  hosts_with_ports: 1,
  scan_duration: 30.06,
};

const P3_HOSTS = [
  {
    ip_address: "10.180.6.14",
    hostname: "ws-14",
    mac_address: "AA",
    vendor: "Dell",
    open_ports: [{ port: 22, service: "ssh" }],
    os_guess: "Windows 11",
    cves: [{}, {}, {}],
    device_category: "Workstation",
    host_risk_level: "High",
    host_risk_score: 72,
    heartbleed_info: { vulnerable: true },
    smb_ms17010_info: { ms17010_likely: true },
    is_active: true,
  },
  { ip_address: "10.180.6.30", is_active: true },
];
const P3_SUMMARY = {
  total_hosts: 2,
  critical_hosts: 0,
  high_risk_hosts: 1,
  scan_duration: 95.44,
};

/* ── Harness ──────────────────────────────────────────────────────────────── */

let downloads;
const originalCreate = URL.createObjectURL;
const originalRevoke = URL.revokeObjectURL;

beforeEach(() => {
  currentUser = ANALYST;
  api.get.mockReset();
  downloads = [];
  let lastBlob = null;
  URL.createObjectURL = vi.fn((blob) => {
    lastBlob = blob;
    return "blob:ccure-test";
  });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
    function captureDownload() {
      downloads.push({ filename: this.download, blob: lastBlob });
    },
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  URL.createObjectURL = originalCreate;
  URL.revokeObjectURL = originalRevoke;
});

const renderPanel = (props = {}) =>
  render(
    <ExportPanel
      results={P1_HOSTS}
      summary={P1_SUMMARY}
      scanId="scan-uuid-1"
      scanNo={42}
      target={TARGET}
      pipelineMode="basic"
      {...props}
    />,
  );

const KINDS = {
  json: (t) => /JSON/.test(t),
  csv: (t) => /CSV/.test(t),
  executive: (t) => /PDF/.test(t) && !/XML|Technical/.test(t),
  technical: (t) => /PDF\/XML|Technical PDF/.test(t),
  copy: (t) => /Copy|Copied/.test(t),
};

const exportButton = (kind) => {
  const matches = screen
    .getAllByRole("button")
    .filter((b) => KINDS[kind](b.textContent));
  expect(matches, `exactly one "${kind}" export control`).toHaveLength(1);
  return matches[0];
};

const readBlob = (blob) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });

async function download(kind) {
  fireEvent.click(exportButton(kind));
  expect(downloads).toHaveLength(1);
  const { filename, blob } = downloads[0];
  return { filename, type: blob.type, text: await readBlob(blob) };
}

/** An error body as axios delivers it for `responseType: "blob"`. */
function blobOf(text, type = "application/json") {
  const blob = new Blob([text], { type });
  if (typeof blob.text !== "function") blob.text = () => Promise.resolve(text);
  return blob;
}

function stubClipboard(impl = () => Promise.resolve()) {
  const writeText = vi.fn(impl);
  Object.defineProperty(window.navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
  return writeText;
}

const STAMP = /\d{2}-\d{2}-\d{4}_\d{2}-\d{2}-\d{2}/.source;
const q = (...cells) =>
  cells.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",");

/* ══════════════════════════════════════════════════════════════════════════
   CSV
   ══════════════════════════════════════════════════════════════════════════ */

describe("ExportPanel — CSV", () => {
  it("exports a basic discovery as active hosts with placeholders emptied", async () => {
    renderPanel();
    const { filename, type, text } = await download("csv");
    expect(filename).toMatch(
      new RegExp(`^host_discovery_scan-42_${STAMP}\\.csv$`),
    );
    expect(type).toBe("text/csv");
    expect(text).toBe(
      [
        '"IP","Hostname","MAC Address","Vendor","Device Category","Discovery Method","Status"',
        '"10.180.6.14","ws-14","AA:BB:CC:00:00:14","Dell","Workstation","ARP","Active"',
        '"10.180.6.15","","","Acme ""Networks""","Switch","ICMP","Active"',
      ].join("\n"),
    );
  });

  it("drops the discovery-method column when the pipeline is inferred", async () => {
    renderPanel({ pipelineMode: undefined });
    const { filename, text } = await download("csv");
    expect(filename).toMatch(/^host_discovery_scan-42_/);
    expect(text.split("\n")).toEqual([
      q("IP", "Hostname", "MAC Address", "Vendor", "Device Category", "Status"),
      q(
        "10.180.6.14",
        "ws-14",
        "AA:BB:CC:00:00:14",
        "Dell",
        "Workstation",
        "Active",
      ),
      q("10.180.6.15", "", "", 'Acme "Networks"', "Switch", "Active"),
    ]);
  });

  it("exports an asset discovery with transport, service and product per port", async () => {
    renderPanel({
      results: P2_HOSTS,
      summary: P2_SUMMARY,
      pipelineMode: "asset",
    });
    const { filename, text } = await download("csv");
    expect(filename).toMatch(
      new RegExp(`^asset_discovery_scan-42_${STAMP}\\.csv$`),
    );
    expect(text.split("\n")).toEqual([
      q(
        "IP",
        "Hostname",
        "MAC Address",
        "Vendor",
        "Device Category",
        "Open Ports",
        "Critical Ports",
        "Status",
      ),
      q(
        "10.180.6.14",
        "ws-14",
        "AA",
        "Dell",
        "Workstation",
        "22/tcp ssh (OpenSSH 9.6); 445/tcp microsoft-ds; 161/udp snmp",
        1,
        "Active",
      ),
      q("10.180.6.20", "", "", "", "", "", 0, "Active"),
    ]);
  });

  it("exports a vulnerability audit without earlier phases as one table", async () => {
    renderPanel({
      results: P3_HOSTS,
      summary: P3_SUMMARY,
      pipelineMode: "vulnerability_audit",
    });
    const { filename, text } = await download("csv");
    expect(filename).toMatch(
      new RegExp(`^vulnerability_audit_scan-42_${STAMP}\\.csv$`),
    );
    expect(text.split("\n")).toEqual([
      q(
        "IP",
        "Hostname",
        "MAC Address",
        "Vendor",
        "Open Ports",
        "OS",
        "CVE Count",
        "Device Category",
        "Risk Level",
        "Risk Score",
        "Status",
      ),
      q(
        "10.180.6.14",
        "ws-14",
        "AA",
        "Dell",
        "22/tcp ssh",
        "Windows 11",
        3,
        "Workstation",
        "High",
        72,
        "Active",
      ),
      q("10.180.6.30", "", "", "", "", "", 0, "", "Info", 0, "Active"),
    ]);
  });

  it("exports the full audit with every phase's summary ahead of the hosts", async () => {
    renderPanel({
      results: P3_HOSTS,
      summary: P3_SUMMARY,
      pipelineMode: "vulnerability_audit",
      phase1Hosts: P1_HOSTS,
      phase1Summary: P1_SUMMARY,
      phase2Results: P2_HOSTS,
      phase2Summary: P2_SUMMARY,
    });
    const { text } = await download("csv");
    const lines = text.split("\n");
    expect(lines.slice(0, 3)).toEqual([
      q("Vulnerability Audit Export"),
      q("Scan No: 42"),
      q(`Target: ${TARGET}`),
    ]);
    expect(lines[3]).toMatch(/^"Exported: .+"$/);
    expect(lines.slice(4)).toEqual([
      "",
      q("Phase 1 — Discovery Summary"),
      q("Total hosts", 3),
      q("Active hosts", 2),
      q("Inactive hosts", 1),
      q("Duration (s)", "12.3"),
      "",
      q("Phase 2 — Port Scan Summary"),
      q("Hosts scanned", 3),
      q("Hosts with ports", 1),
      q("Duration (s)", "30.1"),
      "",
      q("Phase 3 — Vulnerability Audit Summary"),
      q("Hosts audited", 2),
      q("Critical hosts", 0),
      q("High risk hosts", 1),
      q("Duration (s)", "95.4"),
      "",
      q(
        "IP",
        "Hostname",
        "MAC Address",
        "Vendor",
        "Open Ports",
        "OS",
        "CVE Count",
        "Device Category",
        "Risk Level",
        "Risk Score",
        "Status",
      ),
      q(
        "10.180.6.14",
        "ws-14",
        "AA",
        "Dell",
        "22/tcp ssh",
        "Windows 11",
        3,
        "Workstation",
        "High",
        72,
        "Active",
      ),
      q("10.180.6.30", "", "", "", "", "", 0, "", "Info", 0, "Active"),
    ]);
  });

  it("names the file by the time when no scan number exists", async () => {
    renderPanel({ scanNo: null });
    const { filename } = await download("csv");
    expect(filename).toMatch(
      new RegExp(`^host_discovery_scan-\\d{13}_${STAMP}\\.csv$`),
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   JSON
   ══════════════════════════════════════════════════════════════════════════ */

describe("ExportPanel — JSON", () => {
  it("files a basic scan's hosts under phase1 and says so", async () => {
    renderPanel();
    const { filename, type, text } = await download("json");
    expect(filename).toMatch(
      new RegExp(`^host_discovery_scan-42_${STAMP}\\.json$`),
    );
    expect(type).toBe("application/json");
    const payload = JSON.parse(text);
    expect(payload).toEqual({
      scan_no: 42,
      target: TARGET,
      exported_at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      pipeline_mode: "basic",
      result_phase: "phase1",
      summary: P1_SUMMARY,
      hosts: P1_HOSTS,
      phase1: { summary: P1_SUMMARY, hosts: P1_HOSTS },
      phase2: { summary: null, hosts: [] },
      phase3: { summary: null, hosts: [] },
    });
  });

  it("files an asset scan under phase2", async () => {
    renderPanel({
      results: P2_HOSTS,
      summary: P2_SUMMARY,
      pipelineMode: "asset",
    });
    const payload = JSON.parse((await download("json")).text);
    expect(payload.result_phase).toBe("phase2");
    expect(payload.phase2).toEqual({ summary: P2_SUMMARY, hosts: P2_HOSTS });
    expect(payload.phase1).toEqual({ summary: null, hosts: [] });
  });

  it("carries every phase of a full audit", async () => {
    renderPanel({
      results: P3_HOSTS,
      summary: P3_SUMMARY,
      pipelineMode: "vulnerability_audit",
      phase1Hosts: P1_HOSTS,
      phase1Summary: P1_SUMMARY,
      phase2Results: P2_HOSTS,
      phase2Summary: P2_SUMMARY,
    });
    const { filename, text } = await download("json");
    expect(filename).toMatch(/^vulnerability_audit_scan-42_/);
    const payload = JSON.parse(text);
    expect(payload.result_phase).toBe("phase3");
    expect(payload.phase1).toEqual({ summary: P1_SUMMARY, hosts: P1_HOSTS });
    expect(payload.phase2).toEqual({ summary: P2_SUMMARY, hosts: P2_HOSTS });
    expect(payload.phase3).toEqual({ summary: P3_SUMMARY, hosts: P3_HOSTS });
  });

  it("infers the phase from the data when no pipeline is named", async () => {
    renderPanel({
      results: P2_HOSTS,
      summary: P2_SUMMARY,
      pipelineMode: undefined,
    });
    const { filename, text } = await download("json");
    expect(filename).toMatch(/^asset_discovery_scan-42_/);
    expect(JSON.parse(text).result_phase).toBe("phase2");
  });

  it("records a missing scan number as null", async () => {
    renderPanel({ scanNo: undefined });
    expect(JSON.parse((await download("json")).text).scan_no).toBeNull();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   PDF (server-rendered)
   ══════════════════════════════════════════════════════════════════════════ */

describe("ExportPanel — PDF", () => {
  const pdfResponse = (headers = {}) => ({
    data: new Blob(["%PDF-1.7"]),
    headers,
  });

  it("requests the executive PDF under its historical format name", async () => {
    api.get.mockResolvedValue(
      pdfResponse({
        "content-disposition": 'attachment; filename="CCure_Executive_42.pdf"',
      }),
    );
    renderPanel();
    fireEvent.click(exportButton("executive"));
    await waitFor(() => expect(downloads).toHaveLength(1));
    expect(api.get).toHaveBeenCalledTimes(1);
    expect(api.get).toHaveBeenCalledWith("/reports/download/scan-uuid-1", {
      params: { fmt: "JSON" },
      responseType: "blob",
    });
    expect(downloads[0].filename).toBe("CCure_Executive_42.pdf");
    expect(downloads[0].blob.type).toBe("application/pdf");
  });

  it("requests the technical PDF as fmt=XML", async () => {
    api.get.mockResolvedValue(pdfResponse());
    renderPanel();
    fireEvent.click(exportButton("technical"));
    await waitFor(() => expect(downloads).toHaveLength(1));
    expect(api.get).toHaveBeenCalledWith("/reports/download/scan-uuid-1", {
      params: { fmt: "XML" },
      responseType: "blob",
    });
  });

  it("reads an unquoted filename and ignores the RFC 5987 form", async () => {
    api.get.mockResolvedValue(
      pdfResponse({
        "content-disposition":
          "attachment; filename=tech_42.pdf; filename*=UTF-8''tech_42.pdf",
      }),
    );
    renderPanel();
    fireEvent.click(exportButton("technical"));
    await waitFor(() => expect(downloads).toHaveLength(1));
    expect(downloads[0].filename).toBe("tech_42.pdf");
  });

  it("names the file itself when the server gives no disposition", async () => {
    api.get.mockResolvedValue(pdfResponse());
    renderPanel();
    fireEvent.click(exportButton("executive"));
    await waitFor(() => expect(downloads).toHaveLength(1));
    expect(downloads[0].filename).toBe("ccure-report-42-JSON.pdf");
  });

  it("disables both PDF exports while one is in flight, then releases them", async () => {
    let resolve;
    api.get.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderPanel();
    fireEvent.click(exportButton("executive"));
    expect(exportButton("executive")).toBeDisabled();
    expect(exportButton("technical")).toBeDisabled();

    // A second click while in flight issues nothing.
    fireEvent.click(exportButton("executive"));
    fireEvent.click(exportButton("technical"));
    expect(api.get).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolve(pdfResponse());
    });
    await waitFor(() => expect(exportButton("technical")).toBeEnabled());
    expect(exportButton("executive")).toBeEnabled();
  });

  it("refuses without a scan id, and the notice clears after three seconds", () => {
    vi.useFakeTimers();
    try {
      renderPanel({ scanId: undefined });
      fireEvent.click(exportButton("executive"));
      expect(
        screen.getByText(/No scan ID — complete a scan first\./),
      ).toBeInTheDocument();
      expect(api.get).not.toHaveBeenCalled();
      act(() => {
        vi.advanceTimersByTime(3000);
      });
      expect(screen.queryByText(/No scan ID/)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows the server's detail from a JSON error body", async () => {
    api.get.mockRejectedValue({
      response: {
        data: blobOf('{"detail":"Report generation failed: disk full"}'),
      },
    });
    renderPanel();
    fireEvent.click(exportButton("executive"));
    expect(
      await screen.findByText(/Report generation failed: disk full/),
    ).toBeInTheDocument();
    expect(downloads).toHaveLength(0);
    await waitFor(() => expect(exportButton("executive")).toBeEnabled());
  });

  it("shows a non-JSON error body as text", async () => {
    api.get.mockRejectedValue({
      response: { data: blobOf("Bad gateway", "text/plain") },
    });
    renderPanel();
    fireEvent.click(exportButton("technical"));
    expect(await screen.findByText(/Bad gateway/)).toBeInTheDocument();
  });

  it("falls back to a generic message when there is no response", async () => {
    api.get.mockRejectedValue(new Error("Network Error"));
    renderPanel();
    fireEvent.click(exportButton("executive"));
    expect(
      await screen.findByText(/Failed to download PDF\./),
    ).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Clipboard summary
   ══════════════════════════════════════════════════════════════════════════ */

describe("ExportPanel — copy summary", () => {
  const copy = async () => {
    await act(async () => {
      fireEvent.click(exportButton("copy"));
    });
  };

  it("copies the discovery summary, one line per active host", async () => {
    const writeText = stubClipboard();
    renderPanel();
    await copy();
    expect(writeText).toHaveBeenCalledTimes(1);
    const lines = writeText.mock.calls[0][0].split("\n");
    expect(lines.slice(0, 3)).toEqual([
      "CCure Audit PRO — Network Discovery Report",
      `Target:   ${TARGET}`,
      "Scan No:  42",
    ]);
    expect(lines[3]).toMatch(/^Date: {5}\S/);
    expect(lines.slice(4)).toEqual([
      "",
      "── Summary ──────────────────────────",
      "Total hosts:    3",
      "Active hosts:   2",
      "Inactive hosts: 1",
      "Duration:       12.3s",
      "",
      "── Active Hosts ──────────────────────",
      `${"10.180.6.14".padEnd(16)} ${"ws-14".padEnd(20)} MAC: ${"AA:BB:CC:00:00:14".padEnd(17)}`,
      `${"10.180.6.15".padEnd(16)} ${"Unknown".padEnd(20)} MAC: ${"N/A".padEnd(17)}`,
    ]);
    expect(exportButton("copy")).toHaveTextContent("Copied!");
  });

  it("adds type and domain for an inferred discovery", async () => {
    const writeText = stubClipboard();
    renderPanel({ pipelineMode: undefined });
    await copy();
    const lines = writeText.mock.calls[0][0].split("\n");
    expect(lines).toContain(
      `${"10.180.6.14".padEnd(16)} ${"ws-14".padEnd(20)} MAC: ${"AA:BB:CC:00:00:14".padEnd(17)} Type: ${"Workstation".padEnd(10)} Domain: CDAC`,
    );
  });

  it("counts port risk across TCP and UDP for an asset discovery", async () => {
    const writeText = stubClipboard();
    renderPanel({
      results: P2_HOSTS,
      summary: P2_SUMMARY,
      pipelineMode: "asset",
    });
    await copy();
    const lines = writeText.mock.calls[0][0].split("\n");
    expect(lines[0]).toBe("CCure Audit PRO — Asset Discovery Report");
    expect(lines.slice(6, 15)).toEqual([
      "Total hosts:           3",
      "Hosts with open ports: 1",
      "Critical risks:        1",
      "High risk:             1",
      "Medium risk:           1",
      "Low risk:              1",
      "Total CVEs:            2",
      "Duration:              30.1s",
      "",
    ]);
    expect(lines).toContain(
      `${"10.180.6.14".padEnd(16)} ${"Workstation".padEnd(10)} CVEs: ${"2".padEnd(4)} Critical: ${"1".padEnd(2)} High: ${"1".padEnd(2)} Ports: 22/tcp ssh (OpenSSH 9.6), 445/tcp microsoft-ds, 161/udp snmp`,
    );
  });

  it("lists risk and active findings for a vulnerability audit", async () => {
    const writeText = stubClipboard();
    renderPanel({
      results: P3_HOSTS,
      summary: P3_SUMMARY,
      pipelineMode: "vulnerability_audit",
    });
    await copy();
    const lines = writeText.mock.calls[0][0].split("\n");
    expect(lines[0]).toBe("CCure Audit PRO — Vulnerability Audit Report");
    expect(lines.slice(-2)).toEqual([
      `${"10.180.6.14".padEnd(16)} ${"High".padEnd(10)} 72/100  CVEs: ${"3".padEnd(4)} Active Findings: Heartbleed,MS17-010`,
      `${"10.180.6.30".padEnd(16)} ${"Info".padEnd(10)} 0/100  CVEs: ${"0".padEnd(4)} Active Findings: None`,
    ]);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Permission
   ══════════════════════════════════════════════════════════════════════════ */

describe("ExportPanel — permission", () => {
  it("disables every export for a role without reports:read", () => {
    currentUser = VIEWER;
    renderPanel();
    for (const kind of Object.keys(KINDS)) {
      expect(exportButton(kind)).toBeDisabled();
    }
  });

  it("treats a missing user as unpermitted", () => {
    currentUser = null;
    renderPanel();
    for (const kind of Object.keys(KINDS)) {
      expect(exportButton(kind)).toBeDisabled();
    }
  });

  it("issues no request, file or clipboard write when a disabled export is clicked", async () => {
    currentUser = VIEWER;
    const writeText = stubClipboard();
    renderPanel();
    await act(async () => {
      for (const kind of Object.keys(KINDS))
        fireEvent.click(exportButton(kind));
    });
    expect(api.get).not.toHaveBeenCalled();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
    expect(downloads).toHaveLength(0);
    expect(writeText).not.toHaveBeenCalled();
  });

  it.each([
    ["reports:read+delete", MANAGER],
    ["superadmin", SUPERADMIN],
  ])("enables exports for %s", (_label, user) => {
    currentUser = user;
    renderPanel();
    for (const kind of Object.keys(KINDS)) {
      expect(exportButton(kind)).toBeEnabled();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Migration spec — fails on the baseline
   ══════════════════════════════════════════════════════════════════════════ */

describe("ExportPanel — migration spec", () => {
  it("is a region titled by a heading", () => {
    renderPanel();
    const region = screen.getByRole("region", { name: /export results/i });
    expect(
      within(region).getByRole("heading", { name: /export results/i }),
    ).toBeInTheDocument();
  });

  it("names each export by what it produces, with no glyphs", () => {
    renderPanel();
    const names = [
      "JSON Full data",
      "CSV Spreadsheet",
      "Executive PDF Summary report",
      "Technical PDF Detailed report",
      "Copy Summary",
    ];
    const buttons = screen.getAllByRole("button");
    expect(buttons).toHaveLength(names.length);
    buttons.forEach((b, i) => expect(b).toHaveAccessibleName(names[i]));
  });

  it("says why the exports are unavailable to a role without reports:read", () => {
    currentUser = VIEWER;
    renderPanel();
    expect(
      screen.getByText(/role does not include permission to export/i),
    ).toBeInTheDocument();
  });

  it("announces a refused export as an alert", () => {
    renderPanel({ scanId: undefined });
    fireEvent.click(exportButton("executive"));
    expect(screen.getByRole("alert")).toHaveTextContent(/No scan ID/);
  });

  it("marks only the requested PDF as busy", () => {
    api.get.mockReturnValue(new Promise(() => {}));
    renderPanel();
    fireEvent.click(exportButton("technical"));
    expect(exportButton("technical")).toHaveAttribute("aria-busy", "true");
    expect(exportButton("executive")).toBeDisabled();
    expect(exportButton("executive")).not.toHaveAttribute("aria-busy");
  });

  it("reports a clipboard failure instead of failing silently", async () => {
    stubClipboard(() => Promise.reject(new Error("NotAllowedError")));
    renderPanel();
    await act(async () => {
      fireEvent.click(exportButton("copy"));
    });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not copy/i,
    );
    expect(exportButton("copy")).not.toHaveTextContent("Copied!");
  });

  it("confirms a copy in a polite live region", async () => {
    stubClipboard();
    renderPanel();
    await act(async () => {
      fireEvent.click(exportButton("copy"));
    });
    expect(await screen.findByRole("status")).toHaveTextContent(
      /summary copied/i,
    );
  });

  it("writes nothing to the browser console", async () => {
    // The legacy copy handler logged the first host — address, MAC, hostname —
    // to the console on every click.
    const spies = ["log", "info", "debug"].map((m) =>
      vi.spyOn(console, m).mockImplementation(() => {}),
    );
    stubClipboard();
    renderPanel();
    await act(async () => {
      fireEvent.click(exportButton("copy"));
    });
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it("renders no inline styles, permitted or not", () => {
    const { container, unmount } = renderPanel();
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
    unmount();
    currentUser = VIEWER;
    const again = renderPanel();
    expect(again.container.querySelectorAll("[style]")).toHaveLength(0);
  });
});
