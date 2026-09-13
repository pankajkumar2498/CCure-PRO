/**
 * Fixed API responses. Field names are the ones the pages read. Dates are
 * relative to the frozen clock in freeze.mjs, so "3d ago" and certificate
 * expiry bands render the same way on every run.
 */
import { FIXED_TIME } from "./freeze.mjs";

const DAY = 86400000;
export const ago = (days) => new Date(FIXED_TIME - days * DAY).toISOString();
export const ahead = (days) => new Date(FIXED_TIME + days * DAY).toISOString();

/* ── Personas ─────────────────────────────────────────────────────────────── */
const BASE_PERMISSIONS = [
  "dashboard:read",
  "scans:read",
  "scans:execute",
  "assets:read",
  "assets:update",
  "findings:read",
  "findings:update",
  "reports:read",
  "notifications:read",
  "compliance:read",
  "compliance:attest",
  "compliance:manage",
  "compliance:export_report",
];

const persona = (permissions) => ({
  id: 101,
  username: "harness",
  email: "harness@example.test",
  full_name: "Harness Operator",
  org_id: "o-1",
  organization_name: "Harness Org",
  role: { name: "analyst", permissions },
  is_active: true,
  is_verified: true,
  mfa_enabled: false,
});

export const ANALYST = persona(BASE_PERMISSIONS);
export const ASSETS_READONLY = persona(
  BASE_PERMISSIONS.filter((p) => p !== "assets:update"),
);
export const FINDINGS_READONLY = persona(
  BASE_PERMISSIONS.filter((p) => p !== "findings:update"),
);

/* SecurityDashboard gates its widgets on read permissions. These cover the
   audit timeline (audit:read), a dashboard-only reader, and the redirect a
   user without dashboard:read receives. */
export const DASHBOARD_ADMIN = persona([...BASE_PERMISSIONS, "audit:read"]);
export const DASHBOARD_RESTRICTED = persona([
  "dashboard:read",
  "scans:read",
  "notifications:read",
]);
export const NO_DASHBOARD = persona(
  BASE_PERMISSIONS.filter((p) => p !== "dashboard:read"),
);

/* ── Shell ────────────────────────────────────────────────────────────────── */
export const DASHBOARD_SUMMARY = {
  severity: {
    critical: 12,
    high: 30,
    medium: 55,
    low: 20,
    info: 8,
    total: 125,
    deltas: { critical: 2, high: -1, medium: 0, low: 1 },
  },
  assets: {
    total: 42,
    new_24h: 2,
    risk_delta_7d: -3,
    avg_risk_score: 47,
    risk_level: "medium",
    unmanaged: 5,
  },
  scans: { running: 1, queued: 0, last_24h: 4, quota_limit_24h: 50 },
  kev: { open_count: 3 },
};

export const SHELL_STUBS = {
  "/dashboard/summary": DASHBOARD_SUMMARY,
  "/scan/quota": {
    plan: "pro",
    scans_used_24h: 3,
    scans_limit_24h: 10,
    concurrent_running: 1,
    concurrent_limit: 2,
    max_ips_per_scan: 1024,
    quota_exceeded: false,
    concurrent_exceeded: false,
  },
  "/notifications/summary": { total_unread: 2, by_category: { scan: 2 } },
  "/notifications": { notifications: [], total: 0 },
};

/* ── AssetRegistry ────────────────────────────────────────────────────────── */
export const AR_ASSETS = {
  assets: [
    {
      id: "a-1",
      ip_address: "10.180.5.10",
      hostname: "ws-01",
      fqdn: "ws-01.corp.test",
      os_family: "windows",
      os_name: "Windows 11 Pro",
      os_confidence: 95,
      device_category: "endpoint",
      risk_level: "critical",
      risk_score: 91,
      open_ports_count: 7,
      is_managed: false,
      owner: "alice",
      emp_id: "E-1001",
      serial: "SN-ABC",
      tags: ["finance", "dmz/prod"],
      last_seen_at: ago(0.1),
      vuln_counts: { critical: 3, high: 5, medium: 9 },
    },
    {
      id: "a-2",
      ip_address: "10.180.5.11",
      hostname: "srv-02",
      fqdn: "srv-02.corp.test",
      os_family: "linux",
      os_name: "Ubuntu 24.04",
      os_confidence: 88,
      device_category: "server",
      risk_level: "medium",
      risk_score: 44,
      open_ports_count: 3,
      is_managed: true,
      owner: "bob",
      emp_id: "E-1002",
      serial: "SN-DEF",
      tags: [],
      last_seen_at: ago(1),
      vuln_counts: { critical: 0, high: 1, medium: 4 },
    },
    {
      id: "a-3",
      ip_address: "10.180.5.12",
      hostname: null,
      fqdn: null,
      os_family: null,
      os_name: null,
      os_confidence: null,
      device_category: "iot",
      risk_level: "low",
      risk_score: 12,
      open_ports_count: null,
      is_managed: false,
      owner: null,
      emp_id: null,
      serial: null,
      tags: ["iot"],
      last_seen_at: ago(3),
      vuln_counts: { critical: 0, high: 0, medium: 1 },
    },
  ],
  total: 3,
};

export const AR_SERVICES = {
  services: [
    {
      service_name: "ssh",
      port: 22,
      protocol: "tcp",
      asset_count: 12,
      risk_level: "Medium",
      risk_reason: "Remote administration",
      last_seen: ago(0.2),
    },
    {
      service_name: "https",
      port: 443,
      protocol: "tcp",
      asset_count: 5,
      risk_level: "High",
      risk_reason: "Self-signed certificates",
      last_seen: ago(1),
    },
    {
      service_name: "snmp",
      port: 161,
      protocol: "udp",
      asset_count: 3,
      risk_level: "Critical",
      risk_reason: "Default community string",
      last_seen: ago(2),
    },
  ],
  total: 3,
};

export const AR_SERVICE_ASSETS = {
  assets: [
    {
      asset_id: "a-1",
      asset_hostname: "ws-01",
      asset_ip: "10.180.5.10",
      asset_type: "endpoint",
      state: "open",
      service_product: "OpenSSH",
      service_version: "9.6",
      last_scan_time: ago(0.2),
    },
    {
      asset_id: "a-2",
      asset_hostname: "srv-02",
      asset_ip: "10.180.5.11",
      asset_type: "server",
      state: "filtered",
      service_product: null,
      service_version: null,
      last_scan_time: ago(1),
    },
  ],
  total: 2,
};

export const AR_CERTS = {
  certificates: [
    {
      id: "c-1",
      asset_id: "a-1",
      asset_ip: "10.180.5.10",
      asset_hostname: "ws-01",
      port: 443,
      protocol: "tcp",
      protocol_version: "TLSv1.2",
      cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384",
      cert_subject: { common_name: "ws-01.corp.test" },
      cert_issuer: { common_name: "CCure Internal CA" },
      cert_not_after: ago(40),
      cert_is_expired: true,
      cert_is_self_signed: true,
      is_weak_cipher: true,
      grade: "F",
      issues: ["expired"],
    },
    {
      id: "c-2",
      asset_id: "a-2",
      asset_ip: "10.180.5.11",
      asset_hostname: "srv-02",
      port: 8443,
      protocol: "tcp",
      protocol_version: "TLSv1.3",
      cipher_suite: "TLS_AES_256_GCM_SHA384",
      cert_subject: { common_name: "srv-02.corp.test" },
      cert_issuer: { common_name: "CCure Internal CA" },
      cert_not_after: ahead(12),
      cert_is_expired: false,
      cert_is_self_signed: false,
      is_weak_cipher: false,
      grade: "C",
      issues: [],
    },
    {
      id: "c-3",
      asset_id: "a-2",
      asset_ip: "10.180.5.11",
      asset_hostname: "srv-02",
      port: 443,
      protocol: "tcp",
      protocol_version: "TLSv1.3",
      cipher_suite: "TLS_AES_128_GCM_SHA256",
      cert_subject: "srv-02.example.test",
      cert_issuer: "Public CA",
      cert_not_after: ahead(260),
      cert_is_expired: false,
      cert_is_self_signed: false,
      is_weak_cipher: false,
      grade: "A",
      issues: [],
    },
  ],
  total: 3,
};

/* ── VulnerabilityBrowser ─────────────────────────────────────────────────── */
export const VB_GROUPS = {
  groups: [
    {
      component: "google-chrome",
      component_version: "120.0.1",
      fixed_version: "131.0.2",
      finding_count: 1736,
      kev_count: 4,
      in_kev: true,
      exploit_count: 2,
      verified_exploit: true,
      canary_confirmed: true,
      ransomware_linked: false,
      max_cvss: 9.8,
      severity: "Critical",
      remediation: "Upgrade to 131.0.2",
      asset: { id: "a-1", ip_address: "10.180.5.10", hostname: "ws-01" },
    },
    {
      component: "openssl",
      component_version: "3.0.1",
      fixed_version: null,
      finding_count: 12,
      kev_count: 0,
      in_kev: false,
      exploit_count: 0,
      verified_exploit: false,
      canary_confirmed: false,
      ransomware_linked: true,
      max_cvss: 7.5,
      severity: "High",
      remediation: null,
      asset: { id: "a-2", ip_address: "10.180.5.11", hostname: "srv-02" },
    },
  ],
  total: 2,
};

export const VB_FINDINGS = {
  findings: [
    {
      id: "f-1",
      vuln_id: "CVE-2026-1111",
      title: "Chrome use-after-free",
      severity: "Critical",
      cvss_v3_score: 9.8,
      priority_label: "P0",
      in_kev: true,
      status: "open",
      first_found_at: ago(10),
      asset: { id: "a-1", ip_address: "10.180.5.10", hostname: "ws-01" },
    },
    {
      id: "f-2",
      vuln_id: "CVE-2026-2222",
      title: "OpenSSL denial of service",
      severity: "High",
      cvss_v3_score: 7.5,
      priority_label: "P2",
      in_kev: false,
      status: "open",
      first_found_at: ago(1),
      asset: { id: "a-2", ip_address: "10.180.5.11", hostname: "srv-02" },
    },
    {
      id: "f-3",
      vuln_id: "CVE-2026-3333",
      title: "curl header injection",
      severity: "Medium",
      cvss_v3_score: 5.3,
      priority_label: "P3",
      in_kev: false,
      status: "accepted",
      first_found_at: ago(30),
      asset: { id: "a-2", ip_address: "10.180.5.11", hostname: null },
    },
  ],
  total: 3,
};

export const VB_FINDINGS_NULL_CVSS = {
  findings: [
    ...VB_FINDINGS.findings,
    {
      id: "f-4",
      vuln_id: "CVE-2026-4444",
      title: "Legacy CVE with only a v2 score",
      severity: "Medium",
      cvss_v3_score: null,
      priority_label: "P4",
      in_kev: false,
      status: "open",
      first_found_at: ago(5),
      asset: { id: "a-3", ip_address: "10.180.5.12", hostname: null },
    },
  ],
  total: 4,
};

export const VB_FINDING_DETAIL = {
  id: "f-1",
  status: "open",
  proof: "Server: nginx/1.27.0",
  plugin_output: null,
  first_found_at: ago(10),
  last_found_at: ago(1),
  fixed_at: null,
  remediation_notes: "Patch window agreed with the desktop team.",
  vulnerability: {
    id: "CVE-2026-1111",
    title: "Chrome use-after-free",
    severity: "Critical",
    priority_label: "P0",
    in_kev: true,
    has_exploit: true,
    cvss_v3_score: 9.8,
    epss_score: 0.123,
    priority_score: 97.4,
    description: "A crafted page executes code in the renderer.",
    cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    cwe_ids: ["CWE-416"],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2026-1111"],
  },
  asset: {
    id: "a-1",
    ip_address: "10.180.5.10",
    hostname: "ws-01",
    risk_score: 91,
    risk_level: "critical",
  },
};

/* ── SecurityDashboard (batch 17) ─────────────────────────────────────────── */
const SD_CVES = [
  {
    id: "CVE-2026-1111",
    title: "Chrome use-after-free",
    cvss_v3_score: 9.8,
    priority_label: "P0",
    severity: "Critical",
    affected_assets: 3,
    in_kev: true,
  },
  {
    id: "CVE-2026-2222",
    title: "OpenSSL denial of service",
    cvss_v3_score: 7.5,
    priority_label: "P2",
    severity: "High",
    affected_assets: 1,
    in_kev: false,
  },
];

// Every panel carries data, so every widget renders its populated form.
export const SD_STUBS = {
  "/dashboard/risk-breakdown": {
    priority_distribution: { p0_kev: 3, p2_cvss_9: 4 },
    finding_status: { open: 90, accepted: 20, fixed: 15 },
  },
  "/dashboard/top-assets": { assets: AR_ASSETS.assets },
  "/dashboard/top-cves": { cves: SD_CVES },
  "/dashboard/services-exposure": {
    services: [
      {
        service_name: "telnet",
        port: 23,
        protocol: "tcp",
        asset_count: 2,
        is_high_risk: true,
      },
      {
        service_name: "ssh",
        port: 22,
        protocol: "tcp",
        asset_count: 12,
        is_high_risk: false,
      },
      {
        service_name: "https",
        port: 443,
        protocol: "tcp",
        asset_count: 5,
        is_high_risk: false,
      },
    ],
  },
  "/dashboard/tls-health": {
    expiring_in_30d: 1,
    expired: 1,
    total: 3,
    total_tls_services: 3,
    grade_distribution: { A: 1, C: 1, F: 1 },
  },
  "/dashboard/http-headers": {
    coverage: {
      strict_transport_security: { pct: 80 },
      content_security_policy: { pct: 30 },
      x_frame_options: { pct: 55 },
    },
  },
  "/dashboard/compliance": {
    frameworks: [
      { id: "iso27001", name: "ISO/IEC 27001", score: 72.4 },
      { id: "nist_csf_v2", name: "NIST CSF 2.0", score: 55 },
    ],
  },
  "/dashboard/asset-breakdown": {
    totals: { total: 42, managed: 37, unmanaged: 5, active: 40, offline: 2 },
    os_distribution: [
      { os_family: "Linux", count: 20 },
      { os_family: "Windows", count: 22 },
    ],
  },
  "/dashboard/scan-activity": {
    scans: [
      {
        id: "s-1",
        scan_type: "network",
        pipeline_mode: "vulnerability_audit",
        target_str: "10.180.6.0/24",
        status: "running",
        current_phase: "PORT_SCAN",
        progress_pct: 40,
        queued_at: ago(0.01),
      },
      {
        id: "s-2",
        scan_type: "network",
        pipeline_mode: "basic",
        target_str: "10.180.5.0/24",
        status: "complete",
        active_hosts: 12,
        critical_count: 3,
        high_count: 5,
        queued_at: ago(1),
      },
      {
        id: "s-3",
        scan_type: "credentialed",
        target_str: "10.180.5.10",
        status: "failed",
        scan_name: "cred-audit",
        queued_at: ago(2),
      },
    ],
  },
  "/dashboard/insights": {
    insights: [
      {
        id: "i-1",
        severity: "high",
        icon: "⚠",
        title: "Cleartext telnet exposed",
        detail: "2 assets accept telnet connections.",
      },
    ],
  },
  "/admin/audit-logs": {
    logs: [
      {
        id: "l-1",
        action: "scan_started",
        username: "alice",
        resource_type: "scan",
        status: "success",
        created_at: ago(0.05),
      },
      {
        id: "l-2",
        action: "finding_fixed",
        user_id: "u-000000abcdef",
        resource_type: "finding",
        status: "success",
        created_at: ago(1),
      },
    ],
  },
  "/notifications": {
    notifications: [
      {
        id: "n-1",
        type: "scan_completed",
        title: "Scan finished",
        message: "10.180.5.0/24",
        is_read: false,
        created_at: ago(0.02),
      },
    ],
    total: 1,
  },
};

const SD_PANELS = [
  "/dashboard/summary",
  "/dashboard/risk-breakdown",
  "/dashboard/top-assets",
  "/dashboard/top-cves",
  "/dashboard/services-exposure",
  "/dashboard/tls-health",
  "/dashboard/http-headers",
  "/dashboard/compliance",
  "/dashboard/asset-breakdown",
  "/dashboard/scan-activity",
  "/dashboard/insights",
];

// A new organisation: every panel answers, and answers with nothing.
export const SD_STUBS_EMPTY = {
  "/dashboard/summary": {
    severity: { total: 0 },
    assets: {},
    scans: {},
    kev: {},
  },
  "/dashboard/risk-breakdown": {},
  "/dashboard/top-assets": { assets: [] },
  "/dashboard/top-cves": { cves: [] },
  "/dashboard/services-exposure": { services: [] },
  "/dashboard/tls-health": {},
  "/dashboard/http-headers": {},
  "/dashboard/compliance": { frameworks: [] },
  "/dashboard/asset-breakdown": { totals: {}, os_distribution: [] },
  "/dashboard/scan-activity": { scans: [] },
  "/dashboard/insights": { insights: [] },
  "/admin/audit-logs": { logs: [] },
  "/notifications": { notifications: [], total: 0 },
};

// Every panel fails. The page settles every request independently.
export const SD_STUBS_ERROR = {
  ...Object.fromEntries(SD_PANELS.map((p) => [p, { __status: 500 }])),
  "/admin/audit-logs": { __status: 500 },
};

// A CVE NVD scored only under v2 — the batch 16 crash, on the landing page.
export const SD_STUBS_NULL_CVSS = {
  ...SD_STUBS,
  "/dashboard/top-cves": {
    cves: [
      ...SD_CVES,
      {
        ...SD_CVES[1],
        id: "CVE-2026-4444",
        title: "Legacy CVE with only a v2 score",
        cvss_v3_score: null,
      },
    ],
  },
};

/* ── ComplianceWorkspace (regression sweep) ───────────────────────────────── */
export const CW_STUBS = {
  "/compliance/summary": {
    score_pct: 72,
    weighted_score_pct: 70,
    kpis: {
      passed: 40,
      failed: 10,
      exceptions: 2,
      manual_review: 5,
      not_assessed: 3,
      total_controls: 60,
    },
  },
  "/compliance/marketplace": { data: [] },
  "/compliance/policies": { data: [] },
  "/compliance/frameworks/cfw_iso27001_2022/controls": {
    controls: [],
    total: 0,
  },
  "/compliance/findings": { data: [] },
  "/compliance/credentials": [],
  "/compliance/remediations/requests": { data: [] },
};

/* ── Phase2Results (batch 18) ─────────────────────────────────────────────── */
/* Field names are the page's reads, checked against the port scan the
   orchestrator stores: hosts from `_format_host`, the summary written by the
   port-scan phase (`total_hosts`, `hosts_with_ports`, `scan_duration`,
   `custom_ports`). The page chooses which hosts the vulnerability audit
   scans, so these cover each way a host can qualify: TCP services, UDP
   services only, active with nothing detected, and inactive. */
export const SCANS_READONLY = persona(
  BASE_PERMISSIONS.filter((p) => p !== "scans:execute"),
);

const P2_PHASE1_HOSTS = [
  {
    ip_address: "10.20.0.11",
    hostname: "files-01",
    mac_address: "00:1A:2B:3C:4D:11",
    vendor: "Dell Inc.",
    discovery_method: "ARP",
    is_active: true,
  },
  {
    ip_address: "10.20.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mac_address: "00:1A:2B:3C:4D:12",
    vendor: "HP",
    discovery_method: "ICMP",
    is_active: true,
  },
  {
    ip_address: "10.20.0.13",
    hostname: "Unknown",
    netbios_names: [{ name: "KIOSK-07" }],
    mac_address: "N/A",
    vendor: "N/A",
    discovery_method: "TCP",
    is_active: true,
  },
  {
    ip_address: "10.20.0.14",
    hostname: "Unknown",
    mac_address: "N/A",
    vendor: "N/A",
    discovery_method: "ICMP",
    is_active: false,
  },
  {
    ip_address: "10.20.0.15",
    hostname: "Unknown",
    mac_address: "00:1A:2B:3C:4D:15",
    vendor: "Raspberry Pi Trading",
    discovery_method: "ARP",
    is_active: true,
  },
];

const P2_PHASE2_HOSTS = [
  {
    ip_address: "10.20.0.11",
    hostname: "files-01",
    is_active: true,
    os_guess: "Windows Server 2022",
    os_fingerprint_full: {
      os: "Windows Server 2022",
      confidence: "High",
      match_score: 42,
    },
    netbios_names: [{ name: "FILES-01" }],
    netbios_workgroup: "CORP",
    device_category: "server",
    firewall_likely: true,
    firewall_confidence: "Medium",
    open_ports: [
      { port: 22, service: "ssh", version: "OpenSSH 9.6", risk: "Low" },
      {
        port: 445,
        service: "microsoft-ds",
        risk: "High",
        cves: ["CVE-2026-2001", "CVE-2026-2002"],
      },
      {
        port: 3389,
        service: "ms-wbt-server",
        banner: "Remote Desktop",
        risk: "Critical",
        cves: ["CVE-2026-3001"],
      },
    ],
  },
  {
    ip_address: "10.20.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mdns_services: ["_ipp._tcp.local", "_printer._tcp.local"],
    is_active: true,
    os_guess: "Embedded",
    os_confidence: "Medium",
    snmp_device_type: "Printer",
    open_ports: [
      { port: 9100, service: "jetdirect", risk: "Medium" },
      { port: 80, service: "http", banner: "HP HTTP Server", risk: "Info" },
    ],
    udp_services: [
      {
        port: 161,
        service: "snmp",
        state: "open",
        risk: "High",
        banner: "public community",
      },
      { port: 5353, service: "mdns", state: "open|filtered", risk: "Low" },
    ],
    snmp_info: {
      sys_name: "PRN-2F",
      sys_location: "Floor 2, east wing",
      vendor: "HP",
      interfaces: [
        {
          index: 1,
          description: "eth0",
          type: "ethernetCsmacd",
          mac: "00:1A:2B:3C:4D:12",
          admin_up: true,
          oper_up: true,
        },
        {
          index: 2,
          description: "wlan0",
          type: "ieee80211",
          mac: "00:1A:2B:3C:4D:99",
          admin_up: true,
          oper_up: false,
        },
      ],
      ip_addresses: [{ address: "10.20.0.12", netmask: "255.255.255.0" }],
    },
  },
  {
    ip_address: "10.20.0.13",
    hostname: "KIOSK-07",
    is_active: true,
    udp_services: [
      { port: 137, service: "netbios-ns", state: "open|filtered", risk: "Low" },
    ],
  },
  { ip_address: "10.20.0.15", hostname: "Unknown", is_active: true },
  { ip_address: "10.20.0.14", hostname: "Unknown", is_active: false },
];

const P2_SUMMARY = {
  total_hosts: 5,
  active_hosts: 4,
  inactive_hosts: 1,
  hosts_with_ports: 2,
  scan_duration: 84.37,
  phase: 2,
  scan_type: "NORMAL",
  custom_ports: "22,80,161,443,445,3389,9100,8000-8100",
};

const P2_UNREACHABLE_HOST = {
  ip_address: "10.20.0.50",
  hostname: "Unknown",
  mac_address: "N/A",
  vendor: "N/A",
  discovery_method: "ICMP",
  is_active: false,
};

const p2Scan = (id, overrides = {}) => ({
  id,
  scan_no: 1042,
  target: "10.20.0.0/28",
  status: "complete",
  pipeline_mode: "asset",
  results: {
    phase1: { data: P2_PHASE1_HOSTS },
    phase2: { data: P2_PHASE2_HOSTS, summary: P2_SUMMARY },
  },
  ...overrides,
});

export const P2_STUBS = {
  // Asset discovery: no phase 3, so automatic mode stays on the page.
  "/scans/p2-asset": p2Scan("p2-asset"),
  // A full audit pipeline, only ever loaded with interactive mode seeded.
  "/scans/p2-audit": p2Scan("p2-audit", {
    scan_no: 1043,
    pipeline_mode: "vulnerability_audit",
  }),
  "/scans/p2-unreachable": p2Scan("p2-unreachable", {
    scan_no: 1044,
    target: "10.20.0.50",
    results: {
      phase1: { data: [P2_UNREACHABLE_HOST] },
      phase2: {
        data: [P2_UNREACHABLE_HOST],
        summary: {
          total_hosts: 1,
          active_hosts: 0,
          inactive_hosts: 1,
          hosts_with_ports: 0,
          scan_duration: 12.5,
          phase: 2,
          status: "unreachable",
        },
      },
    },
  }),
  "/scans/p2-no-results": {
    id: "p2-no-results",
    scan_no: 1045,
    status: "failed",
    failure_reason:
      "Port scan did not complete: the scanner worker was stopped.",
    results: { phase1: { data: P2_PHASE1_HOSTS }, phase2: {} },
  },
  "/scans/p2-missing": { __status: 404, body: { detail: "Scan not found" } },
  "/scans/p2-running": {
    id: "p2-running",
    scan_no: 1046,
    status: "running",
    pipeline_mode: "asset",
    results: { phase1: { data: P2_PHASE1_HOSTS }, phase2: {} },
  },
};

/* The scan context a running asset discovery leaves in sessionStorage:
   discovered hosts, no port-scan results yet. */
export const P2_RUNNING_SESSION = {
  cc_scanId: "p2-running",
  cc_scanNo: 1046,
  cc_target: "10.20.0.0/28",
  cc_pipelineMode: "asset",
  cc_phase1Hosts: P2_PHASE1_HOSTS,
};
