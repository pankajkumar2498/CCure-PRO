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

/* ── Phase1Results (batch 19) ─────────────────────────────────────────────── */
/* Field names are the page's reads, checked against the host-discovery phase
   the orchestrator stores: hosts from `_format_host(...).to_basic_dict()` and
   the summary (`total_hosts`, `active_hosts`, `inactive_hosts`,
   `scan_duration`, `discovery_profile`, `discovery_intensity`, and the
   `fallback_*` counts written only at normal intensity). The summary has no
   status key, so an unreachable target is an active count of zero. */
const P1_HOSTS = [
  {
    ip_address: "10.20.0.11",
    hostname: "files-01",
    mac_address: "00:1A:2B:3C:4D:11",
    vendor: "Dell Inc.",
    discovery_method: "ARP",
    response_time_ms: 0.84,
    is_active: true,
  },
  {
    ip_address: "10.20.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mac_address: "00:1A:2B:3C:4D:12",
    vendor: "HP",
    discovery_method: "ICMP",
    response_time_ms: 3.27,
    is_active: true,
  },
  {
    ip_address: "10.20.0.13",
    hostname: "Unknown",
    netbios_names: [{ name: "KIOSK-07" }],
    mac_address: "N/A",
    vendor: "N/A",
    discovery_method: "TCP",
    response_time_ms: 12.5,
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
    response_time_ms: 1.9,
    is_active: true,
  },
];

const P1_SUMMARY = {
  total_hosts: 5,
  active_hosts: 4,
  inactive_hosts: 1,
  scan_duration: 12.84,
  phase: 1,
  scan_type: "ADAPTIVE",
  discovery_profile: "BALANCED",
  discovery_intensity: "normal",
  fallback_targets_count: 2,
  fallback_active_hosts: 1,
};

const P1_UNREACHABLE_HOST = {
  ip_address: "10.20.0.50",
  hostname: "Unknown",
  mac_address: "N/A",
  vendor: "N/A",
  discovery_method: "ICMP",
  is_active: false,
};

const p1Scan = (id, overrides = {}) => ({
  id,
  scan_no: 1101,
  target: "10.20.0.0/28",
  status: "complete",
  pipeline_mode: "basic",
  results: { phase1: { data: P1_HOSTS, summary: P1_SUMMARY } },
  ...overrides,
});

export const P1_STUBS = {
  // Host discovery only: completion banner and export panel.
  "/scans/p1-basic": p1Scan("p1-basic"),
  // Pipelines with a port scan still running. Phase 1 polls these every 4 s
  // in automatic mode and never navigates on its own.
  "/scans/p1-asset": p1Scan("p1-asset", {
    scan_no: 1102,
    status: "running",
    pipeline_mode: "asset",
    results: {
      phase1: { data: P1_HOSTS, summary: P1_SUMMARY },
      phase2: {},
    },
  }),
  "/scans/p1-audit": p1Scan("p1-audit", {
    scan_no: 1103,
    status: "running",
    pipeline_mode: "vulnerability_audit",
    results: {
      phase1: { data: P1_HOSTS, summary: P1_SUMMARY },
      phase2: {},
    },
  }),
  "/scans/p1-unreachable": p1Scan("p1-unreachable", {
    scan_no: 1104,
    target: "10.20.0.50",
    pipeline_mode: "asset",
    results: {
      phase1: {
        data: [P1_UNREACHABLE_HOST],
        summary: {
          total_hosts: 1,
          active_hosts: 0,
          inactive_hosts: 1,
          scan_duration: 6.02,
          phase: 1,
          discovery_profile: "FAST",
          discovery_intensity: "light",
        },
      },
    },
  }),
  "/scans/p1-no-results": {
    id: "p1-no-results",
    scan_no: 1105,
    status: "failed",
    failure_reason:
      "Host discovery did not complete: the scanner worker was stopped.",
    results: { phase1: {} },
  },
  "/scans/p1-missing": { __status: 404, body: { detail: "Scan not found" } },
};

/* Scan context left in sessionStorage by a live pipeline. Phase 1 computes its
   default host selection once, from the hosts in context at first render, so
   the interactive states seed the context rather than load from the URL. */
const P1_CONTEXT = {
  cc_scanNo: 1103,
  cc_target: "10.20.0.0/28",
  cc_phase1Hosts: P1_HOSTS,
  cc_phase1Summary: P1_SUMMARY,
};

export const P1_INTERACTIVE_SESSION = {
  ...P1_CONTEXT,
  cc_scanId: "p1-audit",
  cc_pipelineMode: "vulnerability_audit",
  cc_executionMode: "interactive",
  cc_portScanIntensity: "deep",
};

// Custom ports including a sensitive one, exclusions set, one invalid IP.
export const P1_SCOPE_SESSION = {
  ...P1_INTERACTIVE_SESSION,
  cc_portScanMode: "custom",
  cc_customPorts: "22,80,2375,8000-8010",
  cc_excludePorts: "2375, 6443",
  cc_excludeIps: "10.20.0.13,10.20.0.0/33",
};

// An asset discovery whose port scan has already finished.
export const P1_DONE_SESSION = {
  ...P1_CONTEXT,
  cc_scanId: "p1-asset",
  cc_scanNo: 1102,
  cc_pipelineMode: "asset",
  cc_phase2Results: [
    {
      ip_address: "10.20.0.11",
      is_active: true,
      open_ports: [{ port: 22, service: "ssh", risk: "Low" }],
    },
  ],
  cc_phase2Summary: { total_hosts: 4, hosts_with_ports: 1, scan_duration: 40 },
};

/* ── AMTIntegration (batch 20) ────────────────────────────────────────────── */
/* Field names are the page's reads, checked against the backend:
   `/assets/coverage-stats` returns these seven keys, and
   `/assets/reconciliation/drilldown` returns `{ total, skip, limit, data }`
   with `_serialize_asset` rows for the asset categories. The router matches
   paths, not query strings, so one drilldown answers every category and every
   page; the captures open Shadow IT, an asset category. The import and the CSV
   export are never exercised: the harness refuses every write, and no state
   or probe activates the file chooser, Upload & Sync or Export CSV. */
export const AMT_STATS = {
  configured: true,
  total_scanned: 40,
  total_inventory: 50,
  fully_audited: 36,
  shadow_it: 4,
  coverage_gap: 14,
  coverage_percentage: 72,
};

// What the backend returns before any inventory has been imported.
export const AMT_STATS_UNLINKED = {
  configured: false,
  total_scanned: 40,
  total_inventory: 0,
  fully_audited: 0,
  shadow_it: 40,
  coverage_gap: 0,
  coverage_percentage: 0,
};

const AMT_ASSETS = [
  {
    id: "amt-a-1",
    ip_address: "10.20.5.21",
    mac_address: "00:1A:2B:3C:5D:21",
    hostname: "kiosk-lobby-02",
    risk_score: 78,
    risk_level: "high",
    owner: null,
    first_seen_at: ago(12),
  },
  {
    id: "amt-a-2",
    ip_address: "10.20.5.34",
    mac_address: "00:1A:2B:3C:5D:34",
    hostname: null,
    risk_score: 41,
    risk_level: "medium",
    owner: "facilities",
    first_seen_at: ago(3),
  },
  {
    id: "amt-a-3",
    ip_address: "10.20.5.40",
    mac_address: null,
    hostname: "cam-dock-01",
    risk_score: 15,
    risk_level: "low",
    owner: null,
    first_seen_at: null,
  },
];

// 23 results, so the drilldown shows its page controls.
export const AMT_DRILLDOWN = {
  total: 23,
  skip: 0,
  limit: 10,
  data: AMT_ASSETS,
};

export const AMT_STUBS = {
  "/assets/coverage-stats": AMT_STATS,
  "/assets/reconciliation/drilldown": AMT_DRILLDOWN,
};

/* ── NetworkMap (batch 21) ────────────────────────────────────────────────── */
/* Field names follow core.topology.engine.get_topology_graph (graph_version
   3): canonical endpoint ids, host evidence (`source_key`, `source_port`,
   `link_type`) and typed links carrying `link_details`. The router matches
   paths, not query strings, so one payload answers every mask and window.
   Three subnets keep Expand All below the 15-subnet confirmation, which would
   open a native dialog. Collapsed, the graph shows 7 nodes (4 infrastructure,
   3 subnets); expanded, 14. */

// Signed in, without scans:read. The routes check sign-in only; the backend
// refuses the topology read with this detail (auth/rbac.py).
export const NO_SCANS_READ = persona(
  BASE_PERMISSIONS.filter((p) => p !== "scans:read"),
);

const NM_SUBNET_1 = "10.40.1.0/24";
const NM_SUBNET_2 = "10.40.2.0/24";
const NM_MAC_ONLY = "MAC-Only / FDB";

const nmHost = (subnet, fields) => ({
  tier: "host",
  subnet,
  source_key: "ip:10.40.0.2",
  source_label: "dist-sw-01",
  asset_id: null,
  asset_match_status: "unmatched",
  ...fields,
});

export const NM_TOPOLOGY = {
  success: true,
  graph_version: 3,
  nodes: [
    {
      id: "ip:10.40.0.1",
      label: "core-rtr-01",
      group: "router",
      tier: "infra",
      ip: "10.40.0.1",
      mac: "00:1B:54:10:00:01",
      asset_id: "nm-ast-1",
    },
    {
      id: "ip:10.40.0.2",
      label: "dist-sw-01",
      group: "switch",
      tier: "infra",
      ip: "10.40.0.2",
      mac: "00:1B:54:10:00:02",
      asset_id: null,
    },
    {
      id: "ip:10.40.0.3",
      label: "edge-fw-01",
      group: "firewall",
      tier: "infra",
      ip: "10.40.0.3",
      mac: "",
      asset_id: null,
    },
    {
      id: "ip:10.40.0.10",
      label: "app-srv-01",
      group: "server",
      tier: "infra",
      ip: "10.40.0.10",
      mac: "00:1B:54:10:00:0A",
      asset_id: "nm-ast-2",
    },
    {
      id: `subnet:${NM_SUBNET_1}`,
      label: `${NM_SUBNET_1}\n(4 hosts)`,
      group: "subnet",
      tier: "subnet",
      subnet: NM_SUBNET_1,
      host_count: 4,
      data_quality: {
        ip_resolved: 4,
        mac_only: 0,
        asset_matches: 1,
        source_count: 1,
        has_arp: true,
        has_fdb: false,
      },
      recommended_actions: ["Enable LLDP/CDP on infrastructure devices"],
    },
    {
      id: `subnet:${NM_SUBNET_2}`,
      label: `${NM_SUBNET_2}\n(3 hosts)`,
      group: "subnet",
      tier: "subnet",
      subnet: NM_SUBNET_2,
      host_count: 3,
      data_quality: {
        ip_resolved: 3,
        mac_only: 0,
        asset_matches: 0,
        source_count: 1,
        has_arp: false,
        has_fdb: false,
      },
      recommended_actions: [],
    },
    {
      id: `subnet:${NM_MAC_ONLY}`,
      label: "MAC-only endpoints\n2 devices",
      group: "subnet",
      tier: "subnet",
      subnet: NM_MAC_ONLY,
      host_count: 2,
      data_quality: {
        ip_resolved: 0,
        mac_only: 2,
        asset_matches: 0,
        source_count: 1,
        has_arp: false,
        has_fdb: true,
      },
      recommended_actions: [
        "Run ARP-enabled scan",
        "Correlate with asset inventory",
      ],
    },
    nmHost(NM_SUBNET_1, {
      id: "00:1A:2B:40:01:11",
      label: "fin-ws-11",
      group: "workstation",
      ip: "10.40.1.11",
      mac: "00:1A:2B:40:01:11",
      vendor: "Dell Inc.",
      source_port: "Gi1/0/11",
      source_port_desc: "Finance desk 11",
      link_type: "arp",
      vlan_id: 110,
      speed_bps: 1000000000,
      asset_id: "nm-ast-3",
      asset_match_status: "matched",
    }),
    nmHost(NM_SUBNET_1, {
      id: "00:1A:2B:40:01:12",
      label: "fin-pc-12",
      group: "desktop",
      ip: "10.40.1.12",
      mac: "00:1A:2B:40:01:12",
      vendor: "HP",
      source_port: "Gi1/0/12",
      link_type: "arp",
      vlan_id: 110,
      speed_bps: 1000000000,
    }),
    nmHost(NM_SUBNET_1, {
      id: "00:1A:2B:40:01:20",
      label: "10.40.1.20",
      group: "printer",
      ip: "10.40.1.20",
      mac: "00:1A:2B:40:01:20",
      vendor: "Brother",
      source_port: "Gi1/0/20",
      link_type: "arp",
      speed_bps: 100000000,
    }),
    nmHost(NM_SUBNET_1, {
      id: "00:1A:2B:40:01:30",
      label: "lobby-cam-30",
      group: "camera",
      ip: "10.40.1.30",
      mac: "00:1A:2B:40:01:30",
      vendor: "Axis",
      source_port: "Gi1/0/30",
      link_type: "arp",
      speed_bps: 10000000,
    }),
    nmHost(NM_SUBNET_2, {
      id: "00:1A:2B:40:02:14",
      label: "ops-lt-14",
      group: "laptop",
      ip: "10.40.2.14",
      mac: "00:1A:2B:40:02:14",
      vendor: "Lenovo",
      source_port: "Gi1/0/34",
      link_type: "lldp",
      speed_bps: 1000000000,
    }),
    nmHost(NM_SUBNET_2, {
      id: "00:1A:2B:40:02:15",
      label: "ops-ph-15",
      group: "mobile",
      ip: "10.40.2.15",
      mac: "00:1A:2B:40:02:15",
      vendor: "Samsung",
      source_port: "Gi1/0/35",
      link_type: "lldp",
    }),
    nmHost(NM_SUBNET_2, {
      id: "00:1A:2B:40:02:40",
      label: "hvac-ctl-40",
      group: "iot",
      ip: "10.40.2.40",
      mac: "00:1A:2B:40:02:40",
      vendor: "Honeywell",
      source_port: "Gi1/0/40",
      link_type: "lldp",
    }),
    nmHost(NM_MAC_ONLY, {
      id: "00:1A:2B:40:FF:01",
      label: "00:1A:2B:40:FF:01",
      group: "unknown",
      ip: "",
      mac: "00:1A:2B:40:FF:01",
      vendor: "",
      source_port: "Gi1/0/47",
      link_type: "fdb",
    }),
    nmHost(NM_MAC_ONLY, {
      id: "00:1A:2B:40:FF:02",
      label: "00:1A:2B:40:FF:02",
      group: "unknown",
      ip: "",
      mac: "00:1A:2B:40:FF:02",
      vendor: "",
      source_port: "Gi1/0/48",
      link_type: "fdb",
    }),
  ],
  edges: [
    {
      id: "edge:ip:10.40.0.1:ip:10.40.0.2",
      from: "ip:10.40.0.1",
      to: "ip:10.40.0.2",
      tier: "infra",
      link_type: "lldp",
      observed_types: "lldp,arp",
      source_port_desc: "Te0/1/0",
      target_port: "Te1/1/1",
      vlan_id: 1,
      speed_bps: 10000000000,
    },
    {
      id: "edge:ip:10.40.0.2:ip:10.40.0.3",
      from: "ip:10.40.0.2",
      to: "ip:10.40.0.3",
      tier: "infra",
      link_type: "cdp",
      source_port: "Gi1/0/1",
      target_port: "eth1",
      speed_bps: 1000000000,
    },
    {
      id: "edge:ip:10.40.0.2:ip:10.40.0.10",
      from: "ip:10.40.0.2",
      to: "ip:10.40.0.10",
      tier: "infra",
      link_type: "edp",
      source_port: "Gi1/0/2",
      speed_bps: 1000000000,
    },
    {
      id: `edge:ip:10.40.0.2:subnet:${NM_SUBNET_1}`,
      from: "ip:10.40.0.2",
      to: `subnet:${NM_SUBNET_1}`,
      tier: "subnet",
      link_type: "arp",
      host_count: 4,
      source_port: "Gi1/0/11, Gi1/0/12, Gi1/0/20, Gi1/0/30",
      link_details: {
        type_counts: { arp: 4 },
        summary: "arp: 4",
        ports: ["Gi1/0/11", "Gi1/0/12", "Gi1/0/20", "Gi1/0/30"],
      },
    },
    {
      id: `edge:ip:10.40.0.2:subnet:${NM_SUBNET_2}`,
      from: "ip:10.40.0.2",
      to: `subnet:${NM_SUBNET_2}`,
      tier: "subnet",
      link_type: "lldp",
      host_count: 3,
      source_port: "Gi1/0/34, Gi1/0/35, Gi1/0/40",
      link_details: {
        type_counts: { lldp: 3 },
        summary: "lldp: 3",
        ports: ["Gi1/0/34", "Gi1/0/35", "Gi1/0/40"],
      },
    },
    {
      id: `edge:ip:10.40.0.2:subnet:${NM_MAC_ONLY}`,
      from: "ip:10.40.0.2",
      to: `subnet:${NM_MAC_ONLY}`,
      tier: "subnet",
      link_type: "fdb",
      host_count: 2,
      source_port: "Gi1/0/47, Gi1/0/48",
      link_details: { type_counts: { fdb: 2 }, summary: "fdb: 2" },
    },
  ],
  subnets: [NM_SUBNET_1, NM_SUBNET_2, NM_MAC_ONLY],
  stats: {
    infrastructure: 4,
    subnets: 3,
    hosts: 9,
    mac_only: 2,
    asset_matched: 1,
    links: 6,
  },
};

export const NM_EMPTY = {
  success: true,
  graph_version: 3,
  nodes: [],
  edges: [],
  subnets: [],
  stats: { infrastructure: 0, subnets: 0, hosts: 0 },
};

export const NM_STUBS = {
  "/topology/map": NM_TOPOLOGY,
  "/topology/map/nm-scan-7": NM_TOPOLOGY,
};

/* ── ScanHistory (batch 22) ───────────────────────────────────────────────── */
/* Field names are the page's reads from GET /scans and GET /scans/{id}. The
   router matches paths, so `/scans` answers every filter.

   `/scans/events` answers with a finite replay of the backend's stream —
   `connected`, a `scans` snapshot, a `heartbeat` — and then the response
   ends. The page treats an ended stream as a failure: it reconnects once
   2.5 s later, receives the same replay, and on the second end falls back to
   polling GET /scans every 5 s. Every capture therefore settles on "Live sync
   polling", which is deterministic, while still exercising the stream's
   request and its event parsing.

   No state or probe archives, deletes, re-runs or stops a scan. The harness
   refuses every write, and the probes only Tab to those controls; opening the
   re-run and stop confirmations sends nothing. */
export const SCANS_ADMIN = persona([
  ...BASE_PERMISSIONS,
  "scans:archive",
  "scans:recycle",
]);

const shScan = (no, fields = {}) => ({
  id: `sh-${no}`,
  scan_no: no,
  target: `10.30.1.${no - 2100}`,
  scan_type: "network",
  pipeline_mode: "basic",
  phase: 1,
  status: "complete",
  scan_duration: 42.5,
  progress_percentage: 100,
  summary: { active_hosts: 3 },
  created_by: 202,
  started_by: { user_id: 202, display_name: "Priya Nair" },
  started_at: ago(10),
  completed_at: ago(10),
  updated_at: ago(10),
  ...fields,
});

const SH_MINE = {
  created_by: 101,
  started_by: { user_id: 101, display_name: "Harness Operator" },
};

export const SH_SCANS = [
  shScan(2116, {
    status: "running",
    pipeline_mode: "vulnerability_audit",
    phase: 2,
    progress_percentage: 66,
    scan_duration: 640.2,
    summary: { active_hosts: 4 },
    started_at: ago(1 / 48),
    completed_at: null,
    ...SH_MINE,
  }),
  shScan(2115, {
    status: "running",
    pipeline_mode: "asset",
    phase: 1,
    progress_percentage: 40,
    scan_duration: 95.8,
    summary: { active_hosts: 7, vulnerabilities: 3 },
    target: "10.30.2.0/24",
    started_at: ago(1 / 96),
    completed_at: null,
  }),
  shScan(2114, {
    scan_duration: 38.4,
    summary: { active_hosts: 12 },
    completed_at: ago(1 / 48),
    ...SH_MINE,
  }),
  shScan(2113, {
    pipeline_mode: "asset",
    phase: 2,
    scan_duration: 312.6,
    summary: { active_hosts: 9 },
    completed_at: ago(0.25),
  }),
  shScan(2112, {
    status: "failed",
    pipeline_mode: "vulnerability_audit",
    phase: 3,
    scan_duration: 1204,
    summary: {},
    completed_at: ago(1),
  }),
  shScan(2111, {
    status: "unreachable",
    scan_duration: 4.1,
    summary: { active_hosts: 0 },
    completed_at: ago(2),
  }),
  shScan(2110, {
    status: "cancelled",
    pipeline_mode: "asset",
    phase: 2,
    completed_at: ago(3),
    ...SH_MINE,
  }),
  shScan(2109, {
    scan_type: "credentialed",
    pipeline_mode: null,
    completed_at: ago(4),
  }),
  shScan(2108, {
    target: "10.30.1.8, 10.30.1.80",
    targets: ["10.30.1.8", "10.30.1.80"],
    completed_at: ago(5),
  }),
  shScan(2107, { status: "canceled", completed_at: ago(6) }),
  shScan(2106, {
    pipeline_mode: "asset",
    phase: 2,
    completed_at: ago(8),
  }),
  shScan(2105, { status: "failed", completed_at: ago(9) }),
  shScan(2104, {
    pipeline_mode: "vulnerability_audit",
    phase: 3,
    completed_at: ago(12),
  }),
  shScan(2103, {
    status: "unreachable",
    pipeline_mode: "asset",
    completed_at: ago(15),
  }),
  shScan(2102, { completed_at: ago(20) }),
  shScan(2101, { completed_at: ago(28) }),
];

const SH_DETAIL = {
  ...SH_SCANS[2],
  summary: {
    scan_duration: 38.4,
    active_hosts: 12,
    hosts_scanned: 254,
    coverage_percent: 100,
  },
  results: {
    phase1: {
      data: [
        {
          is_active: true,
          ip_address: "10.30.1.21",
          hostname: "files-01",
          mac_address: "00:1A:2B:3C:4D:21",
          vendor: "Dell Inc.",
          host_risk_level: "High",
          host_risk_score: 7.8,
          open_ports: [
            { port: 22, service: "ssh" },
            { port: 445, service: "microsoft-ds" },
          ],
          cves: [
            {
              cve_id: "CVE-2024-6387",
              severity: "High",
              description: "OpenSSH signal handler race condition",
            },
          ],
          suppressed_cves: [{ cve_id: "CVE-2023-38408" }],
        },
        {
          is_active: true,
          ip_address: "10.30.1.40",
          hostname: "Unknown",
          mac_address: "00:1A:2B:3C:4D:40",
          vendor: "HP",
          open_ports: [],
        },
      ],
    },
  },
};

const eventStream = (events) =>
  events
    .map(([name, data]) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`)
    .join("");

const shStream = (scans) => ({
  __eventStream: eventStream([
    ["connected", { scope: "active" }],
    ["scans", { scans, total: scans.length, skip: 0, limit: 200 }],
    ["heartbeat", { ts: ago(0) }],
  ]),
});

export const SH_STUBS = {
  "/scans": { scans: SH_SCANS, total: SH_SCANS.length, skip: 0, limit: 200 },
  "/scans/events": shStream(SH_SCANS),
  "/scans/sh-2114": SH_DETAIL,
};

export const SH_STUBS_EMPTY = {
  "/scans": { scans: [], total: 0, skip: 0, limit: 200 },
  "/scans/events": shStream([]),
};

/* ── CredentialedResults (batch 23) ─────────────────────────────────────────
   A credentialed report is credential-derived output, so every value here is
   synthetic. The flagged environment variables carry obviously fake "hx-"
   values; the page masks them, and the expanded states wait for the masked
   form while asserting the unmasked value never reaches the document.

   Only the running states follow a live scan. They answer the ticket with a
   fixed placeholder (router.mjs) and replace WebSocket, on this page alone,
   with a scripted socket that replays recorded progress frames. No real
   socket is opened and no scan is started. */
export const CR_TICKET = "harness-ticket";
export const CR_SECRETS = [
  "hx-aws-secret-9f2c",
  "hx-token-77aa",
  "hx-dbpass-42",
];

const CR_LINUX = {
  target: "10.40.2.21",
  username: "auditor",
  scan_duration: 48.2,
  detected_os: "linux",
  os_type_was_auto: true,
  system_info: {
    os_name: "Ubuntu 22.04.4 LTS",
    os_version_id: "22.04",
    kernel_version: "5.15.0-105-generic",
    hostname: "web-01",
    manufacturer: "Dell Inc.",
    hardware_model: "PowerEdge R640",
    cpu_model: "Intel Xeon Silver 4214",
    cpu_count: 24,
    cpu_arch: "x86_64",
    uptime: "12 days, 4:11",
    serial_number: "HX-SN-0021",
    bios_version: "2.19.1",
    mac_address: "00:1A:2B:3C:4D:21",
    subnet: "10.40.2.0/24",
    domain: "corp.test",
    fqdn: "web-01.corp.test",
    memory_summary: { total: "64 GiB", used: "21 GiB" },
    disk_usage: [
      {
        filesystem: "/dev/sda1",
        size: "200G",
        used: "170G",
        available: "30G",
        use_pct: "85%",
        mounted_on: "/",
      },
      {
        filesystem: "/dev/sdb1",
        size: "1.0T",
        used: "100G",
        available: "900G",
        use_pct: "10%",
        mounted_on: "/data",
      },
    ],
  },
  packages: [
    { name: "openssl", version: "3.0.2-0ubuntu1.10", manager: "dpkg" },
    { name: "sudo", version: "1.9.9-1ubuntu2.3", manager: "dpkg" },
    { name: "openssh-server", version: "1:8.9p1-3ubuntu0.6", manager: "dpkg" },
    { name: "bash", version: "5.1-6ubuntu1", manager: "dpkg" },
  ],
  package_count: 4,
  running_services: [
    {
      name: "ssh.service",
      sub_state: "running",
      description: "OpenBSD Secure Shell server",
    },
    {
      name: "cron.service",
      description: "Regular background program processing daemon",
    },
  ],
  open_ports_credentialed: [
    {
      port: 22,
      local_addr: "0.0.0.0",
      state: "LISTEN",
      process: "sshd",
      pid: 812,
      product: "OpenSSH",
      version: "8.9p1",
      exposure: "exposed",
    },
    {
      port: 5432,
      local_addr: "127.0.0.1",
      process: "postgres",
      exposure: "host_only",
    },
    {
      port: 8080,
      local_addr: "0.0.0.0",
      process: "java",
      pid: 1200,
      product: "Apache Tomcat",
      exposure: "filtered",
    },
    { port: 9100, local_addr: "0.0.0.0", process: "node_exporter" },
  ],
  users: [
    {
      username: "root",
      uid: 0,
      shell: "/bin/bash",
      home: "/root",
      is_root: true,
      is_system: true,
    },
    {
      username: "daemon",
      uid: 1,
      shell: "/usr/sbin/nologin",
      home: "/usr/sbin",
      is_system: true,
    },
    { username: "alice", uid: 1000, shell: "/bin/bash", home: "/home/alice" },
  ],
  suid_binaries: ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/mount"],
  world_writable_dirs: ["/tmp", "/var/tmp"],
  sudo_nopasswd: true,
  sudo_rules_raw: "alice ALL=(ALL) NOPASSWD: ALL",
  security_issues: [
    "PermitRootLogin is enabled in sshd_config",
    "Password authentication is enabled for SSH",
  ],
  failed_login_count: 37,
  brute_force_warning: true,
  failed_logins_recent: [
    "Sep 11 09:12:01 web-01 sshd[2211]: Failed password for root from 10.9.9.9",
    "Sep 11 09:12:05 web-01 sshd[2213]: Failed password for root from 10.9.9.9",
  ],
  network_interfaces_raw: JSON.stringify([
    {
      ifname: "eth0",
      address: "00:1a:2b:3c:4d:21",
      operstate: "up",
      addr_info: [{ family: "inet", local: "10.40.2.21", prefixlen: 24 }],
    },
  ]),
  env_vars_flagged: [
    `AWS_SECRET_ACCESS_KEY=${CR_SECRETS[0]}`,
    `API_TOKEN: ${CR_SECRETS[1]}`,
    `DATABASE_URL=postgres://auditor:${CR_SECRETS[2]}@db/prod`,
  ],
  cves: [
    {
      cve_id: "CVE-2024-6387",
      severity: "Critical",
      cvss_score: 8.1,
      package: "openssh-server",
      installed_ver: "8.9p1",
      fixed_ver: "8.9p1-3ubuntu0.10",
      description: "Signal handler race condition in sshd",
    },
    {
      cve_id: "CVE-2023-0286",
      severity: "High",
      cvss_score: 7.4,
      package: "openssl",
      installed_ver: "3.0.2",
      fixed_ver: "3.0.2-0ubuntu1.8",
      description: "X.400 address type confusion in X.509 GeneralName",
    },
    {
      cve_id: "CVE-2023-2650",
      severity: "Medium",
      cvss_score: 6.5,
      package: "openssl",
      installed_ver: "3.0.2",
      description: "Possible DoS translating ASN.1 object identifiers",
    },
    {
      cve_id: "CVE-2023-22809",
      severity: "Low",
      cvss_score: 3.9,
      package: "sudo",
      installed_ver: "1.9.9",
      description: "sudoedit mishandles extra arguments",
    },
  ],
  cve_count: 4,
  severity_summary: { Critical: 1, High: 1, Medium: 1, Low: 1 },
  hardening_audits: {
    aslr: {
      label: "ASLR",
      status: "PASS",
      detail: "kernel.randomize_va_space = 2",
    },
    ssh_root: {
      label: "SSH root login",
      status: "FAIL",
      detail: "PermitRootLogin yes",
    },
    auditd: { label: "auditd", status: "WARN", detail: "Service not running" },
  },
  cron_info_raw: "0 3 * * * root /usr/local/bin/backup.sh",
  local_groups: [
    { name: "sudo", gid: "27", members: ["alice"] },
    { name: "docker", gid: "998", members: [] },
  ],
  coverage: {
    authenticated_checks: "Packages, users, services and configuration",
    unauthenticated_checks: "Not performed by this policy",
    network_reachability: "Correlated with the port scan",
    port_range: "1-1024 and 1,103 curated high ports",
    service_detection: "Version probes",
    os_detection: "Authenticated",
    discovery_scan_method: "ICMP echo",
  },
  exposure_summary: {
    correlated_with_port_scan: true,
    listeners_exposed: 1,
    listeners_filtered: 1,
    listeners_host_only: 1,
  },
  collection_errors: { cron: "permission denied reading /var/spool/cron" },
  inventory_complete: false,
};

const CR_WINDOWS = {
  target: "10.40.2.30",
  username: "CORP\\auditor",
  scan_duration: 61.7,
  detected_os: "windows",
  system_info: {
    os_name: "Microsoft Windows 11 Pro",
    os_version_id: "10.0.26200",
    os_build: "26200.6584",
    hostname: "ws-30",
    manufacturer: "Lenovo",
    hardware_model: "ThinkCentre M90q",
    cpu_model: "Intel Core i7-10700T",
    cpu_count: 16,
    cpu_arch: "x64",
    domain: "corp.test",
  },
  packages: [{ name: "7-Zip 23.01", version: "23.01", manager: "registry" }],
  package_count: 1,
  users: [
    {
      username: "Administrator",
      is_admin: true,
      enabled: "True",
      pwd_required: "True",
      last_logon: "2026-09-10 08:00",
    },
    {
      username: "Guest",
      is_admin: false,
      enabled: "False",
      pwd_required: "False",
      last_logon: "None",
    },
    {
      username: "jdoe",
      is_admin: "false",
      enabled: "true",
      pwd_required: "false",
      last_logon: null,
    },
  ],
  local_groups: [
    { name: "Administrators", gid: "S-1-5-32-544", members: ["Administrator"] },
  ],
  suspicious_scheduled_tasks: [
    { TaskName: "VendorUpdater", TaskPath: "\\Vendor\\", State: "Ready" },
    { TaskName: "LegacySync", TaskPath: "\\", State: "Disabled" },
  ],
  network_interfaces_raw: JSON.stringify({
    InterfaceAlias: "Ethernet",
    IPAddress: "10.40.2.30",
    PrefixLength: 24,
    MacAddress: "00-1A-2B-3C-4D-30",
    InterfaceDescription: "Intel Ethernet Connection I219-LM",
  }),
  cves: [],
  cve_count: 0,
  severity_summary: {},
  failed_login_count: 0,
};

const CR_EMPTY = {
  target: "10.40.2.50",
  username: "auditor",
  scan_duration: 22.4,
  detected_os: "linux",
  system_info: { os_name: "Debian GNU/Linux 12", hostname: "idle-50" },
  cves: [],
  cve_count: 0,
  severity_summary: {},
};

const crRecord = (id, scanNo, credentialed, fields = {}) => ({
  id,
  scan_no: scanNo,
  status: "complete",
  results: { credentialed },
  ...fields,
});

export const CR_STUBS = {
  "/scans/cr-report": crRecord("cr-report", 3107, {
    report: CR_LINUX,
    reports: [CR_LINUX, CR_WINDOWS],
    hosts_failed: [
      {
        target: "10.40.2.40",
        reason: "Authentication failed for the supplied account",
      },
    ],
  }),
  "/scans/cr-windows": crRecord("cr-windows", 3108, {
    report: CR_WINDOWS,
    reports: [CR_WINDOWS],
  }),
  "/scans/cr-empty": crRecord("cr-empty", 3109, {
    report: CR_EMPTY,
    reports: [CR_EMPTY],
  }),
  "/scans/cr-run": { id: "cr-run", scan_no: 3110, status: "running" },
  "/scans/cr-fallback": { id: "cr-fallback", scan_no: 3111, status: "running" },
  "/scans/cr-load": { __pending: true },
  "/scans/cr-failed": {
    id: "cr-failed",
    scan_no: 3112,
    status: "failed",
    failure_reason: "Authentication failed for user auditor",
  },
  "/scans/cr-unreachable": {
    id: "cr-unreachable",
    scan_no: 3113,
    status: "failed",
    failure_reason: "No route to host 10.40.2.30",
  },
  "/scans/cr-error": { __status: 500 },
  "/scans/cr-denied": {
    __status: 403,
    body: {
      detail:
        "Insufficient privileges. Your role 'analyst' does not have 'scans:read' permission.",
    },
  },
};

export const CR_FRAMES = [
  {
    phase: 5,
    progress: {
      percentage: 12,
      stage: "connecting",
      status: "running",
      message: "Opening SSH session to 10.40.2.21",
    },
  },
  {
    phase: 5,
    progress: {
      percentage: 28,
      stage: "detection",
      status: "running",
      message: "Detected Ubuntu 22.04.4 LTS",
    },
  },
  {
    phase: 5,
    progress: {
      percentage: 46,
      stage: "collection",
      status: "running",
      message: "Reading crontab failed: permission denied",
    },
  },
  {
    phase: 5,
    progress: {
      percentage: 58,
      stage: "collection",
      status: "running",
      message: "Collected 1,284 installed packages",
    },
  },
];

/**
 * Replaces WebSocket for the credentialed results page only. The socket
 * records the URL it was given (so a state can assert the ticket and path),
 * replays `frames` a few milliseconds apart and then stays open — or, with
 * `close`, drops after the last frame, which is the page's cue to poll.
 */
export const crSocketScript = ({ frames, close = false }) => `(() => {
  if (!/^\\/scan\\/credentialed\\/results$/.test(location.pathname)) return;
  const FRAMES = ${JSON.stringify(frames)};
  const opened = (window.__harnessSockets = []);
  class HarnessSocket {
    constructor(url) {
      this.url = String(url);
      this.readyState = 1;
      opened.push(this.url);
      FRAMES.forEach((frame, i) => {
        setTimeout(() => {
          if (this.readyState !== 1) return;
          if (this.onmessage) this.onmessage({ data: JSON.stringify(frame) });
          if (${close ? "true" : "false"} && i === FRAMES.length - 1) {
            this.readyState = 3;
            window.__harnessSocketClosed = true;
            if (this.onclose) this.onclose({ code: 1006, wasClean: false });
          }
        }, 40 * (i + 1));
      });
    }
    send() {}
    close() {
      if (this.readyState === 3) return;
      this.readyState = 3;
      setTimeout(() => {
        if (this.onclose) this.onclose({ code: 1000, wasClean: true });
      }, 0);
    }
  }
  HarnessSocket.CONNECTING = 0;
  HarnessSocket.OPEN = 1;
  HarnessSocket.CLOSING = 2;
  HarnessSocket.CLOSED = 3;
  window.WebSocket = HarnessSocket;
})();`;

/* ── Phase3Results (batch 24) ───────────────────────────────────────────────
   Phase 3 starts the port scan and the audit from an effect on mount, which is
   why guard.mjs blocks its routes. The p3- states opt out of that one block
   (`allowPhase3`) and nothing else:

   * Seeded states put the scan context where the page's own guards keep it
     from starting anything: a finished report, a running, failed or cancelled
     pipeline, discovery with no live host — or an operator without
     `scans:execute`, whom the page refuses before it requests anything.
   * Pipeline states let it start. The router answers exactly the writes the
     state declares — the two dispatch triggers — and the ticket, with fixed
     placeholders, and refuses every other write; the progress socket is
     scripted (p3SocketScript). Nothing leaves the browser and no scan runs.

   Every value is synthetic. The weak FTP credential's password is the short,
   low-entropy `notreal`, which the page must never render. */
const P3_PHASE1_HOSTS = [
  {
    ip_address: "10.60.0.11",
    hostname: "web-01",
    mac_address: "00:1A:2B:3C:5D:11",
    vendor: "Dell Inc.",
    discovery_method: "ARP",
    is_active: true,
  },
  {
    ip_address: "10.60.0.12",
    hostname: "Unknown",
    mdns_name: "printer-3f.local",
    mac_address: "00:1A:2B:3C:5D:12",
    vendor: "HP",
    discovery_method: "ICMP",
    is_active: true,
  },
  {
    ip_address: "10.60.0.13",
    hostname: "Unknown",
    netbios_names: [{ name: "KIOSK-09" }],
    discovery_method: "TCP",
    is_active: true,
  },
  {
    ip_address: "10.60.0.14",
    hostname: "Unknown",
    discovery_method: "ICMP",
    is_active: false,
  },
];

const P3_PHASE1_SUMMARY = {
  total_hosts: 4,
  active_hosts: 3,
  inactive_hosts: 1,
  scan_duration: 11.8,
};

const P3_PHASE2_HOSTS = [
  {
    ip_address: "10.60.0.11",
    hostname: "web-01",
    is_active: true,
    open_ports: [
      { port: 21, service: "ftp" },
      { port: 22, service: "ssh" },
      { port: 443, service: "https" },
    ],
    os_fingerprint_full: { os: "Linux 5.x" },
  },
  {
    ip_address: "10.60.0.12",
    hostname: "Unknown",
    mdns_name: "printer-3f.local",
    is_active: true,
    open_ports: [{ port: 9100, service: "jetdirect" }],
    os_guess: "HP embedded",
  },
  {
    ip_address: "10.60.0.14",
    hostname: "Unknown",
    is_active: false,
    open_ports: [],
  },
];

const P3_PHASE2_SUMMARY = {
  total_hosts: 3,
  hosts_with_ports: 2,
  scan_duration: 38.4,
};

const P3_AUDIT_HOSTS = [
  {
    ip_address: "10.60.0.11",
    hostname: "web-01",
    is_active: true,
    os_guess: "Ubuntu 22.04",
    open_ports: [{ port: 21 }, { port: 22 }, { port: 443 }],
    device_category: "server",
    device_category_signal: "banner",
    credentialed: true,
    exposure_summary: {
      correlated_with_port_scan: true,
      listeners_exposed: 2,
      listeners_host_only: 1,
    },
    host_risk_level: "Critical",
    cves: [
      {
        cve_id: "CVE-2024-6387",
        severity: "Critical",
        cvss_score: 8.1,
        description: "Signal handler race condition in sshd",
        affected_software: "OpenSSH 8.9p1",
      },
      {
        cve_id: "CVE-2023-0286",
        severity: "High",
        cvss_score: 7.4,
        description: "X.400 address type confusion in X.509 GeneralName",
      },
      {
        cve_id: "CVE-2023-2650",
        severity: "Medium",
        cvss_score: 6.5,
        description: "Possible DoS translating ASN.1 object identifiers",
      },
      {
        cve_id: "CVE-2023-22809",
        severity: "Low",
        cvss_score: 3.9,
        description: "sudoedit mishandles extra arguments",
      },
    ],
    heartbleed_info: { vulnerable: true },
    ldap_info: { anonymous_bind: { allowed: true } },
    ftp_info: {
      open: true,
      banner: "220 ProFTPD 1.3.5 Server (Harness) [10.60.0.11]",
      issues: ["Anonymous login allowed", "Plain-text authentication"],
      anonymous_login: true,
      write_access: true,
      weak_credentials: [{ user: "ftpuser", password: "notreal" }],
    },
    http_audit: {
      server_header: "nginx/1.18.0 (Ubuntu)",
      issues: [
        "Missing Content-Security-Policy",
        "Missing Strict-Transport-Security",
        "Missing X-Frame-Options",
      ],
      exposed_paths: [
        { path: "/.git/config", status: 200, note: "repository metadata" },
        { path: "/backup/", status: 200, note: "directory listing" },
      ],
      admin_panels: [
        { product: "Tomcat Manager", path: "/manager/html", status: 401 },
      ],
      dangerous_methods: ["PUT", "DELETE"],
    },
    tls_info: { cert_expired: true },
    smb_info: { open: true, null_session: true },
  },
  {
    ip_address: "10.60.0.12",
    hostname: "Unknown",
    is_active: true,
    os_guess: "HP embedded",
    open_ports: [{ port: 9100 }],
    snmp_device_type: "printer",
    host_risk_level: "Low",
    cves: [],
  },
  {
    ip_address: "10.60.0.14",
    hostname: "Unknown",
    is_active: false,
    device_category: "unknown",
    cves: [],
  },
];

const P3_AUDIT_SUMMARY = {
  total_hosts: 3,
  critical_hosts: 1,
  high_risk_hosts: 0,
  scan_duration: 84.6,
  credentialed_hosts: 1,
  credentialed_skipped: [
    { target: "10.60.0.12", reason: "No credential matched this host" },
  ],
};

const p3Session = (scanId, extra = {}) => ({
  cc_scanId: scanId,
  cc_scanNo: 3301,
  cc_target: "10.60.0.0/28",
  cc_pipelineMode: "vulnerability_audit",
  cc_intensity: "normal",
  cc_phase1Hosts: P3_PHASE1_HOSTS,
  cc_phase1Summary: P3_PHASE1_SUMMARY,
  cc_pipelineState: "DISCOVERY",
  ...extra,
});

export const P3_REPORT_SESSION = p3Session("p3-report", {
  cc_pipelineState: "REPORT_READY",
  cc_phase2Results: P3_PHASE2_HOSTS,
  cc_phase2Summary: P3_PHASE2_SUMMARY,
  cc_phase3AuditResults: P3_AUDIT_HOSTS,
  cc_phase3Summary: P3_AUDIT_SUMMARY,
  cc_pipelinePhaseTimings: { portScan: "38.4", vulnScan: "84.6" },
});

export const P3_RUNNING_SESSION = p3Session("p3-running", {
  cc_pipelineState: "VULN_SCAN",
  cc_phase2Results: P3_PHASE2_HOSTS,
  cc_phase2Summary: P3_PHASE2_SUMMARY,
  cc_pipelinePhaseTimings: { portScan: "38.4" },
});

export const P3_ERROR_SESSION = p3Session("p3-error", {
  cc_pipelineState: "ERROR",
  cc_pipelineError: {
    phase: "VULN_SCAN",
    message: "Vulnerability audit background task failed.",
  },
  cc_phase2Results: P3_PHASE2_HOSTS,
  cc_phase2Summary: P3_PHASE2_SUMMARY,
});

export const P3_CANCELLED_SESSION = p3Session("p3-cancelled", {
  cc_pipelineState: "CANCELLED",
  cc_phase2Results: P3_PHASE2_HOSTS,
  cc_phase2Summary: P3_PHASE2_SUMMARY,
});

export const P3_UNREACHABLE_SESSION = p3Session("p3-unreachable", {
  cc_phase1Hosts: P3_PHASE1_HOSTS.map((h) => ({ ...h, is_active: false })),
  cc_phase1Summary: {
    total_hosts: 4,
    active_hosts: 0,
    inactive_hosts: 4,
    scan_duration: 30.2,
  },
});

/* Discovery done, nothing else: the page starts the pipeline on mount. */
export const p3StartSession = (scanId) => p3Session(scanId);

export const P3_STUBS = {
  "/scans/p3-live": {
    id: "p3-live",
    scan_no: 3301,
    status: "complete",
    results: {
      phase2: { data: P3_PHASE2_HOSTS, summary: P3_PHASE2_SUMMARY },
      phase3: { data: P3_AUDIT_HOSTS, summary: P3_AUDIT_SUMMARY },
    },
    report_executive_path: "/reports/p3-live-executive.pdf",
    report_technical_path: "/reports/p3-live-technical.pdf",
  },
};

export const P3_TICKET = "harness-ticket";
export const P3_SECRET = "notreal";

export const P3_WRITES = {
  "POST /scan/asset-discovery": { success: true },
  "POST /scan/vulnerability-audit": { success: true },
};

/**
 * Replaces WebSocket on the Phase 3 routes only. Each socket the page opens
 * records its URL and whether the page closed it, and receives the frame at
 * its own position in `frames` — none for a phase that stays running.
 */
export const p3SocketScript = (frames) => `(() => {
  if (!/^\\/scan\\/(vulnerability-audit|[^/]+\\/phase3)$/.test(location.pathname)) return;
  const FRAMES = ${JSON.stringify(frames)};
  const opened = (window.__harnessSockets = []);
  class HarnessSocket {
    constructor(url) {
      this._record = { url: String(url), closed: false };
      this.readyState = 1;
      opened.push(this._record);
      const frame = FRAMES[opened.length - 1];
      if (frame) {
        setTimeout(() => {
          if (this.readyState === 1 && this.onmessage)
            this.onmessage({ data: JSON.stringify(frame) });
        }, 40);
      }
    }
    send() {}
    close() {
      this.readyState = 3;
      this._record.closed = true;
    }
  }
  HarnessSocket.CONNECTING = 0;
  HarnessSocket.OPEN = 1;
  HarnessSocket.CLOSING = 2;
  HarnessSocket.CLOSED = 3;
  window.WebSocket = HarnessSocket;
})();`;
