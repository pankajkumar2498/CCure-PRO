/**
 * CredentialedResults (`/scan/credentialed/results`) — Checkpoint 3C batch 23
 * baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 23 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The report comes from router state (a scan that has just finished) or from
 * GET /scans/{id} for `?scan_id=`. A scan that is not finished yet is followed
 * live: one POST /auth/ticket with no body, then one WebSocket at
 * `${baseURL with http→ws}/scans/{id}/progress?ticket=…`. Frames for phase 5
 * move the progress dashboard; a `complete` frame re-reads the scan record. A
 * socket that closes before results arrive, a refused ticket or a socket that
 * cannot be opened falls back to reading the record every 3 seconds until it
 * settles. Unmounting closes the socket and cancels any pending read.
 *
 * The page writes nothing else. Environment variables flagged by the collector
 * are masked by `maskSecretLine` before they are rendered; the exact output of
 * that rule, partial exposure included, is pinned below.
 *
 * Only the axios instance and `WebSocket` are replaced, so paths and URLs are
 * asserted as they leave the application.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import CredentialedResults from "../../../pages/scan/CredentialedResults";
import api from "../../../api/axiosInstance";

/*
 * The page gained an auth dependency when the Reports & Export panel was added
 * to it: exporting a scan needs `reports:read`, which is a different grant from
 * permission to view the scan. Without a provider the panel throws and every
 * accessibility contract below fails on the exception rather than on anything
 * it is meant to measure.
 *
 * A superadmin is used so the panel renders in full, which is the state those
 * contracts need to see -- gated behind a denial it would render one alert and
 * assert nothing about the controls.
 */
vi.mock("../../../context/AuthContext", () => ({
  useAuth: () => ({ user: { id: "u1", role: { name: "superadmin" } } }),
}));

vi.mock("../../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
  authSession: { getAccessToken: () => "harness-token" },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const LINUX = {
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
    uptime: "12 days",
    serial_number: "HX-SN-001",
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
        size: "1T",
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
    { name: "bash", version: "5.1-6ubuntu1", manager: "dpkg" },
  ],
  package_count: 3,
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
  suid_binaries: ["/usr/bin/sudo", "/usr/bin/passwd"],
  world_writable_dirs: ["/tmp"],
  sudo_nopasswd: true,
  sudo_rules_raw: "alice ALL=(ALL) NOPASSWD: ALL",
  security_issues: [
    "PermitRootLogin is enabled",
    "Password authentication is enabled",
  ],
  failed_login_count: 37,
  brute_force_warning: true,
  failed_logins_recent: [
    "Sep 11 09:12:01 sshd: Failed password for root from 10.9.9.9",
    "Sep 11 09:12:05 sshd: Failed password for root from 10.9.9.9",
  ],
  network_interfaces_raw: JSON.stringify([
    {
      ifname: "eth0",
      address: "00:1a:2b:3c:4d:21",
      operstate: "up",
      addr_info: [
        { family: "inet6", local: "fe80::1" },
        { family: "inet", local: "10.40.2.21", prefixlen: 24 },
      ],
    },
  ]),
  env_vars_flagged: [
    "AWS_SECRET_ACCESS_KEY=placeholder",
    "API_TOKEN: hx-token-77aa",
  ],
  cves: [
    {
      cve_id: "CVE-2024-6387",
      severity: "Critical",
      cvss_score: 9.8,
      package: "openssh-server",
      installed_ver: "8.9p1",
      fixed_ver: "8.9p1-3ubuntu0.10",
      description: "Signal handler race in sshd",
    },
    {
      cve_id: "CVE-2023-0286",
      severity: "High",
      cvss_score: 7.4,
      package: "openssl",
      installed_ver: "3.0.2",
      fixed_ver: "3.0.2-0ubuntu1.8",
      description: "X.400 address type confusion",
    },
    {
      cve_id: "CVE-2023-2650",
      severity: "Medium",
      cvss_score: 6.5,
      package: "OpenSSL",
      installed_ver: "3.0.2",
      description: "Slow OBJ_obj2txt translation",
    },
    {
      cve_id: "CVE-2023-22809",
      severity: "Low",
      package: "sudo",
      installed_ver: "1.9.9",
      description: "sudoedit arbitrary file write",
    },
    {
      cve_id: "CCURE-CFG-LINUX-NOTE",
      severity: "Info",
      description: "Configuration note",
    },
  ],
  cve_count: 5,
  severity_summary: { Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1 },
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
    auditd: { status: "WARN" },
  },
  cron_info_raw: "0 3 * * * root /usr/local/bin/backup.sh",
  local_groups: [
    { name: "sudo", gid: "27", members: ["alice"] },
    { name: "docker", members: [] },
  ],
  coverage: {
    authenticated_checks: "Packages, users, services",
    unauthenticated_checks: "Not performed",
    network_reachability: "Correlated with the port scan",
    port_range: "1-1024",
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
  collection_errors: { cron: "permission denied" },
  inventory_complete: false,
};

const WINDOWS = {
  target: "10.40.2.30",
  username: "CORP\\auditor",
  detected_os: "windows",
  system_info: {
    os_name: "Microsoft Windows 11 Pro",
    os_build: "26200.6584",
    hostname: "ws-30",
  },
  packages: [],
  package_count: 0,
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
  suspicious_scheduled_tasks: [
    { TaskName: "Updater", TaskPath: "\\Vendor\\", State: "Ready" },
    { TaskName: "Odd", TaskPath: "\\", State: "Disabled" },
  ],
  network_interfaces_raw: JSON.stringify({
    InterfaceAlias: "Ethernet",
    IPAddress: "10.40.2.30",
    PrefixLength: 24,
    MacAddress: "00-1A-2B-3C-4D-30",
    InterfaceDescription: "Intel NIC",
  }),
  cves: [],
  cve_count: 0,
  severity_summary: {},
};

const record = (fields = {}) => ({
  id: "cr-7",
  scan_no: 3107,
  status: "complete",
  results: {
    credentialed: { report: LINUX, reports: [LINUX], hosts_failed: [] },
  },
  ...fields,
});
const MULTI = record({
  results: {
    credentialed: {
      report: LINUX,
      reports: [LINUX, WINDOWS],
      hosts_failed: [{ target: "10.40.2.40", reason: "Authentication failed" }],
    },
  },
});
const RUNNING = { id: "cr-7", scan_no: 3107, status: "running", results: {} };

/* ── A WebSocket this file controls ─────────────────────────────────────── */
let sockets;
class FakeWebSocket {
  constructor(url) {
    this.url = url;
    this.closeCalls = 0;
    this.readyState = 1;
    sockets.push(this);
  }
  // A real socket reports its close asynchronously, and only once.
  close() {
    this.closeCalls += 1;
    if (this.readyState === 3) return;
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.({ code: 1000, wasClean: true }));
  }
  frame(data) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
  drop() {
    this.readyState = 3;
    this.onclose?.({ code: 1006, wasClean: false });
  }
}

/* ── Harness ────────────────────────────────────────────────────────────── */
const TICKET = "tk+1/2=";
const RESULTS = "/scan/credentialed/results";
const byId = (id = "cr-7") => `${RESULTS}?scan_id=${id}`;
const withState = (result, search = "") => ({
  pathname: RESULTS,
  search,
  state: { result },
});

let getReplies;
let ticketReply;
let consoleSpies;

const replyWith = (...replies) => {
  getReplies = replies;
};
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

function LocationProbe() {
  const location = useLocation();
  return (
    <output data-testid="location">{`${location.pathname}${location.search}`}</output>
  );
}

const renderAt = (entry) =>
  render(
    <MemoryRouter initialEntries={[entry]}>
      <Routes>
        <Route
          path="/scan/credentialed/results"
          element={<CredentialedResults />}
        />
        <Route
          path="/scan/:scanId/credentialed-results"
          element={<CredentialedResults />}
        />
        <Route path="*" element={<p>Elsewhere</p>} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  );

const flush = async () => {
  for (let i = 0; i < 8; i += 1) {
    await act(async () => {});
  }
};
const loaded = async (entry = byId()) => {
  const view = renderAt(entry);
  await flush();
  return view;
};
const advance = async (ms) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  await flush();
};
const fakeTimers = () =>
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

const socket = (i = -1) => sockets.at(i);
const frame = async (progress, extra = {}) => {
  await act(async () => {
    socket().frame({ phase: 5, progress, ...extra });
  });
  await flush();
};

const location = () => screen.getByTestId("location").textContent;
const pageTitle = () =>
  screen.getByTestId("app-layout").getAttribute("data-page-title");
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);

const open = async (name) => {
  fireEvent.click(screen.getByRole("button", { name }));
  await flush();
};
const kv = (label) =>
  screen
    .queryAllByText(label, { exact: true, selector: "span.kv-key, dt" })
    .filter((el) => el.nextElementSibling)
    .map((el) => squash(el.nextElementSibling));
const tables = () => [...document.querySelectorAll("table")];
const tableWith = (...headers) =>
  tables().find((t) => {
    const hs = [...t.querySelectorAll("thead th")].map(squash);
    return headers.every((h) => hs.includes(h));
  });
const headersOf = (t) => [...t.querySelectorAll("thead th")].map(squash);
const cellsOf = (t) =>
  [...t.querySelectorAll("tbody tr")].map((tr) =>
    [...tr.querySelectorAll("td, th")].map(squash),
  );
const leafTexts = () =>
  [...document.body.querySelectorAll("*")]
    .filter((el) => el.children.length === 0)
    .map((el) => el.textContent);
const cveLinks = () =>
  screen.queryAllByRole("link", { name: /^CVE-/ }).map((a) => squash(a));
// The latest message is also the dashboard's heading; only log lines count.
const logLines = () =>
  screen
    .queryAllByText(/^Frame \d+$/, {
      ignore: "script, style, h1, h2, h3, h4, h5, h6",
    })
    .map(squash);

beforeEach(() => {
  sockets = [];
  vi.stubGlobal("WebSocket", FakeWebSocket);
  api.defaults.baseURL = "/api";
  replyWith(record());
  ticketReply = () => Promise.resolve({ data: { ticket: TICKET } });
  api.get.mockReset();
  api.get.mockImplementation(() => {
    const next = getReplies.length > 1 ? getReplies.shift() : getReplies[0];
    return typeof next === "function"
      ? next()
      : Promise.resolve({ data: next });
  });
  for (const verb of ["post", "put", "patch", "delete"]) api[verb].mockReset();
  api.post.mockImplementation(() => ticketReply());
  consoleSpies = ["log", "info", "warn", "error"].map((m) =>
    vi.spyOn(console, m),
  );
});

afterEach(() => {
  // The one write the page makes is the ticket, with no body; every read is
  // the scan record; every socket is the progress socket.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const call of api.post.mock.calls)
    expect(call).toEqual(["/auth/ticket"]);
  for (const call of api.get.mock.calls) {
    expect(call).toHaveLength(1);
    // The scan record, and its policy sub-resource. The latter was added when
    // the page grew the "what this scan assessed" section, which reads the
    // scan's own immutable configuration snapshot. Widened by one named path
    // rather than relaxed: the property this guard exists for is that the page
    // reads scans and nothing else, and writes nothing at all.
    expect(call[0]).toMatch(/^\/scans\/[^/?]+(\/policy)?$/);
  }
  for (const s of sockets) {
    expect(s.url).toMatch(/\/scans\/[^/]+\/progress\?ticket=[^&]+$/);
  }
  consoleSpies.forEach((spy) => spy.mockRestore());
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("CredentialedResults — contract", () => {
  describe("where the report comes from", () => {
    it("reads GET /scans/{id} once for ?scan_id and renders a finished report, with no ticket or socket", async () => {
      await loaded();
      expect(api.get.mock.calls).toEqual([["/scans/cr-7"]]);
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
      expect(pageTitle()).toBe("Credentialed Results");
      expect(bodyText()).toMatch(/Credentialed Scan Results/);
      expect(bodyText()).toMatch(/Scan No\. 3107/);
    });

    it("accepts a record marked completed", async () => {
      replyWith(record({ status: "COMPLETED" }));
      await loaded();
      expect(bodyText()).toMatch(/Credentialed Scan Results/);
      expect(api.post).not.toHaveBeenCalled();
    });

    it("renders a report carried in router state without any request", async () => {
      await loaded(withState(LINUX, "?scan_id=cr-7"));
      expect(api.get).not.toHaveBeenCalled();
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
      expect(bodyText()).toMatch(/10\.40\.2\.21/);
    });

    it("router state with findings but no system information still reads the scan record", async () => {
      await loaded(
        withState({ target: "10.40.2.21", cves: LINUX.cves }, "?scan_id=cr-7"),
      );
      expect(api.get.mock.calls).toEqual([["/scans/cr-7"]]);
    });

    it("without a scan id or a report, sends the user to a new credentialed scan", async () => {
      await loaded(RESULTS);
      expect(location()).toBe("/scan/credentialed");
      expect(api.get).not.toHaveBeenCalled();
    });

    it("the /scan/{id}/credentialed-results route reads only ?scan_id, so without it the page redirects", async () => {
      await loaded("/scan/cr-7/credentialed-results");
      expect(location()).toBe("/scan/credentialed");
      expect(api.get).not.toHaveBeenCalled();
    });

    it("names the scan by scan_no, falling back to display_id", async () => {
      replyWith(record({ scan_no: null, display_id: "CR-3107" }));
      await loaded();
      expect(bodyText()).toMatch(/Scan No\. CR-3107/);
    });

    it("a finished record with no credentialed report keeps following the scan", async () => {
      replyWith(record({ results: {} }));
      await loaded();
      expect(api.post.mock.calls).toEqual([["/auth/ticket"]]);
      expect(sockets).toHaveLength(1);
      expect(bodyText()).toMatch(/Credentialed Scan In Progress/);
    });

    it.each([
      [
        {
          status: "failed",
          failure_reason: "Authentication failed for auditor",
        },
        "Authentication failed for auditor",
      ],
      [{ status: "cancelled" }, "Scan cancelled"],
      [{ status: "Canceled" }, "Scan canceled"],
    ])(
      "a settled record %j shows why, with no ticket or socket",
      async (fields, message) => {
        replyWith({ ...RUNNING, ...fields });
        await loaded();
        expect(bodyText()).toMatch(/Scan Failed/);
        expect(bodyText()).toContain(message);
        expect(bodyText()).toMatch(
          /Please verify your SSH credentials and ensure the host is reachable\./,
        );
        expect(api.post).not.toHaveBeenCalled();
        expect(sockets).toHaveLength(0);
        expect(pageTitle()).toBe("Credentialed Results");
      },
    );

    it.each([
      "Host 10.40.2.21 unreachable",
      "Connection TIMEOUT after 30s",
      "No route to host",
    ])(
      "a failure reading %j is presented as an unreachable host",
      async (reason) => {
        replyWith({ ...RUNNING, status: "failed", failure_reason: reason });
        await loaded();
        expect(bodyText()).toMatch(/Host is unavailable\/down\/unreachable/);
        expect(bodyText()).toMatch(
          /could not be reached via SSH\. Verify the IP address, network connectivity, and firewall rules\./,
        );
        expect(bodyText()).toMatch(
          /Please ensure the target is powered on and accessible from the scanning engine\./,
        );
        expect(bodyText()).not.toMatch(/Scan Failed/);
      },
    );

    it("a router-state report whose status is unreachable shows the unreachable view", async () => {
      await loaded(withState({ ...LINUX, status: "unreachable" }));
      expect(bodyText()).toMatch(/Host is unavailable\/down\/unreachable/);
    });

    it.each([
      [
        { response: { data: { detail: "Scan not found" } }, message: "x" },
        "Scan not found",
      ],
      [{ message: "Network Error" }, "Network Error"],
      [{}, "Failed to load results."],
    ])(
      "a rejected read %j shows the API detail, else the error message, else a fallback",
      async (err, text) => {
        replyWith(() => Promise.reject(err));
        await loaded();
        expect(bodyText()).toContain(text);
        expect(api.post).not.toHaveBeenCalled();
        expect(sockets).toHaveLength(0);
      },
    );
  });

  describe("ticket and progress socket", () => {
    it("a running scan gets one ticket with POST /auth/ticket and no body, then one socket", async () => {
      replyWith(RUNNING);
      await loaded();
      expect(api.get.mock.calls).toEqual([["/scans/cr-7"]]);
      expect(api.post.mock.calls).toEqual([["/auth/ticket"]]);
      expect(sockets.map((s) => s.url)).toEqual([
        "/api/scans/cr-7/progress?ticket=tk%2B1%2F2%3D",
      ]);
      expect(pageTitle()).toBe("Credentialed Scan In Progress");
    });

    it.each([
      [
        "https://ccure.test/api",
        "wss://ccure.test/api/scans/cr-7/progress?ticket=tk%2B1%2F2%3D",
      ],
      [
        "http://10.0.0.5:8000",
        "ws://10.0.0.5:8000/scans/cr-7/progress?ticket=tk%2B1%2F2%3D",
      ],
      ["", "/scans/cr-7/progress?ticket=tk%2B1%2F2%3D"],
    ])("builds the socket URL from base %j", async (base, url) => {
      api.defaults.baseURL = base;
      replyWith(RUNNING);
      await loaded();
      expect(sockets.map((s) => s.url)).toEqual([url]);
    });

    it("asks for the ticket only once the first read says the scan is still running", async () => {
      const read = deferred();
      replyWith(() => read.promise);
      await loaded();
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
      await act(async () => read.resolve({ data: RUNNING }));
      await flush();
      expect(api.post).toHaveBeenCalledTimes(1);
      expect(sockets).toHaveLength(1);
    });

    it("shows the progress dashboard while the first read is outstanding", async () => {
      replyWith(() => new Promise(() => {}));
      await loaded();
      expect(pageTitle()).toBe("Credentialed Scan In Progress");
      const text = bodyText();
      expect(text).toMatch(/Credentialed Scan In Progress/);
      expect(text).toMatch(/Target: cr-7/);
      expect(text).toMatch(/Scan No\. -/);
      expect(text).toMatch(/Initializing scan\.\.\./);
      expect(text).toMatch(/0%/);
      for (const stage of [
        "Connection",
        "OS Detection",
        "Collection",
        "CVE Analysis",
        "Finalizing",
      ]) {
        expect(text).toContain(stage);
      }
      expect(text).toMatch(/Live Activity/);
      expect(text).toMatch(/Waiting for activity\.\.\./);
      expect(text).toMatch(
        /Performing authenticated system inspection via SSH\. This typically takes 30-90 seconds\./,
      );
    });

    it("takes the target and scan number from router state while it waits", async () => {
      replyWith(RUNNING);
      await loaded(
        withState(
          { target: "10.40.2.21", scan_no: 3107, status: "running" },
          "?scan_id=cr-7",
        ),
      );
      expect(bodyText()).toMatch(/Target: 10\.40\.2\.21/);
      expect(bodyText()).toMatch(/Scan No\. 3107/);
    });

    it("applies phase 5 progress frames: percentage, message, stage and a timestamped log line", async () => {
      replyWith(RUNNING);
      await loaded();
      await frame({
        percentage: 40,
        message: "Collecting packages",
        stage: "collection",
        status: "running",
      });
      const text = bodyText();
      expect(text).toMatch(/40%/);
      expect(text).toMatch(/Collecting packages/);
      expect(text).toMatch(
        /\[[^\]]*\d{1,2}:\d{2}:\d{2}[^\]]*\]\s*Collecting packages/,
      );
      expect(text).not.toMatch(/Waiting for activity/);
      // Stages before the current one are marked done.
      expect((text.match(/✓/g) || []).length).toBe(2);
      await frame({ stage: "syncing" });
      expect((bodyText().match(/✓/g) || []).length).toBe(4);
    });

    it("ignores frames for other phases and frames without progress", async () => {
      replyWith(RUNNING);
      await loaded();
      await act(async () => {
        socket().frame({
          phase: 3,
          progress: { percentage: 90, message: "Other phase" },
        });
        socket().frame({ phase: 5 });
      });
      await flush();
      expect(bodyText()).not.toMatch(/90%|Other phase/);
      expect(bodyText()).toMatch(/Initializing scan\.\.\./);
    });

    it("keeps the last percentage for a frame without one, and logs only frames with a message", async () => {
      replyWith(RUNNING);
      await loaded();
      await frame({ percentage: 40, message: "Frame 1" });
      await frame({ percentage: 0, message: "Frame 2" });
      expect(bodyText()).toMatch(/40%/);
      await frame({ percentage: 55, stage: "analysis" });
      expect(bodyText()).toMatch(/55%/);
      expect(logLines()).toEqual(["Frame 1", "Frame 2"]);
      expect(bodyText()).toMatch(/Frame 2/);
    });

    it("keeps the latest 50 log lines", async () => {
      replyWith(RUNNING);
      await loaded();
      await act(async () => {
        for (let n = 1; n <= 55; n += 1) {
          socket().frame({ phase: 5, progress: { message: `Frame ${n}` } });
        }
      });
      await flush();
      const lines = logLines();
      expect(lines).toHaveLength(50);
      expect(lines[0]).toBe("Frame 6");
      expect(lines.at(-1)).toBe("Frame 55");
    });

    it("a complete frame re-reads the record, shows the report and closes the socket without polling", async () => {
      fakeTimers();
      replyWith(RUNNING, record());
      await loaded();
      await frame({ status: "complete", percentage: 100, message: "Done" });
      expect(api.get).toHaveBeenCalledTimes(2);
      expect(bodyText()).toMatch(/Credentialed Scan Results/);
      expect(socket().closeCalls).toBe(1);
      await advance(30_000);
      expect(api.get).toHaveBeenCalledTimes(2);
      expect(api.post).toHaveBeenCalledTimes(1);
    });

    it("a failed frame shows its message, or 'Scan failed', and leaves the socket open", async () => {
      replyWith(RUNNING);
      const view = await loaded();
      await frame({ status: "failed", message: "SSH authentication failed" });
      expect(bodyText()).toMatch(/Scan Failed/);
      expect(bodyText()).toContain("SSH authentication failed");
      expect(socket().closeCalls).toBe(0);
      expect(api.get).toHaveBeenCalledTimes(1);
      view.unmount();
      expect(socket().closeCalls).toBe(1);

      sockets = [];
      replyWith(RUNNING);
      await loaded();
      await frame({ status: "failed" });
      expect(bodyText()).toContain("Scan failed");
    });

    it("never polls while the socket is open", async () => {
      fakeTimers();
      replyWith(RUNNING);
      await loaded();
      await frame({ percentage: 20, message: "Connected" });
      await advance(60_000);
      expect(api.get).toHaveBeenCalledTimes(1);
      expect(sockets).toHaveLength(1);
      expect(api.post).toHaveBeenCalledTimes(1);
    });

    it("a socket that closes before results arrive polls the record every 3 s until it settles", async () => {
      fakeTimers();
      replyWith(RUNNING, RUNNING, RUNNING, record());
      await loaded();
      await act(async () => socket().drop());
      await advance(2999);
      expect(api.get).toHaveBeenCalledTimes(1);
      await advance(1);
      expect(api.get).toHaveBeenCalledTimes(2);
      await advance(3000);
      expect(api.get).toHaveBeenCalledTimes(3);
      await advance(3000);
      expect(api.get).toHaveBeenCalledTimes(4);
      expect(bodyText()).toMatch(/Credentialed Scan Results/);
      await advance(30_000);
      expect(api.get).toHaveBeenCalledTimes(4);
      expect(sockets).toHaveLength(1);
      expect(api.post).toHaveBeenCalledTimes(1);
    });

    it("a refused ticket is logged and falls back to polling, with no socket", async () => {
      fakeTimers();
      const refusal = new Error("ticket refused");
      ticketReply = () => Promise.reject(refusal);
      console.error.mockImplementation(() => {});
      replyWith(RUNNING, RUNNING, record());
      await loaded();
      expect(console.error).toHaveBeenCalledWith(
        "Failed to start progress WebSocket",
        refusal,
      );
      expect(sockets).toHaveLength(0);
      await advance(2999);
      expect(api.get).toHaveBeenCalledTimes(1);
      await advance(1);
      expect(api.get).toHaveBeenCalledTimes(2);
      await advance(3000);
      expect(api.get).toHaveBeenCalledTimes(3);
      await advance(30_000);
      expect(api.get).toHaveBeenCalledTimes(3);
      expect(api.post).toHaveBeenCalledTimes(1);
    });

    it("a socket that cannot be constructed takes the same fallback", async () => {
      fakeTimers();
      vi.stubGlobal(
        "WebSocket",
        class {
          constructor() {
            throw new SyntaxError("The URL is invalid");
          }
        },
      );
      console.error.mockImplementation(() => {});
      replyWith(RUNNING, record());
      await loaded();
      expect(console.error).toHaveBeenCalledWith(
        "Failed to start progress WebSocket",
        expect.any(SyntaxError),
      );
      await advance(3000);
      expect(api.get).toHaveBeenCalledTimes(2);
    });

    it("a failure read after a complete frame closes the socket, and that close arms one more read", async () => {
      fakeTimers();
      replyWith(RUNNING, {
        ...RUNNING,
        status: "failed",
        failure_reason: "Collector crashed",
      });
      await loaded();
      await frame({ status: "complete" });
      expect(api.get).toHaveBeenCalledTimes(2);
      expect(socket().closeCalls).toBe(1);
      expect(bodyText()).toContain("Collector crashed");
      await advance(3000);
      expect(api.get).toHaveBeenCalledTimes(3);
      await advance(30_000);
      expect(api.get).toHaveBeenCalledTimes(3);
    });

    it("a socket closing after the report has arrived does not poll", async () => {
      fakeTimers();
      replyWith(RUNNING, record());
      await loaded();
      await frame({ status: "complete" });
      await act(async () => socket().drop());
      await advance(30_000);
      expect(api.get).toHaveBeenCalledTimes(2);
    });

    it("unmounting closes the socket, and later frames change nothing", async () => {
      replyWith(RUNNING, record());
      const view = await loaded();
      view.unmount();
      expect(socket().closeCalls).toBe(1);
      await act(async () => {
        socket().frame({ phase: 5, progress: { status: "complete" } });
      });
      await flush();
      expect(api.get).toHaveBeenCalledTimes(1);
    });

    it("unmounting while a poll is pending cancels it", async () => {
      fakeTimers();
      replyWith(RUNNING);
      const view = await loaded();
      await act(async () => socket().drop());
      view.unmount();
      await advance(10_000);
      expect(api.get).toHaveBeenCalledTimes(1);
    });

    it("unmounting before the ticket arrives opens no socket", async () => {
      const ticket = deferred();
      ticketReply = () => ticket.promise;
      replyWith(RUNNING);
      const view = await loaded();
      view.unmount();
      await act(async () => ticket.resolve({ data: { ticket: TICKET } }));
      await flush();
      expect(sockets).toHaveLength(0);
    });

    it("unmounting before the first read settles asks for nothing more", async () => {
      const read = deferred();
      replyWith(() => read.promise);
      const view = await loaded();
      view.unmount();
      await act(async () => read.resolve({ data: RUNNING }));
      await flush();
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
    });

    it("the ticket never reaches the document", async () => {
      replyWith(RUNNING);
      await loaded();
      await frame({ percentage: 30, message: "Connected" });
      expect(document.documentElement.outerHTML).not.toContain("tk+1/2=");
      expect(document.documentElement.outerHTML).not.toContain("tk%2B1");
    });
  });

  describe("the report", () => {
    it("heads the report with target, user, duration, scan number and an auto-detected OS", async () => {
      await loaded();
      const text = bodyText();
      expect(text).toMatch(/10\.40\.2\.21/);
      expect(text).toMatch(/user: auditor/);
      expect(text).toMatch(/48\.2s/);
      expect(text).toMatch(/Scan No\. 3107/);
      expect(text).toMatch(/Linux \(auto-detected\)/);
    });

    it("summarises risk, OS, kernel, packages, CVEs and brute force", async () => {
      await loaded();
      expect(squash(document.querySelector(".cc-sev"))).toBe("Critical");
      const text = bodyText();
      expect(text).toMatch(/Ubuntu 22\.04\.4 LTS/);
      expect(text).toMatch(/Kernel 5\.15\.0-105-generic/);
      expect(text).toMatch(/3 packages/);
      expect(text).toMatch(/5 CVEs/);
      expect(text).toMatch(/Brute-force activity detected/);
    });

    it("rates the overall risk by the worst band present, and says 1 CVE", async () => {
      await loaded(
        withState({
          ...LINUX,
          cves: [LINUX.cves[2]],
          cve_count: 1,
          severity_summary: { Medium: 1 },
          brute_force_warning: false,
        }),
      );
      expect(squash(document.querySelector(".cc-sev"))).toBe("Medium");
      expect(bodyText()).toMatch(/1 CVE(?!s)/);
      expect(bodyText()).not.toMatch(/Brute-force activity detected/);
    });

    it("a Windows host shows its build instead of a kernel, and Info when nothing is rated", async () => {
      await loaded(withState(WINDOWS));
      expect(squash(document.querySelector(".cc-sev"))).toBe("Info");
      expect(bodyText()).toMatch(/Build 26200\.6584/);
      expect(bodyText()).toMatch(/0 CVEs/);
    });

    it("switches between audited hosts, and lists hosts that could not be audited", async () => {
      replyWith(MULTI);
      await loaded();
      const text = bodyText();
      expect(text).toMatch(/2 hosts audited:/);
      expect(text).toMatch(/1 host could not be audited/);
      expect(text).toMatch(/10\.40\.2\.40 — Authentication failed/);
      expect(text).toMatch(
        /These hosts are unassessed\. Their absence from the findings below is not evidence that they are clean\./,
      );
      expect(kv("OS")).toEqual(["Ubuntu 22.04.4 LTS"]);
      fireEvent.click(screen.getByRole("button", { name: /^10\.40\.2\.30/ }));
      await flush();
      expect(kv("OS")).toEqual(["Microsoft Windows 11 Pro"]);
      expect(bodyText()).toMatch(/Build 26200\.6584/);
      expect(
        squash(screen.getByRole("button", { name: /^10\.40\.2\.21/ })),
      ).toMatch(/\(5\)/);
      expect(
        squash(screen.getByRole("button", { name: /^10\.40\.2\.30/ })),
      ).toMatch(/\(0\)/);
    });

    it("shows no host selector for one host, and pluralises failed hosts", async () => {
      replyWith(
        record({
          results: {
            credentialed: {
              report: LINUX,
              hosts_failed: [
                { target: "10.40.2.40", reason: "Timed out" },
                { target: "10.40.2.41", reason: "Refused" },
              ],
            },
          },
        }),
      );
      await loaded();
      expect(bodyText()).not.toMatch(/hosts audited:/);
      expect(bodyText()).toMatch(/2 hosts could not be audited/);
    });

    it("opens System Information by default, with '—' for anything missing and a disk table", async () => {
      await loaded();
      expect(kv("Hostname")).toEqual(["web-01"]);
      expect(kv("CPU Count")).toEqual(["24"]);
      expect(kv("RAM Total")).toEqual(["64 GiB"]);
      expect(kv("RAM Used")).toEqual(["21 GiB"]);
      const disks = tableWith("Filesystem", "Mount");
      expect(headersOf(disks)).toEqual([
        "Filesystem",
        "Size",
        "Used",
        "Available",
        "Use%",
        "Mount",
      ]);
      expect(cellsOf(disks)).toEqual([
        ["/dev/sda1", "200G", "170G", "30G", "85%", "/"],
        ["/dev/sdb1", "1T", "100G", "900G", "10%", "/data"],
      ]);
      await open(/System Information/);
      expect(kv("Hostname")).toEqual([]);

      cleanup();
      await loaded(withState(WINDOWS));
      expect(kv("Kernel")).toEqual(["—"]);
      expect(kv("RAM Total")).toEqual([]);
    });

    it("keeps assessment coverage closed until asked, then shows what was examined", async () => {
      await loaded();
      expect(kv("Port scan")).toEqual([]);
      await open(/Assessment coverage — what this scan examined/);
      expect(bodyText()).toMatch(
        /Coverage bounds every conclusion in this report\./,
      );
      expect(kv("Authenticated checks")).toEqual(["Packages, users, services"]);
      expect(kv("Unauthenticated checks")).toEqual(["Not performed"]);
      expect(kv("Network reachability")).toEqual([
        "Correlated with the port scan",
      ]);
      expect(kv("Port scan")).toEqual(["1-1024"]);
      expect(kv("Service detection")).toEqual(["Version probes"]);
      expect(kv("OS detection")).toEqual(["Authenticated"]);
      expect(kv("Host discovery")).toEqual(["ICMP echo"]);
      expect(kv("Software inventory")).toEqual([
        "Incomplete — see collection errors below",
      ]);
      expect(cellsOf(tableWith("Section", "Reason"))).toEqual([
        ["cron", "permission denied"],
      ]);
    });

    it("a complete inventory says how many packages were enumerated; no coverage, no section", async () => {
      await loaded(
        withState({
          ...LINUX,
          inventory_complete: true,
          collection_errors: {},
        }),
      );
      await open(/Assessment coverage/);
      expect(kv("Software inventory")).toEqual([
        "Complete — 3 package(s) enumerated",
      ]);
      expect(tableWith("Section", "Reason")).toBeUndefined();

      cleanup();
      await loaded(withState({ ...LINUX, coverage: {} }));
      expect(
        screen.queryAllByRole("button", { name: /Assessment coverage/ }),
      ).toHaveLength(0);
    });

    it("lists CVE findings with severity chips, filters and NVD links", async () => {
      await loaded();
      expect(
        screen.getByRole("button", { name: /CVE Findings \(5\)/ }),
      ).toBeTruthy();
      const text = bodyText();
      for (const chip of [
        "1 Critical",
        "1 High",
        "1 Medium",
        "1 Low",
        "1 Info",
      ]) {
        expect(text).toContain(chip);
      }
      expect(text).toMatch(/CVSS 9\.8/);
      expect(text).toMatch(/openssh-server 8\.9p1/);
      expect(text).toMatch(/fixed in 8\.9p1-3ubuntu0\.10/);
      expect(text).toMatch(/Signal handler race in sshd/);
      expect(cveLinks()).toEqual([
        "CVE-2024-6387",
        "CVE-2023-0286",
        "CVE-2023-2650",
        "CVE-2023-22809",
      ]);
      const link = screen.getByRole("link", { name: "CVE-2024-6387" });
      expect(link.getAttribute("href")).toBe(
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
      );
      expect(link.getAttribute("target")).toBe("_blank");
      expect(link.getAttribute("rel")).toBe("noopener noreferrer");
      expect(text).toContain("CCURE-CFG-LINUX-NOTE");

      fireEvent.click(screen.getByRole("button", { name: /^High\b/ }));
      await flush();
      expect(cveLinks()).toEqual(["CVE-2023-0286"]);
      expect(bodyText()).not.toContain("CCURE-CFG-LINUX-NOTE");
      fireEvent.click(screen.getByRole("button", { name: /^Info\b/ }));
      await flush();
      expect(cveLinks()).toEqual([]);
      expect(bodyText()).toContain("CCURE-CFG-LINUX-NOTE");
      fireEvent.click(screen.getByRole("button", { name: /^All\b/ }));
      await flush();
      expect(cveLinks()).toHaveLength(4);
      for (const sev of ["Critical", "High", "Medium", "Low", "Info"]) {
        expect(
          squash(
            screen.getByRole("button", { name: new RegExp(`^${sev}\\b`) }),
          ),
        ).toMatch(/\(1\)/);
      }
    });

    it("shows no CVE section when nothing was found", async () => {
      await loaded(withState(WINDOWS));
      expect(
        screen.queryAllByRole("button", { name: /CVE Findings/ }),
      ).toHaveLength(0);
    });

    it("opens the security audit when there are issues, with counts, hardening results and SUID binaries", async () => {
      await loaded();
      const text = bodyText();
      expect(text).toContain("PermitRootLogin is enabled");
      expect(text).toContain("Password authentication is enabled");
      expect(kv("NOPASSWD Sudo")).toEqual([
        "⚠ YES — any command without password",
      ]);
      expect(kv("SUID Binaries")).toEqual(["2 found"]);
      expect(kv("World-Writable Dirs")).toEqual(["1 found"]);
      expect(kv("Failed Logins")[0]).toBe("37 ⚠ possible brute force");
      const audits = tableWith("Configuration / Audit", "Status");
      expect(headersOf(audits)).toEqual([
        "Configuration / Audit",
        "Status",
        "Audit Findings Detail",
      ]);
      expect(cellsOf(audits)).toEqual([
        ["ASLR", "PASS", "kernel.randomize_va_space = 2"],
        ["SSH root login", "FAIL", "PermitRootLogin yes"],
        ["auditd", "WARN", "—"],
      ]);
      expect(text).toContain("/usr/bin/sudo");
      expect(text).toContain("/usr/bin/passwd");
    });

    it("keeps the security audit closed when there is nothing to flag", async () => {
      await loaded(
        withState({ ...WINDOWS, security_issues: [], sudo_nopasswd: false }),
      );
      expect(kv("NOPASSWD Sudo")).toEqual([]);
      await open(/Security Audit/);
      expect(kv("NOPASSWD Sudo")).toEqual(["No"]);
      expect(kv("SUID Binaries")).toEqual(["0 found"]);
      expect(kv("Failed Logins")).toEqual(["0"]);
    });

    it("lists running services with a search", async () => {
      await loaded();
      await open(/Running Services \(2\)/);
      const table = () => tableWith("Service", "Description");
      expect(cellsOf(table())).toEqual([
        ["ssh.service", "running", "OpenBSD Secure Shell server"],
        [
          "cron.service",
          "running",
          "Regular background program processing daemon",
        ],
      ]);
      const search = screen.getByPlaceholderText("Search services...");
      fireEvent.change(search, { target: { value: "BACKGROUND" } });
      expect(cellsOf(table()).map((r) => r[0])).toEqual(["cron.service"]);
      fireEvent.change(search, { target: { value: "zzz" } });
      expect(table()).toBeUndefined();
      expect(bodyText()).toContain('No services matching "zzz"');
    });

    it("lists listening sockets with exposure, process, software and a search over every column", async () => {
      await loaded();
      await open(/Listening sockets — host socket table \(4\)/);
      const text = bodyText();
      expect(text).toMatch(
        /correlated with the port scan\. 1 exposed, 1 filtered, 1 host-only\./,
      );
      const table = () =>
        tableWith("Exposure", "Local Addr", "Port", "Process", "Software");
      const rows = cellsOf(table());
      expect(rows.map((r) => [r[0], r[1], r[2]])).toEqual([
        ["Exposed", "0.0.0.0", "22"],
        ["Host-only", "127.0.0.1", "5432"],
        ["Filtered", "0.0.0.0", "8080"],
        ["Not tested", "0.0.0.0", "9100"],
      ]);
      expect(rows[0][3]).toMatch(/^sshd\s*pid 812$/);
      expect(rows[0][4]).toMatch(/^OpenSSH\s*8\.9p1$/);
      expect(rows[1][3]).toBe("postgres");
      expect(rows[1][4]).toBe("Not identified");
      expect(rows[2][4]).toBe("Apache Tomcat");
      const titles = {
        Exposed: "Listening and confirmed reachable from the scanner",
        "Host-only": "Bound to loopback — not reachable from the network",
        Filtered: "Listening on the host but not reachable from the scanner",
        "Not tested":
          "No network port scan was performed against this host, so reachability is unknown",
      };
      for (const [label, title] of Object.entries(titles)) {
        expect(
          screen.getByText(label).closest("[title]").getAttribute("title"),
        ).toBe(title);
      }
      const search = screen.getByPlaceholderText(
        "Search ports, IPs, or processes...",
      );
      for (const [q, ports] of [
        ["exposed", ["22"]],
        ["TOMCAT", ["8080"]],
        ["127.0.0.1", ["5432"]],
        ["8.9p1", ["22"]],
        ["LISTEN", ["22"]],
      ]) {
        fireEvent.change(search, { target: { value: q } });
        expect(cellsOf(table()).map((r) => r[2])).toEqual(ports);
      }
      fireEvent.change(search, { target: { value: "zzz" } });
      expect(bodyText()).toContain('No open ports matching "zzz"');
    });

    it("explains uncorrelated sockets", async () => {
      await loaded(withState({ ...LINUX, exposure_summary: {} }));
      await open(/Listening sockets/);
      expect(bodyText()).toMatch(
        /These are the sockets the host reports it is listening on — not the results of a network port scan\. Except for loopback-bound services, whether each one is reachable from the network was not tested\./,
      );
    });

    it("lists only packages named by a finding, case-insensitively, with their CVE links and a search", async () => {
      await loaded();
      await open(/Packages with Vulnerabilities \(2\)/);
      expect(bodyText()).toMatch(
        /Showing only packages that match vulnerability findings\./,
      );
      const table = () =>
        tableWith("Affected Packages", "Version", "Manager", "CVE");
      const rows = [...table().querySelectorAll("tbody tr")];
      expect(rows.map((r) => squash(r.querySelector("td, th")))).toEqual([
        "openssl",
        "sudo",
      ]);
      expect(within(rows[0]).getAllByRole("link").map(squash)).toEqual([
        "CVE-2023-0286",
        "CVE-2023-2650",
      ]);
      expect(within(rows[1]).getAllByRole("link").map(squash)).toEqual([
        "CVE-2023-22809",
      ]);
      const search = screen.getByPlaceholderText("Search packages...");
      fireEvent.change(search, { target: { value: "1.9.9" } });
      expect(cellsOf(table()).map((r) => r[0])).toEqual(["sudo"]);
      fireEvent.change(search, { target: { value: "DPKG" } });
      expect(cellsOf(table())).toHaveLength(2);
      fireEvent.change(search, { target: { value: "zzz" } });
      expect(bodyText()).toContain('No packages matching "zzz"');
    });

    it("lists Linux users without system accounts unless asked, with a search", async () => {
      await loaded();
      await open(/Users \(2\)/);
      const table = () => tableWith("Username", "UID", "Shell", "Home", "Type");
      expect(cellsOf(table())).toEqual([
        ["root", "0", "/bin/bash", "/root", "⚠ root"],
        ["alice", "1000", "/bin/bash", "/home/alice", "user"],
      ]);
      fireEvent.click(
        screen.getByRole("checkbox", {
          name: /Show system & service accounts/,
        }),
      );
      await flush();
      expect(cellsOf(table()).map((r) => [r[0], r[4]])).toEqual([
        ["root", "⚠ root"],
        ["daemon", "system"],
        ["alice", "user"],
      ]);
      expect(screen.getByRole("button", { name: /Users \(3\)/ })).toBeTruthy();
      const search = screen.getByPlaceholderText("Search users...");
      fireEvent.change(search, { target: { value: "/usr/sbin" } });
      expect(cellsOf(table()).map((r) => r[0])).toEqual(["daemon"]);
      fireEvent.change(search, { target: { value: "zzz" } });
      expect(bodyText()).toContain('No users matching "zzz"');
      expect(screen.getByRole("button", { name: /Users \(0\)/ })).toBeTruthy();
    });

    it("lists Windows users by role, status, password requirement and last logon", async () => {
      await loaded(withState(WINDOWS));
      await open(/Users \(2\)/);
      const table = () => tableWith("Username", "Role / Type", "Status");
      expect(headersOf(table())).toEqual([
        "Username",
        "Role / Type",
        "Status",
        "Password Required",
        "Last Logon",
      ]);
      expect(cellsOf(table())).toEqual([
        ["Administrator", "Admin", "Active", "Yes", "2026-09-10 08:00"],
        ["jdoe", "User", "Active", "⚠ No", "—"],
      ]);
      fireEvent.click(
        screen.getByRole("checkbox", {
          name: /Show system & service accounts/,
        }),
      );
      await flush();
      expect(cellsOf(table())[1]).toEqual([
        "Guest",
        "System",
        "Disabled",
        "⚠ No",
        "—",
      ]);
    });

    it("lists local groups", async () => {
      await loaded();
      await open(/Local Groups \(2\)/);
      expect(cellsOf(tableWith("Group Name", "GID", "Members"))).toEqual([
        ["sudo", "27", "alice"],
        ["docker", "—", "—"],
      ]);
    });

    it("shows Linux cron configuration as raw text and Windows scheduled tasks as a table", async () => {
      await loaded();
      await open(/Scheduled Cron Jobs/);
      expect(bodyText()).toMatch(
        /Target crontab files and system schedules configuration\./,
      );
      expect(
        [...document.querySelectorAll("pre")].map((p) => p.textContent),
      ).toContain(LINUX.cron_info_raw);

      cleanup();
      await loaded(withState(WINDOWS));
      await open(/Scheduled Tasks \(2\)/);
      expect(cellsOf(tableWith("Task Name", "Path", "State"))).toEqual([
        ["Updater", "\\Vendor\\", "Ready"],
        ["Odd", "\\", "Disabled"],
      ]);
    });

    it("shows login history only when logins failed", async () => {
      await loaded();
      await open(/Login History/);
      expect(kv("Brute Force Alert")).toEqual(["⚠ YES"]);
      expect(kv("Failed Logins")).toContain("37");

      cleanup();
      await loaded(withState(WINDOWS));
      expect(
        screen.queryAllByRole("button", { name: /Login History/ }),
      ).toHaveLength(0);
    });

    it("keeps raw audit evidence behind a section: sudo rules, login failures, interfaces and the package inventory", async () => {
      await loaded();
      await open(/Audit Evidence/);
      expect(bodyText()).toMatch(
        /Raw evidence is hidden by default to keep the report readable\. Sensitive values are masked\./,
      );
      const pres = () =>
        [...document.querySelectorAll("pre")].map((p) => p.textContent);
      expect(pres()).toContain("alice ALL=(ALL) NOPASSWD: ALL");
      expect(pres()).toContain(LINUX.failed_logins_recent.join("\n"));
      const ifaces = tableWith("Interface Name", "IP Address");
      expect(headersOf(ifaces)).toEqual([
        "Interface Name",
        "IP Address",
        "Subnet Mask / Prefix",
        "MAC Address",
        "Description",
      ]);
      expect(cellsOf(ifaces)).toEqual([
        ["eth0", "10.40.2.21", "/24", "00:1a:2b:3c:4d:21", "State: UP"],
      ]);
      expect(bodyText()).toMatch(/Show Raw Evidence JSON/);
      expect(pres()).toContain(
        JSON.stringify(JSON.parse(LINUX.network_interfaces_raw), null, 2),
      );
      expect(bodyText()).toMatch(/Sensitive Environment Variables \(2\)/);
      expect(bodyText()).toMatch(/Full Package Inventory \(3\)/);
      expect(cellsOf(tableWith("Package", "Version", "Manager"))).toEqual([
        ["openssl", "3.0.2-0ubuntu1.10", "dpkg"],
        ["sudo", "1.9.9-1ubuntu2.3", "dpkg"],
        ["bash", "5.1-6ubuntu1", "dpkg"],
      ]);
    });

    it("reads Windows interface JSON, and falls back to raw text for anything else", async () => {
      await loaded(withState(WINDOWS));
      await open(/Audit Evidence/);
      expect(cellsOf(tableWith("Interface Name", "IP Address"))).toEqual([
        ["Ethernet", "10.40.2.30", "/24", "00-1A-2B-3C-4D-30", "Intel NIC"],
      ]);

      for (const raw of [
        "eth0: flags=4163<UP,BROADCAST>  mtu 1500",
        JSON.stringify([{ unknown: 1 }]),
      ]) {
        cleanup();
        await loaded(withState({ ...WINDOWS, network_interfaces_raw: raw }));
        await open(/Audit Evidence/);
        expect(tableWith("Interface Name")).toBeUndefined();
        expect(
          [...document.querySelectorAll("pre")].map((p) => p.textContent),
        ).toContain(raw);
        cleanup();
      }
    });

    it("shows no audit evidence section when there is no raw evidence", async () => {
      await loaded(
        withState({
          target: "10.40.2.60",
          system_info: { os_name: "Debian" },
          detected_os: "linux",
        }),
      );
      expect(
        screen.queryAllByRole("button", { name: /Audit Evidence/ }),
      ).toHaveLength(0);
      expect(bodyText()).toMatch(
        /Credentialed scan complete — results saved to history\./,
      );
    });

    it("renders scan-supplied text as text, never as markup", async () => {
      const markup = '<img src="x" onerror="window.__crPwned=1"><b>bold</b>';
      await loaded(
        withState({
          ...LINUX,
          cron_info_raw: markup,
          sudo_rules_raw: markup,
          security_issues: [markup],
          cves: [{ ...LINUX.cves[0], description: markup }],
          running_services: [{ name: markup, description: markup }],
        }),
      );
      await open(/Scheduled Cron Jobs/);
      await open(/Audit Evidence/);
      await open(/Running Services/);
      expect(document.querySelector("img")).toBeNull();
      expect(document.querySelector("b")?.textContent).not.toBe("bold");
      expect(window.__crPwned).toBeUndefined();
      expect(bodyText()).toContain(markup);
    });
  });

  describe("sensitive output", () => {
    const CASES = [
      ["AWS_SECRET_ACCESS_KEY=placeholder", "AWS_SECRET_ACCESS_KEY=********"],
      ["DB_PASSWORD=p=ss=w0rd", "DB_PASSWORD=********"],
      ["API_TOKEN: hx-token-77aa", "API_TOKEN: ********"],
      ["Authorization:Bearer hx-bearer-01", "Authorization:********"],
      [
        "DATABASE_URL=postgres://auditor:hx-dbpass-42@db/prod",
        "DATABASE_URL=********",
      ],
      ["export GITHUB_TOKEN = hx-gh-5e", "export GITHUB_TOKEN =********"],
      ["PATH=/usr/bin:/bin", "PATH=********"],
      ["KEY=", "KEY=********"],
      ["a:b:c", "a:********"],
      ["NAME:   ", "NAME:  ********"],
      // Partial exposure, pinned as it is: the rule masks after the first "="
      // even when a ":" separator comes before it.
      ["SECRET:hx-left=hx-right", "SECRET:hx-left=********"],
      // Nothing to mask: shown as it is.
      ["PLAIN_VALUE", "PLAIN_VALUE"],
      [4242, "4242"],
    ];
    const SECRETS = [
      "placeholder",
      "ss=w0rd",
      "hx-token-77aa",
      "hx-bearer-01",
      "hx-dbpass-42",
      "hx-gh-5e",
      "hx-right",
    ];
    const MASKED = {
      target: "10.40.2.50",
      detected_os: "linux",
      system_info: { os_name: "Debian" },
      env_vars_flagged: CASES.map(([input]) => input),
    };

    it("flagged environment variables are not in the document until the evidence is opened", async () => {
      await loaded(withState(MASKED));
      expect(document.documentElement.outerHTML).not.toContain(
        "AWS_SECRET_ACCESS_KEY",
      );
      expect(document.documentElement.outerHTML).not.toContain("PLAIN_VALUE");
    });

    it.each(CASES)("masks %j as %j", async (input, output) => {
      await loaded(withState(MASKED));
      await open(/Audit Evidence/);
      expect(leafTexts()).toContain(output);
    });

    it("renders one line per flagged variable, and no flagged value anywhere in the document", async () => {
      await loaded(withState(MASKED));
      await open(/Audit Evidence/);
      expect(bodyText()).toMatch(
        new RegExp(`Sensitive Environment Variables \\(${CASES.length}\\)`),
      );
      const html = document.documentElement.outerHTML;
      for (const secret of SECRETS) expect(html).not.toContain(secret);
      // The partially exposed case above shows its left-hand part.
      expect(html).toContain("SECRET:hx-left=");
    });

    it("other raw evidence is shown as collected, unmasked", async () => {
      await loaded(
        withState({
          ...MASKED,
          sudo_rules_raw: "svc ALL=(root) NOPASSWD: /opt/token=hx-sudo-1",
        }),
      );
      await open(/Audit Evidence/);
      expect(
        [...document.querySelectorAll("pre")].map((p) => p.textContent),
      ).toContain("svc ALL=(root) NOPASSWD: /opt/token=hx-sudo-1");
    });

    it("writes nothing from the report or the ticket to the console", async () => {
      replyWith(
        RUNNING,
        record({ results: { credentialed: { report: MASKED } } }),
      );
      await loaded();
      await frame({ percentage: 50, message: "Collecting environment" });
      await frame({ status: "complete" });
      await open(/Audit Evidence/);
      const logged = consoleSpies
        .flatMap((spy) => spy.mock.calls)
        .map((args) => args.map(String).join(" "))
        .join("\n");
      for (const secret of [...SECRETS, "hx-left", TICKET])
        expect(logged).not.toContain(secret);
    });
  });

  describe("navigation and permissions", () => {
    it.each([
      [/New Scan$/, "/scan/credentialed"],
      [/^History$/, "/history"],
      [/^View History$/, "/history"],
      [/↺ New Scan|^New Scan$/, "/scan/credentialed"],
    ])("the report's %s button goes to %s", async (name, to) => {
      await loaded();
      const buttons = screen.getAllByRole("button", { name });
      fireEvent.click(buttons.at(-1));
      await flush();
      expect(location()).toBe(to);
    });

    it("the header's New Scan also goes to a new credentialed scan", async () => {
      await loaded();
      fireEvent.click(screen.getAllByRole("button", { name: /New Scan/ })[0]);
      await flush();
      expect(location()).toBe("/scan/credentialed");
    });

    it.each([
      [/^History$/, "/history"],
      [/^New Scan$/, "/scan/credentialed"],
      [/^Try Again$/, "/scan/credentialed"],
    ])("the failure view's %s button goes to %s", async (name, to) => {
      replyWith({
        ...RUNNING,
        status: "failed",
        failure_reason: "Authentication failed",
      });
      await loaded();
      fireEvent.click(screen.getByRole("button", { name }));
      await flush();
      expect(location()).toBe(to);
    });

    it("App.jsx mounts both routes behind the base sign-in check only, and the page checks no permission", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const base = app.indexOf("<Route element={<PrivateRoute />}>");
      const firstGate = app.indexOf("requiredPermission", base);
      for (const re of [
        /path="\/scan\/credentialed\/results"\s+element=\{<CredentialedResults \/>\}/,
        /path="\/scan\/:scanId\/credentialed-results"\s+element=\{<CredentialedResults \/>\}/,
      ]) {
        const at = app.search(re);
        expect(at).toBeGreaterThan(base);
        expect(at).toBeLessThan(firstGate);
      }
      expect(app.match(/<CredentialedResults\b/g)).toHaveLength(2);
      const page = readFileSync(
        path.join(SRC, "pages/scan/CredentialedResults.jsx"),
        "utf8",
      );
      expect(page).not.toMatch(
        /\bcan\(|usePermission|hasPermission|requiredPermission/,
      );
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 23 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const expandAll = async () => {
  for (let i = 0; i < 30; i += 1) {
    const closed = screen.queryAllByRole("button", { expanded: false });
    if (!closed.length) return;
    fireEvent.click(closed[0]);
    await flush();
  }
};

const runningWithFrames = async () => {
  replyWith(RUNNING);
  await loaded();
  await frame({
    percentage: 40,
    message: "Collecting packages",
    stage: "collection",
  });
  await frame({ message: "Reading crontab failed: permission denied" });
};

describe("CredentialedResults — batch 23", () => {
  it("has one level-one heading in each state", async () => {
    replyWith(() => new Promise(() => {}));
    let view = await loaded();
    expect(screen.getAllByRole("heading", { level: 1 }).map(squash)).toEqual([
      expect.stringMatching(/Credentialed Scan In Progress$/),
    ]);
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Credentialed Scan In Progress",
      }),
    ).toBeTruthy();
    view.unmount();

    replyWith({
      ...RUNNING,
      status: "failed",
      failure_reason: "Authentication failed",
    });
    view = await loaded();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Credentialed Scan Results",
      }),
    ).toBeTruthy();
    view.unmount();

    replyWith(record());
    await loaded();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Credentialed Scan Results",
      }),
    ).toBeTruthy();
  });

  it("each report section is a level-two heading holding a disclosure button", async () => {
    await loaded();
    const heading = screen.getByRole("heading", {
      level: 2,
      name: "System Information",
    });
    const toggle = within(heading).getByRole("button", {
      name: "System Information",
    });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(
      document.getElementById(toggle.getAttribute("aria-controls")),
    ).not.toBeNull();

    const coverage = within(
      screen.getByRole("heading", {
        level: 2,
        name: "Assessment coverage — what this scan examined",
      }),
    ).getByRole("button");
    expect(coverage.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(coverage);
    await flush();
    expect(coverage.getAttribute("aria-expanded")).toBe("true");
    expect(
      document.getElementById(coverage.getAttribute("aria-controls")),
    ).not.toBeNull();
  });

  it("sub-sections are level-three headings, and key facts are a description list", async () => {
    await loaded();
    expect(
      screen.getByRole("heading", { level: 3, name: "Disk Usage" }),
    ).toBeTruthy();
    await open(/Audit Evidence/);
    expect(
      screen.getByRole("heading", { level: 3, name: "Sudo Rules" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("heading", {
        level: 3,
        name: "Sensitive Environment Variables (2)",
      }),
    ).toBeTruthy();
    expect(screen.getAllByRole("term").map(squash)).toContain("Hostname");
    expect(screen.getAllByRole("definition").map(squash)).toContain("web-01");
  });

  it("captions every table and scopes its column headers", async () => {
    replyWith(MULTI);
    await loaded();
    await expandAll();
    for (const host of ["10.40.2.21", "10.40.2.30"]) {
      fireEvent.click(
        screen.getByRole("button", {
          name: new RegExp(`^${host.replace(/\./g, "\\.")}`),
        }),
      );
      await flush();
      await expandAll();
      for (const t of tables()) {
        expect(squash(t.querySelector("caption"))).not.toBe("");
        for (const th of t.querySelectorAll("thead th")) {
          expect(th.getAttribute("scope")).toBe("col");
        }
      }
      // The sections really opened: the Linux host has nine tables, the
      // Windows host three.
      expect(tables().length).toBeGreaterThanOrEqual(3);
    }
  });

  it("labels every search box", async () => {
    await loaded();
    await expandAll();
    for (const name of [
      "Search services",
      "Search listening sockets",
      "Search packages",
      "Search users",
    ]) {
      expect(screen.getByRole("searchbox", { name })).toBeTruthy();
    }
  });

  it("groups the severity filter and states which band is selected", async () => {
    await loaded();
    const group = screen.getByRole("group", {
      name: "Filter findings by severity",
    });
    const all = within(group).getByRole("button", { name: /^All/ });
    const high = within(group).getByRole("button", { name: /^High/ });
    expect(all.getAttribute("aria-pressed")).toBe("true");
    expect(high.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(high);
    await flush();
    expect(high.getAttribute("aria-pressed")).toBe("true");
    expect(all.getAttribute("aria-pressed")).toBe("false");
  });

  it("groups the audited hosts and states which one is shown", async () => {
    replyWith(MULTI);
    await loaded();
    const group = screen.getByRole("group", { name: "Audited hosts" });
    const [first, second] = within(group).getAllByRole("button");
    expect(first.getAttribute("aria-pressed")).toBe("true");
    expect(second.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(second);
    await flush();
    expect(second.getAttribute("aria-pressed")).toBe("true");
  });

  it("reports live progress as a named progress bar, an ordered list of stages and a log", async () => {
    await runningWithFrames();
    const bar = screen.getByRole("progressbar", {
      name: "Credentialed scan progress",
    });
    expect(bar.getAttribute("aria-valuenow")).toBe("40");
    const stages = screen.getByRole("list", { name: "Scan stages" });
    const items = within(stages).getAllByRole("listitem");
    expect(items).toHaveLength(5);
    expect(items.map((li) => li.getAttribute("aria-current"))).toEqual([
      null,
      null,
      "step",
      null,
      null,
    ]);
    const log = screen.getByRole("log", { name: "Live activity" });
    expect(within(log).getByText("Collecting packages")).toBeTruthy();
  });

  it("announces a failed scan and an unreachable host", async () => {
    replyWith({
      ...RUNNING,
      status: "failed",
      failure_reason: "Authentication failed for auditor",
    });
    let view = await loaded();
    expect(squash(screen.getByRole("alert"))).toMatch(
      /Scan Failed.*Authentication failed for auditor/,
    );
    view.unmount();

    replyWith({
      ...RUNNING,
      status: "failed",
      failure_reason: "No route to host",
    });
    view = await loaded();
    expect(squash(screen.getByRole("alert"))).toMatch(
      /Host is unavailable\/down\/unreachable/,
    );
  });

  it("presents severities, audit results and exposure as design-system badges", async () => {
    await loaded();
    // Findings are a list, and each one's band is a severity badge.
    const finding = screen
      .getByRole("link", { name: "CVE-2024-6387" })
      .closest("li");
    expect(finding).not.toBeNull();
    expect(finding.querySelector(".cc-sev--critical")).not.toBeNull();
    const audits = tableWith("Configuration / Audit", "Status");
    expect([...audits.querySelectorAll(".cc-badge")].map(squash)).toEqual([
      "PASS",
      "FAIL",
      "WARN",
    ]);
    await open(/Listening sockets/);
    expect(screen.getByText("Exposed").closest(".cc-badge")).not.toBeNull();
  });

  it("hides decorative glyphs from assistive technology in every state", async () => {
    const glyphs = /[🔐🔌🔍📦🧠💾🧭🖥⚠⚙👤📅📋🐧🪟↺←→▲▼✓]/u;
    const exposedGlyphs = () => {
      const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
      );
      const exposed = [];
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (
          glyphs.test(n.textContent) &&
          !n.parentElement.closest("[aria-hidden=true]")
        ) {
          exposed.push(n.textContent.trim());
        }
      }
      return exposed;
    };

    await runningWithFrames();
    await frame({ stage: "syncing" });
    expect(exposedGlyphs()).toEqual([]);
    cleanup();

    replyWith({
      ...RUNNING,
      status: "failed",
      failure_reason: "Authentication failed",
    });
    await loaded();
    expect(exposedGlyphs()).toEqual([]);
    cleanup();

    replyWith({
      ...RUNNING,
      status: "failed",
      failure_reason: "No route to host",
    });
    await loaded();
    expect(exposedGlyphs()).toEqual([]);
    cleanup();

    replyWith(MULTI);
    await loaded();
    await expandAll();
    expect(exposedGlyphs()).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: /^10\.40\.2\.30/ }));
    await flush();
    await expandAll();
    expect(exposedGlyphs()).toEqual([]);
  });

  it("renders no inline style of its own in any state", async () => {
    const styled = () =>
      [...document.body.querySelectorAll("[style]")]
        .filter(
          // A progress bar's width is the one per-instance value, set by CcureProgress.
          (el) => !el.classList.contains("cc-progress__bar"),
        )
        .filter(
          // Same carve-out, second component: CcureToastProvider portals its
          // regions to document.body and sets their offset inline. The contract
          // here is that *this page* hand-rolls no styles, not that no design
          // system component ever sets one on itself.
          (el) => !el.classList.contains("cc-toaster"),
        );

    await runningWithFrames();
    expect(styled()).toEqual([]);
    cleanup();

    replyWith({
      ...RUNNING,
      status: "failed",
      failure_reason: "No route to host",
    });
    await loaded();
    expect(styled()).toEqual([]);
    cleanup();

    replyWith(MULTI);
    await loaded();
    await expandAll();
    expect(styled()).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: /^10\.40\.2\.30/ }));
    await flush();
    await expandAll();
    expect(styled()).toEqual([]);
  });

  it("carries no colour literals or legacy classes, and styles itself from tokens", () => {
    const source = readFileSync(
      path.join(SRC, "pages/scan/CredentialedResults.jsx"),
      "utf8",
    );
    expect(source).toMatch(
      /import\s+["']\.\.\/\.\.\/styles\/credentialed-results\.css["']/,
    );
    expect(source).toMatch(/from\s+["']\.\.\/\.\.\/design-system["']/);
    expect(source).not.toMatch(/style=\{/);
    expect(source).not.toMatch(/\bstyle:\s*\{/);
    expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(source).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(source).not.toMatch(/var\(--/);
    const classes = [
      ...source.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g),
    ].flatMap((m) => (m[1] ?? m[2]).split(/\s+/));
    const legacy = classes.filter((c) =>
      /^(btn|btn--|alert|page-|summary-|kv-|cve-|issue-list|phase-footer|pipeline-|progress-|muted|ip-code|empty-state|section-title)/.test(
        c,
      ),
    );
    expect(legacy).toEqual([]);

    const cssPath = path.join(SRC, "styles/credentialed-results.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)/g) || []).toEqual([]);
    expect(css).toMatch(/var\(--ccure-/);
    expect(css).toMatch(/:focus-visible/);
  });
});
