/**
 * src/modules/audit/pages/scan/CredentialedResults.jsx
 * Displays credentialed scan report.
 * Can hydrate from router state (fresh scan) or GET /scans/{id} (history).
 *
 * Checkpoint 3C batch 23 — on the design system. The report's sources, the
 * ticket, the progress socket and its polling fallback, masking and navigation
 * are unchanged, and pinned by
 * src/__tests__/pages/scan/CredentialedResults.test.jsx, written against the
 * page before migration.
 */
import { useEffect, useId, useState, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import RiskBadge from "@audit/components/common/RiskBadge";
import { getScan } from "@audit/api/scans";
import api from "@shell/api/axiosInstance";
import {
  collectCredentialedReports,
  collectFailedHosts,
} from "@audit/utils/credentialedReport";
import CVELink from "@audit/components/common/CVELink";
import ConfigAuditSection from "@audit/components/credentialed/ConfigAuditSection";
import ReportExportPanel from "@audit/components/common/ReportExportPanel";
import ScanPolicySnapshot from "@audit/components/credentialed/ScanPolicySnapshot";
import FindingsListSection from "@audit/components/credentialed/FindingsListSection";
import PackageCoverageSection from "@audit/components/credentialed/PackageCoverageSection";
import PackageInventorySection from "@audit/components/credentialed/PackageInventorySection";
import SuppressedFindingsSection from "@audit/components/credentialed/SuppressedFindingsSection";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureProgress,
  CcureTable,
  CcureToastProvider,
  CcureCheckbox,
  CcurePage,
  CcurePageHeader,
  CcureIcon,
} from "../../../../design-system";
import "../../styles/credentialed-results.css";

const STAGES = [
  { id: "connecting", label: "Connection", icon: "link" },
  { id: "detection", label: "OS Detection", icon: "search" },
  { id: "collection", label: "Collection", icon: "package" },
  { id: "analysis", label: "CVE Analysis", icon: "cpu" },
  { id: "syncing", label: "Finalizing", icon: "hard-drive" },
];

/**
 * How a listening socket relates to the network.
 *
 * The socket table proves a service is running; only a port scan proves it can
 * be reached. The one case the host settles alone is a loopback bind, which is
 * why "host-only" is a confident verdict while "undetermined" is not.
 */
const EXPOSURE_META = {
  exposed: {
    label: "Exposed",
    variant: "danger",
    title: "Listening and confirmed reachable from the scanner",
  },
  host_only: {
    label: "Host-only",
    variant: "success",
    title: "Bound to loopback — not reachable from the network",
  },
  filtered: {
    label: "Filtered",
    variant: "info",
    title: "Listening on the host but not reachable from the scanner",
  },
  undetermined: {
    label: "Not tested",
    variant: "neutral",
    title:
      "No network port scan was performed against this host, so reachability is unknown",
  },
};

/* A glyph repeats what its text already says, so assistive technology skips
   it. It stays in the page for sighted readers. */
function Glyph({ children }) {
  return (
    <span className="cr-glyph" aria-hidden="true">
      {children}
    </span>
  );
}

function ExposureBadge({ exposure }) {
  const meta = EXPOSURE_META[exposure] || EXPOSURE_META.undetermined;
  return (
    <CcureBadge variant={meta.variant} title={meta.title}>
      {meta.label}
    </CcureBadge>
  );
}

/* ── helpers ── */
function KV({ k, v, danger, warn, mono }) {
  const tone = danger
    ? " cr-kv__value--danger"
    : warn
      ? " cr-kv__value--warning"
      : "";
  return (
    <div className="cr-kv">
      <dt className="cr-kv__key">{k}</dt>
      <dd className={`cr-kv__value${mono ? " cr-kv__value--mono" : ""}${tone}`}>
        {v}
      </dd>
    </div>
  );
}

/**
 * What a transport could not collect, and which part of this page it belongs
 * to.
 *
 * The credentialed report records an unserved item under an `item:` prefix in
 * `collection_errors` — CLAUDE.md: recorded there "rather than left to look
 * like an empty reading from the host". Nothing surfaced them per section, so
 * a host whose password policy was never collected rendered exactly like a
 * host with no password-policy finding: `UNASSESSED ≠ PASS`.
 *
 * The map exists so the state is reported against the section a reader would
 * have looked in. An item with no entry here is still listed, under its own
 * key — an unmapped item must not disappear.
 */
const ITEM_SECTIONS = {
  password_policy: "Password Policy",
  privilege_context: "Privilege Context",
  firewall: "Firewall",
  telnet_status: "Telnet",
  netbios_status: "NetBIOS",
  tls_status: "TLS",
  open_ports: "Listening Sockets",
  scheduled_tasks: "Scheduled Tasks",
  failed_logins: "Login History",
  uptime: "System Information",
  services: "Running Services",
  users: "Users",
  local_groups: "Local Groups",
};

/**
 * The `item:`-prefixed entries of `collection_errors`, as
 * `{ item, section, reason }`.
 *
 * The reason is the backend's own sentence and is rendered verbatim — it says
 * why the transport could not serve the item, which is the part an operator
 * acts on.
 */
function unservedItems(collectionErrors) {
  return Object.entries(collectionErrors || {})
    .filter(([key]) => key.startsWith("item:"))
    .map(([key, reason]) => {
      const item = key.slice("item:".length);
      return {
        item,
        section: ITEM_SECTIONS[item] || item.replace(/_/g, " "),
        reason: String(reason ?? ""),
      };
    })
    .sort((a, b) => a.section.localeCompare(b.section));
}

/* A report section: a heading whose button shows or hides the body. The body
   is rendered only while open, as before — raw evidence, and the masked
   environment variables in it, are not in the page until asked for. */
function Section({ title, icon, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  const bodyId = useId();
  return (
    <section className="cr-section">
      <h2 className="cr-section__heading">
        <CcureButton
          variant="ghost"
          size="sm"
          type="button"
          className="cr-section__toggle"
          aria-expanded={open}
          aria-controls={open ? bodyId : undefined}
          onClick={() => setOpen((o) => !o)}
        >
          {icon ? <Glyph>{icon}</Glyph> : null}
          <span className="cr-section__title">{title}</span>
          <span className="cr-section__chevron" aria-hidden="true">
            {open ? "▲" : "▼"}
          </span>
        </CcureButton>
      </h2>
      {open && (
        <div id={bodyId} className="cr-section__body">
          {children}
        </div>
      )}
    </section>
  );
}

const maskSecretLine = (value) => {
  const text = String(value ?? "");
  const eq = text.indexOf("=");
  if (eq === -1) return text.replace(/(:\s*)(.+)$/i, "$1********");
  return `${text.slice(0, eq + 1)}********`;
};

/**
 * Build the page's view model from a stored scan, whichever shape its
 * credentialed report was written in.
 *
 * This used to read `results.credentialed.report` alone. A vulnerability-audit
 * scan nests one report per host under `results.phase3.data[]` instead, so it
 * returned null there — and because the caller read null on a *completed* scan
 * as "keep polling", the page spun for ever on a scan that had worked.
 * `collectCredentialedReports` walks the same three shapes the export layer
 * does; see Frontend/src/utils/credentialedReport.js.
 *
 * Returns null only when the scan genuinely carries no credentialed report,
 * which the caller renders as a terminal state rather than as progress.
 */
function hydrateFromHistory(detail) {
  const reports = collectCredentialedReports(detail);
  if (!reports.length) return null;
  const [first] = reports;
  return {
    scan_id: detail.id,
    scan_no: detail.scan_no ?? detail.display_id,
    _reports: reports,
    _hostsFailed: collectFailedHosts(detail),
    ...first,
  };
}

export default function CredentialedResults() {
  const navigate = useNavigate();
  const location = useLocation();
  const stateResult = location.state?.result ?? null;
  const scanIdParam = new URLSearchParams(location.search).get("scan_id");
  const hasReport = Boolean(
    stateResult?.system_info || stateResult?.cves || stateResult?.packages,
  );

  const [result, setResult] = useState(hasReport ? stateResult : null);
  const [loading, setLoading] = useState(hasReport ? false : !!scanIdParam);
  const [error, setError] = useState("");
  /* A completed scan that carries no credentialed report in any shape. Its own
     state rather than an error: nothing failed, and "the scan ran and
     authenticated to nothing" is a real answer an operator needs to be given
     rather than left waiting for. */
  const [noReport, setNoReport] = useState(false);
  const [scanStatus, setScanStatus] = useState(
    stateResult?.status || "running",
  );
  const [showSystemUsers, setShowSystemUsers] = useState(false);
  const [servicesSearch, setServicesSearch] = useState("");
  const [portsSearch, setPortsSearch] = useState("");
  const [packagesSearch, setPackagesSearch] = useState("");
  const [usersSearch, setUsersSearch] = useState("");
  // Which audited host is on screen. A scan may cover many; the report body
  // describes one at a time.
  const [hostIndex, setHostIndex] = useState(0);

  // Live progress state
  const [progress, setProgress] = useState({
    percentage: 0,
    message: "Initializing scan...",
    stage: "connecting",
    logs: [],
  });

  const logRef = useRef(null);

  // `ws.onclose` below needs to know whether results have arrived. Reading the
  // `result` state there would read the value captured when the socket was
  // opened — always null — so a socket closing *after* a successful completion
  // still armed the polling fallback and issued one more scan fetch. Listing
  // `result` as a dependency instead would tear down and rebuild the WebSocket
  // on completion, which costs the same extra request. A mirror ref gives the
  // handler the live value while leaving the socket's lifetime alone.
  const resultRef = useRef(hasReport ? stateResult : null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress.logs]);

  useEffect(() => {
    if (stateResult && stateResult.system_info) {
      resultRef.current = stateResult;
      setResult(stateResult);
      setLoading(false);
      return;
    }
    if (!scanIdParam) {
      setLoading(false);
      return;
    }

    let ws = null;
    let pollTimer = null;
    let cancelled = false;

    const fetchResult = async () => {
      try {
        const { data } = await getScan(scanIdParam);
        if (cancelled) return;

        const normalizedStatus = String(data.status || "running").toLowerCase();
        setScanStatus(normalizedStatus);

        if (
          normalizedStatus === "complete" ||
          normalizedStatus === "completed"
        ) {
          const r = hydrateFromHistory(data);
          if (r) {
            resultRef.current = r;
            setResult(r);
            setLoading(false);
            if (ws) ws.close();
            return true;
          }
          /* Completed, and no credentialed report in any of the shapes a scan
             can store one in. That is a terminal answer about the scan, not a
             reason to keep waiting: falling through to `return false` here is
             what left a successful scan rendering an indefinite spinner. */
          setNoReport(true);
          setLoading(false);
          if (ws) ws.close();
          return true;
        } else if (
          normalizedStatus === "failed" ||
          normalizedStatus === "cancelled" ||
          normalizedStatus === "canceled"
        ) {
          setError(data.failure_reason || `Scan ${normalizedStatus}`);
          setLoading(false);
          if (ws) ws.close();
          return true;
        }
        return false;
      } catch (err) {
        if (cancelled) return true;
        setError(
          err.response?.data?.detail ||
            err.message ||
            "Failed to load results.",
        );
        setLoading(false);
        return true;
      }
    };

    const startProgressWs = async () => {
      try {
        const { data: ticketData } = await api.post("/auth/ticket");
        if (cancelled) return;

        const baseURL = api.defaults.baseURL || "";
        const wsPrefix = baseURL.replace(/^http/, "ws");
        const wsUrl = `${wsPrefix}/scans/${scanIdParam}/progress?ticket=${encodeURIComponent(ticketData.ticket)}`;

        ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
          if (cancelled) return;
          const data = JSON.parse(event.data);
          if (data.phase === 5 && data.progress) {
            const p = data.progress;
            setProgress((prev) => ({
              percentage: p.percentage || prev.percentage,
              message: p.message || prev.message,
              stage: p.stage || prev.stage,
              logs: p.message
                ? [
                    ...prev.logs.slice(-49),
                    { text: p.message, time: new Date().toLocaleTimeString() },
                  ]
                : prev.logs,
            }));

            if (p.status === "complete") {
              fetchResult();
            } else if (p.status === "failed") {
              setError(p.message || "Scan failed");
              setLoading(false);
            }
          }
        };
        ws.onclose = () => {
          if (!cancelled && !resultRef.current) {
            // If WS closes but we don't have results yet, fallback to polling
            pollTimer = setTimeout(pollScan, 3000);
          }
        };
      } catch (err) {
        console.error("Failed to start progress WebSocket", err);
        pollTimer = setTimeout(pollScan, 3000);
      }
    };

    const pollScan = async () => {
      const finished = await fetchResult();
      if (!finished && !cancelled) {
        pollTimer = setTimeout(pollScan, 3000);
      }
    };

    // Initial check
    fetchResult().then((finished) => {
      if (!finished && !cancelled) {
        startProgressWs();
      }
    });

    return () => {
      cancelled = true;
      if (ws) ws.close();
      if (pollTimer) clearTimeout(pollTimer);
    };
  }, [scanIdParam, stateResult]);

  useEffect(() => {
    if (!loading && !result && !scanIdParam && !error) {
      navigate("/scan/credentialed", { replace: true });
    }
  }, [loading, result, scanIdParam, error, navigate]);

  /* ── loading (Progress Dashboard) ── */
  if (loading && !result) {
    const currentStageIndex = STAGES.findIndex((s) => s.id === progress.stage);

    return (
      <AppLayout pageTitle="Credentialed Scan In Progress">
        <CcurePage className="cr-page">
          <CcurePageHeader
            title="Credentialed Scan In Progress"
            subtitle={
              <>
                Target:{" "}
                <code className="cr-code">
                  {stateResult?.target || scanIdParam}
                </code>
                <span className="cr-muted">
                  {" "}
                  · Scan No. {stateResult?.scan_no || "-"}
                </span>
              </>
            }
          />

          <section className="cr-progress">
            <div className="cr-progress__intro">
              <span className="cr-progress__pulse" aria-hidden="true" />
              <div>
                <h2 className="cr-progress__message">{progress.message}</h2>
                <p className="cr-progress__desc">
                  Performing authenticated system inspection via SSH. This
                  typically takes 30-90 seconds.
                </p>
              </div>
            </div>

            <CcureProgress
              value={progress.percentage}
              label="Credentialed scan progress"
            />

            <ol className="cr-stages" aria-label="Scan stages">
              {STAGES.map((s, idx) => {
                const isDone = idx < currentStageIndex;
                const isActive = idx === currentStageIndex;
                return (
                  <li
                    key={s.id}
                    className={`cr-stage${isDone ? " cr-stage--done" : ""}${isActive ? " cr-stage--active" : ""}`}
                    aria-current={isActive ? "step" : undefined}
                  >
                    <span className="cr-stage__marker" aria-hidden="true">
                      {isDone ? "✓" : <CcureIcon name={s.icon} />}
                    </span>
                    <span className="cr-stage__label">{s.label}</span>
                    {isDone ? (
                      <span className="cc-sr-only"> (completed)</span>
                    ) : null}
                  </li>
                );
              })}
            </ol>

            <div className="cr-activity">
              <p className="cr-activity__label">
                <span className="cr-activity__dot" aria-hidden="true" />
                Live Activity
              </p>
              {/* A log region announces each new line politely, and it is
                  focusable so its scroll can be driven from the keyboard. */}
              <div
                ref={logRef}
                className="cr-log"
                role="log"
                aria-label="Live activity"
                tabIndex={0}
              >
                {progress.logs.length === 0 ? (
                  <p className="cr-log__empty">Waiting for activity...</p>
                ) : (
                  <ol className="cr-log__lines">
                    {progress.logs.map((log, i) => (
                      <li
                        key={i}
                        className={`cr-log__line${log.text.includes("failed") ? " cr-log__line--failed" : ""}`}
                      >
                        <span className="cr-log__time">[{log.time}]</span>
                        <span className="cr-log__text">{log.text}</span>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </div>
          </section>
        </CcurePage>
      </AppLayout>
    );
  }

  /* ── completed, but this scan carries no credentialed report ── */
  if (noReport && !result) {
    return (
      <AppLayout pageTitle="Credentialed Results">
        <CcurePage className="cr-page">
          <CcurePageHeader
            title="Credentialed Scan Results"
            actions={
              <div className="cr-header__actions">
                <CcureButton
                  variant="secondary"
                  onClick={() => navigate("/history")}
                >
                  History
                </CcureButton>
                <CcureButton onClick={() => navigate("/scan/credentialed")}>
                  New Scan
                </CcureButton>
              </div>
            }
          />

          <CcureAlert variant="info" title="No credentialed report">
            This scan completed, and it recorded no authenticated collection for
            any host. That is not the same as a host with no findings — nothing
            was assessed over a credentialed session here.
          </CcureAlert>
        </CcurePage>
      </AppLayout>
    );
  }

  /* ── error ── */
  if (error || scanStatus === "unreachable") {
    const isUnreachable =
      scanStatus === "unreachable" ||
      String(error).toLowerCase().includes("reach") ||
      String(error).toLowerCase().includes("timeout") ||
      String(error).toLowerCase().includes("route");

    return (
      <AppLayout pageTitle="Credentialed Results">
        <CcurePage className="cr-page">
          <CcurePageHeader
            title="Credentialed Scan Results"
            actions={
              <div className="cr-header__actions">
                <CcureButton
                  variant="secondary"
                  onClick={() => navigate("/history")}
                >
                  History
                </CcureButton>
                <CcureButton onClick={() => navigate("/scan/credentialed")}>
                  New Scan
                </CcureButton>
              </div>
            }
          />

          {isUnreachable ? (
            <CcureAlert
              variant="warning"
              title="Host is unavailable/down/unreachable"
            >
              The credentialed scan failed because the host could not be reached
              via SSH. Verify the IP address, network connectivity, and firewall
              rules.
            </CcureAlert>
          ) : (
            <CcureAlert variant="danger" title="Scan Failed">
              {error}
            </CcureAlert>
          )}

          <div className="cr-failure">
            <p className="cr-muted">
              {isUnreachable
                ? "Please ensure the target is powered on and accessible from the scanning engine."
                : "Please verify your SSH credentials and ensure the host is reachable."}
            </p>
            <CcureButton onClick={() => navigate("/scan/credentialed")}>
              Try Again
            </CcureButton>
          </div>
        </CcurePage>
      </AppLayout>
    );
  }

  if (!result) return null;

  // A scan covers one or more hosts. Everything below renders the selected
  // one; the scan-level identifiers stay on the outer record.
  const allReports =
    Array.isArray(result._reports) && result._reports.length
      ? result._reports
      : [result];
  const activeReport = allReports[Math.min(hostIndex, allReports.length - 1)];
  const hostsFailed = result._hostsFailed || [];
  const view = {
    scan_id: result.scan_id,
    scan_no: result.scan_no,
    display_id: result.display_id,
    ...activeReport,
  };

  const {
    target,
    username,
    scan_id,
    scan_no,
    display_id,
    scan_duration,
    detected_os = "linux",
    os_type_was_auto = false,
    // Six fields the API has always returned and nothing rendered. See
    // docs/api_ui_coverage/PHASE1_BASELINE.md for how that was measured.
    scan_type = "",
    config_audit = null,
    package_coverage = null,
    packages_enumerated = null,
    candidates_evaluated = null,
    suppressed_cves = [],
    // How the authenticated session was actually opened. Recorded by the
    // engine, not chosen by the operator — "credentialed access succeeded" is
    // not a useful answer on its own when the scanner picked the service.
    access = null,
    system_info = {},
    packages = [],
    package_count = 0,
    running_services = [],
    open_ports_credentialed = [],
    users = [],
    suid_binaries = [],
    world_writable_dirs = [],
    sudo_nopasswd = false,
    sudo_rules_raw = "",
    security_issues = [],
    failed_login_count = 0,
    brute_force_warning = false,
    failed_logins_recent = [],
    network_interfaces_raw = "",
    env_vars_flagged = [],
    cves = [],
    cve_count = 0,
    severity_summary = {},
    hardening_audits = {},
    cron_info_raw = "",
    suspicious_scheduled_tasks = [],
    local_groups = [],
    coverage = {},
    exposure_summary = {},
    collection_errors = {},
    inventory_complete = true,
  } = view;

  // Absent is not zero. The vulnerability-audit pipeline stores a host's
  // posture without its package list or the per-item security lists, and the
  // defaults above would render each as "0 found" / "No" — a clean answer to a
  // question this record never asked. Each such field checks it was recorded.
  const recorded = (key) => Object.prototype.hasOwnProperty.call(view, key);
  const NOT_RECORDED = "Not recorded for this scan";
  const inventoryStored = recorded("packages");

  /* Items this transport could not collect. Derived once: the page renders
     them as their own section and the reader needs them before the sections
     that would have shown the data. */
  const unserved = unservedItems(collection_errors);

  // Parse network_interfaces_raw if it is in JSON format
  const parsedInterfaces = (() => {
    if (!network_interfaces_raw) return null;
    try {
      const data = JSON.parse(network_interfaces_raw);
      const list = Array.isArray(data) ? data : [data];
      return list
        .map((iface) => {
          // Windows parser
          if ("InterfaceAlias" in iface || "InterfaceIndex" in iface) {
            return {
              name: iface.InterfaceAlias || `Interface ${iface.InterfaceIndex}`,
              ip: iface.IPAddress || "—",
              prefix: iface.PrefixLength || "",
              mac: iface.MacAddress || "—",
              desc: iface.InterfaceDescription || "—",
            };
          }
          // Linux JSON parser (from ip -j addr)
          if ("ifname" in iface) {
            const ipv4 = iface.addr_info?.find((a) => a.family === "inet");
            return {
              name: iface.ifname,
              ip: ipv4?.local || "—",
              prefix: ipv4?.prefixlen || "",
              mac: iface.address || "—",
              desc: iface.operstate
                ? `State: ${iface.operstate.toUpperCase()}`
                : "—",
            };
          }
          return null;
        })
        .filter(Boolean);
    } catch (e) {
      return null;
    }
  })();

  const osLabel = detected_os === "windows" ? "Windows" : "Linux";

  const overallRisk = (() => {
    if (severity_summary.Critical > 0) return "Critical";
    if (severity_summary.High > 0) return "High";
    if (severity_summary.Medium > 0) return "Medium";
    if (severity_summary.Low > 0) return "Low";
    return "Info";
  })();

  const SEV_ORDER = ["All", "Critical", "High", "Medium", "Low", "Info"];
  // The findings list owns its own severity filter and paging now; the page
  // only supplies the rows. See FindingsListSection for why it had to move.
  const filteredCvesSource = cves;
  const vulnerablePackageNames = new Set(
    cves.map((c) => String(c.package || "").toLowerCase()).filter(Boolean),
  );
  const packagesWithCves = packages.filter((pkg) =>
    vulnerablePackageNames.has(String(pkg.name || "").toLowerCase()),
  );
  const interactiveUsers = users.filter((u) => {
    if (detected_os === "windows") {
      const name = String(u.username || "").toLowerCase();
      const isSystem = [
        "guest",
        "defaultaccount",
        "wdagutilityaccount",
        "sshd",
      ].includes(name);
      return !isSystem;
    }
    return !u.is_system || u.is_root;
  });
  const displayedUsers = showSystemUsers ? users : interactiveUsers;

  const filteredServices = running_services.filter((svc) => {
    if (!servicesSearch) return true;
    const query = servicesSearch.toLowerCase();
    return (
      String(svc.name || "")
        .toLowerCase()
        .includes(query) ||
      String(svc.description || "")
        .toLowerCase()
        .includes(query) ||
      String(svc.sub_state || "")
        .toLowerCase()
        .includes(query)
    );
  });

  const filteredPorts = open_ports_credentialed.filter((p) => {
    if (!portsSearch) return true;
    const query = portsSearch.toLowerCase();
    // Searches every column the table shows, including the resolved software
    // and the exposure verdict — "exposed" is the filter an operator reaches
    // for first on a host with a hundred listeners.
    return [
      p.port,
      p.local_addr,
      p.state,
      p.process,
      p.product,
      p.version,
      p.exposure,
    ].some((field) =>
      String(field || "")
        .toLowerCase()
        .includes(query),
    );
  });

  const filteredPackages = packagesWithCves.filter((pkg) => {
    if (!packagesSearch) return true;
    const query = packagesSearch.toLowerCase();
    return (
      String(pkg.name || "")
        .toLowerCase()
        .includes(query) ||
      String(pkg.version || "")
        .toLowerCase()
        .includes(query) ||
      String(pkg.manager || "")
        .toLowerCase()
        .includes(query)
    );
  });

  const filteredUsers = displayedUsers.filter((u) => {
    if (!usersSearch) return true;
    const query = usersSearch.toLowerCase();
    return (
      String(u.username || "")
        .toLowerCase()
        .includes(query) ||
      String(u.uid || "")
        .toLowerCase()
        .includes(query) ||
      String(u.shell || "")
        .toLowerCase()
        .includes(query) ||
      String(u.home || "")
        .toLowerCase()
        .includes(query)
    );
  });

  const usersTableHead =
    detected_os === "windows"
      ? ["Username", "Role / Type", "Status", "Password Required", "Last Logon"]
      : ["Username", "UID", "Shell", "Home", "Type"];

  // The same reading of each account the table has always shown, as columns.
  const describeWindowsUser = (u) => {
    const isAdmin =
      u.is_admin === true || String(u.is_admin).toLowerCase() === "true";
    const isEnabled = String(u.enabled).toLowerCase() === "true";
    const isPwdRequired = String(u.pwd_required).toLowerCase() === "true";
    const lastLogon =
      u.last_logon && u.last_logon !== "None" && u.last_logon !== "null"
        ? u.last_logon
        : "—";

    const nameLower = String(u.username || "").toLowerCase();
    const isSystem = [
      "guest",
      "defaultaccount",
      "wdagutilityaccount",
      "sshd",
    ].includes(nameLower);

    let typeLabel = "User";
    if (isAdmin) {
      typeLabel = "Admin";
    } else if (isSystem) {
      typeLabel = "System";
    }
    return {
      isAdmin,
      isEnabled,
      isPwdRequired,
      lastLogon,
      isSystem,
      typeLabel,
    };
  };

  const usersColumns =
    detected_os === "windows"
      ? [
          {
            key: "username",
            header: usersTableHead[0],
            isRowHeader: true,
            mono: true,
            cell: (u) => (
              <span
                className={describeWindowsUser(u).isAdmin ? "cr-strong" : ""}
              >
                {u.username}
              </span>
            ),
          },
          {
            key: "type",
            header: usersTableHead[1],
            cell: (u) => {
              const { isAdmin, isSystem, typeLabel } = describeWindowsUser(u);
              return (
                <span
                  className={
                    isAdmin
                      ? "cr-tone-danger cr-strong"
                      : isSystem
                        ? "cr-muted"
                        : ""
                  }
                >
                  {typeLabel}
                </span>
              );
            },
          },
          {
            key: "enabled",
            header: usersTableHead[2],
            cell: (u) =>
              describeWindowsUser(u).isEnabled ? (
                <span className="cr-tone-success">Active</span>
              ) : (
                <span className="cr-muted cr-struck">Disabled</span>
              ),
          },
          {
            key: "pwd_required",
            header: usersTableHead[3],
            cell: (u) =>
              describeWindowsUser(u).isPwdRequired ? (
                <span>Yes</span>
              ) : (
                <span className="cr-tone-warning">
                  <CcureIcon name="alert-triangle" /> No
                </span>
              ),
          },
          {
            key: "last_logon",
            header: usersTableHead[4],
            mono: true,
            cell: (u) => (
              <span className="cr-muted">
                {describeWindowsUser(u).lastLogon}
              </span>
            ),
          },
        ]
      : [
          {
            key: "username",
            header: usersTableHead[0],
            isRowHeader: true,
            mono: true,
            cell: (u) => (
              <span className={u.is_root ? "cr-tone-danger" : ""}>
                {u.username}
              </span>
            ),
          },
          { key: "uid", header: usersTableHead[1], mono: true },
          {
            key: "shell",
            header: usersTableHead[2],
            cell: (u) => <span className="cr-muted">{u.shell}</span>,
          },
          {
            key: "home",
            header: usersTableHead[3],
            cell: (u) => <span className="cr-muted">{u.home}</span>,
          },
          {
            key: "kind",
            header: usersTableHead[4],
            cell: (u) =>
              u.is_root ? (
                <span className="cr-tone-danger">
                  <CcureIcon name="alert-triangle" /> root
                </span>
              ) : u.is_system ? (
                <span className="cr-muted">system</span>
              ) : (
                "user"
              ),
          },
        ];

  const hasAdvancedEvidence = Boolean(
    sudo_rules_raw ||
      network_interfaces_raw ||
      failed_logins_recent.length > 0 ||
      env_vars_flagged.length > 0 ||
      packages.length > 0,
  );

  return (
    <AppLayout pageTitle="Credentialed Results">
      <CcurePage className="cr-page">
        {/* Page header */}
        <CcurePageHeader
          title="Credentialed Scan Results"
          subtitle={
            <>
              <code className="cr-code">{target}</code>
              {username && (
                <span className="cr-muted"> · user: {username}</span>
              )}
              {scan_duration && (
                <span className="cr-muted"> · {scan_duration}s</span>
              )}
              {scan_id && (
                <span className="cr-muted">
                  {" "}
                  · Scan No. {scan_no ?? display_id ?? "-"}
                </span>
              )}
              {scan_type && (
                <span className="cr-muted"> · {scan_type} scan</span>
              )}
              {os_type_was_auto && (
                <CcureBadge variant="info" className="cr-os-badge">
                  <CcureIcon name="monitor" /> {osLabel} (auto-detected)
                </CcureBadge>
              )}
              {access?.transport && (
                <CcureBadge variant="success" className="cr-os-badge">
                  <CcureIcon name="lock" /> Authenticated over{" "}
                  {String(access.transport).toUpperCase()} on port {access.port}
                  {access.how === "discovered" ? " (detected)" : ""}
                </CcureBadge>
              )}
              {/* TLS on the authenticated session is three-valued. The engine
                  carries `use_tls` rather than re-deriving it, because it
                  infers TLS from the port only for the conventional layout —
                  so `null` means "not settled by convention", which is neither
                  on nor off. Collapsing it to a boolean asserts one of them. */}
              {access?.transport && (
                <CcureBadge
                  variant={
                    access.use_tls === true
                      ? "success"
                      : access.use_tls === false
                        ? "warning"
                        : "neutral"
                  }
                  className="cr-os-badge"
                  title={
                    access.use_tls === null || access.use_tls === undefined
                      ? "The scan did not record whether the session used TLS. 5985 and 5986 are settled by convention; anything else is not, and a guess would address an HTTPS listener as http://."
                      : "Whether the authenticated session was carried over TLS."
                  }
                >
                  TLS:{" "}
                  {access.use_tls === true
                    ? "yes"
                    : access.use_tls === false
                      ? "no"
                      : "not recorded"}
                </CcureBadge>
              )}
            </>
          }
          actions={
            <div className="cr-header__actions">
              {/* The comparison is a question about this scan, so it is reached
                from this scan rather than from a separate destination the
                operator has to find and re-identify the scan in. */}
              <CcureButton
                variant="secondary"
                onClick={() =>
                  navigate(
                    `/scan/comparison?scan_id=${encodeURIComponent(scan_id)}`,
                  )
                }
              >
                <Glyph>⇄</Glyph> Compare with a previous scan
              </CcureButton>
              <CcureButton
                variant="secondary"
                onClick={() => navigate("/scan/credentialed")}
              >
                <Glyph>←</Glyph> New Scan
              </CcureButton>
              <CcureButton
                variant="secondary"
                onClick={() => navigate("/history")}
              >
                History
              </CcureButton>
            </div>
          }
        >
          {/* What else was tried. The badge alone says which service
                accepted the credential and silently loses the fact that
                another was probed and refused -- which is the half an
                operator needs when the answer surprises them ("why SMB? I
                thought WinRM was on"). Shown only when there is something to
                say, so the ordinary single-candidate case stays quiet. */}
          {access?.considered?.length > 1 && (
            <p className="cr-muted cr-access-considered">
              Services probed:{" "}
              {access.considered
                .map(
                  (c) =>
                    `${String(c.transport).toUpperCase()} — ${
                      c.resolved ? "used" : "no answer"
                    }`,
                )
                .join(" · ")}
            </p>
          )}
        </CcurePageHeader>

        {/* Summary */}
        <ul className="cr-summary" aria-label="Summary">
          <li className="cr-summary__item">
            <RiskBadge level={overallRisk} />
          </li>
          <li className="cr-summary__item">
            <strong>{system_info.os_name || osLabel}</strong>
          </li>
          <li className="cr-summary__item cr-muted">
            {detected_os === "windows" ? (
              <>
                Build{" "}
                <strong>
                  {system_info.os_build || system_info.os_version_id || "—"}
                </strong>
              </>
            ) : (
              <>
                Kernel <strong>{system_info.kernel_version || "—"}</strong>
              </>
            )}
          </li>
          <li className="cr-summary__item">
            <strong>{package_count}</strong> packages
          </li>
          <li
            className={`cr-summary__item ${cve_count > 0 ? "cr-tone-warning" : "cr-tone-success"}`}
          >
            <strong>{cve_count}</strong> CVE{cve_count !== 1 ? "s" : ""}
          </li>
          {candidates_evaluated !== null &&
            candidates_evaluated !== undefined && (
              <li className="cr-summary__item cr-muted">
                <strong>{Number(candidates_evaluated).toLocaleString()}</strong>{" "}
                candidates evaluated
              </li>
            )}
          {brute_force_warning && (
            <li className="cr-summary__item cr-tone-danger">
              <CcureIcon name="alert-triangle" /> Brute-force activity detected
            </li>
          )}
        </ul>

        {/* Host selector — only when the scan covered more than one host */}
        {allReports.length > 1 && (
          <div className="cr-hosts" role="group" aria-label="Audited hosts">
            <span className="cr-hosts__label">
              {allReports.length} hosts audited:
            </span>
            {allReports.map((r, i) => {
              const isActive = i === hostIndex;
              const worst = r.severity_summary || {};
              const band = worst.Critical
                ? "critical"
                : worst.High
                  ? "high"
                  : worst.Medium
                    ? "medium"
                    : "clear";
              return (
                <CcureButton
                  key={r.target || i}
                  variant="secondary"
                  size="sm"
                  className="cr-toggle cr-host"
                  aria-pressed={isActive}
                  onClick={() => setHostIndex(i)}
                >
                  <span
                    className={`cr-host__dot cr-host__dot--${band}`}
                    aria-hidden="true"
                  />
                  {r.target}
                  <span className="cr-toggle__count">({r.cve_count ?? 0})</span>
                  <span className="cc-sr-only"> CVEs</span>
                </CcureButton>
              );
            })}
          </div>
        )}

        {/* Hosts that could not be audited. Silently omitting them would let a
            partial scan read as a complete one. */}
        {hostsFailed.length > 0 && (
          <CcureAlert
            variant="warning"
            live={false}
            title={
              <>
                {hostsFailed.length} host
                {hostsFailed.length !== 1 ? "s" : ""} could not be audited
              </>
            }
          >
            <ul className="cr-failed-hosts">
              {hostsFailed.map((h) => (
                <li key={h.target}>
                  <code className="cr-code">{h.target}</code> — {h.reason}
                </li>
              ))}
            </ul>
            <p className="cr-failed-hosts__note">
              These hosts are unassessed. Their absence from the findings below
              is not evidence that they are clean.
            </p>
          </CcureAlert>
        )}

        {/* Assessment coverage — what this scan did and did not examine */}
        {Object.keys(coverage).length > 0 && (
          <Section
            icon={<CcureIcon name="compass" />}
            title="Assessment coverage — what this scan examined"
          >
            <p className="cr-note">
              Coverage bounds every conclusion in this report. A check this
              policy does not perform cannot produce a finding here, so an empty
              section means &quot;not looked for&quot;, not &quot;not
              present&quot;.
            </p>
            <dl className="cr-kv-list">
              {coverage.authenticated_checks && (
                <KV
                  k="Authenticated checks"
                  v={coverage.authenticated_checks}
                />
              )}
              {coverage.unauthenticated_checks && (
                <KV
                  k="Unauthenticated checks"
                  v={coverage.unauthenticated_checks}
                  warn
                />
              )}
              {coverage.network_reachability && (
                <KV
                  k="Network reachability"
                  v={coverage.network_reachability}
                  warn={!exposure_summary.correlated_with_port_scan}
                />
              )}
              {coverage.port_range && (
                <KV k="Port scan" v={coverage.port_range} warn />
              )}
              {coverage.service_detection && (
                <KV k="Service detection" v={coverage.service_detection} />
              )}
              {coverage.os_detection && (
                <KV k="OS detection" v={coverage.os_detection} />
              )}
              {/* Part of the assessment context, and on the live credentialed
                  report it says "Not applicable — no network probing
                  performed", which is exactly the sort of sentence a reader
                  needs and a shorter label would lose. */}
              {coverage.timing_template && (
                <KV k="Timing" v={coverage.timing_template} />
              )}
              {coverage.discovery_scan_method && (
                <KV k="Host discovery" v={coverage.discovery_scan_method} />
              )}
              <KV
                k="Software inventory"
                v={
                  inventory_complete
                    ? `Complete — ${package_count} package(s) enumerated`
                    : "Incomplete — see collection errors below"
                }
                danger={!inventory_complete}
              />
            </dl>
            {Object.keys(collection_errors).length > 0 && (
              <div className="cr-subsection">
                <h3 className="cr-subheading">Collection errors</h3>
                <CcureTable
                  caption="Collection errors"
                  density="compact"
                  rows={Object.entries(collection_errors)}
                  rowKey={([section]) => section}
                  columns={[
                    {
                      key: "section",
                      header: "Section",
                      isRowHeader: true,
                      mono: true,
                      cell: ([section]) => section,
                    },
                    {
                      key: "reason",
                      header: "Reason",
                      cell: ([, reason]) => (
                        <span className="cr-tone-warning">
                          {String(reason)}
                        </span>
                      ),
                    },
                  ]}
                />
              </div>
            )}
          </Section>
        )}

        {/* System Info */}
        {unserved.length > 0 && (
          <Section
            icon={<CcureIcon name="slash" />}
            title={`Not assessed (${unserved.length})`}
            defaultOpen
          >
            <p className="cr-note">
              This transport could not collect the items below. They are
              <strong> not</strong> findings-free sections — nothing was
              established about them on this host, and each reason is the
              scanner&apos;s own.
            </p>
            <CcureTable
              caption="Items this transport could not collect"
              density="compact"
              rows={unserved}
              rowKey={(row) => row.item}
              columns={[
                {
                  key: "section",
                  header: "Section",
                  isRowHeader: true,
                  cell: (row) => row.section,
                },
                {
                  key: "state",
                  header: "State",
                  cell: () => (
                    <CcureBadge variant="warning">Not assessed</CcureBadge>
                  ),
                },
                {
                  key: "reason",
                  header: "Reason",
                  cell: (row) => row.reason || "—",
                },
              ]}
            />
          </Section>
        )}

        <Section
          icon={<CcureIcon name="monitor" />}
          title="System Information"
          defaultOpen
        >
          <dl className="cr-kv-grid">
            <KV k="OS" v={system_info.os_name || "—"} />
            <KV k="Version" v={system_info.os_version_id || "—"} />
            <KV k="Kernel" v={system_info.kernel_version || "—"} mono />
            <KV k="Hostname" v={system_info.hostname || "—"} mono />
            <KV k="Manufacturer" v={system_info.manufacturer || "—"} />
            <KV k="Model" v={system_info.hardware_model || "—"} />
            <KV k="CPU" v={system_info.cpu_model || "—"} />
            <KV k="CPU Count" v={system_info.cpu_count || "—"} />
            <KV k="Architecture" v={system_info.cpu_arch || "—"} />
            <KV k="Uptime" v={system_info.uptime || "—"} />
            <KV k="Serial Number" v={system_info.serial_number || "—"} mono />
            <KV k="BIOS Version" v={system_info.bios_version || "—"} mono />
            <KV k="MAC Address" v={system_info.mac_address || "—"} mono />
            <KV k="Subnet" v={system_info.subnet || "—"} mono />
            {/* Three readings the collector records and the grid dropped.
                `os_confidence` arrives as a number here and as a word on the
                discovery phases, so it is printed as it came rather than
                converted; an absent one is never 0. `mac_vendor` arrives as an
                empty string on a host whose OUI did not resolve, which is not
                the same as a vendor called "". */}
            <KV k="OS Family" v={system_info.os_family || "not reported"} />
            <KV
              k="OS Confidence"
              v={
                system_info.os_confidence === null ||
                system_info.os_confidence === undefined ||
                system_info.os_confidence === ""
                  ? "not reported"
                  : String(system_info.os_confidence)
              }
            />
            <KV k="MAC Vendor" v={system_info.mac_vendor || "not resolved"} />
            <KV k="Domain" v={system_info.domain || "—"} mono />
            <KV k="FQDN" v={system_info.fqdn || "—"} mono />
            {system_info.memory_summary?.total && (
              <>
                <KV k="RAM Total" v={system_info.memory_summary.total} />
                <KV k="RAM Used" v={system_info.memory_summary.used} />
              </>
            )}
          </dl>
          {system_info.disk_usage?.length > 0 && (
            <div className="cr-subsection">
              <h3 className="cr-subheading">Disk Usage</h3>
              <CcureTable
                caption="Disk usage"
                density="compact"
                rows={system_info.disk_usage}
                rowKey={(d, i) => i}
                columns={[
                  {
                    key: "filesystem",
                    header: "Filesystem",
                    isRowHeader: true,
                    mono: true,
                  },
                  { key: "size", header: "Size" },
                  { key: "used", header: "Used" },
                  { key: "available", header: "Available" },
                  {
                    key: "use_pct",
                    header: "Use%",
                    cell: (d) => (
                      <span
                        className={
                          parseInt(d.use_pct) > 80 ? "cr-tone-warning" : ""
                        }
                      >
                        {d.use_pct}
                      </span>
                    ),
                  },
                  { key: "mounted_on", header: "Mount", mono: true },
                ]}
              />
            </div>
          )}
        </Section>

        {/* CVEs */}
        {cve_count > 0 && (
          <Section
            icon={<CcureIcon name="alert-triangle" />}
            title={`CVE Findings (${cve_count})`}
            defaultOpen
          >
            <FindingsListSection
              cves={filteredCvesSource}
              severitySummary={severity_summary}
              severityOrder={SEV_ORDER}
              glyph={Glyph}
            />
          </Section>
        )}

        {/* Configuration Audit. Always rendered, never gated on there being
            results: the component draws the distinction between "not
            assessed" and "assessed, nothing failed", and a section that
            disappears when an audit did not run tells the operator nothing
            about why. */}
        <Section
          icon={<CcureIcon name="file-text" />}
          title={
            config_audit && config_audit.assessed !== false
              ? `Configuration Audit (${config_audit.checks_assessed ?? (config_audit.results || []).length} assessed)`
              : "Configuration Audit"
          }
          defaultOpen={Boolean(
            config_audit && (config_audit.counts || {}).fail > 0,
          )}
        >
          <ConfigAuditSection configAudit={config_audit} />
        </Section>

        {/* Package coverage — the denominator for every package finding. */}
        <Section icon={<CcureIcon name="bar-chart" />} title="Package Coverage">
          <PackageCoverageSection coverage={package_coverage} />
        </Section>

        {/* The whole inventory, not only the packages that matched a CVE. */}
        <Section
          icon={<CcureIcon name="package" />}
          title={
            inventoryStored
              ? `Installed Software (${Number(packages_enumerated ?? packages.length).toLocaleString()})`
              : recorded("package_count")
                ? `Installed Software (${Number(package_count).toLocaleString()} enumerated, not stored)`
                : "Installed Software"
          }
        >
          <PackageInventorySection
            packages={packages}
            cves={cves}
            packagesEnumerated={packages_enumerated}
            stored={inventoryStored}
            enumeratedCount={recorded("package_count") ? package_count : null}
          />
        </Section>

        {/* What this scan actually assessed. Read from the scan's own
            record rather than the policy row it names, because the policy may
            have been edited, versioned, archived or deleted since and none of
            that changes what this scan did. */}
        <Section
          icon={<CcureIcon name="clipboard" />}
          title="Scan policy — what this scan assessed"
        >
          <ScanPolicySnapshot scanId={scan_id} />
        </Section>

        {/* Reports and exports. Placed after the findings and before the
            supporting detail: an operator who has read the verdict is the one
            who wants to take it away. */}
        <Section
          icon={<CcureIcon name="upload" />}
          title="Reports & Export"
          defaultOpen={false}
        >
          {/* This app mounts no global toast provider -- each page that wants
              to announce brings its own, as SecurityReports does. The panel
              announces the outcome of a download, so it supplies one here.
              The provider portals its regions to document.body, so sitting
              inside a collapsible section does not affect where they appear. */}
          <CcureToastProvider>
            <ReportExportPanel scanId={scan_id} scanNo={scan_no} />
          </CcureToastProvider>
        </Section>

        {/* Candidates evaluated and then ruled out. */}
        <Section
          icon={<CcureIcon name="slash" />}
          title={`Suppressed Findings (${(suppressed_cves || []).length})`}
        >
          <SuppressedFindingsSection
            suppressed={suppressed_cves}
            candidatesEvaluated={candidates_evaluated}
            reportedCount={cve_count}
          />
        </Section>

        {/* Security Audit */}
        <Section
          icon={<CcureIcon name="lock" />}
          title="Security Audit"
          defaultOpen={security_issues.length > 0 || sudo_nopasswd}
        >
          {security_issues.length > 0 && (
            <ul className="cr-issues">
              {security_issues.map((iss, i) => (
                <li key={i} className="cr-issue">
                  {iss}
                </li>
              ))}
            </ul>
          )}
          <dl className="cr-kv-grid">
            <KV
              k="NOPASSWD Sudo"
              v={
                !recorded("sudo_nopasswd") ? (
                  NOT_RECORDED
                ) : sudo_nopasswd ? (
                  <>
                    <CcureIcon name="alert-triangle" /> YES — any command
                    without password
                  </>
                ) : (
                  "No"
                )
              }
              danger={sudo_nopasswd}
            />
            <KV
              k="SUID Binaries"
              v={
                recorded("suid_binaries")
                  ? `${suid_binaries.length} found`
                  : NOT_RECORDED
              }
              warn={suid_binaries.length > 15}
            />
            <KV
              k="World-Writable Dirs"
              v={
                recorded("world_writable_dirs")
                  ? `${world_writable_dirs.length} found`
                  : NOT_RECORDED
              }
              warn={world_writable_dirs.length > 0}
            />
            <KV
              k="Failed Logins"
              v={
                !recorded("failed_login_count") ? (
                  NOT_RECORDED
                ) : (
                  <>
                    {failed_login_count}
                    {brute_force_warning && (
                      <>
                        {" "}
                        <CcureIcon name="alert-triangle" /> possible brute force
                      </>
                    )}
                  </>
                )
              }
              danger={brute_force_warning}
            />
          </dl>
          {Object.keys(hardening_audits).length > 0 && (
            <div className="cr-subsection">
              <h3 className="cr-subheading">OS Hardening & Auditing</h3>
              <CcureTable
                caption="OS hardening and auditing"
                density="compact"
                rows={Object.entries(hardening_audits)}
                rowKey={([key]) => key}
                columns={[
                  {
                    key: "label",
                    header: "Configuration / Audit",
                    isRowHeader: true,
                    cell: ([key, audit]) => audit.label || key,
                  },
                  {
                    key: "status",
                    header: "Status",
                    cell: ([, audit]) => (
                      <CcureBadge
                        variant={
                          audit.status === "PASS"
                            ? "success"
                            : audit.status === "FAIL"
                              ? "danger"
                              : "warning"
                        }
                      >
                        {audit.status}
                      </CcureBadge>
                    ),
                  },
                  {
                    key: "detail",
                    header: "Audit Findings Detail",
                    cell: ([, audit]) => audit.detail || "—",
                  },
                ]}
              />
            </div>
          )}
          {suid_binaries.length > 0 && (
            <div className="cr-subsection">
              <h3 className="cr-subheading">SUID Binaries</h3>
              <ul
                className="cr-paths cr-scroll"
                tabIndex={0}
                aria-label="SUID binaries"
              >
                {suid_binaries.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
            </div>
          )}
        </Section>

        {/* Running Services */}
        {running_services.length > 0 && (
          <Section
            icon={<CcureIcon name="settings" />}
            title={`Running Services (${running_services.length})`}
          >
            <div className="cr-toolbar">
              <CcureInput
                type="search"
                label="Search services"
                placeholder="Search services..."
                value={servicesSearch}
                onChange={(e) => setServicesSearch(e.target.value)}
                fieldClassName="cr-search"
              />
            </div>
            {filteredServices.length === 0 ? (
              <p className="cr-note">
                No services matching &quot;{servicesSearch}&quot;
              </p>
            ) : (
              <CcureTable
                caption="Running services"
                density="compact"
                rows={filteredServices}
                rowKey={(svc, i) => i}
                columns={[
                  {
                    key: "name",
                    header: "Service",
                    isRowHeader: true,
                    mono: true,
                  },
                  {
                    key: "sub_state",
                    header: "Status",
                    /* `svc.sub_state || "running"` printed "running" for every
                       service on a transport that does not report one — all
                       174 on the live Windows host — which is a state the scan
                       never established. Absent is absent. */
                    cell: (svc) =>
                      svc.sub_state ? (
                        <span className="cr-tone-success">{svc.sub_state}</span>
                      ) : (
                        <span className="cr-muted">not reported</span>
                      ),
                  },
                  {
                    key: "start_type",
                    header: "Start type",
                    /* How the service is configured to start, which is not
                       whether it is running: `Auto` on a stopped service and
                       `Manual` on a running one are both ordinary. Labelled so
                       the two cannot be read as one. */
                    cell: (svc) =>
                      svc.start_type ? (
                        <span
                          className="cr-mono"
                          title="How the service is configured to start. It does not say whether the service is running."
                        >
                          {svc.start_type}
                        </span>
                      ) : (
                        <span className="cr-muted">—</span>
                      ),
                  },
                  {
                    key: "description",
                    header: "Description",
                    cell: (svc) => (
                      <span className="cr-muted">{svc.description}</span>
                    ),
                  },
                ]}
              />
            )}
          </Section>
        )}

        {/* Listening sockets — read from the host, not from a port scan */}
        {open_ports_credentialed.length > 0 && (
          <Section
            icon={<CcureIcon name="link" />}
            title={`Listening sockets — host socket table (${open_ports_credentialed.length})`}
          >
            <p className="cr-note">
              {exposure_summary.correlated_with_port_scan ? (
                <>
                  These are the sockets the host reports it is listening on,
                  correlated with the port scan.{" "}
                  <strong className="cr-tone-danger">
                    {exposure_summary.listeners_exposed || 0} exposed
                  </strong>
                  {", "}
                  <strong className="cr-tone-info">
                    {exposure_summary.listeners_filtered || 0} filtered
                  </strong>
                  {", "}
                  <strong className="cr-tone-success">
                    {exposure_summary.listeners_host_only || 0} host-only
                  </strong>
                  {/* Listeners the correlation could not place on either side
                      of the boundary. Its own figure, never folded into
                      exposed, host-only or zero: `UNKNOWN != ZERO`. Rendered
                      only when the backend supplied it, so an older payload
                      shows nothing rather than a fabricated 0. */}
                  {typeof exposure_summary.listeners_undetermined ===
                  "number" ? (
                    <>
                      {", "}
                      <strong className="cr-tone-warning">
                        {exposure_summary.listeners_undetermined} undetermined
                      </strong>
                    </>
                  ) : null}
                  .
                </>
              ) : (
                <>
                  These are the sockets the host reports it is listening on —
                  not the results of a network port scan. Except for
                  loopback-bound services, whether each one is reachable from
                  the network was not tested.
                </>
              )}
            </p>
            <div className="cr-toolbar">
              <CcureInput
                type="search"
                label="Search listening sockets"
                placeholder="Search ports, IPs, or processes..."
                value={portsSearch}
                onChange={(e) => setPortsSearch(e.target.value)}
                fieldClassName="cr-search"
              />
            </div>
            {filteredPorts.length === 0 ? (
              <p className="cr-note">
                No open ports matching &quot;{portsSearch}&quot;
              </p>
            ) : (
              <CcureTable
                caption="Listening sockets"
                density="compact"
                rows={filteredPorts}
                rowKey={(p, i) => i}
                columns={[
                  {
                    key: "exposure",
                    header: "Exposure",
                    cell: (p) => <ExposureBadge exposure={p.exposure} />,
                  },
                  { key: "local_addr", header: "Local Addr", mono: true },
                  {
                    key: "port",
                    header: "Port",
                    isRowHeader: true,
                    mono: true,
                  },
                  {
                    key: "process",
                    header: "Process",
                    cell: (p) => (
                      <>
                        {p.process}
                        {p.pid && (
                          <span className="cr-muted cr-pid">pid {p.pid}</span>
                        )}
                      </>
                    ),
                  },
                  {
                    // What is actually answering on the port, read from the
                    // binary itself. Absent when the process is protected or
                    // ships no version resource — shown as unknown rather
                    // than left blank, which reads as "nothing there".
                    key: "software",
                    header: "Software",
                    cell: (p) =>
                      p.product ? (
                        <>
                          {p.product}
                          {p.version && (
                            <code className="cr-code cr-version">
                              {p.version}
                            </code>
                          )}
                        </>
                      ) : (
                        <span className="cr-muted">Not identified</span>
                      ),
                  },
                ]}
              />
            )}
          </Section>
        )}

        {/* Packages */}
        {packagesWithCves.length > 0 && (
          <Section
            title={`Packages with Vulnerabilities (${packagesWithCves.length})`}
          >
            <div className="cr-toolbar cr-toolbar--split">
              <p className="cr-note">
                Showing only packages that match vulnerability findings.
              </p>
              <CcureInput
                type="search"
                label="Search packages"
                placeholder="Search packages..."
                value={packagesSearch}
                onChange={(e) => setPackagesSearch(e.target.value)}
                fieldClassName="cr-search"
              />
            </div>
            {filteredPackages.length === 0 ? (
              <p className="cr-note">
                No packages matching &quot;{packagesSearch}&quot;
              </p>
            ) : (
              <CcureTable
                caption="Packages with vulnerabilities"
                density="compact"
                rows={filteredPackages}
                rowKey={(pkg, i) => i}
                columns={[
                  {
                    key: "name",
                    header: "Affected Packages",
                    isRowHeader: true,
                    cell: (pkg) => (
                      <span className="cr-tone-warning cr-strong">
                        {pkg.name}
                      </span>
                    ),
                  },
                  { key: "version", header: "Version", mono: true },
                  {
                    key: "manager",
                    header: "Manager",
                    cell: (pkg) => (
                      <span className="cr-muted">{pkg.manager}</span>
                    ),
                  },
                  {
                    key: "cves",
                    header: "CVE",
                    cell: (pkg) => {
                      const pkgCves = cves.filter(
                        (c) =>
                          String(c.package || "").toLowerCase() ===
                          String(pkg.name || "").toLowerCase(),
                      );
                      const uniqueCveIds = Array.from(
                        new Set(pkgCves.map((c) => c.cve_id)),
                      ).filter(Boolean);
                      return uniqueCveIds.length > 0 ? (
                        <ul className="cr-cve-links">
                          {uniqueCveIds.map((cveId) => (
                            <li key={cveId}>
                              <CVELink cveId={cveId} className="cr-cve-link" />
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="cr-muted">—</span>
                      );
                    },
                  },
                ]}
              />
            )}
          </Section>
        )}

        {/* Users */}
        {users.length > 0 && (
          <Section
            icon={<CcureIcon name="user" />}
            title={`Users (${filteredUsers.length})`}
          >
            <div className="cr-toolbar cr-toolbar--split">
              <CcureInput
                type="search"
                label="Search users"
                placeholder="Search users..."
                value={usersSearch}
                onChange={(e) => setUsersSearch(e.target.value)}
                fieldClassName="cr-search"
              />
              <CcureCheckbox
                className="cr-check"
                checked={showSystemUsers}
                onChange={(e) => setShowSystemUsers(e.target.checked)}
              >
                Show system & service accounts
              </CcureCheckbox>
            </div>
            {filteredUsers.length === 0 ? (
              <p className="cr-note">
                No users matching &quot;{usersSearch}&quot;
              </p>
            ) : (
              <CcureTable
                caption="Users"
                density="compact"
                rows={filteredUsers}
                rowKey={(u, i) => i}
                columns={usersColumns}
              />
            )}
          </Section>
        )}

        {/* Local Groups */}
        {local_groups.length > 0 && (
          <Section
            icon={<CcureIcon name="user" />}
            title={`Local Groups (${local_groups.length})`}
          >
            <CcureTable
              caption="Local groups"
              density="compact"
              rows={local_groups}
              rowKey={(g, i) => i}
              columns={[
                {
                  key: "name",
                  header: "Group Name",
                  isRowHeader: true,
                  cell: (g) => <span className="cr-strong">{g.name}</span>,
                },
                {
                  key: "gid",
                  header: "GID",
                  mono: true,
                  cell: (g) => g.gid || "—",
                },
                {
                  key: "members",
                  header: "Members",
                  cell: (g) =>
                    Array.isArray(g.members) && g.members.length > 0
                      ? g.members.join(", ")
                      : "—",
                },
              ]}
            />
          </Section>
        )}

        {/* Scheduled Tasks & Cron Jobs */}
        {((detected_os === "windows" &&
          suspicious_scheduled_tasks?.length > 0) ||
          (detected_os !== "windows" && cron_info_raw)) && (
          <Section
            icon={<CcureIcon name="calendar" />}
            title={
              detected_os === "windows"
                ? `Scheduled Tasks (${suspicious_scheduled_tasks.length})`
                : "Scheduled Cron Jobs"
            }
          >
            {detected_os === "windows" ? (
              <CcureTable
                caption="Scheduled tasks"
                density="compact"
                rows={suspicious_scheduled_tasks}
                rowKey={(t, i) => i}
                columns={[
                  {
                    key: "TaskName",
                    header: "Task Name",
                    isRowHeader: true,
                    cell: (t) => (
                      <span className="cr-strong">{t.TaskName || "—"}</span>
                    ),
                  },
                  {
                    key: "TaskPath",
                    header: "Path",
                    mono: true,
                    cell: (t) => t.TaskPath || "—",
                  },
                  {
                    key: "State",
                    header: "State",
                    cell: (t) => (
                      <CcureBadge
                        variant={
                          t.State === "Ready" || t.State === "Running"
                            ? "success"
                            : "warning"
                        }
                      >
                        {t.State || "—"}
                      </CcureBadge>
                    ),
                  },
                ]}
              />
            ) : (
              <div>
                <p className="cr-note">
                  Target crontab files and system schedules configuration.
                </p>
                <pre
                  className="cr-pre cr-pre--wrap cr-scroll"
                  tabIndex={0}
                  aria-label="Scheduled cron jobs"
                >
                  {cron_info_raw}
                </pre>
              </div>
            )}
          </Section>
        )}

        {/* Login History */}
        {failed_login_count > 0 && (
          <Section icon={<CcureIcon name="clipboard" />} title="Login History">
            <dl className="cr-kv-grid">
              <KV
                k="Failed Logins"
                v={String(failed_login_count)}
                danger={brute_force_warning}
              />
              <KV
                k="Brute Force Alert"
                v={
                  brute_force_warning ? (
                    <>
                      <CcureIcon name="alert-triangle" /> YES
                    </>
                  ) : (
                    "No"
                  )
                }
                danger={brute_force_warning}
              />
            </dl>
          </Section>
        )}

        {/* Audit Evidence */}
        {hasAdvancedEvidence && (
          <Section title="Audit Evidence">
            <p className="cr-note">
              Raw evidence is hidden by default to keep the report readable.
              Sensitive values are masked.
            </p>
            {sudo_rules_raw && (
              <div className="cr-subsection">
                <h3 className="cr-subheading">Sudo Rules</h3>
                <pre
                  className="cr-pre cr-scroll"
                  tabIndex={0}
                  aria-label="Sudo rules"
                >
                  {sudo_rules_raw}
                </pre>
              </div>
            )}
            {failed_logins_recent.length > 0 && (
              <div className="cr-subsection">
                <h3 className="cr-subheading">Recent Login Failures</h3>
                <pre
                  className="cr-pre cr-scroll"
                  tabIndex={0}
                  aria-label="Recent login failures"
                >
                  {failed_logins_recent.join("\n")}
                </pre>
              </div>
            )}
            {network_interfaces_raw && (
              <div className="cr-subsection">
                <h3 className="cr-subheading">Network Interfaces</h3>
                {parsedInterfaces && parsedInterfaces.length > 0 ? (
                  <div className="cr-stack">
                    <CcureTable
                      caption="Network interfaces"
                      density="compact"
                      rows={parsedInterfaces}
                      rowKey={(iface, i) => i}
                      columns={[
                        {
                          key: "name",
                          header: "Interface Name",
                          isRowHeader: true,
                          cell: (iface) => (
                            <span className="cr-strong">{iface.name}</span>
                          ),
                        },
                        { key: "ip", header: "IP Address", mono: true },
                        {
                          key: "prefix",
                          header: "Subnet Mask / Prefix",
                          mono: true,
                          cell: (iface) =>
                            iface.prefix ? (
                              <span className="cr-muted">/{iface.prefix}</span>
                            ) : (
                              "—"
                            ),
                        },
                        {
                          key: "mac",
                          header: "MAC Address",
                          mono: true,
                          cell: (iface) => (
                            <span className="cr-muted">{iface.mac}</span>
                          ),
                        },
                        {
                          key: "desc",
                          header: "Description",
                          cell: (iface) => (
                            <span className="cr-muted">{iface.desc}</span>
                          ),
                        },
                      ]}
                    />
                    <details className="cr-details">
                      <summary className="cr-details__summary">
                        Show Raw Evidence JSON
                      </summary>
                      <pre
                        className="cr-pre cr-pre--wrap cr-scroll"
                        tabIndex={0}
                        aria-label="Raw network interface evidence"
                      >
                        {JSON.stringify(
                          JSON.parse(network_interfaces_raw),
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  </div>
                ) : (
                  /* Fallback for raw text output (Linux fallback) */
                  <pre
                    className="cr-pre cr-pre--wrap cr-scroll"
                    tabIndex={0}
                    aria-label="Network interfaces"
                  >
                    {network_interfaces_raw}
                  </pre>
                )}
              </div>
            )}
            {env_vars_flagged.length > 0 && (
              <div className="cr-subsection">
                <h3 className="cr-subheading cr-tone-warning">
                  <CcureIcon name="alert-triangle" /> Sensitive Environment
                  Variables ({env_vars_flagged.length})
                </h3>
                <ul className="cr-env">
                  {env_vars_flagged.map((v, i) => (
                    <li key={i}>
                      <code className="cr-env__line">{maskSecretLine(v)}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {packages.length > 0 && (
              <div className="cr-subsection">
                <h3 className="cr-subheading">
                  Full Package Inventory ({package_count})
                </h3>
                <CcureTable
                  caption="Full package inventory"
                  density="compact"
                  rows={packages}
                  rowKey={(pkg, i) => i}
                  columns={[
                    {
                      key: "name",
                      header: "Package",
                      isRowHeader: true,
                    },
                    { key: "version", header: "Version", mono: true },
                    {
                      key: "manager",
                      header: "Manager",
                      cell: (pkg) => (
                        <span className="cr-muted">{pkg.manager}</span>
                      ),
                    },
                  ]}
                />
              </div>
            )}
          </Section>
        )}

        {/* Footer */}
        <div className="cr-footer">
          <p className="cr-muted">
            Credentialed scan complete — results saved to history.
          </p>
          <div className="cr-footer__actions">
            <CcureButton
              variant="secondary"
              onClick={() => navigate("/history")}
            >
              View History
            </CcureButton>
            <CcureButton onClick={() => navigate("/scan/credentialed")}>
              <CcureIcon name="rotate-ccw" /> New Scan
            </CcureButton>
          </div>
        </div>
      </CcurePage>
    </AppLayout>
  );
}
