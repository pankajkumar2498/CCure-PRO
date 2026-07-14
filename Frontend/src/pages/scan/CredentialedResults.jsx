/**
 * src/pages/scan/CredentialedResults.jsx
 * Displays credentialed scan report.
 * Can hydrate from router state (fresh scan) or GET /scans/{id} (history).
 */
import { useEffect, useState, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import RiskBadge from "../../components/scan/RiskBadge";
import { getScan } from "../../api/scans";
import api from "../../api/axiosInstance";
import CVELink from "../../components/common/CVELink";

const SEV_COLOR = {
  Critical: "#ff4d4d",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22c55e",
  Info: "#60a5fa",
};

const STAGES = [
  { id: "connecting", label: "Connection", icon: "🔌" },
  { id: "detection", label: "OS Detection", icon: "🔍" },
  { id: "collection", label: "Collection", icon: "📦" },
  { id: "analysis", label: "CVE Analysis", icon: "🧠" },
  { id: "syncing", label: "Finalizing", icon: "💾" },
];

/* ── helpers ── */
function KV({ k, v, danger, warn, mono }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span
        className="kv-val"
        style={{
          color: danger ? "#ff4d4d" : warn ? "#f59e0b" : undefined,
          fontFamily: mono ? "var(--mono)" : undefined,
          fontSize: mono ? 12 : undefined,
        }}
      >
        {v}
      </span>
    </div>
  );
}

function Section({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginBottom: 10 }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 14px",
          background: "var(--bg-app)",
          border: "1px solid var(--border)",
          borderRadius: open ? "8px 8px 0 0" : 8,
          cursor: "pointer",
          fontFamily: "var(--font)",
          fontWeight: 600,
          fontSize: "0.84rem",
          color: "var(--text-mid)",
          transition: "background 0.12s",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "#f1f5f9")}
        onMouseLeave={(e) =>
          (e.currentTarget.style.background = "var(--bg-app)")
        }
      >
        <span>{title}</span>
        <span style={{ color: "var(--text-faint)", fontSize: "0.75rem" }}>
          {open ? "▲" : "▼"}
        </span>
      </button>
      {open && (
        <div
          style={{
            border: "1px solid var(--border)",
            borderTop: "none",
            borderRadius: "0 0 8px 8px",
            padding: "16px",
            background: "var(--bg-white)",
          }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

function CredTable({ head, rows }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "0.82rem",
        }}
      >
        <thead>
          <tr>
            {head.map((h) => (
              <th
                key={h}
                style={{
                  padding: "7px 10px",
                  background: "var(--bg-app)",
                  fontWeight: 600,
                  fontSize: "0.75rem",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  borderBottom: "1px solid var(--border)",
                  textAlign: "left",
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} style={row._style || {}}>
              {row.cells.map((cell, j) => (
                <td
                  key={j}
                  style={{
                    padding: "7px 10px",
                    borderBottom: "1px solid #f1f5f9",
                    ...(cell.style || {}),
                  }}
                >
                  {cell.content}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const maskSecretLine = (value) => {
  const text = String(value ?? "");
  const eq = text.indexOf("=");
  if (eq === -1) return text.replace(/(:\s*)(.+)$/i, "$1********");
  return `${text.slice(0, eq + 1)}********`;
};

function hydrateFromHistory(detail) {
  const report = detail?.results?.credentialed?.report;
  return report
    ? {
        scan_id: detail.id,
        scan_no: detail.scan_no ?? detail.display_id,
        ...report,
      }
    : null;
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
  const [scanStatus, setScanStatus] = useState(
    stateResult?.status || "running",
  );
  const [cveFilter, setCveFilter] = useState("All");
  const [showSystemUsers, setShowSystemUsers] = useState(false);
  const [servicesSearch, setServicesSearch] = useState("");
  const [portsSearch, setPortsSearch] = useState("");
  const [packagesSearch, setPackagesSearch] = useState("");
  const [usersSearch, setUsersSearch] = useState("");

  // Live progress state
  const [progress, setProgress] = useState({
    percentage: 0,
    message: "Initializing scan...",
    stage: "connecting",
    logs: [],
  });

  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress.logs]);

  useEffect(() => {
    if (stateResult && stateResult.system_info) {
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
            setResult(r);
            setLoading(false);
            if (ws) ws.close();
            return true;
          }
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
          if (!cancelled && !result) {
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
        <div className="page-inner">
          <div className="page-title-row">
            <div>
              <h2 className="page-title">🔐 Credentialed Scan In Progress</h2>
              <p className="page-subtitle">
                Target:{" "}
                <code className="ip-code">
                  {stateResult?.target || scanIdParam}
                </code>
                <span className="muted">
                  {" "}
                  · Scan No. {stateResult?.scan_no || "-"}
                </span>
              </p>
            </div>
          </div>

          <div
            className="pipeline-progress-card"
            style={{ marginTop: 20, padding: "16px 20px" }}
          >
            <div
              className="pipeline-progress-header"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 14,
                marginBottom: 12,
              }}
            >
              <div className="pipeline-pulse" />
              <div style={{ flex: 1 }}>
                <h3
                  className="pipeline-progress-title"
                  style={{ fontSize: "0.95rem" }}
                >
                  {progress.message}
                </h3>
                <p
                  className="pipeline-progress-desc"
                  style={{ fontSize: "0.8rem", marginTop: 2 }}
                >
                  Performing authenticated system inspection via SSH. This
                  typically takes 30-90 seconds.
                </p>
              </div>
              <div style={{ textAlign: "right" }}>
                <span
                  style={{
                    fontSize: "1.5rem",
                    fontWeight: 800,
                    color: "var(--accent)",
                  }}
                >
                  {progress.percentage}%
                </span>
              </div>
            </div>

            <div
              className="progress-bar progress-bar--pipeline"
              style={{ height: 4 }}
            >
              <div
                className="progress-fill progress-fill--animated"
                style={{
                  width: `${progress.percentage}%`,
                  transition: "width 0.5s ease-out",
                }}
              />
            </div>

            {/* Stage Stepper */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginTop: 30,
                marginBottom: 20,
                padding: "0 10px",
              }}
            >
              {STAGES.map((s, idx) => {
                const isDone = idx < currentStageIndex;
                const isActive = idx === currentStageIndex;
                return (
                  <div
                    key={s.id}
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      gap: 8,
                      flex: 1,
                      position: "relative",
                    }}
                  >
                    <div
                      style={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        background: isDone
                          ? "var(--ok)"
                          : isActive
                            ? "var(--accent)"
                            : "var(--bg-app)",
                        color:
                          isDone || isActive ? "#fff" : "var(--text-faint)",
                        border: `2px solid ${isDone ? "var(--ok)" : isActive ? "var(--accent)" : "var(--border)"}`,
                        zIndex: 2,
                        fontSize: 14,
                        transition: "all 0.3s",
                      }}
                    >
                      {isDone ? "✓" : s.icon}
                    </div>
                    <span
                      style={{
                        fontSize: 11,
                        fontWeight: isActive ? 700 : 500,
                        color: isActive
                          ? "var(--accent)"
                          : isDone
                            ? "var(--text)"
                            : "var(--text-faint)",
                        textAlign: "center",
                      }}
                    >
                      {s.label}
                    </span>
                    {idx < STAGES.length - 1 && (
                      <div
                        style={{
                          position: "absolute",
                          top: 16,
                          left: "60%",
                          width: "80%",
                          height: 2,
                          background: isDone ? "var(--ok)" : "var(--border)",
                          zIndex: 1,
                        }}
                      />
                    )}
                  </div>
                );
              })}
            </div>

            {/* Live Logs */}
            <div style={{ marginTop: 20 }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  marginBottom: 8,
                }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: "var(--ok)",
                    animation: "pulse 1.5s infinite",
                  }}
                />
                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  Live Activity
                </span>
              </div>
              <div
                ref={logRef}
                style={{
                  background: "#0f172a",
                  color: "#e2e8f0",
                  padding: "12px 16px",
                  borderRadius: 8,
                  fontFamily: "var(--mono)",
                  fontSize: 12,
                  lineHeight: 1.6,
                  maxHeight: 180,
                  overflowY: "auto",
                  border: "1px solid #334155",
                  boxShadow: "inset 0 2px 4px rgba(0,0,0,0.3)",
                }}
              >
                {progress.logs.length === 0 ? (
                  <div style={{ color: "#64748b", fontStyle: "italic" }}>
                    Waiting for activity...
                  </div>
                ) : (
                  progress.logs.map((log, i) => (
                    <div
                      key={i}
                      style={{ display: "flex", gap: 12, marginBottom: 2 }}
                    >
                      <span style={{ color: "#64748b", flexShrink: 0 }}>
                        [{log.time}]
                      </span>
                      <span
                        style={{
                          color: log.text.includes("failed")
                            ? "#fca5a5"
                            : "#94a3b8",
                        }}
                      >
                        {log.text}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
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
        <div className="page-inner">
          <div className="page-title-row">
            <h2 className="page-title">Credentialed Scan Results</h2>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn btn--ghost"
                onClick={() => navigate("/history")}
              >
                History
              </button>
              <button
                className="btn btn--primary"
                onClick={() => navigate("/scan/credentialed")}
              >
                New Scan
              </button>
            </div>
          </div>

          {isUnreachable ? (
            <div
              style={{
                margin: "16px 0",
                padding: "16px 20px",
                borderRadius: 8,
                background: "rgba(245, 158, 11, 0.08)",
                border: "1px solid rgba(245, 158, 11, 0.3)",
                display: "flex",
                alignItems: "center",
                gap: 16,
                color: "#92400e",
              }}
            >
              <span style={{ fontSize: 24 }}>⚠️</span>
              <div>
                <strong style={{ display: "block", fontSize: 16 }}>
                  Host is unavailable/down/unreachable
                </strong>
                <p style={{ margin: "4px 0 0", fontSize: 14, opacity: 0.9 }}>
                  The credentialed scan failed because the host could not be
                  reached via SSH. Verify the IP address, network connectivity,
                  and firewall rules.
                </p>
              </div>
            </div>
          ) : (
            <div className="alert alert--error">
              <div style={{ fontWeight: 700, marginBottom: 4 }}>
                ⚠ Scan Failed
              </div>
              {error}
            </div>
          )}

          <div className="empty-state" style={{ marginTop: 40 }}>
            <p className="muted">
              {isUnreachable
                ? "Please ensure the target is powered on and accessible from the scanning engine."
                : "Please verify your SSH credentials and ensure the host is reachable."}
            </p>
            <button
              className="btn btn--primary"
              style={{ marginTop: 20 }}
              onClick={() => navigate("/scan/credentialed")}
            >
              Try Again
            </button>
          </div>
        </div>
      </AppLayout>
    );
  }

  if (!result) return null;

  const {
    target,
    username,
    scan_id,
    scan_no,
    display_id,
    scan_duration,
    detected_os = "linux",
    os_type_was_auto = false,
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
  } = result;

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
  const osIcon = detected_os === "windows" ? "🪟" : "🐧";
  const osBadgeClr = detected_os === "windows" ? "#0078d4" : "#f97316";

  const overallRisk = (() => {
    if (severity_summary.Critical > 0) return "Critical";
    if (severity_summary.High > 0) return "High";
    if (severity_summary.Medium > 0) return "Medium";
    if (severity_summary.Low > 0) return "Low";
    return "Info";
  })();

  const SEV_ORDER = ["All", "Critical", "High", "Medium", "Low", "Info"];
  const filteredCves =
    cveFilter === "All" ? cves : cves.filter((c) => c.severity === cveFilter);
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
    return (
      String(p.port || "")
        .toLowerCase()
        .includes(query) ||
      String(p.local_addr || "")
        .toLowerCase()
        .includes(query) ||
      String(p.state || "")
        .toLowerCase()
        .includes(query) ||
      String(p.process || "")
        .toLowerCase()
        .includes(query)
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

  const usersTableRows = filteredUsers.map((u) => {
    if (detected_os === "windows") {
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
      let typeStyle = {};
      if (isAdmin) {
        typeLabel = "Admin";
        typeStyle = { color: "#ff4d4d", fontWeight: 600 };
      } else if (isSystem) {
        typeLabel = "System";
        typeStyle = { color: "var(--text-faint)" };
      }

      return {
        _style: isAdmin ? { background: "rgba(239, 68, 68, 0.03)" } : {},
        cells: [
          {
            content: (
              <code
                style={{ fontSize: 12, fontWeight: isAdmin ? 600 : undefined }}
              >
                {u.username}
              </code>
            ),
          },
          { content: <span style={typeStyle}>{typeLabel}</span> },
          {
            content: isEnabled ? (
              <span style={{ color: "var(--ok)", fontWeight: 500 }}>
                Active
              </span>
            ) : (
              <span
                className="muted"
                style={{
                  textDecoration: "line-through",
                  color: "var(--text-faint)",
                }}
              >
                Disabled
              </span>
            ),
          },
          {
            content: isPwdRequired ? (
              <span>Yes</span>
            ) : (
              <span style={{ color: "#f59e0b", fontWeight: 500 }}>⚠ No</span>
            ),
          },
          {
            content: (
              <span
                style={{
                  fontSize: 11,
                  color: "var(--text-muted)",
                  fontFamily: "var(--mono)",
                }}
              >
                {lastLogon}
              </span>
            ),
          },
        ],
      };
    } else {
      return {
        _style: u.is_root ? { color: "#ff4d4d" } : {},
        cells: [
          { content: <code style={{ fontSize: 12 }}>{u.username}</code> },
          { content: u.uid, style: { fontSize: 11 } },
          {
            content: u.shell,
            style: { fontSize: 11, color: "var(--text-muted)" },
          },
          {
            content: u.home,
            style: { fontSize: 11, color: "var(--text-muted)" },
          },
          {
            content: u.is_root ? "⚠ root" : u.is_system ? "system" : "user",
            style: {
              fontSize: 11,
              color: u.is_system ? "var(--text-faint)" : undefined,
            },
          },
        ],
      };
    }
  });

  const hasAdvancedEvidence = Boolean(
    sudo_rules_raw ||
      network_interfaces_raw ||
      failed_logins_recent.length > 0 ||
      env_vars_flagged.length > 0 ||
      packages.length > 0,
  );

  return (
    <AppLayout pageTitle="Credentialed Results">
      <div className="page-inner">
        {/* Page header */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">🔐 Credentialed Scan Results</h2>
            <p className="page-subtitle">
              <code className="ip-code">{target}</code>
              {username && <span className="muted"> · user: {username}</span>}
              {scan_duration && (
                <span className="muted"> · {scan_duration}s</span>
              )}
              {scan_id && (
                <span className="muted">
                  {" "}
                  · Scan No. {scan_no ?? display_id ?? "-"}
                </span>
              )}
              {os_type_was_auto && (
                <span
                  style={{
                    marginLeft: 8,
                    padding: "2px 8px",
                    borderRadius: 4,
                    fontSize: 11,
                    background: osBadgeClr + "22",
                    color: osBadgeClr,
                    border: `1px solid ${osBadgeClr}44`,
                    fontWeight: 600,
                  }}
                >
                  {osIcon} {osLabel} (auto-detected)
                </span>
              )}
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="btn btn--ghost"
              onClick={() => navigate("/scan/credentialed")}
            >
              ← New Scan
            </button>
            <button
              className="btn btn--ghost"
              onClick={() => navigate("/history")}
            >
              History
            </button>
          </div>
        </div>

        {/* Summary bar */}
        <div className="summary-bar" style={{ flexWrap: "wrap" }}>
          <span className="summary-item">
            <RiskBadge level={overallRisk} />
          </span>
          <span className="summary-item">
            <b>{system_info.os_name || osLabel}</b>
          </span>
          <span className="summary-item muted">
            {detected_os === "windows" ? (
              <>
                Build{" "}
                <b>
                  {system_info.os_build || system_info.os_version_id || "—"}
                </b>
              </>
            ) : (
              <>
                Kernel <b>{system_info.kernel_version || "—"}</b>
              </>
            )}
          </span>
          <span className="summary-item">
            <b>{package_count}</b> packages
          </span>
          <span
            className="summary-item"
            style={{ color: cve_count > 0 ? "#f97316" : "var(--ok)" }}
          >
            <b>{cve_count}</b> CVE{cve_count !== 1 ? "s" : ""}
          </span>
          {brute_force_warning && (
            <span className="summary-item" style={{ color: "#ff4d4d" }}>
              ⚠ Brute-force activity detected
            </span>
          )}
        </div>

        {/* System Info */}
        <Section title="🖥 System Information" defaultOpen>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
              gap: "0 24px",
            }}
          >
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
            <KV k="Domain" v={system_info.domain || "—"} mono />
            <KV k="FQDN" v={system_info.fqdn || "—"} mono />
            {system_info.memory_summary?.total && (
              <>
                <KV k="RAM Total" v={system_info.memory_summary.total} />
                <KV k="RAM Used" v={system_info.memory_summary.used} />
              </>
            )}
          </div>
          {system_info.disk_usage?.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <h4 className="section-title">Disk Usage</h4>
              <CredTable
                head={[
                  "Filesystem",
                  "Size",
                  "Used",
                  "Available",
                  "Use%",
                  "Mount",
                ]}
                rows={system_info.disk_usage.map((d) => ({
                  cells: [
                    {
                      content: (
                        <code style={{ fontSize: 11 }}>{d.filesystem}</code>
                      ),
                    },
                    { content: d.size },
                    { content: d.used },
                    { content: d.available },
                    {
                      content: d.use_pct,
                      style: {
                        color: parseInt(d.use_pct) > 80 ? "#f97316" : undefined,
                      },
                    },
                    {
                      content: (
                        <code style={{ fontSize: 11 }}>{d.mounted_on}</code>
                      ),
                    },
                  ],
                }))}
              />
            </div>
          )}
        </Section>

        {/* CVEs */}
        {cve_count > 0 && (
          <Section title={`⚠ CVE Findings (${cve_count})`} defaultOpen>
            {/* Severity summary chips */}
            <div
              style={{
                display: "flex",
                gap: 10,
                flexWrap: "wrap",
                marginBottom: 12,
              }}
            >
              {Object.entries(severity_summary)
                .filter(([, n]) => n > 0)
                .map(([sev, n]) => (
                  <span
                    key={sev}
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: 12,
                      color: SEV_COLOR[sev] || "var(--text-muted)",
                    }}
                  >
                    {n} {sev}
                  </span>
                ))}
            </div>

            {/* Filter tabs */}
            <div
              style={{
                display: "flex",
                gap: 6,
                flexWrap: "wrap",
                marginBottom: 12,
              }}
            >
              {SEV_ORDER.map((sev) => (
                <button
                  key={sev}
                  onClick={() => setCveFilter(sev)}
                  style={{
                    padding: "4px 12px",
                    borderRadius: 5,
                    border: `1px solid ${SEV_COLOR[sev] || "var(--border)"}`,
                    background:
                      cveFilter === sev
                        ? SEV_COLOR[sev] || "var(--accent)"
                        : "transparent",
                    color:
                      cveFilter === sev
                        ? "#fff"
                        : SEV_COLOR[sev] || "var(--text-muted)",
                    fontFamily: "var(--font)",
                    fontSize: "0.78rem",
                    cursor: "pointer",
                    transition: "all 0.12s",
                  }}
                >
                  {sev}
                  {sev !== "All" && severity_summary[sev] > 0 && (
                    <span style={{ marginLeft: 4, opacity: 0.8 }}>
                      ({severity_summary[sev]})
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="cve-list">
              {filteredCves.map((cve, i) => (
                <div
                  key={i}
                  className="cve-row"
                  style={{
                    flexDirection: "column",
                    gap: 4,
                    alignItems: "flex-start",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      gap: 10,
                      alignItems: "center",
                      flexWrap: "wrap",
                    }}
                  >
                    <CVELink
                      cveId={cve.cve_id}
                      style={{ color: SEV_COLOR[cve.severity] || "#60a5fa" }}
                    />
                    <span
                      className="cve-sev"
                      style={{ color: SEV_COLOR[cve.severity] }}
                    >
                      {cve.severity}
                    </span>
                    {cve.cvss_score && (
                      <span
                        style={{
                          fontFamily: "var(--mono)",
                          fontSize: 11,
                          color: "var(--text-muted)",
                        }}
                      >
                        CVSS {cve.cvss_score}
                      </span>
                    )}
                    {cve.package && (
                      <span
                        style={{
                          fontFamily: "var(--mono)",
                          fontSize: 11,
                          color: "var(--text-faint)",
                        }}
                      >
                        {cve.package} {cve.installed_ver}
                      </span>
                    )}
                    {cve.fixed_ver && (
                      <span style={{ fontSize: 11, color: "var(--ok)" }}>
                        → fixed in {cve.fixed_ver}
                      </span>
                    )}
                  </div>
                  <span className="cve-desc">{cve.description}</span>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Security Audit */}
        <Section
          title="🔒 Security Audit"
          defaultOpen={security_issues.length > 0 || sudo_nopasswd}
        >
          {security_issues.length > 0 && (
            <ul className="issue-list" style={{ marginBottom: 12 }}>
              {security_issues.map((iss, i) => (
                <li key={i} style={{ color: "#f97316" }}>
                  {iss}
                </li>
              ))}
            </ul>
          )}
          <div className="kv-grid">
            <KV
              k="NOPASSWD Sudo"
              v={sudo_nopasswd ? "⚠ YES — any command without password" : "No"}
              danger={sudo_nopasswd}
            />
            <KV
              k="SUID Binaries"
              v={`${suid_binaries.length} found`}
              warn={suid_binaries.length > 15}
            />
            <KV
              k="World-Writable Dirs"
              v={`${world_writable_dirs.length} found`}
              warn={world_writable_dirs.length > 0}
            />
            <KV
              k="Failed Logins"
              v={`${failed_login_count}${brute_force_warning ? " ⚠ possible brute force" : ""}`}
              danger={brute_force_warning}
            />
          </div>
          {Object.keys(hardening_audits).length > 0 && (
            <div style={{ marginTop: 16 }}>
              <h4 className="section-title">OS Hardening & Auditing</h4>
              <CredTable
                head={[
                  "Configuration / Audit",
                  "Status",
                  "Audit Findings Detail",
                ]}
                rows={Object.entries(hardening_audits).map(([key, audit]) => {
                  const isPass = audit.status === "PASS";
                  const isFail = audit.status === "FAIL";
                  const statusBg = isPass
                    ? "rgba(22, 163, 74, 0.15)"
                    : isFail
                      ? "rgba(239, 68, 68, 0.15)"
                      : "rgba(245, 158, 11, 0.15)";
                  const statusColor = isPass
                    ? "#16a34a"
                    : isFail
                      ? "#ef4444"
                      : "#f59e0b";

                  return {
                    cells: [
                      {
                        content: (
                          <span style={{ fontWeight: 600 }}>
                            {audit.label || key}
                          </span>
                        ),
                      },
                      {
                        content: (
                          <span
                            style={{
                              padding: "2px 8px",
                              borderRadius: 4,
                              fontSize: 10,
                              fontWeight: "bold",
                              backgroundColor: statusBg,
                              color: statusColor,
                              display: "inline-block",
                            }}
                          >
                            {audit.status}
                          </span>
                        ),
                      },
                      { content: <span>{audit.detail || "—"}</span> },
                    ],
                  };
                })}
              />
            </div>
          )}
          {suid_binaries.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <h4 className="section-title">SUID Binaries</h4>
              <div
                style={{
                  maxHeight: 160,
                  overflowY: "auto",
                  fontFamily: "var(--mono)",
                  fontSize: 11,
                  color: "var(--text-muted)",
                  lineHeight: 1.6,
                }}
              >
                {suid_binaries.map((b, i) => (
                  <div key={i}>{b}</div>
                ))}
              </div>
            </div>
          )}
        </Section>

        {/* Running Services */}
        {running_services.length > 0 && (
          <Section title={`⚙️ Running Services (${running_services.length})`}>
            <div style={{ marginBottom: 12 }}>
              <input
                type="text"
                placeholder="Search services..."
                value={servicesSearch}
                onChange={(e) => setServicesSearch(e.target.value)}
                style={{
                  padding: "6px 12px",
                  fontSize: "0.85rem",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-card)",
                  color: "var(--text)",
                  width: "100%",
                  maxWidth: "320px",
                  outline: "none",
                }}
              />
            </div>
            {filteredServices.length === 0 ? (
              <p className="muted" style={{ padding: "12px 0", fontSize: 13 }}>
                No services matching "{servicesSearch}"
              </p>
            ) : (
              <CredTable
                head={["Service", "Status", "Description"]}
                rows={filteredServices.map((svc) => ({
                  cells: [
                    {
                      content: <code style={{ fontSize: 11 }}>{svc.name}</code>,
                    },
                    {
                      content: svc.sub_state || "running",
                      style: { color: "var(--ok)", fontSize: 11 },
                    },
                    {
                      content: svc.description,
                      style: { fontSize: 12, color: "var(--text-muted)" },
                    },
                  ],
                }))}
              />
            )}
          </Section>
        )}

        {/* Open Ports */}
        {open_ports_credentialed.length > 0 && (
          <Section
            title={`🔌 Open Ports — socket table (${open_ports_credentialed.length})`}
          >
            <div style={{ marginBottom: 12 }}>
              <input
                type="text"
                placeholder="Search ports, IPs, or processes..."
                value={portsSearch}
                onChange={(e) => setPortsSearch(e.target.value)}
                style={{
                  padding: "6px 12px",
                  fontSize: "0.85rem",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-card)",
                  color: "var(--text)",
                  width: "100%",
                  maxWidth: "320px",
                  outline: "none",
                }}
              />
            </div>
            {filteredPorts.length === 0 ? (
              <p className="muted" style={{ padding: "12px 0", fontSize: 13 }}>
                No open ports matching "{portsSearch}"
              </p>
            ) : (
              <CredTable
                head={["State", "Local Addr", "Port", "Process"]}
                rows={filteredPorts.map((p) => ({
                  cells: [
                    {
                      content: p.state,
                      style: { color: "var(--ok)", fontSize: 11 },
                    },
                    {
                      content: (
                        <code style={{ fontSize: 11 }}>{p.local_addr}</code>
                      ),
                    },
                    { content: <code style={{ fontSize: 12 }}>{p.port}</code> },
                    {
                      content: p.process,
                      style: { fontSize: 11, color: "var(--text-muted)" },
                    },
                  ],
                }))}
              />
            )}
          </Section>
        )}

        {/* Packages */}
        {packagesWithCves.length > 0 && (
          <Section
            title={`Packages with Vulnerabilities (${packagesWithCves.length})`}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: 12,
                marginBottom: 12,
              }}
            >
              <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                Showing only packages that match vulnerability findings.
              </p>
              <input
                type="text"
                placeholder="Search packages..."
                value={packagesSearch}
                onChange={(e) => setPackagesSearch(e.target.value)}
                style={{
                  padding: "6px 12px",
                  fontSize: "0.85rem",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-card)",
                  color: "var(--text)",
                  width: "100%",
                  maxWidth: "320px",
                  outline: "none",
                }}
              />
            </div>
            {filteredPackages.length === 0 ? (
              <p className="muted" style={{ padding: "12px 0", fontSize: 13 }}>
                No packages matching "{packagesSearch}"
              </p>
            ) : (
              <CredTable
                head={["Affected Packages", "Version", "Manager", "CVE"]}
                rows={filteredPackages.map((pkg) => {
                  const pkgCves = cves.filter(
                    (c) =>
                      String(c.package || "").toLowerCase() ===
                      String(pkg.name || "").toLowerCase(),
                  );
                  const uniqueCveIds = Array.from(
                    new Set(pkgCves.map((c) => c.cve_id)),
                  ).filter(Boolean);

                  return {
                    _style: { background: "rgba(249,115,22,0.07)" },
                    cells: [
                      {
                        content: (
                          <span style={{ fontWeight: 600, color: "#f97316" }}>
                            {pkg.name}
                          </span>
                        ),
                      },
                      {
                        content: (
                          <code style={{ fontSize: 11 }}>{pkg.version}</code>
                        ),
                      },
                      {
                        content: pkg.manager,
                        style: { fontSize: 11, color: "var(--text-muted)" },
                      },
                      {
                        content:
                          uniqueCveIds.length > 0 ? (
                            <div
                              style={{
                                display: "flex",
                                flexWrap: "wrap",
                                gap: "4px 8px",
                                alignItems: "center",
                              }}
                            >
                              {uniqueCveIds.map((cveId, idx) => (
                                <span
                                  key={cveId}
                                  style={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                  }}
                                >
                                  <CVELink
                                    cveId={cveId}
                                    style={{
                                      color: "#f97316",
                                      fontWeight: 600,
                                      fontSize: "0.82rem",
                                    }}
                                  />
                                  {idx < uniqueCveIds.length - 1 && (
                                    <span
                                      style={{
                                        color: "var(--text-faint)",
                                        marginLeft: 4,
                                      }}
                                    >
                                      ,
                                    </span>
                                  )}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span style={{ color: "var(--text-faint)" }}>
                              —
                            </span>
                          ),
                      },
                    ],
                  };
                })}
              />
            )}
          </Section>
        )}

        {/* Users */}
        {users.length > 0 && (
          <Section title={`👤 Users (${filteredUsers.length})`}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
                marginBottom: 12,
              }}
            >
              <input
                type="text"
                placeholder="Search users..."
                value={usersSearch}
                onChange={(e) => setUsersSearch(e.target.value)}
                style={{
                  padding: "6px 12px",
                  fontSize: "0.85rem",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-card)",
                  color: "var(--text)",
                  width: "100%",
                  maxWidth: "320px",
                  outline: "none",
                }}
              />
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: "0.8rem",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  userSelect: "none",
                }}
              >
                <input
                  type="checkbox"
                  checked={showSystemUsers}
                  onChange={(e) => setShowSystemUsers(e.target.checked)}
                  style={{ cursor: "pointer" }}
                />
                Show system & service accounts
              </label>
            </div>
            {filteredUsers.length === 0 ? (
              <p className="muted" style={{ padding: "12px 0", fontSize: 13 }}>
                No users matching "{usersSearch}"
              </p>
            ) : (
              <CredTable head={usersTableHead} rows={usersTableRows} />
            )}
          </Section>
        )}

        {/* Local Groups */}
        {local_groups.length > 0 && (
          <Section title={`👤 Local Groups (${local_groups.length})`}>
            <CredTable
              head={["Group Name", "GID", "Members"]}
              rows={local_groups.map((g) => ({
                cells: [
                  {
                    content: <span style={{ fontWeight: 600 }}>{g.name}</span>,
                  },
                  { content: <code>{g.gid || "—"}</code> },
                  {
                    content: (
                      <span>
                        {Array.isArray(g.members) && g.members.length > 0
                          ? g.members.join(", ")
                          : "—"}
                      </span>
                    ),
                  },
                ],
              }))}
            />
          </Section>
        )}

        {/* Scheduled Tasks & Cron Jobs */}
        {((detected_os === "windows" &&
          suspicious_scheduled_tasks?.length > 0) ||
          (detected_os !== "windows" && cron_info_raw)) && (
          <Section
            title={
              detected_os === "windows"
                ? `📅 Scheduled Tasks (${suspicious_scheduled_tasks.length})`
                : "📅 Scheduled Cron Jobs"
            }
          >
            {detected_os === "windows" ? (
              <CredTable
                head={["Task Name", "Path", "State"]}
                rows={suspicious_scheduled_tasks.map((t) => ({
                  cells: [
                    {
                      content: (
                        <span style={{ fontWeight: 600 }}>
                          {t.TaskName || "—"}
                        </span>
                      ),
                    },
                    {
                      content: (
                        <code style={{ fontSize: 11 }}>
                          {t.TaskPath || "—"}
                        </code>
                      ),
                    },
                    {
                      content: (
                        <span
                          style={{
                            padding: "2px 6px",
                            borderRadius: 4,
                            fontSize: 10,
                            fontWeight: "bold",
                            backgroundColor:
                              t.State === "Ready" || t.State === "Running"
                                ? "rgba(22, 163, 74, 0.15)"
                                : "rgba(245, 158, 11, 0.15)",
                            color:
                              t.State === "Ready" || t.State === "Running"
                                ? "#16a34a"
                                : "#f59e0b",
                            display: "inline-block",
                          }}
                        >
                          {t.State || "—"}
                        </span>
                      ),
                    },
                  ],
                }))}
              />
            ) : (
              <div>
                <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
                  Target crontab files and system schedules configuration.
                </p>
                <pre
                  style={{
                    background: "var(--bg-app)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    padding: "10px 12px",
                    fontFamily: "var(--mono)",
                    fontSize: 12,
                    color: "var(--text-mid)",
                    overflowX: "auto",
                    maxHeight: 250,
                    overflowY: "auto",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {cron_info_raw}
                </pre>
              </div>
            )}
          </Section>
        )}

        {/* Login History */}
        {failed_login_count > 0 && (
          <Section title="📋 Login History">
            <div className="kv-grid">
              <KV
                k="Failed Logins"
                v={String(failed_login_count)}
                danger={brute_force_warning}
              />
              <KV
                k="Brute Force Alert"
                v={brute_force_warning ? "⚠ YES" : "No"}
                danger={brute_force_warning}
              />
            </div>
          </Section>
        )}

        {/* Audit Evidence */}
        {hasAdvancedEvidence && (
          <Section title="Audit Evidence">
            <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>
              Raw evidence is hidden by default to keep the report readable.
              Sensitive values are masked.
            </p>
            {sudo_rules_raw && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title">Sudo Rules</h4>
                <pre
                  style={{
                    background: "var(--bg-app)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    padding: "10px 12px",
                    fontFamily: "var(--mono)",
                    fontSize: 12,
                    color: "var(--text-mid)",
                    overflowX: "auto",
                    maxHeight: 160,
                    overflowY: "auto",
                  }}
                >
                  {sudo_rules_raw}
                </pre>
              </div>
            )}
            {failed_logins_recent.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title">Recent Login Failures</h4>
                <pre
                  style={{
                    background: "var(--bg-app)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    padding: "10px 12px",
                    fontFamily: "var(--mono)",
                    fontSize: 12,
                    maxHeight: 140,
                    overflowY: "auto",
                  }}
                >
                  {failed_logins_recent.join("\n")}
                </pre>
              </div>
            )}
            {network_interfaces_raw && (
              <div style={{ marginTop: 14 }}>
                <h4 className="section-title">Network Interfaces</h4>
                {parsedInterfaces && parsedInterfaces.length > 0 ? (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                    }}
                  >
                    <CredTable
                      head={[
                        "Interface Name",
                        "IP Address",
                        "Subnet Mask / Prefix",
                        "MAC Address",
                        "Description",
                      ]}
                      rows={parsedInterfaces.map((iface) => ({
                        cells: [
                          {
                            content: (
                              <span
                                style={{
                                  fontWeight: 600,
                                  color: "var(--text)",
                                }}
                              >
                                {iface.name}
                              </span>
                            ),
                          },
                          {
                            content: (
                              <code
                                style={{
                                  fontSize: 11,
                                  fontFamily: "var(--mono)",
                                }}
                              >
                                {iface.ip}
                              </code>
                            ),
                          },
                          {
                            content: iface.prefix ? (
                              <span
                                className="muted"
                                style={{ fontFamily: "var(--mono)" }}
                              >
                                /{iface.prefix}
                              </span>
                            ) : (
                              "—"
                            ),
                          },
                          {
                            content: (
                              <code
                                style={{
                                  fontSize: 11,
                                  fontFamily: "var(--mono)",
                                  color: "var(--text-muted)",
                                }}
                              >
                                {iface.mac}
                              </code>
                            ),
                          },
                          {
                            content: (
                              <span
                                style={{
                                  fontSize: 11,
                                  color: "var(--text-faint)",
                                }}
                              >
                                {iface.desc}
                              </span>
                            ),
                          },
                        ],
                      }))}
                    />
                    <details style={{ marginTop: 4 }}>
                      <summary
                        style={{
                          fontSize: 11,
                          color: "var(--text-faint)",
                          cursor: "pointer",
                          userSelect: "none",
                        }}
                      >
                        Show Raw Evidence JSON
                      </summary>
                      <pre
                        style={{
                          background: "var(--bg-app)",
                          border: "1px solid var(--border)",
                          borderRadius: 6,
                          padding: "10px 12px",
                          fontFamily: "var(--mono)",
                          fontSize: 11,
                          color: "var(--text-mid)",
                          maxHeight: 140,
                          overflowY: "auto",
                          marginTop: 6,
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                        }}
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
                    style={{
                      background: "var(--bg-app)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      padding: "10px 12px",
                      fontFamily: "var(--mono)",
                      fontSize: 12,
                      color: "var(--text-mid)",
                      maxHeight: 180,
                      overflowY: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {network_interfaces_raw}
                  </pre>
                )}
              </div>
            )}
            {env_vars_flagged.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title" style={{ color: "#f97316" }}>
                  ⚠ Sensitive Environment Variables ({env_vars_flagged.length})
                </h4>
                {env_vars_flagged.map((v, i) => (
                  <div
                    key={i}
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: 11,
                      color: "#f97316",
                      marginBottom: 2,
                    }}
                  >
                    {maskSecretLine(v)}
                  </div>
                ))}
              </div>
            )}
            {packages.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title">
                  Full Package Inventory ({package_count})
                </h4>
                <CredTable
                  head={["Package", "Version", "Manager"]}
                  rows={packages.map((pkg) => ({
                    cells: [
                      { content: pkg.name },
                      {
                        content: (
                          <code style={{ fontSize: 11 }}>{pkg.version}</code>
                        ),
                      },
                      {
                        content: pkg.manager,
                        style: { fontSize: 11, color: "var(--text-muted)" },
                      },
                    ],
                  }))}
                />
              </div>
            )}
          </Section>
        )}

        {/* Footer */}
        <div className="phase-footer" style={{ marginTop: 16 }}>
          <span className="muted" style={{ fontSize: 13 }}>
            Credentialed scan complete — results saved to history.
          </span>
          <div style={{ display: "flex", gap: 10 }}>
            <button
              className="btn btn--ghost"
              onClick={() => navigate("/history")}
            >
              View History
            </button>
            <button
              className="btn btn--primary"
              onClick={() => navigate("/scan/credentialed")}
            >
              ↺ New Scan
            </button>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
