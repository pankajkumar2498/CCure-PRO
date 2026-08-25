import { useEffect, useState, useCallback, useRef } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { listAuditLogs, getAuditLogDetail } from "../../api/admin";
import { formatDateTime } from "../../utils/date";
import Button from "../../components/common/Button";
import FormField from "../../components/common/FormField";
import { useToasts, ToastContainer } from "../../components/common/Toast";
import AuditLogDetailsModal from "../../components/admin/AuditLogDetailsModal";

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({
    action: "",
    resource_type: "",
    status: "",
    severity: "",
    user_id: "",
    ip_address: "",
    range: "",
    date_from: "",
    date_to: "",
    q: "",
  });
  // The search box is held separately from `filters` and copied across on a
  // debounce. Bound directly, every keystroke would be a request — and at 100+
  // concurrent users that is the most expensive query in the module fired per
  // character typed.
  const [searchInput, setSearchInput] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const [newEventsCount, setNewEventsCount] = useState(0);
  const [latestLogTime, setLatestLogTime] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const isFirstLoad = useRef(true);

  const loadData = useCallback(
    // `targetPage` has no default. It used to fall back to `page`, which made
    // `page` a dependency of this callback while every one of the four call
    // sites already passes the page it wants explicitly — a fallback that could
    // only ever fire with a stale value.
    async (quiet = false, targetPage) => {
      if (!quiet) setLoading(true);
      else setRefreshing(true);
      try {
        const params = {
          skip: (targetPage - 1) * pageSize,
          limit: pageSize,
          ...Object.fromEntries(
            Object.entries(filters).filter(([_, v]) => v !== ""),
          ),
        };
        const data = await listAuditLogs(params);
        setLogs(data.logs);
        setTotal(data.total);
        if (targetPage === 1) {
          if (data.logs && data.logs.length > 0) {
            setLatestLogTime(data.logs[0].created_at);
          } else {
            setLatestLogTime(null);
          }
        }
        setNewEventsCount(0);
      } catch (err) {
        setError("Failed to load audit logs.");
        pushToast(
          err.response?.data?.detail || "Unable to refresh audit logs.",
          "error",
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [filters, pageSize, pushToast],
  );

  // Debounce the search box into the filter set. 350ms is long enough that a
  // normal typing burst produces one request, short enough not to feel laggy.
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => {
        if (prev.q === searchInput) return prev; // no-op: don't re-render
        return { ...prev, q: searchInput };
      });
      setPage(1);
    }, 350);
    return () => clearTimeout(timer);
  }, [searchInput]);

  useEffect(() => {
    // Only show full-page loading spinner on initial mount when logs are empty.
    // Subsequent page navigations or refreshes load "quietly" (with table opacity indicator).
    if (isFirstLoad.current) {
      loadData(false, page);
      isFirstLoad.current = false;
    } else {
      loadData(true, page);
    }
  }, [loadData, page]);

  // Background auto-refresh polling for new events
  // Background auto-refresh polling for new events
  // The active filter set, serialised. The poll below has to re-subscribe
  // whenever any filter changes, and there are now ten of them — listing each
  // one in the dependency array is how a newly added filter silently stops
  // being applied to the poll while still applying to the table.
  const activeFilterKey = JSON.stringify(filters);

  useEffect(() => {
    if (!latestLogTime || loading) return;

    const activeFilters = Object.fromEntries(
      Object.entries(JSON.parse(activeFilterKey)).filter(([, v]) => v !== ""),
    );

    const checkNewLogs = async () => {
      try {
        const params = {
          skip: 0,
          limit: 10,
          ...activeFilters,
        };
        const data = await listAuditLogs(params);
        if (data && data.logs && data.logs.length > 0) {
          const newestTime = new Date(latestLogTime).getTime();
          const newLogs = data.logs.filter(
            (log) => new Date(log.created_at).getTime() > newestTime,
          );
          if (newLogs.length > 0) {
            setNewEventsCount(newLogs.length);
          }
        }
      } catch (err) {
        // Silent catch for background polling errors
      }
    };

    const interval = setInterval(checkNewLogs, 5000); // Poll every 5 seconds for snappy feedback

    return () => clearInterval(interval);
  }, [latestLogTime, activeFilterKey, loading]);

  const handleFilterChange = (e) => {
    setFilters({ ...filters, [e.target.name]: e.target.value });
    setPage(1);
  };

  // Presets and a custom window are mutually exclusive: the backend gives
  // explicit dates precedence, and leaving a stale preset set would make the
  // active filter chips lie about what is being shown.
  const handleRangePreset = (value) => {
    setFilters((prev) => ({
      ...prev,
      range: value,
      date_from: "",
      date_to: "",
    }));
    setPage(1);
  };

  const handleCustomDate = (e) => {
    setFilters((prev) => ({
      ...prev,
      range: "",
      [e.target.name]: e.target.value,
    }));
    setPage(1);
  };

  const clearFilters = () => {
    setSearchInput("");
    setFilters({
      action: "",
      resource_type: "",
      status: "",
      severity: "",
      user_id: "",
      ip_address: "",
      range: "",
      date_from: "",
      date_to: "",
      q: "",
    });
    setPage(1);
  };

  const activeFilterCount = Object.entries(filters).filter(
    ([, v]) => v !== "",
  ).length;

  const SEVERITY_STYLES = {
    critical: { bg: "rgba(220, 38, 38, 0.15)", fg: "#f87171" },
    high: { bg: "rgba(234, 88, 12, 0.15)", fg: "#fb923c" },
    medium: { bg: "rgba(217, 119, 6, 0.15)", fg: "#fbbf24" },
    low: { bg: "rgba(37, 99, 235, 0.15)", fg: "#60a5fa" },
    info: { bg: "rgba(107, 114, 128, 0.15)", fg: "#9ca3af" },
  };

  const renderSeverity = (severity) => {
    const key = String(severity || "info").toLowerCase();
    const style = SEVERITY_STYLES[key] || SEVERITY_STYLES.info;
    return (
      <span
        title={`Severity: ${key}`}
        style={{
          display: "inline-block",
          background: style.bg,
          color: style.fg,
          border: `1px solid ${style.fg}33`,
          borderRadius: 4,
          padding: "1px 6px",
          fontSize: "0.62rem",
          fontWeight: 700,
          letterSpacing: "0.04em",
          textTransform: "uppercase",
          whiteSpace: "nowrap",
        }}
      >
        {key}
      </span>
    );
  };

  // The row carries a lean projection; the detail view needs fields the list
  // deliberately omits (session id, timezone, org). Open immediately with what
  // the row already has so the modal never appears empty, then fill in.
  const openDetails = async (log, actInfo) => {
    const seed = {
      ...log,
      _displayActor: getActorDisplay(log),
      _displayTarget: renderAffectedObject(log),
      _displayAction: actInfo.label,
      _displayTime: formatDateTime(log.created_at),
    };
    setSelectedLog(seed);
    setDetailsOpen(true);
    setDetailsLoading(true);
    try {
      const full = await getAuditLogDetail(log.id);
      setSelectedLog({ ...seed, ...full });
    } catch (err) {
      // The row data is already on screen and is correct as far as it goes.
      // Losing the three detail-only fields is not worth closing the modal the
      // reviewer just opened.
      pushToast("Could not load full event detail.", "error");
    } finally {
      setDetailsLoading(false);
    }
  };

  const renderAffectedObject = (log) => {
    const resType =
      String(log.resource_type || "").toLowerCase() ||
      (String(log.action || "").includes("session")
        ? "session"
        : String(log.action || "").startsWith("user.")
          ? "user"
          : String(log.action || "").startsWith("organization.")
            ? "organization"
            : String(log.action || "").startsWith("scan.")
              ? "scan"
              : "event");

    let targetVal = log.resource_id || log.user_id;
    if (!targetVal && log.changes?.session_id) {
      targetVal = String(log.changes.session_id);
    }
    if (!targetVal) {
      targetVal = log.id || "—";
    }

    if (resType === "session") {
      return (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 14 }}>🎫</span>
          <span style={{ fontSize: 13, fontWeight: 500 }}>
            Session #{targetVal}
          </span>
        </div>
      );
    }

    if (resType === "user") {
      if (log.user_id && targetVal === log.user_id) {
        return (
          <span style={{ color: "var(--text-faint)", fontSize: 13 }}>
            Self Account
          </span>
        );
      }
      const cleanTarget = targetVal.split("_").slice(-2, -1)[0] || targetVal;
      return (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 14 }}>👤</span>
          <span style={{ fontSize: 13, fontWeight: 500 }}>
            User: {cleanTarget}
          </span>
        </div>
      );
    }

    if (resType === "scan") {
      const displayId = targetVal.includes("_")
        ? targetVal.split("_").pop()
        : targetVal;
      return (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 14 }}>📡</span>
          <span
            style={{ fontSize: 13, fontWeight: 500, fontFamily: "monospace" }}
          >
            Scan #{displayId.slice(-6)}
          </span>
        </div>
      );
    }

    return (
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 14 }}>📌</span>
        <span style={{ fontSize: 13, fontWeight: 500 }}>
          {resType.charAt(0).toUpperCase() + resType.slice(1)}
        </span>
      </div>
    );
  };

  const getActorDisplay = (log) => {
    if (log.username) return log.username;
    if (log.user_email) return log.user_email.split("@")[0];
    if (log.user_id) {
      const parts = log.user_id.split("_");
      if (parts.length >= 3) {
        return parts[parts.length - 2];
      }
      return log.user_id;
    }
    return "System";
  };

  const parseUserAgent = (ua) => {
    if (!ua) return "";
    const uaStr = String(ua);
    let os = "Unknown OS";
    let browser = "Unknown Browser";

    if (uaStr.includes("Windows NT 10.0")) os = "Windows 10/11";
    else if (uaStr.includes("Windows NT 6.3")) os = "Windows 8.1";
    else if (uaStr.includes("Windows NT 6.2")) os = "Windows 8";
    else if (uaStr.includes("Windows NT 6.1")) os = "Windows 7";
    else if (uaStr.includes("Macintosh") || uaStr.includes("Mac OS"))
      os = "macOS";
    else if (uaStr.includes("Linux")) os = "Linux";
    else if (uaStr.includes("Android")) os = "Android";
    else if (uaStr.includes("iPhone") || uaStr.includes("iPad")) os = "iOS";

    if (uaStr.includes("Edg/")) browser = "Edge";
    else if (uaStr.includes("Chrome/") && uaStr.includes("Safari/"))
      browser = "Chrome";
    else if (uaStr.includes("Firefox/")) browser = "Firefox";
    else if (uaStr.includes("Safari/") && !uaStr.includes("Chrome/"))
      browser = "Safari";
    else if (uaStr.includes("Trident/") || uaStr.includes("MSIE"))
      browser = "IE";

    return `${browser} on ${os}`;
  };

  const getActionDisplay = (action) => {
    const act = String(action || "").toLowerCase();
    const config = {
      "user.login": { label: "Logged In", icon: "🔑", color: "var(--ok)" },
      "user.login_failed": {
        label: "Failed Login",
        icon: "⚠️",
        color: "var(--danger)",
      },
      "user.logout": {
        label: "Logged Out",
        icon: "🚪",
        color: "var(--accent)",
      },
      "user.created": {
        label: "User Created",
        icon: "👤",
        color: "var(--primary)",
      },
      "user.updated": {
        label: "User Updated",
        icon: "⚙️",
        color: "var(--warning)",
      },
      "user.deleted": {
        label: "User Deleted",
        icon: "🗑️",
        color: "var(--danger)",
      },
      "scan.created": {
        label: "Scan Started",
        icon: "📡",
        color: "var(--primary)",
      },
      "scan.completed": {
        label: "Scan Completed",
        icon: "✅",
        color: "var(--ok)",
      },
      "scan.failed": {
        label: "Scan Failed",
        icon: "❌",
        color: "var(--danger)",
      },
    };

    if (config[act]) {
      return config[act];
    }

    const cleanLabel = act
      .replace(/_/g, " ")
      .split(".")
      .pop()
      .split(" ")
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(" ");

    return { label: cleanLabel, icon: "📌", color: "var(--text)" };
  };

  if (loading) {
    return (
      <AppLayout pageTitle="Audit Logs">
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <div className="spinner" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle="Audit Logs">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Audit Logs</h2>
            <p className="page-subtitle">
              Immutable trail of system activities and user actions
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {newEventsCount > 0 && (
              <div
                onClick={() => {
                  setPage(1);
                  loadData(true, 1);
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  background: "rgba(96, 165, 250, 0.15)",
                  backdropFilter: "blur(10px)",
                  WebkitBackdropFilter: "blur(10px)",
                  border: "1px solid rgba(96, 165, 250, 0.3)",
                  color: "#60a5fa",
                  padding: "6px 14px",
                  borderRadius: "20px",
                  cursor: "pointer",
                  fontSize: "0.78rem",
                  fontWeight: 600,
                  boxShadow: "0 4px 15px rgba(0, 0, 0, 0.2)",
                  transition: "all 0.2s ease-in-out",
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.background = "rgba(96, 165, 250, 0.22)";
                  e.currentTarget.style.transform = "translateY(-1px)";
                  e.currentTarget.style.boxShadow =
                    "0 6px 20px rgba(96, 165, 250, 0.2)";
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.background = "rgba(96, 165, 250, 0.15)";
                  e.currentTarget.style.transform = "translateY(0)";
                  e.currentTarget.style.boxShadow =
                    "0 4px 15px rgba(0, 0, 0, 0.2)";
                }}
              >
                <span>
                  💬 {newEventsCount} new event{newEventsCount > 1 ? "s" : ""}
                </span>
              </div>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setPage(1);
                loadData(true, 1);
              }}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing..." : "Refresh"}
            </Button>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <div className="filter-bar">
          <FormField
            className="filter-group"
            htmlFor="filter-action"
            label="Action"
          >
            <select
              id="filter-action"
              name="action"
              className="field-input"
              value={filters.action}
              onChange={handleFilterChange}
            >
              <option value="">All Actions</option>
              <option value="user.login">Login</option>
              <option value="user.login_failed">Login Failed</option>
              <option value="user.created">User Created</option>
              <option value="user.updated">User Updated</option>
              <option value="user.deleted">User Deleted</option>
              <option value="scan.created">Scan Created</option>
            </select>
          </FormField>

          <FormField
            className="filter-group"
            htmlFor="filter-resource"
            label="Resource"
          >
            <select
              id="filter-resource"
              name="resource_type"
              className="field-input"
              value={filters.resource_type}
              onChange={handleFilterChange}
            >
              <option value="">All Resources</option>
              <option value="user">User</option>
              <option value="scan">Scan</option>
              <option value="organization">Organization</option>
            </select>
          </FormField>

          <FormField
            className="filter-group"
            htmlFor="filter-status"
            label="Status"
          >
            <select
              id="filter-status"
              name="status"
              className="field-input"
              value={filters.status}
              onChange={handleFilterChange}
            >
              <option value="">All Status</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="denied">Denied</option>
              <option value="blocked_malware">Blocked (malware)</option>
              <option value="scanner_unavailable">Scanner unavailable</option>
            </select>
          </FormField>

          <FormField
            className="filter-group"
            htmlFor="filter-severity"
            label="Severity"
          >
            <select
              id="filter-severity"
              name="severity"
              className="field-input"
              value={filters.severity}
              onChange={handleFilterChange}
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </FormField>

          <FormField
            className="filter-group"
            htmlFor="filter-range"
            label="Time Range"
          >
            <select
              id="filter-range"
              name="range"
              className="field-input"
              value={filters.range}
              onChange={(e) => handleRangePreset(e.target.value)}
            >
              <option value="">All Time</option>
              <option value="today">Today</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </FormField>

          <FormField
            className="filter-group"
            htmlFor="filter-search"
            label="Search"
          >
            <input
              id="filter-search"
              type="search"
              className="field-input"
              placeholder="Event ID, request ID, user, IP…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              style={{ minWidth: 220 }}
            />
          </FormField>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            marginTop: -4,
            marginBottom: 12,
            flexWrap: "wrap",
          }}
        >
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setShowAdvanced((v) => !v)}
          >
            {showAdvanced ? "▾ Fewer filters" : "▸ More filters"}
          </Button>
          {activeFilterCount > 0 && (
            <>
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {activeFilterCount} filter{activeFilterCount > 1 ? "s" : ""}{" "}
                active
              </span>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={clearFilters}
              >
                Clear all
              </Button>
            </>
          )}
        </div>

        {showAdvanced && (
          <div className="filter-bar" style={{ marginBottom: 16 }}>
            <FormField
              className="filter-group"
              htmlFor="filter-ip"
              label="IP Address"
            >
              <input
                id="filter-ip"
                name="ip_address"
                className="field-input"
                placeholder="10.180.6. (prefix ok)"
                value={filters.ip_address}
                onChange={handleFilterChange}
              />
            </FormField>

            <FormField
              className="filter-group"
              htmlFor="filter-user"
              label="User ID"
            >
              <input
                id="filter-user"
                name="user_id"
                className="field-input"
                placeholder="usr_…"
                value={filters.user_id}
                onChange={handleFilterChange}
              />
            </FormField>

            <FormField
              className="filter-group"
              htmlFor="filter-from"
              label="From (UTC)"
            >
              <input
                id="filter-from"
                name="date_from"
                type="datetime-local"
                className="field-input"
                value={filters.date_from}
                onChange={handleCustomDate}
              />
            </FormField>

            <FormField
              className="filter-group"
              htmlFor="filter-to"
              label="To (UTC)"
            >
              <input
                id="filter-to"
                name="date_to"
                type="datetime-local"
                className="field-input"
                value={filters.date_to}
                onChange={handleCustomDate}
              />
            </FormField>
          </div>
        )}

        {total > 0 && (
          <div className="pagination-row" style={{ marginBottom: 16 }}>
            <div className="pagination-summary">
              Showing {total === 0 ? 0 : (page - 1) * pageSize + 1}-
              {Math.min(page * pageSize, total)} of {total} events
            </div>
            <div
              className="pagination-controls"
              style={{ display: "flex", alignItems: "center", gap: 12 }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: 12,
                  marginRight: 12,
                }}
              >
                <span className="text-muted">Show</span>
                <select
                  className="field-input"
                  style={{
                    width: 70,
                    height: 28,
                    padding: "0 4px",
                    fontSize: 12,
                  }}
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setPage(1);
                  }}
                  disabled={refreshing}
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                  <option value={250}>250</option>
                </select>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={page <= 1 || refreshing}
                onClick={() => setPage(1)}
              >
                {"<<"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={page <= 1 || refreshing}
                onClick={() => setPage(page - 1)}
              >
                Prev
              </Button>
              <span className="pagination-page" style={{ fontSize: 12 }}>
                Page {page} of {Math.max(1, Math.ceil(total / pageSize))}
              </span>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={page >= Math.ceil(total / pageSize) || refreshing}
                onClick={() => setPage(page + 1)}
              >
                Next
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={page >= Math.ceil(total / pageSize) || refreshing}
                onClick={() =>
                  setPage(Math.max(1, Math.ceil(total / pageSize)))
                }
              >
                {">>"}
              </Button>
            </div>
          </div>
        )}

        <div
          className="table-wrap"
          style={{
            opacity: refreshing ? 0.6 : 1,
            transition: "opacity 0.15s ease-in-out",
          }}
        >
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>User</th>
                <th>Action</th>
                <th>Target Resource</th>
                <th>Status &amp; Severity</th>
                <th>Source</th>
                <th>Changes</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const actInfo = getActionDisplay(log.action);
                return (
                  <tr
                    key={log.id}
                    onClick={() => openDetails(log, actInfo)}
                    style={{ cursor: "pointer" }}
                    title="Open full event details"
                  >
                    <td
                      style={{
                        fontSize: 12,
                        color: "var(--text-muted)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {formatDateTime(log.created_at)}
                    </td>
                    <td>
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span style={{ fontSize: 13, fontWeight: 600 }}>
                          {getActorDisplay(log)}
                        </span>
                        {log.user_email && (
                          <span
                            style={{
                              fontSize: "0.68rem",
                              color: "var(--text-faint)",
                            }}
                          >
                            {log.user_email}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                        }}
                      >
                        <span style={{ fontSize: 14 }}>{actInfo.icon}</span>
                        <strong style={{ fontSize: 13, color: actInfo.color }}>
                          {actInfo.label}
                        </strong>
                      </div>
                    </td>
                    <td>{renderAffectedObject(log)}</td>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          alignItems: "flex-start",
                          gap: 3,
                        }}
                      >
                        <span
                          style={{
                            color:
                              log.status === "success"
                                ? "var(--ok)"
                                : "var(--danger)",
                            fontSize: 12,
                            fontWeight: 600,
                          }}
                        >
                          {String(log.status || "").toUpperCase()}
                        </span>
                        {renderSeverity(log.severity)}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <code style={{ fontSize: 12, fontWeight: 600 }}>
                          {log.ip_address || "—"}
                        </code>
                        {log.user_agent && (
                          <span
                            style={{
                              fontSize: "0.68rem",
                              color: "var(--text-faint)",
                              marginTop: 2,
                            }}
                          >
                            {parseUserAgent(log.user_agent)}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      {log.changes &&
                      Object.keys(log.changes).length > 0 &&
                      ![
                        "user.login",
                        "user.login_failed",
                        "user.logout",
                        "scan.started",
                        "scan.created",
                        "scan.completed",
                        "scan.failed",
                      ].includes(log.action) ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            // The row itself opens the same modal now. Without
                            // this the click runs twice and fires two detail
                            // requests for one user action.
                            e.stopPropagation();
                            openDetails(log, actInfo);
                          }}
                        >
                          View Changes
                        </Button>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                );
              })}
              {logs.length === 0 && (
                <tr>
                  <td
                    colSpan="7"
                    style={{
                      textAlign: "center",
                      padding: 60,
                      color: "var(--text-muted)",
                    }}
                  >
                    No audit logs found matching your criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <AuditLogDetailsModal
        isOpen={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        log={selectedLog}
        loading={detailsLoading}
      />
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
