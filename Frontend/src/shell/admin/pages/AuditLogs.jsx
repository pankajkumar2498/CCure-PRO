import { useEffect, useState, useCallback, useRef } from "react";
import ProductFrame from "../../layout/ProductFrame";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureLoader,
  CcurePagination,
  CcureSelect,
  CcureTable,
  CcurePage,
  CcurePageHeader,
  CcureIcon,
} from "../../../design-system";
import "../styles/audit-logs.css";
import {
  listAuditLogs,
  getAuditLogDetail,
  exportAuditLogs,
  previewAuditRetention,
} from "../../api/admin";
import { useAuth } from "../../auth/AuthContext";
import { can } from "../../auth/permissions";
import { formatDateTime } from "../../utils/date";
import { useToasts, ToastContainer } from "../../feedback/Toast";
import AuditLogDetailsModal from "../components/AuditLogDetailsModal";

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
  const [exporting, setExporting] = useState("");
  const isFirstLoad = useRef(true);

  // The button is hidden without the permission, and that is a courtesy, not a
  // control: `require_permission("audit", "export")` on the route is what
  // actually refuses. Hiding it only stops offering an action that would 403.
  const { user: currentUser } = useAuth();
  const canExport = can(currentUser, "platform.audit_log.export");
  // The platform-scope retention capability, matching the backend's
  // `platform.audit_log.retention` guard. A purge is not tenant-scoped in effect
  // -- it destroys a record other parties may need -- so it is a platform key.
  const canSeeRetention = can(currentUser, "platform.audit_log.retention");
  const [retention, setRetention] = useState(null);
  const [retentionOpen, setRetentionOpen] = useState(false);

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

  // Retention status. Fetched once, not polled: it changes when an operator
  // edits configuration or a nightly job runs, not between renders.
  useEffect(() => {
    if (!canSeeRetention) return;
    let cancelled = false;
    previewAuditRetention()
      .then((data) => {
        if (!cancelled) setRetention(data);
      })
      .catch(() => {
        // Silent. This is a status panel; a failure to load it must not
        // interrupt reading the audit trail, which is what the page is for.
      });
    return () => {
      cancelled = true;
    };
  }, [canSeeRetention]);

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

  // Export what is currently on screen — the same filters, never the whole
  // table. Pagination is deliberately not passed: the export is capped and
  // keyset-paginated server-side, so sending `skip`/`limit` would hand back one
  // page of a file that is meant to be the whole filtered set.
  const handleExport = async (format) => {
    if (exporting) return;
    setExporting(format);
    try {
      const params = Object.fromEntries(
        Object.entries(filters).filter(([, value]) => value !== ""),
      );
      const result = await exportAuditLogs(params, format);
      if (result.integrity === "FAILED") {
        // Never a routine "downloaded" message. At least one exported row's
        // stored hash did not reproduce, which means the trail was modified
        // outside the application.
        pushToast(
          `${result.filename} downloaded - INTEGRITY FAILURE: at least one event did not match its stored hash. Investigate before relying on this trail.`,
          "error",
        );
      } else if (result.verificationMode !== "performed") {
        pushToast(
          `${result.filename} downloaded (${result.rows} events). Verification was NOT performed for this export.`,
          // "info", not "warning": there is no toast--warning style, and an
          // unstyled toast is less legible than a plain one. The file itself
          // says so in words, which is where it matters.
          "info",
        );
      } else {
        pushToast(
          `${result.filename} downloaded (${result.rows} events, all verified).`,
          "success",
        );
      }
    } catch (err) {
      // 413 is the row cap refusing rather than truncating, and its detail names
      // the count and what to do about it, so it is shown verbatim.
      let detail = err.response?.data?.detail;
      if (!detail && err.response?.data instanceof Blob) {
        try {
          detail = JSON.parse(await err.response.data.text())?.detail;
        } catch {
          detail = "";
        }
      }
      pushToast(detail || "Unable to export the audit log.", "error");
    } finally {
      setExporting("");
    }
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

  /* Severity is a CCure vocabulary, so the page no longer keeps a private
     palette keyed on it. The five entries here were rgba backgrounds with hex
     foregrounds and a `${fg}33` border — a light-on-dark set hardcoded on a
     page that renders in whichever theme the account chose. */
  const SEVERITY_VARIANT = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "info",
  };

  const renderSeverity = (severity) => {
    const key = String(severity || "info").toLowerCase();
    return (
      <CcureBadge
        variant={SEVERITY_VARIANT[key] || "info"}
        className="al-sev"
        title={`Severity: ${key}`}
      >
        {key}
      </CcureBadge>
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
        <div className="al-row">
          <span className="al-t-md" aria-hidden="true">
            <CcureIcon name="tag" />
          </span>
          <span className="al-t-sm al-medium">Session #{targetVal}</span>
        </div>
      );
    }

    if (resType === "user") {
      if (log.user_id && targetVal === log.user_id) {
        return <span className="al-muted al-t-sm">Self Account</span>;
      }
      const cleanTarget = targetVal.split("_").slice(-2, -1)[0] || targetVal;
      return (
        <div className="al-row">
          <span className="al-t-md" aria-hidden="true">
            <CcureIcon name="user" />
          </span>
          <span className="al-t-sm al-medium">User: {cleanTarget}</span>
        </div>
      );
    }

    if (resType === "scan") {
      const displayId = targetVal.includes("_")
        ? targetVal.split("_").pop()
        : targetVal;
      return (
        <div className="al-row">
          <span className="al-t-md" aria-hidden="true">
            <CcureIcon name="radio" />
          </span>
          <span className="al-t-sm al-medium al-mono">
            Scan #{displayId.slice(-6)}
          </span>
        </div>
      );
    }

    return (
      <div className="al-row">
        <span className="al-t-md" aria-hidden="true">
          <CcureIcon name="flag" />
        </span>
        <span className="al-t-sm al-medium">
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
      "user.login": { label: "Logged In", icon: "key", color: "var(--ok)" },
      "user.login_failed": {
        label: "Failed Login",
        icon: "alert-triangle",
        color: "var(--danger)",
      },
      "user.logout": {
        label: "Logged Out",
        icon: "log-out",
        color: "var(--accent)",
      },
      "user.created": {
        label: "User Created",
        icon: "user",
        color: "var(--primary)",
      },
      "user.updated": {
        label: "User Updated",
        icon: "settings",
        color: "var(--warning)",
      },
      "user.deleted": {
        label: "User Deleted",
        icon: "trash",
        color: "var(--danger)",
      },
      "scan.created": {
        label: "Scan Started",
        icon: "radio",
        color: "var(--primary)",
      },
      "scan.completed": {
        label: "Scan Completed",
        icon: "check-circle",
        color: "var(--ok)",
      },
      "scan.failed": {
        label: "Scan Failed",
        icon: "x-circle",
        color: "var(--danger)",
      },
      "scan.recycled": {
        label: "Scan Moved to Recycle Bin",
        icon: "trash",
        color: "var(--warning)",
      },
      "scan.restored": {
        label: "Scan Restored",
        icon: "rotate-ccw",
        color: "var(--accent)",
      },
      "scan.purged": {
        label: "Scan Permanently Deleted",
        icon: "trash",
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

    return { label: cleanLabel, icon: "flag", color: "var(--text)" };
  };

  if (loading) {
    return (
      <ProductFrame>
        <CcurePage>
          <CcurePageHeader title="Audit Logs" />
          <div className="al-centered">
            <CcureLoader label="Loading audit logs…" />
          </div>
        </CcurePage>
      </ProductFrame>
    );
  }

  return (
    <ProductFrame pageTitle="Audit Logs">
      <CcurePage>
        <CcurePageHeader
          title="Audit Logs"
          subtitle={<>Immutable trail of system activities and user actions</>}
          actions={
            <>
              <div className="al-title-actions">
                {/* The region is mounted unconditionally and the button appears
                inside it. A `role="status"` that mounts at the same moment its
                content arrives is frequently not announced at all — the reader
                has nothing to observe changing.

                It was a `<div onClick>` with inline hover handlers: not
                focusable, not announced, and the only way to catch up with new
                events. It is a button now, so Enter and Space work and it is in
                the tab order. Polite, not assertive: a background freshness
                notice is not an emergency, and this one can arrive every five
                seconds. */}
                <div role="status" aria-live="polite" className="al-newevents">
                  {newEventsCount > 0 && (
                    <CcureButton
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setPage(1);
                        loadData(true, 1);
                      }}
                    >
                      <CcureIcon name="message-square" /> {newEventsCount} new
                      event
                      {newEventsCount > 1 ? "s" : ""} — show
                    </CcureButton>
                  )}
                </div>
                <CcureButton
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
                </CcureButton>
                {canExport && (
                  <>
                    <CcureButton
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => handleExport("csv")}
                      disabled={Boolean(exporting)}
                      title="Download the events matching the current filters, with every stored hash re-verified"
                    >
                      {exporting === "csv" ? "Exporting..." : "Export CSV"}
                    </CcureButton>
                    <CcureButton
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => handleExport("pdf")}
                      disabled={Boolean(exporting)}
                      title="Summary document; the CSV carries the hashes"
                    >
                      {exporting === "pdf" ? "Exporting..." : "Export PDF"}
                    </CcureButton>
                  </>
                )}
              </div>
            </>
          }
        />

        {canSeeRetention && retention && (
          <div className="al-note">
            <CcureButton
              type="button"
              variant="ghost"
              block
              aria-expanded={retentionOpen}
              aria-controls="al-retention-details"
              onClick={() => setRetentionOpen((open) => !open)}
              className="al-retention-toggle"
            >
              <strong>Retention</strong>
              <CcureBadge
                variant={
                  retention.installed && retention.enabled
                    ? "warning"
                    : "neutral"
                }
              >
                {!retention.installed
                  ? "NOT INSTALLED"
                  : retention.enabled
                    ? `${retention.retention_days} DAYS`
                    : "DISABLED"}
              </CcureBadge>
              <span className="al-muted">
                {retention.installed
                  ? `${retention.would_delete_total ?? 0} event(s) would be removed`
                  : "no purge can run"}
              </span>
              <span className="al-push al-muted">
                {retentionOpen ? "▲" : "▼"}
              </span>
            </CcureButton>

            {retentionOpen && (
              <div id="al-retention-details" className="al-mt al-relaxed">
                {!retention.installed ? (
                  <div>{retention.detail}</div>
                ) : (
                  <>
                    <div>Scope: {retention.scope}</div>
                    <div>
                      Cutoff: {retention.cutoff ?? "none — retention disabled"}
                      {retention.reason ? ` (${retention.reason})` : ""}
                    </div>
                    <div>
                      Floor: {retention.floor_days} days &middot; batch{" "}
                      {retention.batch_size} &middot; max{" "}
                      {retention.max_rows_per_run} per run &middot; dry run by
                      default: {String(retention.dry_run_default)}
                    </div>
                    <div>
                      Backup:{" "}
                      {retention.backup?.newest
                        ? `${retention.backup.newest}, ${retention.backup.age_hours}h old (required within ${retention.backup.required_within_hours}h)`
                        : "none found — a purge would be refused"}
                    </div>
                    {Object.keys(retention.holds || {}).length > 0 && (
                      <div className="al-warn-text">
                        Holds:{" "}
                        {Object.entries(retention.holds)
                          .map(([org, reason]) => `${org} (${reason})`)
                          .join(", ")}
                      </div>
                    )}
                    <CcureTable
                      caption="Audit retention preview by organization"
                      className="al-mt-sm"
                      columns={[
                        { key: "organization", header: "Organization" },
                        { key: "eligible", header: "Eligible" },
                        { key: "legacy", header: "Legacy" },
                        { key: "chained", header: "Chained" },
                        { key: "hold", header: "Hold" },
                      ]}
                    >
                      {(retention.organizations || []).map((row) => (
                        <tr key={row.org_id}>
                          <td>{row.org_id}</td>
                          <td>{row.eligible_count}</td>
                          <td>{row.legacy_total}</td>
                          <td>{row.chained_total}</td>
                          <td>{row.on_hold ? "YES" : "—"}</td>
                        </tr>
                      ))}
                    </CcureTable>
                    <div className="al-mt-sm al-muted">
                      This panel is read-only. A purge runs from the scheduler
                      or
                      <code>
                        {" "}
                        scripts/audit/purge_audit_retention.py --apply
                      </code>
                      , so removing audit history needs host access as well as
                      this role.
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {error && <CcureAlert variant="danger">{error}</CcureAlert>}

        <div className="al-filters">
          <CcureSelect
            label="Action"
            fieldClassName="al-filter"
            id="filter-action"
            name="action"
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
            <option value="scan.recycled">Scan Moved to Recycle Bin</option>
            <option value="scan.restored">Scan Restored</option>
            <option value="scan.purged">Scan Permanently Deleted</option>
          </CcureSelect>

          <CcureSelect
            label="Resource"
            fieldClassName="al-filter"
            id="filter-resource"
            name="resource_type"
            value={filters.resource_type}
            onChange={handleFilterChange}
          >
            <option value="">All Resources</option>
            <option value="user">User</option>
            <option value="scan">Scan</option>
            <option value="organization">Organization</option>
          </CcureSelect>

          <CcureSelect
            label="Status"
            fieldClassName="al-filter"
            id="filter-status"
            name="status"
            value={filters.status}
            onChange={handleFilterChange}
          >
            <option value="">All Status</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
            <option value="blocked_malware">Blocked (malware)</option>
            <option value="scanner_unavailable">Scanner unavailable</option>
          </CcureSelect>

          <CcureSelect
            label="Severity"
            fieldClassName="al-filter"
            id="filter-severity"
            name="severity"
            value={filters.severity}
            onChange={handleFilterChange}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </CcureSelect>

          <CcureSelect
            label="Time Range"
            fieldClassName="al-filter"
            id="filter-range"
            name="range"
            value={filters.range}
            onChange={(e) => handleRangePreset(e.target.value)}
          >
            <option value="">All Time</option>
            <option value="today">Today</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </CcureSelect>

          <CcureInput
            label="Search"
            fieldClassName="al-filter"
            id="filter-search"
            type="search"
            placeholder="Event ID, request ID, user, IP…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="al-minw"
          />
        </div>

        <div className="al-row al-row--gap-lg al-row--wrap al-chipbar">
          <CcureButton
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setShowAdvanced((v) => !v)}
          >
            {showAdvanced ? "▾ Fewer filters" : "▸ More filters"}
          </CcureButton>
          {activeFilterCount > 0 && (
            <>
              <span className="al-t-xs al-muted">
                {activeFilterCount} filter{activeFilterCount > 1 ? "s" : ""}{" "}
                active
              </span>
              <CcureButton
                type="button"
                variant="ghost"
                size="sm"
                onClick={clearFilters}
              >
                Clear all
              </CcureButton>
            </>
          )}
        </div>

        {showAdvanced && (
          <div className="al-filters">
            <CcureInput
              label="IP Address"
              fieldClassName="al-filter"
              id="filter-ip"
              name="ip_address"
              placeholder="10.180.6. (prefix ok)"
              value={filters.ip_address}
              onChange={handleFilterChange}
            />

            <CcureInput
              label="User ID"
              fieldClassName="al-filter"
              id="filter-user"
              name="user_id"
              placeholder="usr_…"
              value={filters.user_id}
              onChange={handleFilterChange}
            />

            <CcureInput
              label="From (UTC)"
              fieldClassName="al-filter"
              id="filter-from"
              name="date_from"
              type="datetime-local"
              value={filters.date_from}
              onChange={handleCustomDate}
            />

            <CcureInput
              label="To (UTC)"
              fieldClassName="al-filter"
              id="filter-to"
              name="date_to"
              type="datetime-local"
              value={filters.date_to}
              onChange={handleCustomDate}
            />
          </div>
        )}

        {total > 0 && (
          <CcurePagination
            page={page}
            pageSize={pageSize}
            total={total}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setPage(1);
            }}
            pageSizeOptions={[25, 50, 100, 250]}
            pageSizeLabel="Events per page"
            showBoundaryLinks
            itemNoun="events"
            disabled={refreshing}
            className="al-mb"
          />
        )}

        <div
          className={`al-table-wrap${refreshing ? " al-table-wrap--busy" : ""}`}
          aria-busy={refreshing || undefined}
        >
          <CcureTable
            caption={`Audit trail — ${total} event${total === 1 ? "" : "s"} matching the current filters`}
            columns={[
              { key: "timestamp", header: "Timestamp" },
              { key: "user", header: "User" },
              { key: "action", header: "Action" },
              { key: "target", header: "Target Resource" },
              { key: "status", header: "Status & Severity" },
              { key: "source", header: "Source" },
              { key: "changes", header: "Changes" },
            ]}
            hoverable
          >
            {logs.map((log) => {
              const actInfo = getActionDisplay(log.action);
              return (
                <tr
                  key={log.id}
                  onClick={() => openDetails(log, actInfo)}
                  className="al-clickable"
                  title="Open full event details"
                >
                  <td className="al-t-xs al-muted al-nowrap">
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      aria-label={`Open event ${log.id} details`}
                      onClick={(e) => {
                        e.stopPropagation();
                        openDetails(log, actInfo);
                      }}
                    >
                      {formatDateTime(log.created_at)}
                    </CcureButton>
                  </td>
                  <td>
                    <div className="al-col">
                      <span className="al-t-sm al-semibold">
                        {getActorDisplay(log)}
                      </span>
                      {log.user_email && (
                        <span className="al-t-2xs al-muted">
                          {log.user_email}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="al-row">
                      <span className="al-t-md" aria-hidden="true">
                        <CcureIcon name={actInfo.icon} />
                      </span>
                      <strong className="al-t-sm al-semibold">
                        {actInfo.label}
                      </strong>
                    </div>
                  </td>
                  <td>{renderAffectedObject(log)}</td>
                  <td>
                    <div className="al-col al-col--start">
                      {/* The word is the status; the colour is the sighted
                          half of the same fact, never the whole of it. */}
                      <CcureBadge
                        variant={
                          log.status === "success" ? "success" : "danger"
                        }
                      >
                        {String(log.status || "").toUpperCase()}
                      </CcureBadge>
                      {renderSeverity(log.severity)}
                    </div>
                  </td>
                  <td>
                    <div className="al-col">
                      <code className="al-t-xs al-semibold">
                        {log.ip_address || "—"}
                      </code>
                      {log.user_agent && (
                        <span className="al-t-2xs al-muted al-mt-2xs">
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
                      <CcureButton
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
                      </CcureButton>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              );
            })}
            {logs.length === 0 && (
              <tr>
                <td colSpan="7" className="al-centered-note">
                  No audit logs found matching your criteria.
                </td>
              </tr>
            )}
          </CcureTable>
        </div>
      </CcurePage>

      <AuditLogDetailsModal
        isOpen={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        log={selectedLog}
        loading={detailsLoading}
      />
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </ProductFrame>
  );
}
