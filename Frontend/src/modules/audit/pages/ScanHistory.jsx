/**
 * src/modules/audit/pages/ScanHistory.jsx
 * Production-grade scan history with:
 *   • Custom confirm dialogs (Re-run / Stop) — no browser confirm/alert
 *   • Toast notifications for success / error feedback
 *   • Re-run shows scan details + live-network warning before executing
 * APIs: GET /scans, GET /scans/{id}, the /scans/events stream,
 *       DELETE /scans/{id}, POST /scans/{id}/archive, POST /scans/{id}/stop,
 *       POST /scan/host-discovery (re-run)
 *
 * Checkpoint 3C batch 22 — on the design system. Requests, the live stream's
 * reconnect and polling fallback, filtering, sorting, paging, permissions and
 * every action are unchanged, and pinned by
 * src/__tests__/pages/ScanHistory.test.jsx, written against the page before
 * migration. Archive and Delete still act on the first press; only Re-run and
 * Stop ask first.
 */
import { useEffect, useState, useCallback, useId, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import RiskBadge from "@audit/components/scan/RiskBadge";
import { useAuth } from "@shell/auth/AuthContext";
import { useScan } from "@audit/context/ScanContext";
import { usePreferences } from "@shell/preferences/PreferencesContext";
import {
  getScans,
  getScan,
  deleteScan,
  stopScan,
  archiveScan,
  streamScanEvents,
} from "@audit/api/scans";
import { buildPhasePayload, SCAN_PIPELINES } from "@audit/config/scanConfig";
import api from "@shell/api/axiosInstance";
import { dateTimeMs, formatDateTime } from "@shell/utils/date";
import { can, denyMessage } from "@shell/auth/permissions";
import CVELink from "@audit/components/common/CVELink";
import { useToasts, ToastContainer } from "@shell/feedback/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureModal,
  CcurePagination,
  CcureScanProgress,
  CcureScanStatus,
  CcureSeverityBadge,
  CcureTable,
} from "../../../design-system";
import "../styles/scan-history.css";

/* ── constants ── */
const STATUS_LABELS = {
  complete: "Completed",
  completed: "Completed",
  running: "Running",
  failed: "Failed",
  cancelled: "Cancelled",
  canceled: "Cancelled",
  unreachable: "Host Unreachable",
};
const TERMINAL_PHASES = {
  basic: 1,
  asset: 2,
  advanced: 3,
  vulnerability_audit: 3,
};
const PHASE_LABELS = { 1: "Discovery", 2: "Port Scan", 3: "Vulnerability" };
const DATE_MS = { "1h": 3.6e6, "24h": 8.64e7, "7d": 6.048e8, "30d": 2.592e9 };
const LIVE_LABELS = {
  connecting: "Live sync connecting",
  connected: "Live sync active",
  reconnecting: "Live sync reconnecting",
  polling: "Live sync polling",
};

const TERMINAL_STATUSES = [
  "complete",
  "failed",
  "cancelled",
  "canceled",
  "unreachable",
];

const normalizeStatus = (status) => {
  const raw = String(status || "running").toLowerCase();
  if (raw === "completed") return "complete";
  if (raw === "canceled") return "cancelled";
  return raw;
};

/**
 * Render a summary value for display.
 *
 * The summary block dumps raw values, so a duration arrived as
 * "9.252127170562744" next to a header that correctly read "9.3s". Seconds and
 * percentages are the only keys that need shaping; everything else is passed
 * through so a new summary field never silently loses precision.
 */
const fmtSummaryValue = (key, value) => {
  if (typeof value !== "number") return String(value);
  const name = String(key).toLowerCase();
  if (name.includes("duration") || name.endsWith("_seconds")) {
    return fmtDur(value);
  }
  if (name.includes("percent")) return `${Math.round(value)}%`;
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
};

const isCred = (scan) => scan.scan_type === "credentialed";
const scanNumber = (scan) => scan?.scan_no ?? scan?.display_id ?? "-";
const scanLabel = (scan) =>
  `Scan No. ${scan?.scan_no ?? scan?.display_id ?? "-"}`;
const phaseLabel = (scan) =>
  isCred(scan)
    ? "Credentialed Audit"
    : `P${scan.phase} — ${PHASE_LABELS[scan.phase] || "-"}`;

const scanTypeLabel = (scan) => {
  if (!scan) return "Unknown";
  if (isCred(scan)) return "Credentialed Scan";
  const mode = scan.pipeline_mode || "basic";
  const pipeline = SCAN_PIPELINES[mode];
  if (pipeline?.label) return pipeline.label;
  return String(scan.pipeline_mode || scan.scan_type || "Unknown").replace(
    /_/g,
    " ",
  );
};

const getScanStartedByLabel = (scan, currentUser) => {
  const startedBy = scan?.started_by;
  if (!startedBy) return "Unknown";
  if (
    startedBy.user_id &&
    currentUser?.id &&
    startedBy.user_id === currentUser.id
  ) {
    return "You";
  }
  return startedBy.display_name || startedBy.username || "Unknown";
};

const fmtDate = (iso) =>
  formatDateTime(iso, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

// When a scan finished is a property of the scan, not of the row's last write.
// Using updated_at meant anything that touched the record afterwards — a report
// download, an archive toggle — retroactively changed the date the scan appeared
// to have run.
const getScanDisplayDate = (scan) =>
  ["complete", "failed", "cancelled", "unreachable"].includes(
    normalizeStatus(scan.status),
  )
    ? scan.completed_at || scan.started_at || scan.created_at
    : scan.started_at || scan.created_at;

/**
 * The scan's lifecycle, from its own timestamps.
 *
 * The Date column shows one instant, chosen by status — which is right for a
 * column, and loses the sequence. A scan that waited eleven minutes for a
 * worker and ran for four seconds reads identically to one that started at
 * once, and `queued_at` is on every row and was displayed nowhere.
 *
 * Only the stages the record actually carries appear. A scan that never
 * started has no start, and inventing one would be the opposite of the point.
 */
const lifecycleTitle = (scan) => {
  const stages = [
    ["Queued", scan?.queued_at],
    ["Started", scan?.started_at],
    ["Completed", scan?.completed_at],
  ].filter(([, iso]) => Boolean(iso));
  if (!stages.length) return undefined;
  return stages.map(([label, iso]) => `${label}: ${fmtDate(iso)}`).join("\n");
};

const fmtDur = (sec) =>
  !sec
    ? "—"
    : sec < 60
      ? `${sec.toFixed(1)}s`
      : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

const normCve = (cve) => {
  const cvss = Number(cve.cvss_score ?? cve.cvss ?? 0) || 0;
  return {
    cve_id: cve.cve_id || cve.cve || "Unknown",
    severity:
      cve.severity ||
      (cvss >= 9
        ? "Critical"
        : cvss >= 7
          ? "High"
          : cvss >= 4
            ? "Medium"
            : cvss > 0
              ? "Low"
              : "Info"),
    description: cve.description || cve.desc || "",
  };
};

const getStoredTargets = (scan) => {
  if (Array.isArray(scan.targets) && scan.targets.length > 0)
    return scan.targets;
  return String(scan.target || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
};

const getScanProgress = (scan) => {
  const fromApi = Number(scan.progress_percentage);
  if (Number.isFinite(fromApi)) return Math.max(0, Math.min(100, fromApi));

  const status = normalizeStatus(scan.status);
  if (status === "complete") return 100;

  const terminal = TERMINAL_PHASES[scan.pipeline_mode || "basic"] || 1;
  const phase = Math.max(0, Math.min(Number(scan.phase || 0), terminal));
  const percent = Math.round((phase / terminal) * 100);
  return status === "running"
    ? Math.max(8, Math.min(96, percent))
    : Math.max(8, percent);
};

const isSameScan = (a, b) =>
  a &&
  b &&
  a.id === b.id &&
  a.scan_no === b.scan_no &&
  a.status === b.status &&
  a.phase === b.phase &&
  a.updated_at === b.updated_at &&
  a.scan_duration === b.scan_duration &&
  a.progress_percentage === b.progress_percentage &&
  JSON.stringify(a.summary || {}) === JSON.stringify(b.summary || {});

const mergeScanSnapshot = (current, incoming) => {
  const byId = new Map(current.map((scan) => [scan.id, scan]));
  return incoming.map((scan) => {
    const previous = byId.get(scan.id);
    return isSameScan(previous, scan) ? previous : { ...previous, ...scan };
  });
};

/* ══════════════════════════════════════════════════════════════════════════
   CONFIRM DIALOG COMPONENT
   ══════════════════════════════════════════════════════════════════════════ */
/* Built on CcureModal rather than CcureConfirmDialog, because it keeps this
   page's confirmation exactly: the scan's details, the confirm button focused
   on open, Escape and a click outside both cancelling, and both buttons
   disabled while the request runs. */
/* CcureModal's own click-outside dismissal reads the React event's
   `currentTarget` after dispatch has finished, by which point React has
   cleared it, so it never closes (recorded as deferred). Both of this page's
   dialogs closed on a click outside them before migration, so the page listens
   for a click whose target is that dialog's own overlay instead. */
function useCloseOnOverlayClick(dialogClass, onClose) {
  useEffect(() => {
    const onClick = (event) => {
      const target = event.target;
      if (
        target instanceof Element &&
        target.classList.contains("cc-modal__overlay") &&
        target.firstElementChild?.classList.contains(dialogClass)
      ) {
        onClose();
      }
    };
    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, [dialogClass, onClose]);
}

function ConfirmDialog({ config, onConfirm, onCancel }) {
  const { type, title, subtitle, meta, warning, confirmLabel, confirmClass } =
    config;
  const [busy, setBusy] = useState(false);
  const confirmRef = useRef(null);

  // Focus confirm button on mount. The focus trap records what to restore on
  // close before this runs, and focuses the same button itself a frame later.
  useEffect(() => {
    confirmRef.current?.focus();
  }, []);

  useCloseOnOverlayClick("sh-confirm", onCancel);

  const handleConfirm = async () => {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <CcureModal
      open
      onClose={onCancel}
      closeOnOverlayClick={false}
      size="md"
      className="sh-confirm"
      title={
        <>
          <span aria-hidden="true">{config.icon}</span> {title}
        </>
      }
      subtitle={subtitle}
      initialFocus={confirmRef}
      footer={
        <>
          <CcureButton variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </CcureButton>
          <CcureButton
            ref={confirmRef}
            variant={confirmClass === "danger" ? "danger" : "primary"}
            onClick={handleConfirm}
            loading={busy}
          >
            {confirmLabel}
          </CcureButton>
        </>
      }
    >
      {meta && meta.length > 0 && (
        <dl className="sh-confirm__meta">
          {meta.map(([label, value]) => (
            <div className="sh-confirm__row" key={label}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      )}

      {warning && (
        <CcureAlert
          variant={type === "delete" ? "danger" : "info"}
          live={false}
          className="sh-confirm__warning"
        >
          {warning}
        </CcureAlert>
      )}
    </CcureModal>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   DETAIL MODAL (View button)
   ══════════════════════════════════════════════════════════════════════════ */
function DetailModal({ scanId, onClose, onOpenFullResults }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const summaryEntries = Object.entries(detail?.summary || {}).filter(
    ([key, value]) => {
      if (String(key).startsWith("_")) return false;
      return (
        value == null || ["string", "number", "boolean"].includes(typeof value)
      );
    },
  );

  useEffect(() => {
    getScan(scanId)
      .then(({ data }) => setDetail(data))
      .catch(() => setError("Failed to load scan details."))
      .finally(() => setLoading(false));
  }, [scanId]);

  useCloseOnOverlayClick("sh-detail", onClose);

  return (
    <CcureModal
      open
      onClose={onClose}
      closeOnOverlayClick={false}
      size="lg"
      className="sh-detail"
      title={detail ? scanLabel(detail) : "Scan Details"}
    >
      {loading && (
        <CcureLoader
          className="sh-detail__state"
          label="Loading scan details…"
        />
      )}
      {error && (
        <CcureAlert variant="danger" className="sh-detail__alert">
          {error}
        </CcureAlert>
      )}

      {detail && (
        <div className="sh-detail__body">
          <dl className="sh-detail__meta">
            <div>
              <dt>Target</dt>
              <dd className="sh-mono">{detail.target}</dd>
            </div>
            <div>
              <dt>Scan Type</dt>
              <dd>{scanTypeLabel(detail)}</dd>
            </div>
            <div>
              <dt>Phase</dt>
              <dd>
                {isCred(detail)
                  ? "Credentialed"
                  : PHASE_LABELS[detail.phase] || detail.phase}
              </dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <CcureScanStatus status={normalizeStatus(detail.status)} />
              </dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd className="sh-mono">{fmtDur(detail.scan_duration)}</dd>
            </div>
            <div>
              <dt>Completed</dt>
              <dd>{fmtDate(getScanDisplayDate(detail))}</dd>
            </div>
          </dl>

          {/* Why a scan failed used to live only in the database, so the UI
              could say "Failed" and nothing more. */}
          {detail.failure_reason && (
            <CcureAlert
              variant="danger"
              live={false}
              className="sh-detail__alert"
            >
              {detail.failure_reason}
            </CcureAlert>
          )}

          {summaryEntries.length > 0 && (
            <section className="sh-detail__section">
              <h3 className="sh-detail__heading">Summary</h3>
              <dl className="sh-detail__summary">
                {summaryEntries.map(([k, v]) => (
                  <div key={k} className="sh-detail__summary-row">
                    <dt>{k.replace(/_/g, " ")}</dt>
                    <dd>{fmtSummaryValue(k, v)}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}

          {detail.results &&
            Object.entries(detail.results).map(([pk, pd]) => {
              const hosts = (pd?.data || []).filter((h) => h.is_active);
              if (!hosts.length) return null;
              return (
                <section key={pk} className="sh-detail__section">
                  <h3 className="sh-detail__heading">
                    {PHASE_LABELS[pk.replace("phase", "")] || pk} Results
                    <span className="sh-muted sh-detail__count">
                      ({hosts.length} host{hosts.length !== 1 ? "s" : ""})
                    </span>
                  </h3>
                  <ul className="sh-hosts">
                    {hosts.map((h) => (
                      <li key={h.ip_address} className="sh-host">
                        <div className="sh-host__header">
                          <span className="sh-mono sh-host__ip">
                            {h.ip_address}
                          </span>
                          {h.hostname && h.hostname !== "Unknown" && (
                            <span className="sh-muted">{h.hostname}</span>
                          )}
                          {/* MAC and vendor are the headline result of a LAN
                              discovery scan; omitting them here meant the only
                              view reachable from history hid them. */}
                          {(h.mac_address || h.mac) && (
                            <span className="sh-mono sh-muted">
                              {String(h.mac_address || h.mac).toLowerCase()}
                            </span>
                          )}
                          {h.vendor && h.vendor !== "Unknown" && (
                            <span className="sh-muted">{h.vendor}</span>
                          )}
                          {h.host_risk_level && (
                            <RiskBadge
                              level={h.host_risk_level}
                              score={h.host_risk_score}
                            />
                          )}
                          {h.open_ports?.length > 0 && (
                            <CcureBadge variant="neutral">
                              {h.open_ports.length} ports
                            </CcureBadge>
                          )}
                          {h.cves?.length > 0 && (
                            <CcureBadge variant="warning">
                              {h.cves.length} verified
                            </CcureBadge>
                          )}
                          {/* Candidates the scan examined and ruled out. Shown
                              so this count reconciles with the report, which
                              lists the same suppressed candidates. */}
                          {h.suppressed_cves?.length > 0 && (
                            <span
                              className="sh-muted sh-mono"
                              title="Candidate CVEs ruled out: the affected product or version is not present on this host"
                            >
                              {h.suppressed_cves.length} ruled out
                            </span>
                          )}
                        </div>
                        {h.open_ports?.length > 0 && (
                          <ul className="sh-ports">
                            {h.open_ports.map((p, i) => (
                              <li key={i} className="sh-port">
                                <span className="sh-mono">{p.port}</span>{" "}
                                {p.service}
                              </li>
                            ))}
                          </ul>
                        )}
                        {h.cves?.length > 0 && (
                          <ul className="sh-cves">
                            {h.cves.slice(0, 5).map((rawCve, i) => {
                              const cve = normCve(rawCve);
                              return (
                                <li key={i} className="sh-cve">
                                  <CVELink cveId={cve.cve_id} />
                                  <CcureSeverityBadge severity={cve.severity} />
                                  <span className="sh-cve__desc">
                                    {cve.description}
                                  </span>
                                </li>
                              );
                            })}
                          </ul>
                        )}
                        {h.cves?.length > 5 && (
                          <p className="sh-muted sh-more">
                            +{h.cves.length - 5} more
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              );
            })}

          {/* The modal is a summary. The full results view — sortable host
              table, Active/All filters, and the JSON/CSV/Copy exports — used
              to be unreachable for any scan that was not still in session. */}
          {detail.results?.phase1?.data?.length > 0 && (
            <div className="sh-detail__actions">
              <CcureButton onClick={() => onOpenFullResults(detail)}>
                Open full results &amp; exports{" "}
                <span aria-hidden="true">→</span>
              </CcureButton>
            </div>
          )}
        </div>
      )}
    </CcureModal>
  );
}

/* ── sub-components ── */
function FilterGroup({ label, children }) {
  const labelId = useId();
  return (
    <div className="sh-filter">
      <span className="sh-filter__label" id={labelId}>
        {label}
      </span>
      <div
        className="sh-filter__options"
        role="group"
        aria-labelledby={labelId}
      >
        {children}
      </div>
    </div>
  );
}

function FilterOption({ active, children, ...rest }) {
  return (
    <CcureButton
      variant="secondary"
      size="sm"
      className="sh-filter__option"
      aria-pressed={active}
      {...rest}
    >
      {children}
    </CcureButton>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   MONITOR CARD COMPONENT
   ══════════════════════════════════════════════════════════════════════════ */
function ScanMonitorCard({ scan, onStop, onView }) {
  const progress = getScanProgress(scan);
  const status = normalizeStatus(scan.status);
  const summary = scan.summary || {};
  const number = scanNumber(scan);

  return (
    <CcureCard
      className="sh-monitor-card"
      title={
        <>
          <span className="sh-mono">{number}</span>{" "}
          <span className="sh-monitor-card__target" title={scan.target}>
            {scan.target}
          </span>
        </>
      }
      actions={<CcureScanStatus status={status} />}
      footer={
        <>
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() => onView(scan)}
            aria-label={`View Detailed Results for scan ${number}`}
          >
            View Detailed Results
          </CcureButton>
          <CcureButton
            variant="danger"
            size="sm"
            onClick={() => onStop(scan)}
            aria-label={`Stop Scan ${number}`}
          >
            Stop Scan
          </CcureButton>
        </>
      }
    >
      <dl className="sh-monitor-card__meta">
        <div>
          <dt>Phase:</dt>
          <dd>{phaseLabel(scan)}</dd>
        </div>
        <div>
          <dt>Duration:</dt>
          <dd>{fmtDur(scan.scan_duration)}</dd>
        </div>
        <div>
          <dt>Type:</dt>
          <dd>{scanTypeLabel(scan)}</dd>
        </div>
      </dl>

      <CcureScanProgress
        value={progress}
        status={status}
        label="Overall Progress"
      />

      {summary.active_hosts !== undefined && (
        <ul className="sh-monitor-card__stats">
          <li>
            <strong className="sh-stat__value">{summary.active_hosts}</strong>{" "}
            <span className="sh-stat__label">Active Hosts</span>
          </li>
          {summary.vulnerabilities !== undefined && (
            <li>
              <strong className="sh-stat__value sh-stat__value--danger">
                {summary.vulnerabilities}
              </strong>{" "}
              <span className="sh-stat__label">Findings</span>
            </li>
          )}
        </ul>
      )}
    </CcureCard>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   MAIN PAGE
   ══════════════════════════════════════════════════════════════════════════ */
export default function ScanHistory({ mode = "history" }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isMonitor = mode === "monitor";

  const { user } = useAuth();
  const {
    setTarget,
    setScanType,
    setPipelineMode,
    setScanId,
    setScanNo,
    resetScan,
  } = useScan();
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const canReadScans = can(user, "scans", "read");
  const canExecuteScans = can(user, "scans", "execute");
  const canArchiveScans = can(user, "scans", "archive");
  const canRecycleScans = can(user, "scans", "recycle");

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [liveState, setLiveState] = useState("connecting");
  const [lastLiveAt, setLastLiveAt] = useState(null);
  const [error, setError] = useState("");
  const [viewId, setViewId] = useState(null);
  const [filterStatus, setFilterStatus] = useState(() => {
    if (isMonitor) return "running";
    return searchParams.get("status") || "all";
  });
  const [filterOwner, setFilterOwner] = useState(
    () => searchParams.get("owner") || "all",
  );
  const [filterDate, setFilterDate] = useState("all");
  const [page, setPage] = useState(1);
  // Search input vs. the debounced value actually sent to the API, so typing
  // does not fire a request per keystroke.
  const [searchInput, setSearchInput] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [sort, setSort] = useState({ key: "scan_no", dir: "desc" });
  const { preferences } = usePreferences();

  // Sync filterStatus with query param
  useEffect(() => {
    if (isMonitor) {
      setFilterStatus("running");
      return;
    }
    const status = searchParams.get("status");
    setFilterStatus(status || "all");
    setFilterOwner(searchParams.get("owner") || "all");
  }, [searchParams, isMonitor]);

  const ownerParam = filterOwner === "mine" ? "me" : undefined;

  // Confirm dialog state
  const [dialog, setDialog] = useState(null); // { type, scan, config }

  const applySnapshot = useCallback((data) => {
    if (!Array.isArray(data?.scans)) return;
    setScans((prev) => mergeScanSnapshot(prev, data.scans));
    setTotal(
      Number.isFinite(Number(data.total))
        ? Number(data.total)
        : data.scans.length,
    );
    setLastLiveAt(new Date());
    setError("");
  }, []);

  const load = useCallback(
    async ({ initial = false, quiet = false } = {}) => {
      if (initial) setLoading(true);
      if (!quiet) {
        setRefreshing(!initial);
        setError("");
      }
      try {
        // Search goes to the server so it covers the whole history rather than
        // whichever rows this page happens to be holding.
        const { data } = await getScans(0, 200, "active", ownerParam, {
          search: searchTerm || undefined,
        });
        applySnapshot(data);
      } catch {
        if (!quiet) setError("Failed to load scan history.");
      } finally {
        if (initial) setLoading(false);
        if (!quiet) setRefreshing(false);
      }
    },
    [applySnapshot, ownerParam, searchTerm],
  );

  useEffect(() => {
    load({ initial: true });
  }, [load]);

  useEffect(() => {
    const handle = setTimeout(() => {
      setSearchTerm(searchInput.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(handle);
  }, [searchInput]);

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    const runPollingFallback = async () => {
      setLiveState("polling");
      while (!stopped) {
        await load({ quiet: true });
        await wait(5000);
      }
    };

    const connect = async () => {
      let failures = 0;
      while (!stopped) {
        try {
          setLiveState(failures ? "reconnecting" : "connecting");
          await streamScanEvents({
            scope: "active",
            limit: 200,
            interval: 2,
            created_by: ownerParam,
            // Same filter as the list request, so a live snapshot cannot
            // replace the filtered view with an unfiltered one.
            search: searchTerm || undefined,
            signal: controller.signal,
            onEvent: ({ event, data }) => {
              if (stopped) return;
              if (event === "connected") setLiveState("connected");
              if (event === "heartbeat") setLastLiveAt(new Date());
              if (event === "scans") {
                applySnapshot(data);
                setLiveState("connected");
              }
            },
          });

          if (!stopped) throw new Error("Scan history stream closed.");
        } catch {
          if (stopped || controller.signal.aborted) return;
          failures += 1;
          setLiveState("reconnecting");
          if (failures >= 2) {
            await runPollingFallback();
            return;
          }
          await wait(2500);
        }
      }
    };

    connect();
    return () => {
      stopped = true;
      controller.abort();
    };
    // `ownerParam` is read inside the stream's request. `load` already depends
    // on it, so the effect was in fact restarting when the owner filter moved —
    // listing it makes that guarantee explicit instead of transitive.
  }, [applySnapshot, load, ownerParam, searchTerm]);

  const handleView = (scan) => {
    if (!canReadScans) {
      pushToast(denyMessage, "error");
      return;
    }
    if (isCred(scan)) {
      navigate(`/scan/credentialed/results?scan_id=${scan.id}`);
      return;
    }
    setViewId(scan.id);
  };

  /* ── Dialog openers ── */
  const openRerunDialog = (scan) => {
    if (!canExecuteScans) {
      pushToast(denyMessage, "error");
      return;
    }
    setDialog({
      type: "rerun",
      scan,
      config: {
        type: "rerun",
        icon: "🔁",
        iconClass: "info",
        title: `Re-run ${scanLabel(scan)}?`,
        subtitle:
          "This will start a fresh scan against the same target using the same configuration.",
        meta: [
          ["Target", scan.target],
          ["Type", scanTypeLabel(scan)],
          ["Phase", phaseLabel(scan)],
          ["Last run", fmtDate(getScanDisplayDate(scan))],
        ],
        warning:
          "This action will send live network packets to the target. Only proceed if you have authorisation to scan this host.",
        confirmLabel: "Re-run Scan",
        confirmClass: "rerun",
      },
    });
  };

  /* ── Dialog confirm handlers ── */
  const handleConfirmRerun = async () => {
    if (!canExecuteScans) {
      setDialog(null);
      pushToast(denyMessage, "error");
      return;
    }
    const scan = dialog.scan;
    try {
      // Handle credentialed scans separately
      if (isCred(scan)) {
        resetScan();
        setDialog(null);
        navigate("/scan/credentialed", {
          state: { prefill: { ip: scan.target } },
        });
        return;
      }

      // Extract scan parameters
      const target = scan.target;
      const scanType = scan.scan_type || "adaptive";
      const pipelineMode = scan.pipeline_mode || "basic";
      const targets = getStoredTargets(scan);

      // Build payload with correct phases based on pipeline mode
      const payload = buildPhasePayload(pipelineMode, {
        targets,
        scan_type: scanType,
      });

      // Execute the scan with the same pipeline as the original
      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error || "Re-run failed");

      // Reset context FIRST
      resetScan();

      // Set up context for the new scan session with the ORIGINAL configuration
      setTarget(target);
      setScanType(scanType);
      setPipelineMode(pipelineMode);
      setScanId(data.scan_id);
      setScanNo(data.scan_no ?? data.display_id);

      setDialog(null);

      // Navigate to the "Active Scan" view and tell it to show the mission for this scan
      navigate(`/scan/active/${data.scan_id}`, {
        state: {
          missionMode: true,
          scanId: data.scan_id,
          scanNo: data.scan_no ?? data.display_id,
          target: target,
          pipelineMode: pipelineMode,
        },
      });

      pushToast(`Initiating re-run for ${target}`, "success");
    } catch (err) {
      setDialog(null);
      pushToast(
        "Re-run failed: " + (err.response?.data?.detail || err.message),
        "error",
      );
    }
  };

  const handleConfirmArchive = async (dialogObj) => {
    if (!canArchiveScans) {
      setDialog(null);
      pushToast(denyMessage, "error");
      return;
    }
    const scan = dialogObj?.scan || dialog?.scan;
    if (!scan) return;
    try {
      await archiveScan(scan.id);
      setScans((prev) => prev.filter((s) => s.id !== scan.id));
      setTotal((prev) => Math.max(prev - 1, 0));
      setDialog(null);
      pushToast(
        `${scanLabel(scan)} archived. You can restore it from Archived Scans.`,
        "success",
      );
    } catch {
      setDialog(null);
      pushToast("Failed to archive scan. Please try again.", "error");
    }
  };

  const handleConfirmDelete = async (dialogObj) => {
    if (!canRecycleScans) {
      setDialog(null);
      pushToast(denyMessage, "error");
      return;
    }
    const scan = dialogObj?.scan || dialog?.scan;
    if (!scan) return;
    try {
      await deleteScan(scan.id);
      setScans((prev) => prev.filter((s) => s.id !== scan.id));
      setTotal((prev) => Math.max(prev - 1, 0));
      setDialog(null);
      pushToast(`${scanLabel(scan)} moved to Recycle Bin.`, "info");
    } catch {
      setDialog(null);
      pushToast("Failed to delete scan. Please try again.", "error");
    }
  };

  const handleConfirmStop = async () => {
    if (!canExecuteScans) {
      setDialog(null);
      pushToast(denyMessage, "error");
      return;
    }
    const scan = dialog?.scan;
    if (!scan) return;
    try {
      await stopScan(scan.id);
      setScans((prev) =>
        prev.map((s) => (s.id === scan.id ? { ...s, status: "cancelled" } : s)),
      );
      setDialog(null);
      pushToast(`${scanLabel(scan)} stopped.`, "success");
    } catch (err) {
      setDialog(null);
      pushToast(
        "Failed to stop scan: " + (err.response?.data?.detail || err.message),
        "error",
      );
    }
  };

  const handleDialogConfirm = () => {
    if (!dialog) return;
    if (dialog.type === "rerun") return handleConfirmRerun();
    if (dialog.type === "stop") return handleConfirmStop();
  };

  /* ── Filtering & Pagination ── */
  const now = Date.now();
  const visible = scans.filter((scan) => {
    const status = normalizeStatus(scan.status);
    const isTerminal = TERMINAL_STATUSES.includes(status);

    // 1. Separation logic
    if (isMonitor) {
      if (isTerminal) return false; // Monitor only shows non-terminal
    } else {
      if (!isTerminal) return false; // History only shows terminal
    }

    // 2. Status tab filtering
    if (filterStatus !== "all" && status !== filterStatus) return false;

    // 3. Owner filtering
    if (filterOwner === "mine" && user?.id) {
      if (
        String(scan.created_by) !== String(user.id) &&
        String(scan?.started_by?.user_id) !== String(user.id)
      ) {
        return false;
      }
    }

    // 4. Date filtering
    if (
      filterDate !== "all" &&
      now - dateTimeMs(getScanDisplayDate(scan)) > DATE_MS[filterDate]
    )
      return false;

    return true;
  });

  /* ── Sorting ──
     Column sorting was missing entirely, so a long history could only be read
     newest-first. Values are compared by type so numbers do not sort as text. */
  const SORT_ACCESSORS = {
    scan_no: (s) => s.scan_no ?? s.display_id ?? 0,
    target: (s) => String(s.target || "").toLowerCase(),
    type: (s) => scanTypeLabel(s).toLowerCase(),
    started_by: (s) => getScanStartedByLabel(s, user).toLowerCase(),
    status: (s) => normalizeStatus(s.status),
    active_hosts: (s) => Number(s.summary?.active_hosts ?? 0),
    duration: (s) => Number(s.scan_duration ?? 0),
    date: (s) => dateTimeMs(getScanDisplayDate(s)) || 0,
  };

  const sorted = [...visible].sort((a, b) => {
    const accessor = SORT_ACCESSORS[sort.key] || SORT_ACCESSORS.scan_no;
    const av = accessor(a);
    const bv = accessor(b);
    let cmp;
    if (typeof av === "number" && typeof bv === "number") cmp = av - bv;
    else
      cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
    return sort.dir === "asc" ? cmp : -cmp;
  });

  const toggleSort = (key) => {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { key, dir: key === "target" || key === "type" ? "asc" : "desc" },
    );
    setPage(1);
  };

  const rowsPerPage = preferences?.default_rows_per_page || 10;
  const totalPages = Math.ceil(sorted.length / rowsPerPage) || 1;
  const paginated = sorted.slice((page - 1) * rowsPerPage, page * rowsPerPage);

  // Reset page when filters or total pages change
  useEffect(() => {
    if (page > totalPages) setPage(1);
  }, [totalPages, page]);

  /* ── Presentation ── */
  const openStopDialog = (s) => {
    setDialog({
      type: "stop",
      scan: s,
      config: {
        type: "delete", // Reuse danger style
        icon: "⏹",
        iconClass: "danger",
        title: "Stop Scan?",
        subtitle: `Are you sure you want to terminate ${scanLabel(s)}?`,
        warning:
          "Stopping a scan will immediately terminate all active probes. Any results gathered so far will be saved, but the scan will be marked as cancelled.",
        confirmLabel: "Stop Scan",
        confirmClass: "danger",
      },
    });
  };

  const rowActions = (scan) => {
    const isRunning = normalizeStatus(scan.status) === "running";
    const number = scanNumber(scan);
    return (
      <div className="sh-actions">
        {canReadScans && (
          <CcureButton
            variant="secondary"
            size="sm"
            onClick={() => handleView(scan)}
            title="View scan details"
            aria-label={`View scan ${number}`}
          >
            View
          </CcureButton>
        )}

        {/* Compare — a running scan has no findings to compare yet, and a
            failed one produced none, so the control is offered only where the
            question has an answer. The accessible name carries the scan
            number: every action in this list must be distinguishable across
            rows, or a reader picks the wrong scan's comparison. */}
        {canReadScans && !isRunning && (
          <CcureButton
            variant="secondary"
            size="sm"
            onClick={() =>
              navigate(
                `/scan/comparison?scan_id=${encodeURIComponent(scan.id)}`,
              )
            }
            title="Compare this scan with a previous one"
            aria-label={`Compare scan ${number} with a previous scan`}
          >
            Compare
          </CcureButton>
        )}

        {/* Re-run — disabled for running scans */}
        {canExecuteScans && (
          <CcureButton
            variant="secondary"
            size="sm"
            onClick={() => openRerunDialog(scan)}
            disabled={isRunning}
            title={
              isRunning
                ? "Scan is already running"
                : "Re-run this scan against the same target"
            }
            aria-label={`Re-run scan ${number}`}
          >
            Re-run
          </CcureButton>
        )}

        {/* Archive — disabled for running scans */}
        {canArchiveScans && (
          <CcureButton
            variant="secondary"
            size="sm"
            onClick={() => handleConfirmArchive({ scan })}
            disabled={isRunning}
            title={
              isRunning
                ? "Cannot archive a running scan"
                : "Move to archived scans"
            }
            aria-label={`Archive scan ${number}`}
          >
            Archive
          </CcureButton>
        )}

        {/* Delete */}
        {canRecycleScans && (
          <CcureButton
            variant="danger"
            size="sm"
            onClick={() => handleConfirmDelete({ scan })}
            title="Move to Recycle Bin"
            aria-label={`Delete scan ${number}`}
          >
            Delete
          </CcureButton>
        )}
      </div>
    );
  };

  const columns = [
    {
      key: "scan_no",
      header: "Scan No.",
      sortable: true,
      isRowHeader: true,
      mono: true,
      nowrap: true,
      cell: (scan) => scanNumber(scan),
    },
    {
      key: "target",
      header: "Target",
      sortable: true,
      mono: true,
      cell: (scan) => <span className="sh-target">{scan.target}</span>,
    },
    {
      key: "type",
      header: "Type",
      sortable: true,
      cell: (scan) => (
        <CcureBadge variant="neutral">{scanTypeLabel(scan)}</CcureBadge>
      ),
    },
    {
      key: "started_by",
      header: "Started By",
      sortable: true,
      cell: (scan) => getScanStartedByLabel(scan, user),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      cell: (scan) => (
        <div className="sh-status">
          <CcureScanStatus status={normalizeStatus(scan.status)} />
          <CcureScanProgress
            className="sh-progress"
            value={getScanProgress(scan)}
            status={normalizeStatus(scan.status)}
            label={`Scan ${scanNumber(scan)} progress`}
          />
        </div>
      ),
    },
    {
      key: "active_hosts",
      header: "Active Hosts",
      sortable: true,
      mono: true,
      cell: (scan) => {
        const summary = scan.summary || {};
        return summary.active_hosts !== undefined ? (
          <span className="sh-hosts-count">{summary.active_hosts}</span>
        ) : (
          <span className="sh-muted">—</span>
        );
      },
    },
    {
      key: "duration",
      header: "Duration",
      sortable: true,
      mono: true,
      nowrap: true,
      cell: (scan) => fmtDur(scan.scan_duration),
    },
    {
      key: "date",
      header: "Date",
      sortable: true,
      mono: true,
      nowrap: true,
      cell: (scan) => (
        <span className="sh-muted" title={lifecycleTitle(scan)}>
          {fmtDate(getScanDisplayDate(scan))}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      cell: rowActions,
    },
  ];

  return (
    <AppLayout pageTitle={isMonitor ? "Active Scans" : "Scan History"}>
      <div className="sh-page">
        {/* Page header */}
        <header className="sh-header">
          <div>
            <h1 className="sh-title">
              {isMonitor ? "Active Scans" : "Scan History"}
            </h1>
            <p className="sh-subtitle">
              {isMonitor
                ? `${visible.length} active operation${visible.length !== 1 ? "s" : ""}`
                : `${total} scan${total !== 1 ? "s" : ""} · ${user?.username}`}
            </p>
          </div>
          <div className="sh-header__actions">
            <p
              className={`sh-live sh-live--${liveState}`}
              role="status"
              title={
                lastLiveAt
                  ? `Last update ${lastLiveAt.toLocaleTimeString()}`
                  : ""
              }
            >
              <span className="sh-live__dot" aria-hidden="true" />
              <span>{LIVE_LABELS[liveState]}</span>
            </p>
            <CcureButton
              variant="ghost"
              onClick={() => load()}
              loading={refreshing}
            >
              Sync now
            </CcureButton>
          </div>
        </header>

        {/* Filters */}
        <div className="sh-filters">
          {!isMonitor && (
            <CcureInput
              id="scan-search"
              type="search"
              label="Search"
              fieldClassName="sh-filters__search"
              placeholder="Target IP or scan no…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          )}
          <FilterGroup label="Status">
            {/* "unreachable" is a real terminal outcome the backend sets when
                no target answered. Without a tab for it those scans could
                only be found under "All". */}
            {(isMonitor
              ? ["running"]
              : ["all", "complete", "unreachable", "failed", "cancelled"]
            ).map((s) => (
              <FilterOption
                key={s}
                active={filterStatus === s}
                onClick={() => setFilterStatus(s)}
                disabled={isMonitor}
              >
                {s === "all" ? "All" : STATUS_LABELS[s]}
              </FilterOption>
            ))}
          </FilterGroup>
          {!isMonitor && (
            <FilterGroup label="Owner">
              {["all", "mine"].map((o) => (
                <FilterOption
                  key={o}
                  active={filterOwner === o}
                  onClick={() => setFilterOwner(o)}
                >
                  {o === "all" ? "All scans" : "My scans"}
                </FilterOption>
              ))}
            </FilterGroup>
          )}
          {!isMonitor && (
            <FilterGroup label="Time range">
              {[
                ["all", "All time"],
                ["1h", "1 hr"],
                ["24h", "24 hrs"],
                ["7d", "7 days"],
                ["30d", "30 days"],
              ].map(([v, l]) => (
                <FilterOption
                  key={v}
                  active={filterDate === v}
                  onClick={() => setFilterDate(v)}
                >
                  {l}
                </FilterOption>
              ))}
            </FilterGroup>
          )}
        </div>

        {error && (
          <CcureAlert variant="danger" className="sh-message">
            {error}
          </CcureAlert>
        )}

        {loading && (
          <div className="sh-state">
            <CcureLoader label="Loading scan history…" />
          </div>
        )}

        {!loading && !error && visible.length === 0 && (
          <CcureEmptyState
            icon={isMonitor ? "📡" : "📋"}
            title={
              isMonitor
                ? "No active scans running right now."
                : filterStatus !== "all" || filterDate !== "all"
                  ? "No scans match your filters."
                  : "No scans yet."
            }
            action={
              <CcureButton onClick={() => navigate("/scan")}>
                {isMonitor ? "Launch new scan" : "Start your first scan"}{" "}
                <span aria-hidden="true">→</span>
              </CcureButton>
            }
          />
        )}

        {!loading && visible.length > 0 && isMonitor && (
          <div className="sh-monitor-grid">
            {visible.map((scan) => (
              <ScanMonitorCard
                key={scan.id}
                scan={scan}
                onView={handleView}
                onStop={openStopDialog}
              />
            ))}
          </div>
        )}

        {!loading && visible.length > 0 && !isMonitor && (
          <div className="sh-table">
            <CcureTable
              caption={`Scan history — ${sorted.length} scan${sorted.length !== 1 ? "s" : ""}`}
              columns={columns}
              rows={paginated}
              rowKey={(scan) => scan.id}
              density="comfortable"
              sort={{
                key: sort.key,
                direction: sort.dir === "asc" ? "ascending" : "descending",
              }}
              // The next direction is this page's own rule (text ascending
              // first, numbers and dates descending first), not the table's.
              onSortChange={({ key }) => toggleSort(key)}
            />

            {totalPages > 1 && (
              <CcurePagination
                page={page}
                pageSize={rowsPerPage}
                total={sorted.length}
                onPageChange={setPage}
                label="Scan history pages"
                itemNoun="scans"
              />
            )}
          </div>
        )}

        {sorted.length > 0 && sorted.length < total && totalPages <= 1 && (
          <p className="sh-footnote">
            Showing {sorted.length} of {total} scans
          </p>
        )}
      </div>

      {/* Detail modal */}
      {viewId && (
        <DetailModal
          scanId={viewId}
          onClose={() => setViewId(null)}
          onOpenFullResults={(scan) => {
            setViewId(null);
            navigate(`/scan/${scan.id}/phase1`);
          }}
        />
      )}

      {/* Confirm dialog */}
      {dialog && (
        <ConfirmDialog
          config={dialog.config}
          onConfirm={handleDialogConfirm}
          onCancel={() => setDialog(null)}
        />
      )}

      {/* Toast notifications */}
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
