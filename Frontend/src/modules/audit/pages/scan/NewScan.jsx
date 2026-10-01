/**
 * src/modules/audit/pages/scan/NewScan.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Scan setup page with "Active Mission" view.
 *
 * Checkpoint 3C batch 25 — on the design system. The dispatch, the ticket and
 * progress socket, the 2.5-second read of the scan record, Stop Scan, the
 * automatic hand-off to the next phase, the route-requested start and the
 * target-file import are unchanged, and pinned by
 * src/__tests__/pages/scan/NewScan.contract.test.jsx, written against the page
 * before migration.
 */
import "../../styles/NewScan.css";
import {
  useState,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useId,
} from "react";
import { useNavigate, useLocation, useParams } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useScan, PIPELINE_STATES } from "@audit/context/ScanContext";
import { buildPhasePayload, getScanPipeline } from "@audit/config/scanConfig";
import api from "@shell/api/axiosInstance";
import { stopScan } from "@audit/api/scans";
import { can } from "@shell/auth/permissions";
import { useAuth } from "@shell/auth/AuthContext";
import ScanQuotaBar from "@audit/components/scan/ScanQuotaBar";
import { detectTargetType, parseExcludeIpsJS } from "@audit/utils/ipValidation";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureField,
  CcureInput,
  CcureModal,
  CcureProgress,
  CcureSelect,
  CcureTable,
} from "../../../../design-system";

/* ── Constants ─────────────────────────────────────────────────────────────── */

const DISCOVERY_INTENSITIES = [
  {
    value: "light",
    label: "Light",
    icon: "⚡",
    desc: "Fastest — may miss firewalled hosts",
    badge: "Fastest",
    badgeVariant: "info",
  },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Fast-first with coverage fallback",
    badge: "Recommended",
    badgeVariant: "success",
  },
  {
    value: "deep",
    label: "Deep",
    icon: "🔬",
    desc: "Max coverage — best for firewalled nets",
    badge: "Thorough",
    badgeVariant: "warning",
  },
];

const SCAN_INTENSITIES = [
  {
    value: "light",
    label: "Light",
    icon: "🏃",
    desc: "Fast scan, fewer ports",
  },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Balanced port coverage",
  },
  { value: "deep", label: "Deep", icon: "🔭", desc: "Full port range scan" },
];

const PORT_SCAN_INTENSITIES = [
  { value: "light", label: "Light", icon: "⚡", desc: "Quick top-ports only" },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Balanced port coverage",
  },
  {
    value: "deep",
    label: "Deep",
    icon: "🔭",
    desc: "Full port range — comprehensive",
  },
];

const QUICK_TARGETS = [
  "10.180.4.1",
  "10.180.6.0/24",
  "10.180.6.45",
  "10.180.6.14",
];

const PIPELINE_BADGE = {
  basic: { label: "Basic Scan", variant: "neutral" },
  asset: { label: "Asset Discovery", variant: "info" },
  advanced: { label: "Vulnerability Audit", variant: "warning" },
  vulnerability_audit: {
    label: "Vulnerability Audit",
    variant: "warning",
  },
};

const SENSITIVE_PORTS = [2375, 2376, 6443, 10250];

const PORT_PROFILES = {
  it: {
    label: "IT Infrastructure",
    ports:
      "21,22,23,25,53,67,80,88,110,111,123,135,137,139,143,161,389,443,445,465,587,623,636,902,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,10250,27017",
  },
  scada: {
    label: "SCADA / OT",
    ports:
      "102,502,789,1089,1091,2222,2404,2455,4000,4840,4911,5007,9600,18245,20000,44818,47808,55000,55003",
  },
  web: {
    label: "Web Services",
    ports: "80,443,3000,5000,8000,8080,8443,8888,9000,9090,9443",
  },
  database: {
    label: "Database",
    ports: "1433,1521,3306,5432,6379,9042,9200,27017,28017",
  },
  remote: {
    label: "Remote Access",
    ports: "22,23,3389,5900,5985,5986",
  },
  custom: {
    label: "Custom",
    ports: "",
  },
};

/* ── Helpers ───────────────────────────────────────────────────────────────── */

const fmtTime = (date) =>
  date.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const fmtElapsed = (startMs) => {
  const secs = Math.floor((Date.now() - startMs) / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
};

/* SVG progress ring circumference for r=22 */
const RING_R = 22;
const RING_C = 2 * Math.PI * RING_R; // ≈ 138.23

/* ── Presentation ──────────────────────────────────────────────────────────── */

/* A glyph repeats what its text already says, so assistive technology skips
   it. It stays on screen. */
function Glyph({ children }) {
  return (
    <span className="ns-glyph" aria-hidden="true">
      {children}
    </span>
  );
}

/* The badge tone for each kind of imported target. */
const TARGET_TYPE_VARIANT = {
  IP: "primary",
  CIDR: "info",
  Range: "warning",
  Hostname: "neutral",
};

/* ── HostCard sub-component ─────────────────────────────────────────────────── */

function HostCard({ host, isNew }) {
  const hostname =
    host.hostname && host.hostname !== "Unknown" ? host.hostname : null;
  const mac =
    host.mac_address && host.mac_address !== "N/A" ? host.mac_address : null;

  const isEnrichingHostname = host._enriching_hostname === true;
  const isEnrichingMac = host._enriching_mac === true;

  const hostnameContent = isEnrichingHostname ? (
    <span className="ns-host__resolving">Resolving…</span>
  ) : hostname ? (
    <span>{hostname}</span>
  ) : (
    <span className="ns-muted">—</span>
  );

  const macContent = isEnrichingMac ? (
    <span className="ns-host__resolving">Resolving…</span>
  ) : mac ? (
    <span>{mac}</span>
  ) : (
    <span className="ns-muted">—</span>
  );

  return (
    <li className={`ns-host${isNew ? " ns-host--new" : ""}`}>
      <span className="ns-host__dot" aria-hidden="true" />
      <span className="ns-host__ip" title={host.ip_address}>
        {host.ip_address}
      </span>
      <span className="ns-host__name" title={hostname || ""}>
        {hostnameContent}
      </span>
      <span className="ns-host__mac">{macContent}</span>
    </li>
  );
}

/* ── Active Mission sub-component ──────────────────────────────────────────── */

function ActiveMission({
  scanState,
  onRunInBackground,
  onViewResults,
  onNewScan,
  onCancel,
  cancelling,
}) {
  const { target, scanNo, pipelineMode } = scanState;
  const {
    status,
    progress,
    discovered,
    totalIps,
    discoveredHosts,
    newHostIps,
    startMs,
    error,
  } = scanState;

  const [elapsed, setElapsed] = useState("0s");
  const hostsListRef = useRef(null);
  const hostsTitleId = useId();

  useEffect(() => {
    if (status === "running") {
      const id = setInterval(() => setElapsed(fmtElapsed(startMs)), 1000);
      return () => clearInterval(id);
    }
  }, [status, startMs]);

  useEffect(() => {
    if (hostsListRef.current) {
      hostsListRef.current.scrollTop = hostsListRef.current.scrollHeight;
    }
  }, [discoveredHosts]);

  const pct = Math.max(0, Math.min(100, progress));
  const offset = RING_C - (pct / 100) * RING_C;
  const isRunning = status === "running";
  const isComplete = status === "complete";
  const isCancelled = status === "cancelled" || status === "canceled";
  const isFailed = status === "failed";
  const isUnreachable =
    status === "unreachable" || (isComplete && discovered === 0);

  /* One sentence saying what happened and what to do about it. A live scan
     screen that ends on a stopped spinner and no words is the single thing
     this view was worst at: the operator could not tell a host that was down
     from a scanner that had died. `error` carries the backend's own
     `failure_reason` where there is one, so a timeout explains itself. */
  const outcomeMessage = isFailed
    ? error ||
      "The scan stopped before it finished. Check that the scanner worker is running."
    : isCancelled
      ? error ||
        "Scan cancelled. Any results collected before you stopped it are kept."
      : isUnreachable
        ? `No host responded on ${target || "the requested target"}. The target may be ` +
          "powered off, on a different network, or blocking discovery probes " +
          "(ARP, ICMP and TCP connect were all tried)."
        : "";

  /* `cancelled` is checked before `failed` everywhere below: a scan the
     operator stopped is not a fault, and reporting it in red as "Failed" —
     which is what happened before this branch existed — makes the Stop button
     look like it broke something. */
  const variant = isCancelled
    ? "warning"
    : isFailed
      ? "failed"
      : isUnreachable
        ? "warning"
        : isComplete
          ? "complete"
          : null;
  const badgeLabel = isCancelled
    ? "Cancelled"
    : isFailed
      ? "Failed"
      : isUnreachable
        ? "Unreachable"
        : isComplete
          ? "Complete"
          : "Live Scanning";

  const pipelineLabel =
    {
      basic: "Host Discovery",
      asset: "Asset Discovery",
      advanced: "Vulnerability Audit",
      vulnerability_audit: "Vulnerability Audit",
    }[pipelineMode] || "Scan";

  /* The tone every part of the console takes from the outcome. `variant` is
     null while the scan runs. */
  const tone = variant || "running";
  const badgeVariant = {
    running: "info",
    complete: "success",
    failed: "danger",
    warning: "warning",
  }[tone];
  const progressVariant = {
    running: "primary",
    complete: "success",
    failed: "danger",
    warning: "warning",
  }[tone];

  return (
    <div className={`ns-mission ns-mission--${tone}`}>
      <header className="ns-mission__bar">
        <div className="ns-mission__heading">
          <span className="ns-live-dot" aria-hidden="true" />
          <h1 className="ns-mission__title">Active Mission</h1>
          {scanNo && (
            <CcureBadge variant="neutral" mono>
              #{scanNo}
            </CcureBadge>
          )}
        </div>
        <div className="ns-mission__actions">
          {!isComplete && !isFailed && !isUnreachable && (
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={onRunInBackground}
            >
              <Glyph>📥</Glyph> Run in Background
            </CcureButton>
          )}
          <CcureButton variant="secondary" size="sm" onClick={onNewScan}>
            <Glyph>←</Glyph> New Scan
          </CcureButton>
        </div>
      </header>

      <div className="ns-mission__card">
        <div className="ns-console">
          <div className="ns-console__lead">
            <div className="ns-ring">
              <svg
                className="ns-ring__svg"
                viewBox="0 0 52 52"
                aria-hidden="true"
                focusable="false"
              >
                <circle className="ns-ring__track" cx="26" cy="26" r={RING_R} />
                <circle
                  className="ns-ring__fill"
                  cx="26"
                  cy="26"
                  r={RING_R}
                  strokeDasharray={RING_C}
                  strokeDashoffset={offset}
                />
              </svg>
              <div className="ns-ring__pct" aria-hidden="true">
                {isUnreachable ? "!" : `${pct}%`}
              </div>
            </div>
            <div className="ns-console__info">
              <p className="ns-console__pipeline">{pipelineLabel}</p>
              <p className="ns-console__target">{target}</p>
            </div>
          </div>
          <CcureBadge variant={badgeVariant} className="ns-console__status">
            {isRunning && <span className="ns-spinner" aria-hidden="true" />}
            {badgeLabel}
          </CcureBadge>
        </div>

        {isUnreachable && (
          <CcureAlert
            variant="warning"
            live={false}
            title="Target Unreachable"
            className="ns-unreachable"
          >
            <p className="ns-unreachable__text">
              The host <code className="ns-code">{target}</code> did not respond
              to discovery probes.
            </p>
            <p className="ns-unreachable__text">Possible reasons:</p>
            <ul className="ns-unreachable__list">
              <li>Host is currently powered off.</li>
              <li>Firewall is dropping ICMP/TCP packets.</li>
              <li>Target is in a different network segment.</li>
            </ul>
          </CcureAlert>
        )}

        <CcureProgress
          value={isUnreachable ? 100 : pct}
          label="Scan progress"
          showValue={false}
          variant={progressVariant}
          className="ns-mission__progress"
        />

        <ul className="ns-stats">
          <li className="ns-stat">
            <span
              className={`ns-stat__value${discovered > 0 ? " ns-stat__value--found" : ""}`}
            >
              {discovered}
            </span>{" "}
            <span className="ns-stat__label">Hosts Found</span>
          </li>
          <li className="ns-stat">
            <span className="ns-stat__value ns-stat__value--accent">
              {totalIps || "—"}
            </span>{" "}
            <span className="ns-stat__label">Total IPs</span>
          </li>
          <li className="ns-stat">
            <span className="ns-stat__value">{pct}%</span>{" "}
            <span className="ns-stat__label">Progress</span>
          </li>
          <li className="ns-stat">
            <span className="ns-stat__value">{elapsed}</span>{" "}
            <span className="ns-stat__label">Elapsed</span>
          </li>
        </ul>

        <section className="ns-hosts" aria-labelledby={hostsTitleId}>
          <div className="ns-hosts__header">
            <div className="ns-hosts__heading">
              <h2 id={hostsTitleId} className="ns-hosts__title">
                <Glyph>🖥</Glyph> Discovered Systems
              </h2>
              {discoveredHosts.length > 0 && (
                <CcureBadge variant="primary">
                  {discoveredHosts.length}
                </CcureBadge>
              )}
            </div>
            {isRunning && (
              <div className="ns-hosts__scanning">
                <span className="ns-hosts__pulse" aria-hidden="true" />
                scanning…
              </div>
            )}
          </div>
          {discoveredHosts.length === 0 ? (
            <div className="ns-hosts__empty">
              <div className="ns-radar" aria-hidden="true">
                <span className="ns-radar__ring" />
                <span className="ns-radar__ring" />
                <span className="ns-radar__ring" />
                <span className="ns-radar__dot" />
              </div>
              <p className="ns-hosts__empty-text">
                Scanning subnet… waiting for active hosts.
              </p>
            </div>
          ) : (
            <ul
              className="ns-hosts__list"
              ref={hostsListRef}
              aria-labelledby={hostsTitleId}
            >
              {discoveredHosts.map((h) => (
                <HostCard
                  key={h.ip_address}
                  host={h}
                  isNew={newHostIps.includes(h.ip_address)}
                />
              ))}
            </ul>
          )}
        </section>

        <div className="ns-console__footer">
          <span className="ns-console__elapsed">
            {isRunning
              ? `Elapsed: ${elapsed}`
              : isComplete
                ? "Scan complete"
                : isCancelled
                  ? "Scan cancelled"
                  : "Scan ended"}
          </span>
          <div className="ns-console__actions">
            {isRunning && (
              <CcureButton
                variant="secondary"
                size="sm"
                onClick={onRunInBackground}
              >
                <Glyph>📥</Glyph> Run in Background
              </CcureButton>
            )}
            {/* Stop is only offered while the scan is actually running.
                Offering it on a settled scan invites a click that answers
                "already in a terminal state" and reads as a broken button. */}
            {isRunning && onCancel && (
              <CcureButton
                variant="danger"
                size="sm"
                onClick={onCancel}
                loading={cancelling}
                title="Stop this scan"
              >
                {cancelling ? (
                  "Stopping…"
                ) : (
                  <>
                    <Glyph>⏹</Glyph> Stop Scan
                  </>
                )}
              </CcureButton>
            )}
            {isComplete && (
              <CcureButton size="sm" onClick={onViewResults}>
                View Results <Glyph>→</Glyph>
              </CcureButton>
            )}
            {(isFailed || isCancelled || isUnreachable) && (
              <CcureButton variant="secondary" size="sm" onClick={onNewScan}>
                <Glyph>↩</Glyph> Try Again
              </CcureButton>
            )}
          </div>
        </div>
      </div>
      {(outcomeMessage || error) && (
        <CcureAlert
          variant={isFailed ? "danger" : "warning"}
          className="ns-mission__outcome"
        >
          {outcomeMessage || error}
        </CcureAlert>
      )}
    </div>
  );
}

/* ── Setup building blocks ─────────────────────────────────────────────────── */

/* A labelled set of mutually exclusive choices. Each is a toggle button that
   says whether it is the current one; the description of the current choice
   sits inside the group it describes. */
function ChoiceGroup({
  label,
  hint,
  options,
  value,
  onChange,
  disabled,
  children,
}) {
  const id = useId();
  return (
    <div className="ns-choices" role="group" aria-labelledby={`${id}-label`}>
      <div className="ns-choices__label">
        <span id={`${id}-label`} className="ns-label">
          {label}
        </span>
        {hint ? <span className="ns-hint">{hint}</span> : null}
      </div>
      <div className="ns-segmented">
        {options.map((option) => (
          <CcureButton
            key={option.value}
            variant="secondary"
            size="sm"
            className="ns-segmented__option"
            aria-pressed={value === option.value}
            onClick={() => onChange(option.value)}
            disabled={disabled}
          >
            <Glyph>{option.icon}</Glyph> {option.label}
          </CcureButton>
        ))}
      </div>
      {children}
    </div>
  );
}

/* An option switched on or off: a native checkbox exposed as a switch, named
   by its visible title and described by its hint. What the option reveals
   when on is passed as children, outside the row. */
function OptionRow({
  icon,
  title,
  hint,
  checked,
  onChange,
  disabled,
  status,
  children,
}) {
  const id = useId();
  return (
    <section className="ns-option">
      <div className="ns-option__row">
        <div className="ns-option__text">
          <label htmlFor={id} className="ns-option__title">
            {icon ? <Glyph>{icon}</Glyph> : null} {title}
          </label>
          {hint ? (
            <p id={`${id}-hint`} className="ns-hint">
              {hint}
            </p>
          ) : null}
        </div>
        <div className="ns-option__control">
          <input
            id={id}
            type="checkbox"
            role="switch"
            className="ns-switch"
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            disabled={disabled}
            aria-describedby={hint ? `${id}-hint` : undefined}
          />
          {status ? <span className="ns-option__status">{status}</span> : null}
        </div>
      </div>
      {children}
    </section>
  );
}

const SCAN_MODELS = [
  {
    mode: "intensity",
    icon: "⚡",
    title: "Intensity-Based Scan",
    desc: "Predefined scan depths (Light, Normal, Deep) without selecting individual ports.",
  },
  {
    mode: "port",
    icon: "🔌",
    title: "Port-Based Scan",
    desc: "Select predefined templates (IT, SCADA, Web, Database, Remote) or input custom ports.",
  },
];

/* The port scan model: two cards that are one radio group, so the choice is
   reachable and announced from the keyboard. */
function ScanModelChoice({ value, onChange }) {
  const id = useId();
  return (
    <div className="ns-model" role="radiogroup" aria-labelledby={`${id}-label`}>
      <p id={`${id}-label`} className="ns-label">
        Scan Configuration Model
      </p>
      <div className="ns-model__cards">
        {SCAN_MODELS.map((model) => (
          <label
            key={model.mode}
            className={`ns-model__card${value === model.mode ? " ns-model__card--selected" : ""}`}
          >
            <input
              type="radio"
              name={`${id}-model`}
              value={model.mode}
              className="ns-model__input"
              checked={value === model.mode}
              onChange={() => onChange(model.mode)}
            />
            <span className="ns-model__icon" aria-hidden="true">
              {model.icon}
            </span>
            <span className="ns-model__title">{model.title}</span>
            <span className="ns-model__desc">{model.desc}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

/* The target field, its file picker button and the area a target list can be
   dropped on. The drop area is a convenience: Upload File reaches the same
   reader from the keyboard. */
function TargetField({
  value,
  onChange,
  onKeyDown,
  disabled,
  onBrowse,
  dragging,
  onDragOver,
  onDragLeave,
  onDrop,
}) {
  const id = useId();
  return (
    <div
      className={`ns-drop${dragging ? " ns-drop--active" : ""}`}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
    >
      <CcureField id={id} label="Target" hint="IP, CIDR, or range">
        <div className="ns-drop__row">
          <input
            id={id}
            className="cc-field__control ns-target"
            value={value}
            onChange={onChange}
            onKeyDown={onKeyDown}
            placeholder="10.180.6.0/24   ·   10.180.6.1-50"
            disabled={disabled}
            aria-describedby={`${id}-hint`}
            autoFocus
          />
          <CcureButton
            variant="secondary"
            className="ns-drop__browse"
            onClick={onBrowse}
            disabled={disabled}
          >
            <Glyph>📂</Glyph> Upload File
          </CcureButton>
        </div>
      </CcureField>
    </div>
  );
}

/**
 * CcureModal's own outside-click handling never fires (it reads the React
 * event's currentTarget after dispatch, when React has already cleared it).
 * The legacy settings drawer closed on a click on its backdrop, so the page
 * listens for a click on this dialog's own overlay, as ScanHistory and
 * Phase3Results do.
 */
function useCloseOnOverlayClick(active, dialogClass, onClose) {
  useEffect(() => {
    if (!active) return undefined;
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
  }, [active, dialogClass, onClose]);
}

/* Advanced settings: a modal dialog drawn as a side sheet. Its contents are
   rendered only while it is open; every value lives in the page or the scan
   context, so closing it loses nothing. */
function SettingsDialog({ open, setOpen, children }) {
  const close = useCallback(() => setOpen(false), [setOpen]);
  useCloseOnOverlayClick(open, "ns-settings", close);
  return (
    <CcureModal
      open={open}
      onClose={close}
      title="Advanced Settings"
      size="lg"
      closeLabel="Close settings"
      closeOnOverlayClick={false}
      className="ns-settings"
      footer={<CcureButton onClick={close}>Save & Close</CcureButton>}
    >
      {children}
    </CcureModal>
  );
}

/* ── Main Component ─────────────────────────────────────────────────────────── */

export default function NewScan() {
  const navigate = useNavigate();
  const location = useLocation();
  const { scanId: urlScanId } = useParams();
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");

  const {
    target,
    setTarget,
    pipelineMode,
    intensity,
    setIntensity,
    discoveryIntensity,
    setDiscoveryIntensity,
    osDetection,
    setOsDetection,
    portScanIntensity,
    setPortScanIntensity,
    setPhase1Hosts,
    setPhase1Summary,
    setScanId,
    setScanNo,
    setPipelineState,
    setPipelineMode,
    autoRunAdvancedSingleTarget,
    ctxScanNo,
    executionMode,
    setExecutionMode,
    portScanMode,
    setPortScanMode,
    customPorts,
    setCustomPorts,
    portProfile,
    setPortProfile,
    excludePorts,
    setExcludePorts,
    excludeIps,
    setExcludeIps,
  } = useScan();

  const isActiveRoute = !!urlScanId;
  const [view, setView] = useState(isActiveRoute ? "mission" : "setup");
  const [loading, setLoading] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [error, setError] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [quotaBlocked, setQuotaBlocked] = useState(false);
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [parsedTargets, setParsedTargets] = useState([]);
  const [uploadSummary, setUploadSummary] = useState({
    total: 0,
    valid: 0,
    invalid: 0,
    invalidEntries: [],
    duplicates: 0,
    show: false,
  });
  const [customPortsError, setCustomPortsError] = useState("");
  const [parsedCustomPortsCount, setParsedCustomPortsCount] = useState(0);

  // Authenticated checks — a policy option on the Vulnerability Audit, not a
  // separate scan. Only stored credentials qualify: the pipeline runs
  // unattended, so there is nothing to hold a one-time secret for.
  const [credentialedEnabled, setCredentialedEnabled] = useState(false);
  const [credentialsList, setCredentialsList] = useState([]);
  const [selectedCredIds, setSelectedCredIds] = useState([]);

  // SNMP settings for topology mapping (optional)
  const [snmpEnabled, setSnmpEnabled] = useState(false);
  const [snmpVersion, setSnmpVersion] = useState("v2c");
  const [snmpCommunity, setSnmpCommunity] = useState("public");
  const [snmpUsername, setSnmpUsername] = useState("");
  const [snmpAuthProtocol, setSnmpAuthProtocol] = useState("SHA");
  const [snmpAuthPassphrase, setSnmpAuthPassphrase] = useState("");
  const [snmpPrivProtocol, setSnmpPrivProtocol] = useState("");
  const [snmpPrivPassphrase, setSnmpPrivPassphrase] = useState("");
  const [snmpContextName, setSnmpContextName] = useState("");

  const [excludePortsEnabled, setExcludePortsEnabled] = useState(
    () => !!excludePorts,
  );
  const [excludePortsError, setExcludePortsError] = useState("");
  const [, setParsedExcludePortsCount] = useState(0);
  const [sensitivePortsFound, setSensitivePortsFound] = useState(false);

  const [excludeIpsEnabled, setExcludeIpsEnabled] = useState(
    () => !!excludeIps,
  );
  const [excludeIpsError, setExcludeIpsError] = useState("");

  // Load the org's stored credentials the first time authenticated checks are
  // switched on, rather than on every visit to this page.
  useEffect(() => {
    if (!credentialedEnabled || credentialsList.length) return;
    let cancelled = false;
    api
      .get("/compliance/credentials")
      .then((res) => {
        if (!cancelled) setCredentialsList(res.data || []);
      })
      .catch((err) => {
        console.error("Failed to load credentials for scan", err);
      });
    return () => {
      cancelled = true;
    };
  }, [credentialedEnabled, credentialsList.length]);

  const parseCustomPortsJS = (portsStr) => {
    if (!portsStr || !portsStr.trim()) {
      return { ports: [], error: "", sensitiveFound: false };
    }
    const clean = portsStr.replace(/\s+/g, "");
    if (!/^[0-9,-]+$/.test(clean)) {
      return {
        ports: [],
        error:
          "Invalid characters. Only numbers, commas, and hyphens are allowed.",
        sensitiveFound: false,
      };
    }
    const tokens = clean.split(",");
    const portsSet = new Set();

    for (const token of tokens) {
      if (!token) continue;
      if (token.includes("-")) {
        const rangeParts = token.split("-");
        if (rangeParts.length !== 2) {
          return {
            ports: [],
            error: `Invalid range format: "${token}"`,
            sensitiveFound: false,
          };
        }
        const start = parseInt(rangeParts[0], 10);
        const end = parseInt(rangeParts[1], 10);
        if (isNaN(start) || isNaN(end)) {
          return {
            ports: [],
            error: `Invalid range bounds: "${token}"`,
            sensitiveFound: false,
          };
        }
        if (start > end) {
          return {
            ports: [],
            error: `Range start must be <= end: "${token}"`,
            sensitiveFound: false,
          };
        }
        if (start < 1 || end > 65535) {
          return {
            ports: [],
            error: `Ports must be between 1 and 65535: "${token}"`,
            sensitiveFound: false,
          };
        }
        for (let p = start; p <= end; p++) {
          if (portsSet.has(p)) {
            return {
              ports: [],
              error: `Duplicate port detected: ${p}`,
              sensitiveFound: false,
            };
          }
          portsSet.add(p);
        }
      } else {
        const p = parseInt(token, 10);
        if (isNaN(p)) {
          return {
            ports: [],
            error: `Invalid port number: "${token}"`,
            sensitiveFound: false,
          };
        }
        if (p < 1 || p > 65535) {
          return {
            ports: [],
            error: `Port must be between 1 and 65535: ${p}`,
            sensitiveFound: false,
          };
        }
        if (portsSet.has(p)) {
          return {
            ports: [],
            error: `Duplicate port detected: ${p}`,
            sensitiveFound: false,
          };
        }
        portsSet.add(p);
      }
    }

    const portsArray = Array.from(portsSet);
    const sensitiveFound = portsArray.some((p) => SENSITIVE_PORTS.includes(p));
    return { ports: portsArray, error: "", sensitiveFound };
  };

  const parseExcludePortsJS = (portsStr) => {
    if (!portsStr || !portsStr.trim()) {
      return { ports: [], error: "" };
    }
    const clean = portsStr.replace(/\s+/g, "");
    if (!/^[0-9,-]+$/.test(clean)) {
      return {
        ports: [],
        error:
          "Invalid characters. Only numbers, commas, and hyphens are allowed.",
      };
    }
    const tokens = clean.split(",");
    const portsSet = new Set();

    for (const token of tokens) {
      if (!token) continue;
      if (token.includes("-")) {
        const rangeParts = token.split("-");
        if (rangeParts.length !== 2) {
          return { ports: [], error: `Invalid range format: "${token}"` };
        }
        const start = parseInt(rangeParts[0], 10);
        const end = parseInt(rangeParts[1], 10);
        if (isNaN(start) || isNaN(end)) {
          return { ports: [], error: `Invalid range bounds: "${token}"` };
        }
        if (start > end) {
          return { ports: [], error: `Range start must be <= end: "${token}"` };
        }
        if (start < 1 || end > 65535) {
          return {
            ports: [],
            error: `Ports must be between 1 and 65535: "${token}"`,
          };
        }
        for (let p = start; p <= end; p++) {
          if (portsSet.has(p)) {
            return { ports: [], error: `Duplicate port detected: ${p}` };
          }
          portsSet.add(p);
        }
      } else {
        const p = parseInt(token, 10);
        if (isNaN(p)) {
          return { ports: [], error: `Invalid port number: "${token}"` };
        }
        if (p < 1 || p > 65535) {
          return { ports: [], error: `Port must be between 1 and 65535: ${p}` };
        }
        if (portsSet.has(p)) {
          return { ports: [], error: `Duplicate port detected: ${p}` };
        }
        portsSet.add(p);
      }
    }

    const portsArray = Array.from(portsSet);
    return { ports: portsArray, error: "" };
  };

  const handleCustomPortsChange = (val) => {
    setCustomPorts(val);
    const { ports, error, sensitiveFound } = parseCustomPortsJS(val);
    setCustomPortsError(error);
    setParsedCustomPortsCount(ports.length);
    setSensitivePortsFound(sensitiveFound);
  };

  const handleExcludeToggleChange = (checked) => {
    setExcludePortsEnabled(checked);
    if (!checked) {
      setExcludePorts("");
    }
  };

  const handleExcludeIpsToggleChange = (checked) => {
    setExcludeIpsEnabled(checked);
    if (!checked) {
      setExcludeIps("");
    }
  };

  useEffect(() => {
    if (excludeIps) {
      const { error } = parseExcludeIpsJS(excludeIps);
      setExcludeIpsError(error);
    } else {
      setExcludeIpsError("");
    }
  }, [excludeIps]);

  const excludeTokens = excludePorts
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  const handleRemoveExcludeToken = (tokenToRemove) => {
    const updatedTokens = excludeTokens.filter((t) => t !== tokenToRemove);
    setExcludePorts(updatedTokens.join(", "));
  };

  const getPreviewData = () => {
    const isPortMode = portScanMode === "port";
    let typeLabel = isPortMode ? "Port-Based Scan" : "Intensity-Based Scan";
    let targetPortsLabel = "";
    let finalCount = "";

    if (isPortMode) {
      const profileLabel = PORT_PROFILES[portProfile]?.label || "Custom";
      targetPortsLabel = `${profileLabel}`;
      if (portProfile === "custom") {
        finalCount = `${parsedCustomPortsCount} custom port${parsedCustomPortsCount !== 1 ? "s" : ""}`;
      } else {
        const baseCount = PORT_PROFILES[portProfile]?.ports
          ? PORT_PROFILES[portProfile].ports.split(",").length
          : 0;
        finalCount = `${baseCount} port${baseCount !== 1 ? "s" : ""}`;
      }
    } else {
      const depthLabel =
        { light: "Light Scan", normal: "Normal Scan", deep: "Deep Scan" }[
          portScanIntensity
        ] || "Normal Scan";
      targetPortsLabel = depthLabel;
      finalCount =
        {
          light: "Top 100 ports",
          normal: "Top 1000 ports",
          deep: "All 65535 ports",
        }[portScanIntensity] || "Top 1000 ports";
    }

    let excludedLabel = "None";
    if (excludePortsEnabled && excludePorts.trim()) {
      const { ports, error } = parseExcludePortsJS(excludePorts);
      if (!error && ports.length > 0) {
        excludedLabel = `${ports.join(", ")} (${ports.length} port${ports.length !== 1 ? "s" : ""})`;
      } else if (error) {
        excludedLabel = "Invalid exclude ports string";
      }
    }

    return { typeLabel, targetPortsLabel, finalCount, excludedLabel };
  };

  const preview = getPreviewData();

  useEffect(() => {
    if (pipelineMode !== "asset" || portScanMode !== "port") {
      setCustomPortsError("");
      setParsedCustomPortsCount(0);
      setSensitivePortsFound(false);
      return;
    }
    const activePortsStr =
      portProfile === "custom"
        ? customPorts
        : PORT_PROFILES[portProfile]?.ports || "";
    if (activePortsStr) {
      const { ports, error, sensitiveFound } =
        parseCustomPortsJS(activePortsStr);
      setCustomPortsError(error);
      setParsedCustomPortsCount(ports.length);
      setSensitivePortsFound(sensitiveFound);
    } else {
      setCustomPortsError("");
      setParsedCustomPortsCount(0);
      setSensitivePortsFound(false);
    }
  }, [pipelineMode, portScanMode, portProfile, customPorts]);

  useEffect(() => {
    if (excludePorts) {
      const { ports, error } = parseExcludePortsJS(excludePorts);
      setExcludePortsError(error);
      setParsedExcludePortsCount(ports.length);
    } else {
      setExcludePortsError("");
      setParsedExcludePortsCount(0);
    }
  }, [excludePorts]);

  const [missionState, setMissionState] = useState({
    status: "running",
    progress: 0,
    discovered: 0,
    totalIps: 0,
    discoveredHosts: [],
    newHostIps: [],
    startMs: Date.now(),
    error: "",
    scanId: null,
    scanNo: null,
  });
  const missionScanIdRef = useRef(null);
  const pollHostsRef = useRef(null);
  const hostFirstSeenRef = useRef(new Map());
  const latestDiscoveredHostsRef = useRef([]);

  const pipeline = getScanPipeline(pipelineMode || "basic");
  const badgeMeta = PIPELINE_BADGE[pipelineMode] || PIPELINE_BADGE.basic;
  const btnLabel =
    pipelineMode === "asset"
      ? `Start Discovery · ${discoveryIntensity || "normal"}`
      : "Start Scan";

  const stopHostPolling = useCallback(() => {
    if (pollHostsRef.current) {
      clearInterval(pollHostsRef.current);
      pollHostsRef.current = null;
    }
  }, []);

  /* Statuses that mean the scan is over, whatever the WebSocket has or has
     not delivered. */
  const TERMINAL_SCAN_STATUSES = useMemo(
    () => [
      "complete",
      "completed",
      "failed",
      "cancelled",
      "canceled",
      "unreachable",
    ],
    [],
  );

  const startHostPolling = useCallback(
    (scanId) => {
      if (pollHostsRef.current) clearInterval(pollHostsRef.current);
      pollHostsRef.current = setInterval(async () => {
        try {
          const { data: scan } = await api.get(`/scans/${scanId}`);

          /* The scan's own status is read on every tick, and this is a safety
           net rather than a duplicate of the WebSocket.

           The mission view used to reach a terminal state *only* through the
           progress socket. A task that died without publishing a final frame
           -- a killed worker, a failure inside its own error handler, a
           dropped socket -- left this screen showing "LIVE SCANNING" until a
           600s client-side timeout fired, and that timeout then reported the
           scan as complete. Polling the status means the UI is correct within
           one tick no matter what happened to the socket. */
          const st = (scan?.status || "").toLowerCase();
          if (TERMINAL_SCAN_STATUSES.includes(st)) {
            stopHostPolling();
            const finalHosts = (scan?.results?.phase1?.data || []).filter(
              (h) => h.is_active,
            );
            setMissionState((prev) => ({
              ...prev,
              status: st === "completed" ? "complete" : st,
              progress: 100,
              discovered: finalHosts.length || prev.discovered,
              discoveredHosts: finalHosts.length
                ? finalHosts
                : prev.discoveredHosts,
              error: scan?.failure_reason || prev.error,
            }));
            return;
          }

          const hosts = (scan?.results?.phase1?.data || []).filter(
            (h) => h.is_active,
          );
          if (!hosts.length) return;
          const now = fmtTime(new Date());
          hosts.forEach((h) => {
            if (!hostFirstSeenRef.current.has(h.ip_address))
              hostFirstSeenRef.current.set(h.ip_address, now);
          });
          const enriched = hosts.map((h) => ({
            ...h,
            _seenAt: hostFirstSeenRef.current.get(h.ip_address),
            _enriching_hostname: !h.hostname || h.hostname === "Unknown",
            _enriching_mac: !h.mac_address || h.mac_address === "N/A",
          }));
          latestDiscoveredHostsRef.current = enriched;
          setMissionState((prev) => {
            const existingIps = new Set(
              prev.discoveredHosts.map((x) => x.ip_address),
            );
            const newOnes = enriched
              .filter((h) => !existingIps.has(h.ip_address))
              .map((h) => h.ip_address);
            if (newOnes.length > 0)
              setTimeout(
                () => setMissionState((p) => ({ ...p, newHostIps: [] })),
                3000,
              );
            return {
              ...prev,
              discoveredHosts: enriched,
              newHostIps: newOnes,
              discovered: enriched.length,
            };
          });
        } catch {
          /* ignore */
        }
      }, 2500);
    },
    [TERMINAL_SCAN_STATUSES, stopHostPolling],
  );

  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");
  const listenForProgress = useCallback(
    async (scanId) => {
      let ticket;
      try {
        const res = await api.post("/auth/ticket");
        ticket = res.data.ticket;
      } catch {
        return null;
      }
      return new Promise((resolve) => {
        const ws = new WebSocket(
          `${wsPrefix}/scans/${scanId}/progress?ticket=${encodeURIComponent(ticket)}`,
        );
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            const prog = data.progress || {};
            setMissionState((prev) => {
              const next = {
                ...prev,
                totalIps: prog.total_ips ?? prev.totalIps,
                progress:
                  prog.status === "complete" || prog.status === "unreachable"
                    ? 100
                    : prog.status === "failed"
                      ? prev.progress
                      : Math.max(
                          prev.progress,
                          Math.round(
                            ((prog.discovered || 0) /
                              Math.max(prog.total_ips || 1, 1)) *
                              85,
                          ),
                        ),
              };
              const incomingHosts = prog.hosts;
              if (Array.isArray(incomingHosts) && incomingHosts.length > 0) {
                const now = fmtTime(new Date());
                if (prog.status === "enriching") {
                  const patchMap = new Map(
                    incomingHosts.map((h) => [h.ip_address, h]),
                  );
                  const merged = prev.discoveredHosts.map((existing) => {
                    const patch = patchMap.get(existing.ip_address);
                    if (!patch) return existing;
                    const updated = {
                      ...existing,
                      hostname:
                        patch.hostname && patch.hostname !== "Unknown"
                          ? patch.hostname
                          : existing.hostname,
                      mac_address:
                        patch.mac_address && patch.mac_address !== "N/A"
                          ? patch.mac_address
                          : existing.mac_address,
                      vendor:
                        patch.vendor && patch.vendor !== "Unknown"
                          ? patch.vendor
                          : existing.vendor,
                    };
                    if (patch.hostname !== undefined)
                      updated._enriching_hostname = false;
                    if (patch.mac_address !== undefined)
                      updated._enriching_mac = false;
                    return updated;
                  });
                  const existingIps = new Set(
                    prev.discoveredHosts.map((x) => x.ip_address),
                  );
                  const brandNew = incomingHosts
                    .filter((h) => !existingIps.has(h.ip_address))
                    .map((h) => ({
                      ...h,
                      _seenAt:
                        hostFirstSeenRef.current.get(h.ip_address) || now,
                      _enriching_hostname: false,
                      _enriching_mac: false,
                    }));
                  next.discoveredHosts = [...merged, ...brandNew];
                  next.discovered = next.discoveredHosts.length;
                  latestDiscoveredHostsRef.current = next.discoveredHosts;
                } else {
                  incomingHosts.forEach((h) => {
                    if (!hostFirstSeenRef.current.has(h.ip_address))
                      hostFirstSeenRef.current.set(h.ip_address, now);
                  });
                  const enriched = incomingHosts.map((h) => ({
                    ...h,
                    _seenAt: hostFirstSeenRef.current.get(h.ip_address),
                    _enriching_hostname:
                      !h.hostname || h.hostname === "Unknown",
                    _enriching_mac: !h.mac_address || h.mac_address === "N/A",
                  }));
                  const existingIps = new Set(
                    prev.discoveredHosts.map((x) => x.ip_address),
                  );
                  const newIps = enriched
                    .filter((h) => !existingIps.has(h.ip_address))
                    .map((h) => h.ip_address);
                  if (newIps.length > 0)
                    setTimeout(
                      () => setMissionState((p) => ({ ...p, newHostIps: [] })),
                      3000,
                    );
                  next.discoveredHosts = enriched;
                  next.discovered = enriched.length;
                  next.newHostIps = newIps;
                  latestDiscoveredHostsRef.current = next.discoveredHosts;
                }
              }
              return next;
            });
            if (
              prog.status === "complete" ||
              prog.status === "failed" ||
              prog.status === "unreachable" ||
              data.phase > 1
            ) {
              ws.close();
              resolve({ status: prog.status || "complete" });
            }
          } catch {
            /* ignore */
          }
        };
        ws.onerror = () => {
          ws.close();
          resolve({ status: "unknown" });
        };
        setTimeout(() => {
          if (ws.readyState === WebSocket.OPEN) ws.close();
          resolve({ status: "timeout" });
        }, 600000);
      });
    },
    [wsPrefix],
  );

  /* ── Strict Target Validation Helpers ──────────────────────────────────────── */

  /* The `accept` attribute on the <input> is a picker hint and nothing more:
     it does not apply to drag-and-drop, and the drop zone below feeds the same
     function. These guards are the ones that actually run on every path.

     Nothing here is a security boundary — the file never leaves the browser,
     and only the extracted target strings are POSTed, which the API
     re-validates from scratch. This is about not handing the operator
     "No valid targets found." when the real answer is "that is a .zip", and
     not calling readAsText() on something large enough to hang the tab. */
  const MAX_TARGET_FILE_BYTES = 5 * 1024 * 1024;
  const ACCEPTED_TARGET_EXTENSIONS = [".txt", ".csv"];

  const processFile = (file) => {
    if (!file) return;

    const name = (file.name || "").toLowerCase();
    if (!ACCEPTED_TARGET_EXTENSIONS.some((ext) => name.endsWith(ext))) {
      setError(
        `Unsupported file format: ${file.name || "unnamed file"}. ` +
          `Upload a ${ACCEPTED_TARGET_EXTENSIONS.join(" or ")} file with one target per line.`,
      );
      return;
    }

    if (file.size === 0) {
      setError(`${file.name} is empty — no targets to import.`);
      return;
    }

    if (file.size > MAX_TARGET_FILE_BYTES) {
      setError(
        `${file.name} is ${(file.size / (1024 * 1024)).toFixed(1)} MB, above the ` +
          `${MAX_TARGET_FILE_BYTES / (1024 * 1024)} MB limit for a target list.`,
      );
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => {
      setError(`Could not read ${file.name}.`);
    };
    reader.onload = (event) => {
      const rawTokens = event.target.result
        .replace(/\s*-\s*/g, "-")
        .split(/[,\s;]+/)
        .map((t) => t.trim())
        .filter(Boolean);

      const valid = [];
      const inv = [];
      const seen = new Set();
      let dups = 0;

      rawTokens.forEach((t) => {
        const clean = t.replace(/[^\w.:/[\]-]/g, "");
        if (
          !clean ||
          clean.toLowerCase() === "target" ||
          clean.toLowerCase() === "ipaddress"
        )
          return;
        if (seen.has(clean)) {
          dups++;
          return;
        }

        const type = detectTargetType(clean);
        if (type) {
          valid.push({ value: clean, type });
          seen.add(clean);
        } else {
          inv.push(clean);
        }
      });

      if (valid.length > 0) {
        setError("");
        setTarget(valid.map((r) => r.value).join(", "));
        setParsedTargets(valid);
        setUploadSummary({
          total: valid.length + inv.length + dups,
          valid: valid.length,
          invalid: inv.length,
          invalidEntries: inv,
          duplicates: dups,
          show: true,
        });
      } else {
        setError(
          `No valid targets found in ${file.name}. Expected one IP, CIDR or range per line.`,
        );
      }
    };
    reader.readAsText(file);
  };

  const handleRemoveTarget = (indexToRemove) => {
    const updatedParsed = parsedTargets.filter(
      (_, idx) => idx !== indexToRemove,
    );
    setParsedTargets(updatedParsed);

    const updatedTargetString = updatedParsed.map((pt) => pt.value).join(", ");
    setTarget(updatedTargetString);

    setUploadSummary((prev) => {
      const newValid = Math.max(0, prev.valid - 1);
      const newTotal = Math.max(0, prev.total - 1);
      return {
        ...prev,
        total: newTotal,
        valid: newValid,
        show: newValid > 0,
      };
    });
  };

  const handleScan = async () => {
    if (!canExecuteScans || !target.trim()) return;
    const trimmedTarget = target.trim();

    if (pipelineMode === "asset") {
      if (portScanMode === "port") {
        const activePortsStr =
          portProfile === "custom"
            ? customPorts
            : PORT_PROFILES[portProfile]?.ports || "";
        if (!activePortsStr || !activePortsStr.trim()) {
          setError("Ports list cannot be empty.");
          return;
        }
        const { error } = parseCustomPortsJS(activePortsStr);
        if (error) {
          setError(error);
          return;
        }
      }
    }

    if (excludePortsEnabled && excludePorts.trim()) {
      const { error } = parseExcludePortsJS(excludePorts);
      if (error) {
        setError(`Exclude ports error: ${error}`);
        return;
      }
    }

    if (excludeIpsEnabled && excludeIps.trim()) {
      const { error } = parseExcludeIpsJS(excludeIps);
      if (error) {
        setError(`Exclude IPs error: ${error}`);
        return;
      }
    }

    hostFirstSeenRef.current = new Map();
    latestDiscoveredHostsRef.current = [];
    setMissionState({
      status: "running",
      progress: 5,
      discovered: 0,
      totalIps: 0,
      discoveredHosts: [],
      newHostIps: [],
      startMs: Date.now(),
      error: "",
      scanId: null,
      scanNo: null,
    });
    setView("mission");
    setLoading(true);
    setPipelineState(PIPELINE_STATES.DISCOVERY);
    try {
      const scanOptions = {
        ...(snmpEnabled
          ? {
              snmp: {
                version: snmpVersion,
                ...(snmpVersion !== "v3" ? { community: snmpCommunity } : {}),
                ...(snmpVersion === "v3"
                  ? {
                      username: snmpUsername,
                      auth_protocol: snmpAuthProtocol,
                      auth_passphrase: snmpAuthPassphrase,
                      ...(snmpPrivProtocol
                        ? {
                            priv_protocol: snmpPrivProtocol,
                            priv_passphrase: snmpPrivPassphrase,
                          }
                        : {}),
                      ...(snmpContextName
                        ? { context_name: snmpContextName }
                        : {}),
                    }
                  : {}),
              },
            }
          : {}),
        ...(credentialedEnabled && selectedCredIds.length
          ? {
              credentials: selectedCredIds.map((id) => ({
                credential_id: id,
              })),
            }
          : {}),
      };
      const hasScanOptions = Object.keys(scanOptions).length > 0;

      const payload = buildPhasePayload(pipelineMode || "basic", {
        targets: trimmedTarget
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        scan_type: "adaptive",
        execution_mode: executionMode,
        ...(pipelineMode === "asset"
          ? { discovery_intensity: discoveryIntensity }
          : {}),
        ...(pipelineMode === "asset"
          ? {
              port_scan_intensity:
                portScanMode === "port" ? "custom" : portScanIntensity,
              ...(portScanMode === "port"
                ? {
                    custom_ports:
                      portProfile === "custom"
                        ? customPorts
                        : PORT_PROFILES[portProfile].ports,
                  }
                : {}),
            }
          : {}),
        ...(pipelineMode === "asset" ||
        pipelineMode === "advanced" ||
        pipelineMode === "vulnerability_audit"
          ? { os_detection: osDetection }
          : {}),
        ...(excludePorts && excludePorts.trim()
          ? { exclude_ports: excludePorts.trim() }
          : {}),
        ...(excludeIps && excludeIps.trim()
          ? { exclude_ips: excludeIps.trim() }
          : {}),
        ...(rateLimit ? { rate_limit: parseInt(rateLimit, 10) } : {}),
        // SNMP and credentials both live under `options`, so they are merged
        // into one object — sending them as separate `options` keys would let
        // whichever came last silently discard the other.
        ...(hasScanOptions ? { options: scanOptions } : {}),
      });
      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error);
      const sid = data.scan_id,
        sno = data.scan_no ?? data.display_id;

      navigate(`/scan/active/${sid}`, {
        replace: true,
        state: {
          missionMode: true,
          scanId: sid,
          scanNo: sno,
          target: trimmedTarget,
          pipelineMode: pipelineMode || "basic",
        },
      });
    } catch (err) {
      stopHostPolling();
      setMissionState((prev) => ({
        ...prev,
        status: "failed",
        error: err.message,
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleRunInBackground = useCallback(
    () => navigate("/scan-history"),
    [navigate],
  );

  const [cancelling, setCancelling] = useState(false);
  const handleCancelScan = useCallback(async () => {
    const id = missionScanIdRef.current;
    if (!id || cancelling) return;
    setCancelling(true);
    try {
      await stopScan(id);
      /* The backend has committed status='cancelled' and published a terminal
         frame. It does *not* wait for the worker: `revoke(terminate=True)`
         cannot kill a running thread on the host worker's threads pool, so the
         task stops at its next cooperative cancellation checkpoint. Reflecting
         it here immediately is honest -- the scan is cancelled as a matter of
         record from this moment, whatever the probe in flight does. */
      setMissionState((prev) => ({
        ...prev,
        status: "cancelled",
        error: "Scan cancelled by user.",
      }));
      stopHostPolling();
    } catch (e) {
      setMissionState((prev) => ({
        ...prev,
        error:
          e?.response?.data?.detail ||
          "Could not cancel the scan. It may have already finished.",
      }));
    } finally {
      setCancelling(false);
    }
  }, [cancelling, stopHostPolling]);
  const handleViewResults = useCallback(() => {
    if (executionMode === "interactive") {
      navigate("/scan/host-discovery");
      return;
    }
    if (pipelineMode === "asset") {
      navigate("/scan/asset-discovery");
      return;
    }
    if (
      (pipelineMode === "advanced" || pipelineMode === "vulnerability_audit") &&
      autoRunAdvancedSingleTarget
    ) {
      navigate("/scan/vulnerability-audit", {
        state: { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" },
      });
      return;
    }
    navigate(
      pipelineMode === "advanced" || pipelineMode === "vulnerability_audit"
        ? "/scan/vulnerability-audit"
        : "/scan/host-discovery",
    );
  }, [navigate, pipelineMode, autoRunAdvancedSingleTarget, executionMode]);

  const handleNewScan = useCallback(() => {
    stopHostPolling();
    navigate("/scan/new");
    setView("setup");
    setMissionState({
      status: "running",
      progress: 0,
      discovered: 0,
      totalIps: 0,
      discoveredHosts: [],
      newHostIps: [],
      startMs: Date.now(),
      error: "",
      scanId: null,
      scanNo: null,
    });
    setLoading(false);
  }, [stopHostPolling, navigate]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        setShowAdvanced(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const hasAutoRunRef = useRef(false);

  // Everything this bootstrap calls that is rebuilt each render — the scan
  // context's session-storage-backed setters, the polling helpers, and
  // `handleScan` — is reached through a ref rather than named as a dependency.
  // It is a one-shot: both branches latch `hasAutoRunRef`, so re-running it is
  // pure waste, and listing those values made it re-run on literally every
  // render. The dependency array below now holds exactly the values that decide
  // *whether* the bootstrap should fire.
  const bootstrapRef = useRef(null);
  bootstrapRef.current = {
    setTarget,
    setPipelineMode,
    setScanId,
    setScanNo,
    setPhase1Hosts,
    setPhase1Summary,
    startHostPolling,
    listenForProgress,
    stopHostPolling,
    handleScan,
    executionMode,
  };

  useEffect(() => {
    const boot = bootstrapRef.current;
    const effectiveScanId = location.state?.scanId || urlScanId;
    const isMission = location.state?.missionMode || !!urlScanId;

    if (isMission && !hasAutoRunRef.current && effectiveScanId) {
      hasAutoRunRef.current = true;
      const {
        scanNo,
        target: rt,
        pipelineMode: rm,
      } = location.state || { scanId: effectiveScanId };

      setView("mission");
      setMissionState((prev) => ({
        ...prev,
        scanId: effectiveScanId,
        scanNo: scanNo || prev.scanNo,
        status: "running",
        progress: 10,
        startMs: Date.now(),
      }));
      missionScanIdRef.current = effectiveScanId;
      if (rt) boot.setTarget(rt);
      if (rm) boot.setPipelineMode(rm);
      boot.setScanId(effectiveScanId);
      if (scanNo) boot.setScanNo(scanNo);

      boot.startHostPolling(effectiveScanId);
      boot.listenForProgress(effectiveScanId).then((res) => {
        boot.stopHostPolling();
        /* `timeout` and `unknown` are what the socket reports when it gave up
           or errored -- they are not outcomes, and mapping them to "complete"
           (which is what this did) told the operator a scan had finished
           successfully when in fact nothing had been heard from it for ten
           minutes. The scan record is the authority, so those two cases fall
           through to whatever the API says below. */
        const wsStatus = res?.status;
        const KNOWN = ["failed", "unreachable", "cancelled", "canceled"];
        api.get(`/scans/${effectiveScanId}`).then(({ data: f }) => {
          const apiStatus = (f?.status || "").toLowerCase();
          const fs = KNOWN.includes(apiStatus)
            ? apiStatus === "canceled"
              ? "cancelled"
              : apiStatus
            : apiStatus === "complete" || apiStatus === "completed"
              ? "complete"
              : KNOWN.includes(wsStatus)
                ? wsStatus
                : "complete";
          const d =
              f?.results?.phase1?.data || latestDiscoveredHostsRef.current,
            active = d.filter((h) => h.is_active);
          bootstrapRef.current.setPhase1Hosts(d);
          bootstrapRef.current.setPhase1Summary(
            f?.results?.phase1?.summary || {},
          );
          setMissionState((prev) => ({
            ...prev,
            status: fs,
            progress: fs === "complete" ? 100 : prev.progress,
            discovered: active.length,
            discoveredHosts: active,
            error: f?.failure_reason || prev.error,
          }));
          if (fs === "complete" && (rm || f?.pipeline_mode) !== "basic") {
            if (
              ((rm || f?.pipeline_mode) === "advanced" ||
                (rm || f?.pipeline_mode) === "vulnerability_audit") &&
              active.length === 1
            )
              navigate("/scan/vulnerability-audit", {
                replace: true,
                state: {
                  autoRunAdvancedSingleTarget: true,
                  startPhase: "PORT_SCAN",
                },
              });
            else {
              if (bootstrapRef.current.executionMode === "interactive") {
                navigate("/scan/host-discovery", { replace: true });
              } else {
                navigate("/scan/asset-discovery", { replace: true });
              }
            }
          }
        });
      });

      // Clean up state but stay on the active URL
      if (location.state?.missionMode) {
        navigate(`/scan/active/${effectiveScanId}`, {
          replace: true,
          state: {},
        });
      }
    } else if (
      location.state?.autoRun &&
      !hasAutoRunRef.current &&
      canExecuteScans &&
      target &&
      !loading &&
      !quotaBlocked
    ) {
      hasAutoRunRef.current = true;
      navigate(".", { replace: true, state: {} });
      setTimeout(() => bootstrapRef.current.handleScan(), 100);
    }
  }, [
    location.state,
    urlScanId,
    canExecuteScans,
    target,
    loading,
    quotaBlocked,
    navigate,
  ]);

  if (view === "mission")
    return (
      <AppLayout pageTitle="Active Scan Mission">
        <ActiveMission
          scanState={{
            ...missionState,
            target,
            scanNo: missionState.scanNo ?? ctxScanNo,
            pipelineMode: pipelineMode || "basic",
          }}
          onRunInBackground={handleRunInBackground}
          onViewResults={handleViewResults}
          onNewScan={handleNewScan}
          onCancel={handleCancelScan}
          cancelling={cancelling}
        />
      </AppLayout>
    );

  return (
    <AppLayout pageTitle="New Scan">
      <div className="ns-page">
        <header className="ns-hero">
          <CcureButton
            variant="ghost"
            size="sm"
            className="ns-back"
            onClick={() => navigate("/audit-dashboard")}
          >
            <Glyph>←</Glyph> Back
          </CcureButton>
          <CcureBadge variant={badgeMeta.variant} className="ns-hero__badge">
            {badgeMeta.label}
          </CcureBadge>
          <h1 className="ns-title">{pipeline.label}</h1>
          <p className="ns-sub">{pipeline.description}</p>
        </header>
        <ScanQuotaBar
          onQuotaChange={({ quota_exceeded, concurrent_exceeded }) =>
            setQuotaBlocked(quota_exceeded || concurrent_exceeded)
          }
        />
        <div className="ns-card">
          <section className="ns-section">
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => processFile(e.target.files[0])}
              accept=".txt,.csv"
              hidden
              aria-label="Target list file"
            />
            <TargetField
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                if (uploadSummary.show)
                  setUploadSummary((p) => ({ ...p, show: false }));
                if (parsedTargets.length) setParsedTargets([]);
              }}
              onKeyDown={(e) =>
                e.key === "Enter" && canExecuteScans && !loading && handleScan()
              }
              disabled={loading || !canExecuteScans}
              onBrowse={() => fileInputRef.current.click()}
              dragging={isDragging}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (e.dataTransfer.files?.length)
                  processFile(e.dataTransfer.files[0]);
              }}
            />
            {uploadSummary.show && (
              <div className="ns-import">
                <div className="ns-import__content">
                  <ul className="ns-import__stats" aria-label="Import summary">
                    <li>
                      Total: <strong>{uploadSummary.total}</strong>
                    </li>
                    <li className="ns-import__stat--valid">
                      Valid: <strong>{uploadSummary.valid}</strong>
                    </li>
                    {uploadSummary.invalid > 0 && (
                      <li className="ns-import__stat--invalid">
                        Invalid: <strong>{uploadSummary.invalid}</strong>
                      </li>
                    )}
                    {uploadSummary.duplicates > 0 && (
                      <li className="ns-import__stat--dup">
                        Duplicates: <strong>{uploadSummary.duplicates}</strong>
                      </li>
                    )}
                  </ul>
                  {uploadSummary.invalid > 0 && (
                    <p className="ns-import__hint">
                      Some invalid entries were ignored.
                      <CcureButton
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          const blob = new Blob(
                            [uploadSummary.invalidEntries.join("\n")],
                            { type: "text/plain" },
                          );
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = "invalid_targets.txt";
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        <Glyph>📥</Glyph> Export Invalid
                      </CcureButton>
                    </p>
                  )}
                </div>
                <CcureButton
                  variant="ghost"
                  size="sm"
                  className="ns-import__close"
                  aria-label="Dismiss import summary"
                  onClick={() => {
                    setUploadSummary((p) => ({ ...p, show: false }));
                    setParsedTargets([]);
                  }}
                >
                  <Glyph>×</Glyph>
                </CcureButton>
              </div>
            )}

            {/* Target List Preview Grid */}
            {parsedTargets.length > 0 && (
              <div className="ns-preview">
                <div className="ns-preview__header">
                  <p className="ns-label">Target List Preview</p>
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setParsedTargets([]);
                      setTarget("");
                      setUploadSummary((p) => ({ ...p, show: false }));
                    }}
                  >
                    Clear Targets
                  </CcureButton>
                </div>
                <CcureTable
                  caption="Imported targets"
                  density="compact"
                  rows={parsedTargets.map((pt, idx) => ({ ...pt, idx }))}
                  rowKey={(row) => row.idx}
                  columns={[
                    {
                      key: "idx",
                      header: "#",
                      cell: (row) => row.idx + 1,
                    },
                    {
                      key: "value",
                      header: "Target Value",
                      isRowHeader: true,
                      mono: true,
                    },
                    {
                      key: "type",
                      header: "Type",
                      cell: (row) => (
                        <CcureBadge
                          variant={TARGET_TYPE_VARIANT[row.type] || "neutral"}
                        >
                          {row.type}
                        </CcureBadge>
                      ),
                    },
                    {
                      key: "actions",
                      header: "Actions",
                      align: "end",
                      cell: (row) => (
                        <CcureButton
                          variant="ghost"
                          size="sm"
                          className="ns-remove"
                          onClick={() => handleRemoveTarget(row.idx)}
                          aria-label={`Remove ${row.value}`}
                        >
                          <Glyph>❌</Glyph> Remove
                        </CcureButton>
                      ),
                    },
                  ]}
                />
              </div>
            )}
            <div className="ns-quick" role="group" aria-label="Quick targets">
              <span className="ns-quick__label">Quick:</span>
              {QUICK_TARGETS.map((t) => (
                <CcureButton
                  key={t}
                  variant="secondary"
                  size="sm"
                  className="ns-chip"
                  onClick={() => setTarget(t)}
                  disabled={loading || !canExecuteScans}
                >
                  {t}
                </CcureButton>
              ))}
            </div>
          </section>
          {pipelineMode === "asset" && (
            <section className="ns-section ns-section--divided">
              <ChoiceGroup
                label="Discovery Profile"
                options={DISCOVERY_INTENSITIES}
                value={discoveryIntensity}
                onChange={setDiscoveryIntensity}
                disabled={loading || !canExecuteScans}
              >
                {(() => {
                  const activeDi = DISCOVERY_INTENSITIES.find(
                    (di) => di.value === discoveryIntensity,
                  );
                  return activeDi ? (
                    <p className="ns-choices__desc">
                      {activeDi.desc}
                      {activeDi.badge && (
                        <CcureBadge variant={activeDi.badgeVariant}>
                          {activeDi.badge}
                        </CcureBadge>
                      )}
                    </p>
                  ) : null;
                })()}
              </ChoiceGroup>
            </section>
          )}

          {(pipelineMode === "advanced" ||
            pipelineMode === "vulnerability_audit") && (
            <section className="ns-section ns-section--divided">
              <ChoiceGroup
                label="Scan Profile"
                options={SCAN_INTENSITIES}
                value={intensity}
                onChange={setIntensity}
                disabled={loading || !canExecuteScans}
              >
                {(() => {
                  const activeSi = SCAN_INTENSITIES.find(
                    (si) => si.value === intensity,
                  );
                  return activeSi ? (
                    <p className="ns-choices__desc">{activeSi.desc}</p>
                  ) : null;
                })()}
              </ChoiceGroup>
            </section>
          )}

          <div className="ns-section ns-section--divided">
            {/* Advanced Settings Trigger Button */}
            <CcureButton
              variant="secondary"
              className="ns-settings-trigger"
              onClick={() => setShowAdvanced(true)}
              disabled={loading}
              aria-haspopup="dialog"
            >
              <Glyph>⚙️</Glyph> Configure Advanced Settings
            </CcureButton>

            {error && <CcureAlert variant="danger">{error}</CcureAlert>}
            <CcureButton
              id="ns-start-btn"
              size="lg"
              block
              onClick={handleScan}
              disabled={
                loading || !target.trim() || !canExecuteScans || quotaBlocked
              }
            >
              {btnLabel} <Glyph>→</Glyph>
            </CcureButton>
          </div>
        </div>
      </div>

      {/* Advanced settings, a side sheet */}
      <SettingsDialog open={showAdvanced} setOpen={setShowAdvanced}>
        {/* 1. Port Scan Configuration (Asset Discovery Mode Only) */}
        {pipelineMode === "asset" && (
          <>
            <ScanModelChoice value={portScanMode} onChange={setPortScanMode} />

            {portScanMode === "intensity" ? (
              <div className="ns-settings__block">
                <ChoiceGroup
                  label="Port Scan Intensity"
                  hint="depth of Phase 2 port scan"
                  options={PORT_SCAN_INTENSITIES}
                  value={portScanIntensity}
                  onChange={setPortScanIntensity}
                  disabled={loading || !canExecuteScans}
                >
                  {(() => {
                    const activePi = PORT_SCAN_INTENSITIES.find(
                      (pi) => pi.value === portScanIntensity,
                    );
                    return activePi ? (
                      <p className="ns-choices__desc">{activePi.desc}</p>
                    ) : null;
                  })()}
                </ChoiceGroup>
              </div>
            ) : (
              <div className="ns-settings__block">
                <CcureSelect
                  label="Port Profile"
                  value={portProfile}
                  onChange={(e) => setPortProfile(e.target.value)}
                  disabled={loading || !canExecuteScans}
                >
                  {Object.entries(PORT_PROFILES).map(([key, prof]) => (
                    <option key={key} value={key}>
                      {prof.label}
                    </option>
                  ))}
                </CcureSelect>

                {/* Port pills display for predefined profiles */}
                {portProfile !== "custom" &&
                  PORT_PROFILES[portProfile]?.ports && (
                    <div className="ns-pills">
                      <p className="ns-hint">
                        Included Ports (
                        {PORT_PROFILES[portProfile].ports.split(",").length}{" "}
                        total)
                      </p>
                      <ul
                        className="ns-pills__list"
                        aria-label="Included ports"
                      >
                        {PORT_PROFILES[portProfile].ports
                          .split(",")
                          .map((pStr) => {
                            const pNum = parseInt(pStr, 10);
                            const isSensitive = SENSITIVE_PORTS.includes(pNum);
                            return (
                              <li
                                key={pStr}
                                className={`ns-pill${isSensitive ? " ns-pill--sensitive" : ""}`}
                              >
                                {pStr}
                                {isSensitive ? (
                                  <span className="cc-sr-only">
                                    {" "}
                                    (sensitive)
                                  </span>
                                ) : null}
                              </li>
                            );
                          })}
                      </ul>
                    </div>
                  )}

                {/* Custom Ports Input (when profile = custom) */}
                {portProfile === "custom" && (
                  <div className="ns-custom-ports">
                    <CcureInput
                      label="Custom Ports / Ranges"
                      hint="e.g. 22, 80, 443, 8080-8090"
                      value={customPorts}
                      onChange={(e) => handleCustomPortsChange(e.target.value)}
                      placeholder="e.g. 22,80,443,8000-8100"
                      disabled={loading || !canExecuteScans}
                      error={customPortsError || undefined}
                    />

                    <div
                      className="ns-quick"
                      role="group"
                      aria-label="Port presets"
                    >
                      <span className="ns-quick__label">Presets:</span>
                      {Object.entries(PORT_PROFILES)
                        .filter(([k]) => k !== "custom")
                        .map(([k, prof]) => (
                          <CcureButton
                            key={k}
                            variant="secondary"
                            size="sm"
                            className="ns-chip"
                            onClick={() => handleCustomPortsChange(prof.ports)}
                            disabled={loading || !canExecuteScans}
                          >
                            {prof.label}
                          </CcureButton>
                        ))}
                    </div>

                    {!customPortsError && parsedCustomPortsCount > 0 && (
                      <div className="ns-estimate">
                        <p className="ns-estimate__title">
                          <Glyph>⚡</Glyph> Scan Estimation
                        </p>
                        <dl className="ns-estimate__grid">
                          <div className="ns-estimate__row">
                            <dt>Unique ports:</dt>{" "}
                            <dd>{parsedCustomPortsCount}</dd>
                          </div>
                          <div className="ns-estimate__row">
                            <dt>Est. packets per host:</dt>{" "}
                            <dd>{parsedCustomPortsCount} packets</dd>
                          </div>
                          <div className="ns-estimate__row">
                            <dt>Est. duration per host:</dt>{" "}
                            <dd>
                              {Math.max(
                                1,
                                Math.round(parsedCustomPortsCount / 50),
                              )}{" "}
                              -{" "}
                              {Math.max(
                                2,
                                Math.round(parsedCustomPortsCount / 10),
                              )}{" "}
                              seconds
                            </dd>
                          </div>
                        </dl>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Exclude Ports Section */}
        <OptionRow
          icon="🚫"
          title="Exclude Specific Ports"
          hint="Exclude sensitive or firewalled ports from scanning"
          checked={excludePortsEnabled}
          onChange={(checked) => handleExcludeToggleChange(checked)}
        >
          {excludePortsEnabled && (
            <div className="ns-option__body">
              <CcureInput
                label="Ports to exclude"
                value={excludePorts}
                onChange={(e) => setExcludePorts(e.target.value)}
                placeholder="e.g. 2375,2376,6443,10250 or 80-90"
                disabled={loading || !canExecuteScans}
                error={excludePortsError || undefined}
              />

              {excludeTokens.length > 0 && (
                <ul className="ns-tags" aria-label="Excluded ports">
                  {excludeTokens.map((token, idx) => (
                    <li key={`${token}-${idx}`} className="ns-tag">
                      <span>{token}</span>
                      <CcureButton
                        variant="ghost"
                        size="sm"
                        className="ns-tag__remove"
                        onClick={() => handleRemoveExcludeToken(token)}
                        disabled={loading || !canExecuteScans}
                        aria-label={`Remove excluded port ${token}`}
                      >
                        <Glyph>×</Glyph>
                      </CcureButton>
                    </li>
                  ))}
                </ul>
              )}

              <div
                className="ns-quick"
                role="group"
                aria-label="Quick exclusions"
              >
                <span className="ns-quick__label">Quick:</span>
                <CcureButton
                  variant="secondary"
                  size="sm"
                  className="ns-chip"
                  onClick={() => setExcludePorts("2375,2376,6443,10250")}
                  disabled={loading || !canExecuteScans}
                >
                  Exclude Sensitive Ports
                </CcureButton>
              </div>
            </div>
          )}
        </OptionRow>

        {/* Exclude IPs Section */}
        <OptionRow
          icon="🚫"
          title="Exclude Specific IPs / Subnets"
          hint="Exclude sensitive target hosts or subnets from scanning"
          checked={excludeIpsEnabled}
          onChange={(checked) => handleExcludeIpsToggleChange(checked)}
        >
          {excludeIpsEnabled && (
            <div className="ns-option__body">
              <CcureInput
                label="IPs to exclude"
                value={excludeIps}
                onChange={(e) => setExcludeIps(e.target.value)}
                placeholder="e.g. 10.180.12.10,10.190.0.0/16"
                disabled={loading || !canExecuteScans}
                error={excludeIpsError || undefined}
              />
            </div>
          )}
        </OptionRow>

        {/* Sensitive Warning Banner */}
        {sensitivePortsFound && (
          <CcureAlert
            variant="warning"
            live={false}
            title="Sensitive Ports Detected"
          >
            <p className="ns-sensitive__text">
              Your selection includes sensitive ports (Docker API{" "}
              <code className="ns-code">2375/2376</code>, Kubernetes{" "}
              <code className="ns-code">6443/10250</code>). While these are
              allowed, scanning them can trigger intrusion detection systems or
              crash services if they are not configured correctly.
            </p>
          </CcureAlert>
        )}

        {/* Live Preview Panel (Asset mode only) */}
        {pipelineMode === "asset" && (
          <section className="ns-summary">
            <h3 className="ns-summary__title">
              <Glyph>🎯</Glyph> Scan Configuration Preview
            </h3>
            <dl className="ns-summary__grid">
              <div className="ns-summary__item">
                <dt>Scan Type</dt>
                <dd>{preview.typeLabel}</dd>
              </div>
              <div className="ns-summary__item">
                <dt>Target Profile / Depth</dt>
                <dd>{preview.targetPortsLabel}</dd>
              </div>
              <div className="ns-summary__item">
                <dt>Ports Count</dt>
                <dd>{preview.finalCount}</dd>
              </div>
              <div className="ns-summary__item">
                <dt>Excluded Ports</dt>
                <dd>{preview.excludedLabel}</dd>
              </div>
            </dl>
          </section>
        )}

        {/* 2. OS Detection (shown for asset / advanced / vulnerability_audit) */}
        {(pipelineMode === "asset" ||
          pipelineMode === "advanced" ||
          pipelineMode === "vulnerability_audit") && (
          <OptionRow
            title="OS Detection"
            hint="Fingerprint target operating systems"
            checked={osDetection}
            onChange={(checked) => setOsDetection(checked)}
            disabled={loading || !canExecuteScans}
            status={osDetection ? "ON (Fingerprint)" : "OFF (Faster Scan)"}
          />
        )}

        {/* 3. Execution Mode (shown for asset / advanced / vulnerability_audit) */}
        {(pipelineMode === "asset" ||
          pipelineMode === "advanced" ||
          pipelineMode === "vulnerability_audit") && (
          <div className="ns-settings__block">
            <CcureSelect
              label="Execution Mode"
              hint="Automatic full chain vs interactive vetting"
              value={executionMode}
              onChange={(e) => setExecutionMode(e.target.value)}
              disabled={loading || !canExecuteScans}
            >
              <option value="automatic">Automatic (Full Chain)</option>
              <option value="interactive">Interactive (Vetted Steps)</option>
            </CcureSelect>
          </div>
        )}

        {/* 4. Rate Limit (PPS) */}
        <div className="ns-settings__block">
          <CcureInput
            type="number"
            label="Rate Limit (PPS)"
            hint="limit packets per second"
            value={rateLimit}
            onChange={(e) => setRateLimit(e.target.value)}
            placeholder="e.g. 500"
            disabled={loading || !canExecuteScans}
          />
        </div>

        {/* 5. Authenticated checks (Vulnerability Audit only).
            Credentials are a policy option on the ordinary scan, not a
            separate scan type: discovery, port scanning and unauthenticated
            checks run first, then each reachable host is logged into and the
            local results are merged into the same report. */}
        {(pipelineMode === "advanced" ||
          pipelineMode === "vulnerability_audit") && (
          <OptionRow
            icon="🔐"
            title="Authenticated Checks (Credentialed)"
            hint="Log in to each host and match installed packages, then correlate with the port scan to find what is actually exposed"
            checked={credentialedEnabled}
            onChange={(checked) => setCredentialedEnabled(checked)}
            disabled={loading || !canExecuteScans}
          >
            {credentialedEnabled && (
              <div className="ns-option__body">
                {credentialsList.length === 0 ? (
                  <p className="ns-hint">
                    No stored credentials are registered for this organisation.
                    Add one under the Credentials Manager in{" "}
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      className="ns-link"
                      onClick={() => navigate("/compliance")}
                    >
                      Compliance
                    </CcureButton>
                    , then re-run this scan. Only stored credentials are
                    accepted here — a pipeline scan runs unattended, so one-time
                    credentials cannot be held for it.
                  </p>
                ) : (
                  <fieldset className="ns-creds">
                    <legend className="ns-label">Stored credentials</legend>
                    <p className="ns-hint">
                      Select the credentials to try. Each host is audited with
                      the first one whose scope covers it; hosts with no
                      matching credential, or with the SSH port closed, are
                      reported as unauthenticated and listed in the scan&apos;s
                      coverage.
                    </p>
                    {credentialsList.map((c) => {
                      const checked = selectedCredIds.includes(c.id);
                      return (
                        <label key={c.id} className="ns-cred">
                          <input
                            type="checkbox"
                            className="ns-cred__check"
                            checked={checked}
                            onChange={() =>
                              setSelectedCredIds((prev) =>
                                checked
                                  ? prev.filter((id) => id !== c.id)
                                  : [...prev, c.id],
                              )
                            }
                            disabled={loading || !canExecuteScans}
                          />
                          <span className="ns-cred__name">{c.name}</span>
                          <span className="ns-cred__account">
                            {c.username}@:{c.port ?? 22}
                          </span>
                        </label>
                      );
                    })}
                  </fieldset>
                )}
              </div>
            )}
          </OptionRow>
        )}

        {/* 6. SNMP / Network Topology (optional, all modes) */}
        <OptionRow
          icon="🗺️"
          title="Network Topology (SNMP)"
          hint="Enable SNMP to discover network connections"
          checked={snmpEnabled}
          onChange={(checked) => setSnmpEnabled(checked)}
          disabled={loading || !canExecuteScans}
        >
          {snmpEnabled && (
            <div className="ns-option__body">
              <CcureSelect
                label="SNMP Version"
                value={snmpVersion}
                onChange={(e) => setSnmpVersion(e.target.value)}
                disabled={loading}
              >
                <option value="v1">v1</option>
                <option value="v2c">v2c</option>
                <option value="v3">v3</option>
              </CcureSelect>

              {snmpVersion !== "v3" ? (
                <CcureInput
                  label="Community String"
                  value={snmpCommunity}
                  onChange={(e) => setSnmpCommunity(e.target.value)}
                  placeholder="public"
                  disabled={loading}
                />
              ) : (
                <>
                  <CcureInput
                    label="Username"
                    value={snmpUsername}
                    onChange={(e) => setSnmpUsername(e.target.value)}
                    placeholder="SNMPv3 username"
                    disabled={loading}
                  />
                  <CcureSelect
                    label="Auth Protocol"
                    value={snmpAuthProtocol}
                    onChange={(e) => setSnmpAuthProtocol(e.target.value)}
                    disabled={loading}
                  >
                    <option value="MD5">MD5</option>
                    <option value="SHA">SHA</option>
                    <option value="SHA256">SHA-256</option>
                  </CcureSelect>
                  <CcureInput
                    type="password"
                    label="Auth Passphrase"
                    value={snmpAuthPassphrase}
                    onChange={(e) => setSnmpAuthPassphrase(e.target.value)}
                    placeholder="Auth passphrase"
                    disabled={loading}
                  />
                  <CcureSelect
                    label="Privacy Protocol"
                    hint="optional"
                    value={snmpPrivProtocol}
                    onChange={(e) => setSnmpPrivProtocol(e.target.value)}
                    disabled={loading}
                  >
                    <option value="">None (authNoPriv)</option>
                    <option value="DES">DES</option>
                    <option value="AES128">AES-128</option>
                    <option value="AES256">AES-256</option>
                  </CcureSelect>
                  {snmpPrivProtocol && (
                    <CcureInput
                      type="password"
                      label="Privacy Passphrase"
                      value={snmpPrivPassphrase}
                      onChange={(e) => setSnmpPrivPassphrase(e.target.value)}
                      placeholder="Privacy passphrase"
                      disabled={loading}
                    />
                  )}
                  <CcureInput
                    label="Context Name"
                    hint="optional, VLAN-aware switches"
                    value={snmpContextName}
                    onChange={(e) => setSnmpContextName(e.target.value)}
                    placeholder="e.g. vlan-100"
                    disabled={loading}
                  />
                </>
              )}
            </div>
          )}
        </OptionRow>
      </SettingsDialog>
    </AppLayout>
  );
}
