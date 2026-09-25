/**
 * src/pages/scan/Phase2Results.jsx
 *
 * Pattern B — Pure Reporting Screen
 *
 * Port scan results are produced by the backend auto-chain (Phase 1 → Phase 2).
 * All configuration (intensity, OS detection) was captured upfront on NewScan.jsx.
 * This page only loads and displays already-computed Phase 2 data.
 *
 * The "Proceed to Vulnerability Audit" action is preserved — it passes scan results
 * forward to Phase 3 and is a result-review action, not a scan trigger.
 *
 * Checkpoint 3C batch 18 — design-system migration. Presentation only: the
 * load, the 4-second poll, the automatic hand-off and the audit queue are the
 * code that was here, and `__tests__/pages/scan/Phase2Results.test.jsx` pins
 * them. The queue matters more than its button suggests: Phase 3 starts the
 * port scan or the audit from an effect when it mounts, so the hosts handed
 * over here are the hosts that get scanned.
 */
import { useId, useState, useEffect, useRef } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import {
  HostMeasurements,
  PortLabel,
  PortStates,
  ScanContext,
  TcpFingerprint,
} from "../../components/scan/AssessmentContext";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureProgress,
  CcureSeverityBadge,
  CcureTable,
  normalizeSeverity,
} from "../../design-system";
import "../../styles/phase2-results.css";

/* Only `recommended` is implemented: the backend selects checks by the host's
   open ports and never read the profile at all, so "Conservative" ran the full
   check set against the fragile or OT systems it was chosen to protect, and
   nothing said so (finding F4). The API now refuses the other two values; they
   stay visible, disabled and labelled, so the absence is stated rather than
   hidden — until a profile actually changes what runs. */
const NOT_IMPLEMENTED =
  "Not yet available — every vulnerability audit currently runs the Recommended checks.";

const VULN_PROFILES = [
  {
    value: "recommended",
    label: "Recommended",
    desc: "Service-aware checks for discovered open ports",
    implemented: true,
  },
  {
    value: "conservative",
    label: "Conservative",
    desc: `Lower-impact checks for fragile or OT systems. ${NOT_IMPLEMENTED}`,
    implemented: false,
  },
  {
    value: "deep",
    label: "Deep",
    desc: `Broader audit scope for approved maintenance windows. ${NOT_IMPLEMENTED}`,
    implemented: false,
  },
];

const textValue = (value, fallback = "—") => {
  if (value == null || value === "" || value === "Unknown" || value === "N/A")
    return fallback;
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  )
    return String(value);
  if (Array.isArray(value))
    return (
      value
        .map((v) => textValue(v, ""))
        .filter(Boolean)
        .join(", ") || fallback
    );
  if (typeof value === "object")
    return (
      value.name || value.vendor || value.address || value.value || fallback
    );
  return fallback;
};

const fmtNumber = (value, digits = 1, fallback = "—") => {
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(digits) : fallback;
};

const hasDetectedServices = (host) =>
  (host?.open_ports?.length || 0) > 0 || (host?.udp_services?.length || 0) > 0;

const getCategoryLabel = (cat) => {
  const labels = {
    router: "Router",
    switch: "Switch",
    firewall: "Firewall",
    wireless_ap: "Wireless AP",
    printer: "Printer",
    iot: "IoT/ICS",
    server: "Server",
    endpoint: "Endpoint",
    voip: "VoIP",
    storage: "Storage",
    network_appliance: "Net Appliance",
    scada_ics: "Industrial/OT",
    virtual_machine: "Virtual Machine",
    unknown: "Unknown",
  };
  return labels[cat] || cat;
};

/* ── Presentation helpers ─────────────────────────────────────────────────── */

/* A risk the design system recognises is a severity badge; anything else is
   printed as the scanner wrote it, rather than relabelled "Unscored". */
const RiskLabel = ({ risk }) => {
  const label = risk || "Info";
  return normalizeSeverity(label) === "unscored" ? (
    <CcureBadge mono>{textValue(label)}</CcureBadge>
  ) : (
    <CcureSeverityBadge severity={label} />
  );
};

const CONFIDENCE_TONE = { High: "success", Medium: "warning" };
const UDP_STATE_TONE = { open: "success", "open|filtered": "warning" };

const toneClass = (tone) => (tone ? `p2-tone--${tone}` : "p2-muted");

const Fact = ({ label, children }) => (
  <div className="p2-fact">
    <dt className="p2-fact__label">{label}</dt>
    <dd className="p2-fact__value">{children}</dd>
  </div>
);

/**
 * How precisely the version was established, which qualifies the version and
 * must travel with it: `exact` and a guess read identically otherwise.
 */
const PRECISION_TONE = {
  exact: "success",
  approximate: "warning",
  range: "warning",
  unknown: "neutral",
};

const TCP_COLUMNS = [
  {
    key: "port",
    header: "Port",
    mono: true,
    nowrap: true,
    /* The scanner's own protocol. This list is the TCP table, but the row
       carries its transport and the row is what is believed. */
    cell: (port) => <PortLabel row={port} />,
  },
  {
    key: "service",
    header: "Service",
    cell: (port) => (
      <>
        <span className="p2-service">
          {textValue(port.service || port.service_name)}
        </span>
        {port.product ? (
          <span className="p2-muted p2-small"> {port.product}</span>
        ) : null}
      </>
    ),
  },
  {
    key: "banner",
    header: "Banner / Version",
    mono: true,
    cell: (port) => (
      <>
        <span className="p2-muted p2-small">
          {textValue(port.banner || port.version)}
        </span>
        {/* A version without its precision reads as exact. */}
        {port.version_precision ? (
          <CcureBadge
            variant={PRECISION_TONE[port.version_precision] || "neutral"}
            title="How precisely the scanner established this version."
          >
            {port.version_precision}
          </CcureBadge>
        ) : null}
        {port.extra ? (
          <span className="p2-muted p2-small"> · {port.extra}</span>
        ) : null}
      </>
    ),
  },
  {
    key: "identification",
    header: "Identified by",
    cell: (port) => (
      <>
        {port.fingerprint_source ? (
          <span className="p2-small">{port.fingerprint_source}</span>
        ) : (
          <span className="p2-muted">not reported</span>
        )}
        {Array.isArray(port.cpe) && port.cpe.length ? (
          <span
            className="p2-muted p2-small p2-cpe"
            title={port.cpe.join("\n")}
          >
            {port.cpe[0]}
          </span>
        ) : null}
      </>
    ),
  },
  {
    key: "risk",
    header: "Risk",
    cell: (port) => <RiskLabel risk={port.risk} />,
  },
  {
    key: "cves",
    header: "CVEs",
    cell: (port) =>
      port.cves?.length > 0 ? (
        <CcureBadge variant="warning" mono>
          {port.cves.length} CVE{port.cves.length > 1 ? "s" : ""}
        </CcureBadge>
      ) : (
        <span className="p2-muted">—</span>
      ),
  },
];

const UDP_COLUMNS = [
  {
    key: "port",
    header: "Port",
    mono: true,
    nowrap: true,
    /* This table is the UDP one, so `udp` is the fallback when the row does
       not carry its own protocol — but a row that *does* is believed. */
    cell: (svc) => <PortLabel row={svc} fallbackProtocol="udp" />,
  },
  {
    key: "service",
    header: "Service",
    cell: (svc) => (
      <>
        <span className="p2-service">
          {textValue(svc.service || svc.service_name)}
        </span>
        {svc.product ? (
          <span className="p2-muted p2-small"> {svc.product}</span>
        ) : null}
      </>
    ),
  },
  {
    key: "state",
    header: "State",
    mono: true,
    cell: (svc) => (
      <span
        className={`p2-strong p2-small ${toneClass(UDP_STATE_TONE[svc.state])}`}
      >
        {textValue(svc.state)}
      </span>
    ),
  },
  {
    key: "risk",
    header: "Risk",
    cell: (svc) => <RiskLabel risk={svc.risk} />,
  },
  {
    key: "banner",
    header: "Banner",
    mono: true,
    cell: (svc) => (
      <span className="p2-muted p2-small">{textValue(svc.banner)}</span>
    ),
  },
];

const SNMP_COLUMNS = [
  { key: "index", header: "#", mono: true, cell: (iface) => iface.index },
  {
    key: "description",
    header: "Interface",
    cell: (iface) => textValue(iface.description),
  },
  {
    key: "type",
    header: "Type",
    cell: (iface) => (
      <span className="p2-muted p2-small">{textValue(iface.type)}</span>
    ),
  },
  {
    key: "mac",
    header: "MAC",
    mono: true,
    cell: (iface) => <span className="p2-small">{textValue(iface.mac)}</span>,
  },
  {
    key: "admin",
    header: "Admin",
    cell: (iface) => (
      <span
        className={`p2-small ${toneClass(iface.admin_up ? "success" : "danger")}`}
      >
        {iface.admin_up ? "Up" : "Down"}
      </span>
    ),
  },
  {
    key: "oper",
    header: "Oper",
    cell: (iface) => (
      <span
        className={`p2-small ${toneClass(iface.oper_up ? "success" : null)}`}
      >
        {iface.oper_up ? "Up" : "Down"}
      </span>
    ),
  },
];

const byIndex = (_row, index) => index;

export default function Phase2Results() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");
  const {
    phase1Hosts,
    phase2Results,
    phase2Summary,
    scanId,
    scanNo,
    target,
    pipelineMode,
    saveStatus,
    setPhase2Results,
    setPhase2Summary,
    setPhase3Results,
    setPipelineState,
    executionMode,
    setScanId,
    setScanNo,
    setTarget,
    setPipelineMode,
    setPhase1Hosts,
  } = useScan();

  // Load the scan named in the URL when it is not the one already in context.
  // This screen used to read context only, so /scan/:scanId/phase2 rendered
  // nothing and bounced to the template picker — a refresh, a bookmark, a new
  // tab or a shared link all lost the port-scan results. Phase 1 already
  // hydrates this way; Phase 2 now matches it.
  const { scanId: routeScanId } = useParams();
  const [searchParams] = useSearchParams();
  const requestedScanId = routeScanId || searchParams.get("scan_id") || null;
  const needsHydration = !!requestedScanId && requestedScanId !== scanId;
  const [hydrating, setHydrating] = useState(needsHydration);
  const [hydrateError, setHydrateError] = useState("");

  const [filter, setFilter] = useState("active");
  const [results, setResults] = useState(() =>
    phase2Results.length ? phase2Results : [],
  );
  const [summary, setSummary] = useState(() => phase2Summary || null);
  const [vulnProfile, setVulnProfile] = useState("recommended");
  const [expanded, setExpanded] = useState(new Set());
  const [error, setError] = useState("");
  // phase2Running = true while port scan is still in progress (no results yet)
  const [phase2Running, setPhase2Running] = useState(
    phase2Results.length === 0,
  );
  const [, setPhase2Polling] = useState(false);
  const hasResults = results.length > 0;
  const idBase = useId();

  useEffect(() => {
    if (!needsHydration) {
      setHydrating(false);
      return;
    }
    let cancelled = false;
    setHydrating(true);
    setHydrateError("");

    (async () => {
      try {
        const { data } = await api.get(`/scans/${requestedScanId}`);
        if (cancelled) return;
        const phase1 = data?.results?.phase1 || {};
        const phase2 = data?.results?.phase2 || {};
        const hosts2 = phase2.data || [];
        if (!hosts2.length) {
          setHydrateError(
            data?.failure_reason ||
              "This scan has no port-scan results to display.",
          );
          return;
        }
        setScanId(data.id);
        setScanNo(data.scan_no ?? null);
        setTarget(data.target || "");
        setPipelineMode(data.pipeline_mode || "asset");
        setPhase1Hosts(phase1.data || phase1.hosts || hosts2);
        setPhase2Results(hosts2);
        setPhase2Summary(phase2.summary || null);
        setResults(hosts2);
        setSummary(phase2.summary || null);
        setPhase2Running(false);
      } catch (err) {
        if (cancelled) return;
        setHydrateError(
          err?.response?.data?.detail || "Could not load this scan's results.",
        );
      } finally {
        if (!cancelled) setHydrating(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    needsHydration,
    requestedScanId,
    setScanId,
    setScanNo,
    setTarget,
    setPipelineMode,
    setPhase1Hosts,
    setPhase2Results,
    setPhase2Summary,
  ]);

  const [selected, setSelected] = useState(() => new Set());
  const selectionInitialized = useRef(false);

  const showCheckboxes = executionMode === "interactive";
  const finalSelectedHosts = showCheckboxes
    ? results.filter((h) => h.is_active && selected.has(h.ip_address))
    : results.filter((h) => h.is_active && hasDetectedServices(h));
  const selectedCount = finalSelectedHosts.length;

  const toggleHost = (ip) => {
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  // Initialize selected hosts when results are loaded
  useEffect(() => {
    if (results.length > 0) {
      if (!selectionInitialized.current) {
        const defaultSelected = results
          .filter((h) => h.is_active && hasDetectedServices(h))
          .map((h) => h.ip_address);
        setSelected(new Set(defaultSelected));
        selectionInitialized.current = true;
      }
    } else {
      selectionInitialized.current = false;
    }
  }, [results]);

  // Auto-redirect in Automatic mode to Phase 3 if enabled
  useEffect(() => {
    if (
      hasResults &&
      executionMode === "automatic" &&
      isPhaseEnabled(pipelineMode, 3)
    ) {
      const autoQueue = results.filter(
        (h) => h.is_active && hasDetectedServices(h),
      );
      setPhase3Results(autoQueue);
      navigate("/scan/vulnerability-audit");
    }
  }, [
    hasResults,
    executionMode,
    pipelineMode,
    results,
    navigate,
    setPhase3Results,
  ]);

  // ── Sync from context whenever Phase1Results polling saves data ──────────────
  useEffect(() => {
    if (phase2Results.length) {
      setResults(phase2Results);
      setPhase2Running(false);
      setPhase2Polling(false);
    }
    if (phase2Summary) setSummary(phase2Summary);
  }, [phase2Results, phase2Summary]);

  // ── Update pipeline state in context to drive the stepper ──────────────────
  useEffect(() => {
    if (phase2Running) {
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
    } else if (hasResults) {
      const hasPhase3 = isPhaseEnabled(pipelineMode, 3);
      setPipelineState(
        hasPhase3 ? PIPELINE_STATES.IDLE : PIPELINE_STATES.COMPLETE,
      );
    }
  }, [phase2Running, hasResults, pipelineMode, setPipelineState]);

  // ── Polling loop — runs while phase2Running and scanId is known ────────────
  // Handles first load when Phase 2 is still executing and direct navigation.
  useEffect(() => {
    if (!scanId || !phase2Running) return;
    let stopped = false;
    setPhase2Polling(true);

    const applyResults = (p2Data, p2Sum) => {
      setResults(p2Data);
      setPhase2Results(p2Data);
      if (p2Sum) {
        setSummary(p2Sum);
        setPhase2Summary(p2Sum);
      }
      setPhase2Running(false);
      setPhase2Polling(false);
    };

    const poll = async () => {
      // Immediate first check on mount
      try {
        const { data: scan } = await api.get(`/scans/${scanId}`);
        if (stopped) return;
        const d = scan?.results?.phase2?.data;
        if (Array.isArray(d) && d.length > 0) {
          applyResults(d, scan?.results?.phase2?.summary);
          return;
        }
      } catch {
        /* ignore */
      }

      // Then poll every 4s
      while (!stopped) {
        await new Promise((r) => setTimeout(r, 4000));
        if (stopped) break;
        try {
          const { data: scan } = await api.get(`/scans/${scanId}`);
          const d = scan?.results?.phase2?.data;
          const s = scan?.results?.phase2?.summary;
          if (Array.isArray(d) && d.length > 0) {
            applyResults(d, s);
            break;
          }
          if (scan?.status === "complete" || scan?.status === "failed") {
            setPhase2Running(false);
            setPhase2Polling(false);
            if (scan?.status === "failed") {
              setError("Port scan failed on the backend.");
              setPipelineState(PIPELINE_STATES.ERROR);
            }
            break;
          }
        } catch {
          /* ignore transient errors */
        }
      }
    };

    poll();
    return () => {
      stopped = true;
    };
  }, [scanId, phase2Running]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    // Don't bounce while a scan named in the URL is still loading, or when it
    // failed to load — the error belongs on screen, not behind a redirect.
    if (needsHydration || hydrating || hydrateError) return;
    if (!phase1Hosts.length) {
      navigate("/scan/host-discovery", { replace: true });
    }
  }, [phase1Hosts.length, navigate, needsHydration, hydrating, hydrateError]);

  const discoveredHosts = phase1Hosts;
  const activeHosts = discoveredHosts.filter((h) => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : discoveredHosts;

  const canProceedToPhase3 = isPhaseEnabled(pipelineMode, 3);
  const nextPhase = getNextPhase(pipelineMode, 2);

  const toggleExpand = (ip) => {
    const next = new Set(expanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setExpanded(next);
  };

  const proceedToNextPhase = () => {
    if (!canExecuteScans) {
      setError(denyMessage);
      return;
    }
    if (!canProceedToPhase3 || !nextPhase) return;
    if (!selectedCount) {
      setError(
        "No active hosts with open ports selected to run Vulnerability Audit.",
      );
      return;
    }
    setPhase3Results(finalSelectedHosts);
    setPipelineState(PIPELINE_STATES.IDLE);
    navigate(nextPhase.route, {
      state: {
        vulnerabilityProfile: vulnProfile,
        startPhase: "VULN_SCAN",
      },
    });
  };

  const activeResults = results.filter((h) => h.is_active);

  if (hydrating) {
    return (
      <AppLayout pageTitle="Port Scan Results">
        <div className="p2-page">
          <h1 className="p2-title">Port Scan Results</h1>
          <p className="p2-loading" role="status">
            Loading scan results…
          </p>
        </div>
      </AppLayout>
    );
  }

  if (hydrateError) {
    return (
      <AppLayout pageTitle="Port Scan Results">
        <div className="p2-page">
          <h1 className="p2-title">Port Scan Results</h1>
          <CcureAlert variant="danger" className="p2-alert">
            {hydrateError}
          </CcureAlert>
          <CcureButton as={Link} to="/history" variant="secondary">
            <span aria-hidden="true">←</span> Back to Scan History
          </CcureButton>
        </div>
      </AppLayout>
    );
  }

  // Stepper advances: step 2 = port scan active, step 3 = port scan complete
  const stepperCurrent = hasResults ? 3 : 2;

  const unreachable =
    (!summary && activeHosts.length === 0 && discoveredHosts.length > 0) ||
    (summary &&
      (summary.status === "unreachable" ||
        (Number(summary.active_hosts) === 0 &&
          Number(summary.total_hosts) > 0)));

  const hostColumns = [
    ...(showCheckboxes
      ? [
          {
            key: "select",
            className: "p2-col-select",
            header: (
              <input
                type="checkbox"
                className="p2-check"
                aria-label="Select all active hosts for vulnerability audit"
                checked={
                  activeHosts.length > 0 &&
                  activeHosts.every((h) => selected.has(h.ip_address))
                }
                onChange={(e) => {
                  if (e.target.checked) {
                    setSelected(new Set(activeHosts.map((h) => h.ip_address)));
                  } else {
                    setSelected(new Set());
                  }
                }}
                disabled={!canExecuteScans}
              />
            ),
          },
        ]
      : []),
    { key: "ip", header: "IP Address" },
    { key: "hostname", header: "Hostname" },
    { key: "mac", header: "MAC" },
    { key: "vendor", header: "Vendor" },
    { key: "method", header: "Method" },
    { key: "status", header: "Status" },
  ];

  const profileLabelId = `${idBase}-profile`;

  return (
    <AppLayout pageTitle="Port Scan Results" saveStatus={saveStatus}>
      <ScanStepper current={stepperCurrent} />

      <div className="p2-page">
        <header className="p2-header">
          <div>
            <h1 className="p2-title">Port Scan Results</h1>
            <p className="p2-subtitle">
              Target: <code className="p2-mono">{target}</code>
              {scanId && (
                <span className="p2-muted"> · Scan No. {scanNo ?? "—"}</span>
              )}
            </p>
          </div>
          <CcureButton
            as={Link}
            to="/scan/host-discovery"
            variant="ghost"
            size="sm"
          >
            <span aria-hidden="true">←</span> Back
          </CcureButton>
        </header>

        {unreachable && (
          <CcureAlert
            variant="warning"
            live={false}
            title="Host is unavailable/down/unreachable"
            className="p2-alert"
          >
            The discovery scan completed but the target did not respond. Verify
            the IP address and network connectivity before re-scanning.
          </CcureAlert>
        )}

        {phase2Running && (
          <div className="p2-running" role="status">
            <div className="p2-running__head">
              <span className="p2-pulse" aria-hidden="true" />
              <div>
                <h2 className="p2-running__title">Port Scan Running…</h2>
                <p className="p2-running__desc">
                  Probing TCP/UDP services on discovered hosts — results will
                  appear automatically when complete.
                </p>
              </div>
            </div>
            <CcureProgress showValue={false} className="p2-running__progress" />
          </div>
        )}

        <div
          className="p2-filters"
          role="group"
          aria-label="Discovered hosts to show"
        >
          {[
            ["active", `Active (${activeHosts.length})`],
            ["all", `All (${discoveredHosts.length})`],
          ].map(([val, lbl]) => (
            <CcureButton
              key={val}
              variant="secondary"
              size="sm"
              className="p2-toggle"
              aria-pressed={filter === val}
              onClick={() => setFilter(val)}
            >
              {lbl}
            </CcureButton>
          ))}
        </div>

        <div className="p2-card">
          <CcureTable
            caption="Discovered hosts"
            columns={hostColumns}
            density="compact"
          >
            {displayHosts.map((host) => {
              let displayHost = host.hostname;
              if (!displayHost || displayHost === "Unknown") {
                if (host.mdns_name) displayHost = host.mdns_name;
                else if (host.netbios_names && host.netbios_names.length)
                  displayHost = host.netbios_names[0]?.name;
              }

              return (
                <tr
                  key={host.ip_address}
                  className={host.is_active ? undefined : "p2-row--inactive"}
                >
                  {showCheckboxes && (
                    <td className="p2-col-select">
                      <input
                        type="checkbox"
                        className="p2-check"
                        aria-label={`Select ${host.ip_address} for vulnerability audit`}
                        checked={selected.has(host.ip_address)}
                        onChange={() => toggleHost(host.ip_address)}
                        disabled={!host.is_active || !canExecuteScans}
                      />
                    </td>
                  )}
                  <td>
                    <code className="p2-mono">{host.ip_address}</code>
                  </td>
                  <td>
                    {textValue(
                      displayHost,
                      <span className="p2-muted">—</span>,
                    )}
                  </td>
                  <td>
                    {textValue(
                      host.mac_address,
                      <span className="p2-muted">—</span>,
                    )}
                  </td>
                  <td>
                    {textValue(
                      host.vendor,
                      <span className="p2-muted">—</span>,
                    )}
                  </td>
                  <td>
                    {textValue(
                      host.discovery_method,
                      <span className="p2-muted">—</span>,
                    )}
                  </td>
                  <td>
                    <span
                      className={`p2-status-dot p2-status-dot--${host.is_active ? "up" : "down"}`}
                      aria-hidden="true"
                    />
                    {host.is_active ? "Active" : "Inactive"}
                  </td>
                </tr>
              );
            })}
          </CcureTable>
        </div>

        {summary && (
          <ul className="p2-summary">
            <li className="p2-summary__item">
              <strong>{summary.total_hosts}</strong> Hosts scanned
            </li>
            <li className="p2-summary__item p2-summary__item--accent">
              <strong>{summary.hosts_with_ports}</strong> Have open ports
            </li>
            <li className="p2-summary__item">
              <strong>{fmtNumber(summary.scan_duration)}s</strong> Duration
            </li>
            <li className="p2-summary__item p2-summary__item--accent">
              <strong>{selectedCount}</strong> queued for audit
            </li>
            {summary.custom_ports && (
              <li
                className="p2-summary__item p2-summary__item--info"
                title={summary.custom_ports}
              >
                <span aria-hidden="true">🔌</span> Custom Ports:{" "}
                <strong>
                  {summary.custom_ports.length > 25
                    ? summary.custom_ports.substring(0, 22) + "..."
                    : summary.custom_ports}
                </strong>
              </li>
            )}
          </ul>
        )}

        {error && (
          <CcureAlert variant="danger" className="p2-alert">
            {error}
          </CcureAlert>
        )}

        {hasResults && activeResults.length === 0 && (
          <CcureEmptyState
            icon="🔍"
            title="No active hosts returned open ports"
            className="p2-empty"
          />
        )}

        {activeResults.map((host) => {
          const portCount = host.open_ports?.length || 0;
          const critPorts =
            host.open_ports?.filter((p) => p.risk === "Critical").length || 0;
          const isExpanded = expanded.has(host.ip_address);
          const bodyId = `${idBase}-host-${host.ip_address.replace(/[^\w-]/g, "-")}`;

          let hostName = host.hostname;
          if (!hostName || hostName === "Unknown") {
            if (host.mdns_name) hostName = host.mdns_name;
            else if (host.netbios_names && host.netbios_names.length)
              hostName = host.netbios_names[0]?.name;
          }
          const safeName = textValue(hostName, "");

          const showOs =
            host.os_fingerprint_full?.os ||
            (host.os_guess && host.os_guess !== "Unknown");
          const showIdentity =
            host.mdns_name ||
            host.mdns_services?.length ||
            (host.netbios_names && host.netbios_names.length > 0) ||
            host.snmp_device_type ||
            host.device_category ||
            host.firewall_likely ||
            host.snmp_info;
          const ipCount = host.snmp_info?.ip_addresses?.length || 0;

          return (
            <article key={host.ip_address} className="p2-host">
              <div className="p2-host__header">
                {showCheckboxes && (
                  <input
                    type="checkbox"
                    className="p2-check"
                    aria-label={`Select ${host.ip_address} for vulnerability audit`}
                    checked={selected.has(host.ip_address)}
                    onChange={() => toggleHost(host.ip_address)}
                    disabled={!canExecuteScans}
                  />
                )}
                <h2 className="p2-host__heading">
                  <button
                    type="button"
                    className="p2-host__toggle"
                    aria-expanded={isExpanded}
                    aria-controls={isExpanded ? bodyId : undefined}
                    onClick={() => toggleExpand(host.ip_address)}
                  >
                    <span className="p2-host__identity">
                      <code className="p2-mono p2-host__ip">
                        {host.ip_address}
                      </code>
                      {safeName ? (
                        <span className="p2-muted p2-small">{safeName}</span>
                      ) : null}
                    </span>
                    <span className="p2-host__meta">
                      {portCount > 0 ? (
                        <CcureBadge mono>
                          {portCount} port{portCount !== 1 ? "s" : ""}
                        </CcureBadge>
                      ) : (
                        <span className="p2-muted p2-small">No open ports</span>
                      )}
                      {critPorts > 0 && (
                        <CcureBadge variant="danger">
                          {critPorts} Critical
                        </CcureBadge>
                      )}
                      {host.os_guess && host.os_guess !== "Unknown" && (
                        <CcureBadge>{textValue(host.os_guess)}</CcureBadge>
                      )}
                    </span>
                    <span className="p2-host__chevron" aria-hidden="true">
                      {isExpanded ? "▲" : "▼"}
                    </span>
                  </button>
                </h2>
              </div>

              {isExpanded && (
                <div id={bodyId} className="p2-host__body">
                  {/* What the scan measured about the host itself, and the
                      per-port states — including the ones it could not
                      resolve, which the open-ports list cannot carry. */}
                  <HostMeasurements host={host} />
                  <TcpFingerprint fingerprint={host.tcp_fingerprint} />
                  <PortStates portStates={host.port_states} />
                  {(showOs || showIdentity) && (
                    <div className="p2-host__facts">
                      {showOs && (
                        <section className="p2-facts">
                          <h3 className="p2-subhead">Target OS Fingerprint</h3>
                          <dl className="p2-facts__list">
                            {host.os_fingerprint_full?.os ? (
                              <>
                                <Fact label="OS Guess:">
                                  <strong>
                                    {textValue(host.os_fingerprint_full.os)}
                                  </strong>
                                </Fact>
                                <Fact label="Confidence:">
                                  <span
                                    className={`p2-strong ${toneClass(
                                      CONFIDENCE_TONE[
                                        host.os_fingerprint_full.confidence
                                      ],
                                    )}`}
                                  >
                                    {host.os_fingerprint_full.confidence}
                                  </span>{" "}
                                  <span className="p2-muted p2-small">
                                    ({host.os_fingerprint_full.match_score ?? 0}{" "}
                                    pts)
                                  </span>
                                </Fact>
                              </>
                            ) : (
                              <>
                                <Fact label="OS Guess:">
                                  <strong>{textValue(host.os_guess)}</strong>
                                </Fact>
                                <Fact label="Confidence:">
                                  {textValue(host.os_confidence)}
                                </Fact>
                              </>
                            )}
                          </dl>
                        </section>
                      )}

                      {showIdentity && (
                        <section className="p2-facts">
                          <h3 className="p2-subhead">Network Identity</h3>
                          <dl className="p2-facts__list">
                            <Fact label="mDNS:">
                              {textValue(host.mdns_name)}
                            </Fact>
                            {host.mdns_services &&
                              host.mdns_services.length > 0 && (
                                <div className="p2-fact p2-fact--chips">
                                  <dt className="cc-sr-only">mDNS services</dt>
                                  <dd className="p2-chips">
                                    {host.mdns_services
                                      .slice(0, 6)
                                      .map((svc) => (
                                        <CcureBadge
                                          key={svc}
                                          variant="info"
                                          mono
                                        >
                                          {textValue(svc, "")
                                            .replace("._tcp.local", "")
                                            .replace("._udp.local", "")}
                                        </CcureBadge>
                                      ))}
                                  </dd>
                                </div>
                              )}
                            <Fact label="NetBIOS:">
                              {host.netbios_names && host.netbios_names.length
                                ? host.netbios_names
                                    .map((n) => textValue(n?.name, ""))
                                    .filter(Boolean)
                                    .join(", ")
                                : "—"}
                            </Fact>
                            {host.netbios_workgroup && (
                              <Fact label="Domain:">
                                <strong>
                                  {textValue(host.netbios_workgroup)}
                                </strong>
                              </Fact>
                            )}
                            <Fact label="Device Type:">
                              {textValue(
                                host.snmp_device_type ||
                                  getCategoryLabel(host.device_category),
                              )}
                            </Fact>
                            {host.snmp_info?.sys_name && (
                              <Fact label="SNMP Name:">
                                <span className="p2-mono p2-small">
                                  {textValue(host.snmp_info.sys_name)}
                                </span>
                              </Fact>
                            )}
                            {host.snmp_info?.sys_location && (
                              <Fact label="Location:">
                                {textValue(host.snmp_info.sys_location)}
                              </Fact>
                            )}
                            {host.snmp_info?.vendor && (
                              <Fact label="SNMP Vendor:">
                                <strong>
                                  {textValue(host.snmp_info.vendor)}
                                </strong>
                              </Fact>
                            )}
                            {host.firewall_likely && (
                              <Fact label="Firewall:">
                                <CcureBadge variant="warning">
                                  <span aria-hidden="true">🛡</span> Detected (
                                  {host.firewall_confidence})
                                </CcureBadge>
                              </Fact>
                            )}
                          </dl>
                        </section>
                      )}
                    </div>
                  )}

                  {host.snmp_info?.interfaces &&
                    host.snmp_info.interfaces.length > 0 && (
                      <section className="p2-section">
                        <h3 className="p2-subhead">
                          SNMP Interfaces ({host.snmp_info.interfaces.length})
                          {ipCount > 0 && (
                            <span className="p2-subhead__note">
                              {" "}
                              · {ipCount} IP{ipCount !== 1 ? "s" : ""} bound
                            </span>
                          )}
                        </h3>
                        <CcureTable
                          caption={`SNMP interfaces on ${host.ip_address}`}
                          columns={SNMP_COLUMNS}
                          rows={host.snmp_info.interfaces}
                          rowKey={(iface) => iface.index}
                          density="compact"
                        />
                        {ipCount > 0 && (
                          <ul className="p2-chips p2-chips--list">
                            {host.snmp_info.ip_addresses.map((a) => (
                              <li key={a.address}>
                                <CcureBadge
                                  variant="info"
                                  mono
                                  title={`Netmask: ${a.netmask}`}
                                >
                                  {textValue(a.address)}/{textValue(a.netmask)}
                                </CcureBadge>
                              </li>
                            ))}
                          </ul>
                        )}
                      </section>
                    )}

                  <section className="p2-section">
                    <h3 className="p2-subhead">Discovered Services</h3>
                    {host.open_ports?.length > 0 ? (
                      <CcureTable
                        caption={`Open TCP ports on ${host.ip_address}`}
                        columns={TCP_COLUMNS}
                        rows={host.open_ports}
                        rowKey={byIndex}
                        density="compact"
                      />
                    ) : (
                      <p className="p2-muted p2-note">
                        No open ports detected on this host.
                      </p>
                    )}
                  </section>

                  {host.udp_services && host.udp_services.length > 0 && (
                    <section className="p2-section">
                      <h3 className="p2-subhead">
                        UDP Services ({host.udp_services.length})
                      </h3>
                      <CcureTable
                        caption={`UDP services on ${host.ip_address}`}
                        columns={UDP_COLUMNS}
                        rows={host.udp_services}
                        rowKey={byIndex}
                        density="compact"
                      />
                    </section>
                  )}
                </div>
              )}
            </article>
          );
        })}

        {/* The scan's own parameters. A reader cannot tell a clean host from
            an unscanned range without them, and they were on the summary the
            page already held. */}
        {summary ? <ScanContext summary={summary} /> : null}

        {summary &&
          results.length > 0 &&
          pipelineMode !== "advanced" &&
          pipelineMode !== "vulnerability_audit" && (
            <ExportPanel
              results={results}
              summary={summary}
              scanId={scanId}
              scanNo={scanNo}
              target={target}
              pipelineMode={pipelineMode}
            />
          )}

        {hasResults && canProceedToPhase3 && (
          <div className="p2-footer">
            <div className="p2-footer__queue">
              <p className="p2-footer__count" role="status">
                {selectedCount === 0
                  ? "No active hosts with open ports found to run vulnerability audit."
                  : `${selectedCount} host${selectedCount > 1 ? "s" : ""} queued for vulnerability audit.`}
              </p>
              <div
                className="p2-profiles"
                role="group"
                aria-labelledby={profileLabelId}
              >
                <span id={profileLabelId} className="p2-profiles__label">
                  Audit profile
                </span>
                {VULN_PROFILES.map((profile) => (
                  <CcureButton
                    key={profile.value}
                    variant="secondary"
                    size="sm"
                    className="p2-toggle"
                    aria-pressed={vulnProfile === profile.value}
                    aria-describedby={`${profileLabelId}-${profile.value}`}
                    title={profile.desc}
                    onClick={() => setVulnProfile(profile.value)}
                    disabled={!canExecuteScans || !profile.implemented}
                  >
                    {profile.label}
                  </CcureButton>
                ))}
                {VULN_PROFILES.map((profile) => (
                  <span
                    key={profile.value}
                    id={`${profileLabelId}-${profile.value}`}
                    className="cc-sr-only"
                  >
                    {profile.desc}
                  </span>
                ))}
              </div>
            </div>
            <CcureButton
              variant="danger"
              onClick={proceedToNextPhase}
              disabled={selectedCount === 0 || !canExecuteScans}
            >
              Run Vulnerability Audit <span aria-hidden="true">→</span>
            </CcureButton>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
