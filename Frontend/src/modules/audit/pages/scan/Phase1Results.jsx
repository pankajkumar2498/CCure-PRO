/**
 * src/modules/audit/pages/scan/Phase1Results.jsx
 *
 * Pattern B — Pure Reporting Screen
 *
 * For the ASSET pipeline:
 *   Phase 1 (host discovery) results are shown here as a read-only table.
 *   Phase 2 (port scan) is auto-chained on the backend immediately after Phase 1.
 *   No mid-run controls here — all configuration happened on NewScan.jsx upfront.
 *   A status indicator links to the Phase 2 results page when ready.
 *
 * For the BASIC pipeline:
 *   Behaviour unchanged — shows host table + export panel.
 *
 * For the VULNERABILITY AUDIT pipeline:
 *   Shows host table + "Continue to Port Scan" button (navigates to Phase2Results).
 *
 * Checkpoint 3C batch 19 — design-system migration. Presentation only: the
 * load, the port-scan request and its guards, the port and address parsers,
 * the default host selection, the 4-second poll and every navigation are the
 * code that was here, and `__tests__/pages/scan/Phase1Results.test.jsx` pins
 * them. "Run Port Scan" starts a port scan against the selected hosts with the
 * options beneath it, so each of those controls is named for what it sends.
 */
import { useId, useState, useEffect } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import ScanStepper from "@audit/components/layout/ScanStepper";
import ExportPanel from "@audit/components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "@audit/context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "@audit/config/scanConfig";
import api from "@shell/api/axiosInstance";
import {
  HostMeasurements,
  OsIdentification,
  PortStates,
  ScanContext,
  TcpFingerprint,
} from "@audit/components/scan/AssessmentContext";
import { useAuth } from "@shell/auth/AuthContext";
import { can } from "@shell/auth/permissions";
import { parseExcludeIpsJS } from "@audit/utils/ipValidation";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureTable,
} from "../../../../design-system";
import "../../styles/phase1-results.css";

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

export default function Phase1Results() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canExecuteScans = can(user, "audit.scan.run");
  const {
    target,
    scanId,
    scanNo,
    phase1Hosts,
    phase1Summary,
    phase2Results,
    pipelineMode,
    saveStatus,
    setSaveStatus,
    setPhase2Results,
    setPhase2Summary,
    setPipelineState,
    executionMode,
    portScanIntensity,
    osDetection,
    portScanMode,
    setPortScanMode,
    customPorts,
    setCustomPorts,
    excludePorts,
    setExcludePorts,
    excludeIps,
    setExcludeIps,
    setScanId,
    setScanNo,
    setTarget,
    setPipelineMode,
    setPhase1Hosts,
    setPhase1Summary,
  } = useScan();

  // ── Hydration from the URL ────────────────────────────────────────────────
  // This page used to read only from in-session state, so opening a past scan
  // showed nothing and bounced the user to the scan template picker. The whole
  // results view — host table, filters and every client-side export — was
  // unreachable the moment you navigated away from a live scan.
  const { scanId: routeScanId } = useParams();
  const [searchParams] = useSearchParams();
  const requestedScanId = routeScanId || searchParams.get("scan_id") || null;
  const needsHydration = !!requestedScanId && requestedScanId !== scanId;
  const [hydrating, setHydrating] = useState(needsHydration);
  const [hydrateError, setHydrateError] = useState("");

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
        const hosts = phase1.data || phase1.hosts || [];
        if (!hosts.length) {
          setHydrateError(
            data?.failure_reason ||
              "This scan has no host-discovery results to display.",
          );
          return;
        }
        setScanId(data.id);
        setScanNo(data.scan_no ?? null);
        setTarget(data.target || "");
        setPipelineMode(data.pipeline_mode || "basic");
        setPhase1Hosts(hosts);
        setPhase1Summary(phase1.summary || data.summary || null);
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
    setPhase1Summary,
  ]);

  const [filter, setFilter] = useState("active");
  // For asset pipeline: poll once to know if Phase 2 is already done
  const [phase2Done, setPhase2Done] = useState(phase2Results.length > 0);
  const [phase2Polling, setPhase2Polling] = useState(false);
  const [selected, setSelected] = useState(
    () =>
      new Set(phase1Hosts.filter((h) => h.is_active).map((h) => h.ip_address)),
  );
  /* Which host's discovery evidence is open. One at a time: the detail row
     carries fingerprints and port states, and several open at once buries the
     table it belongs to. */
  const [openHost, setOpenHost] = useState(null);
  const [assetLoading, setAssetLoading] = useState(false);
  const [error, setError] = useState("");
  const [customPortsError, setCustomPortsError] = useState("");

  const [excludePortsEnabled, setExcludePortsEnabled] = useState(
    () => !!excludePorts,
  );
  const [, setExcludePortsError] = useState("");
  const [, setParsedExcludePortsCount] = useState(0);
  const [sensitivePortsFound, setSensitivePortsFound] = useState(false);

  const [excludeIpsEnabled, setExcludeIpsEnabled] = useState(
    () => !!excludeIps,
  );
  const [excludeIpsError, setExcludeIpsError] = useState("");
  const idBase = useId();

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

  useEffect(() => {
    if (portScanMode !== "custom") {
      setSensitivePortsFound(false);
      return;
    }
    if (customPorts) {
      const { sensitiveFound } = parseCustomPortsJS(customPorts);
      setSensitivePortsFound(sensitiveFound);
    } else {
      setSensitivePortsFound(false);
    }
  }, [portScanMode, customPorts]);

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

  const hasPhase2 = isPhaseEnabled(pipelineMode, 2);
  const showCheckboxes =
    executionMode === "interactive" && pipelineMode !== "basic";

  const toggleHost = (ip) => {
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  const runPortScan = async () => {
    if (!canExecuteScans) {
      setError("You do not have permission to execute scans.");
      return;
    }
    const selectedHosts = phase1Hosts.filter(
      (h) => selected.has(h.ip_address) && h.is_active,
    );
    if (!selectedHosts.length) {
      setError("Select at least one host to port scan.");
      return;
    }

    if (portScanMode === "custom") {
      if (!customPorts || !customPorts.trim()) {
        setError(
          "Custom ports list cannot be empty when custom ports mode is active.",
        );
        return;
      }
      const { error: portErr } = parseCustomPortsJS(customPorts);
      if (portErr) {
        setError(portErr);
        return;
      }
    }

    if (excludePortsEnabled && excludePorts.trim()) {
      const { error: portErr } = parseExcludePortsJS(excludePorts);
      if (portErr) {
        setError(`Exclude ports error: ${portErr}`);
        return;
      }
    }

    if (excludeIpsEnabled && excludeIps.trim()) {
      const { error: ipErr } = parseExcludeIpsJS(excludeIps);
      if (ipErr) {
        setError(`Exclude IPs error: ${ipErr}`);
        return;
      }
    }

    setAssetLoading(true);
    setError("");
    setSaveStatus("saving");
    try {
      const { data } = await api.post("/scan/asset-discovery", {
        hosts: selectedHosts,
        intensity:
          portScanMode === "custom" ? "custom" : portScanIntensity || "normal",
        scan_id: scanId,
        pipeline_mode: pipelineMode,
        os_detection: osDetection,
        phases: [1, 2],
        ...(portScanMode === "custom" ? { custom_ports: customPorts } : {}),
        ...(excludePorts && excludePorts.trim()
          ? { exclude_ports: excludePorts.trim() }
          : {}),
        ...(excludeIps && excludeIps.trim()
          ? { exclude_ips: excludeIps.trim() }
          : {}),
      });
      if (!data.success)
        throw new Error(data.error || "Port scan failed to start.");
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 4000);
      navigate("/scan/asset-discovery");
    } catch (err) {
      setError(err.message || "Failed to start Port Scan");
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setAssetLoading(false);
    }
  };

  useEffect(() => {
    // Only bounce to the scan picker when there is genuinely nothing to show.
    // While a scan id from the URL is still loading — or has failed to load, so
    // the error can be read — an empty host list is expected, not a dead end.
    if (needsHydration || hydrating || hydrateError) return;
    if (!phase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [phase1Hosts.length, navigate, needsHydration, hydrating, hydrateError]);

  const isBasicScan = pipelineMode === "basic";
  const isAssetPipeline = pipelineMode === "asset";
  const activeHosts = phase1Hosts.filter((h) => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : phase1Hosts;

  const isUnreachable =
    phase1Summary &&
    (phase1Summary.status === "unreachable" ||
      (Number(phase1Summary.active_hosts) === 0 &&
        Number(phase1Summary.total_hosts) > 0));

  const canProceedToPhase2 = isPhaseEnabled(pipelineMode, 2) && !isUnreachable;
  const nextPhase = getNextPhase(pipelineMode, 1);

  // ── Stepper: configure active step state ──
  useEffect(() => {
    if (hasPhase2) {
      if (phase2Done) {
        setPipelineState(
          pipelineMode === "asset"
            ? PIPELINE_STATES.REPORT_READY
            : PIPELINE_STATES.PORT_SCAN,
        );
      } else {
        setPipelineState(
          executionMode === "interactive"
            ? PIPELINE_STATES.IDLE
            : PIPELINE_STATES.PORT_SCAN,
        );
      }
    } else if (phase1Hosts.length > 0) {
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
    }
  }, [
    hasPhase2,
    phase2Done,
    phase1Hosts.length,
    executionMode,
    pipelineMode,
    setPipelineState,
  ]);

  // ── For pipelines with phase 2: poll the scan until Phase 2 is complete ──────────
  useEffect(() => {
    if (
      !hasPhase2 ||
      phase2Done ||
      !scanId ||
      isUnreachable ||
      executionMode === "interactive"
    )
      return;

    let stopped = false;
    setPhase2Polling(true);

    const poll = async () => {
      while (!stopped) {
        await new Promise((r) => setTimeout(r, 4000));
        if (stopped) break;
        try {
          const { data: scan } = await api.get(`/scans/${scanId}`);
          const p2 = scan?.results?.phase2?.data;
          const p2Summary = scan?.results?.phase2?.summary;
          if (Array.isArray(p2) && p2.length > 0) {
            // Save results into context so Phase2Results.jsx can read them
            setPhase2Results(p2);
            if (p2Summary) setPhase2Summary(p2Summary);
            setPhase2Done(true);
            setPhase2Polling(false);
            break;
          }
          // Also stop polling if scan has completed/failed
          if (scan?.status === "complete" || scan?.status === "failed") {
            if (Array.isArray(p2) && p2.length > 0) {
              setPhase2Results(p2);
              if (p2Summary) setPhase2Summary(p2Summary);
            }
            setPhase2Done(Array.isArray(p2) && p2.length > 0);
            setPhase2Polling(false);
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
  }, [
    hasPhase2,
    phase2Done,
    scanId,
    isUnreachable,
    executionMode,
    setPhase2Results,
    setPhase2Summary,
  ]);

  if (hydrating) {
    return (
      <AppLayout pageTitle="Discovery Results">
        <div className="p1-page">
          <h1 className="p1-title">Discovery Results</h1>
          <p className="p1-loading" role="status">
            Loading scan results…
          </p>
        </div>
      </AppLayout>
    );
  }

  if (hydrateError) {
    return (
      <AppLayout pageTitle="Discovery Results">
        <div className="p1-page">
          <h1 className="p1-title">Discovery Results</h1>
          <CcureAlert variant="danger" className="p1-alert">
            {hydrateError}
          </CcureAlert>
          <CcureButton as={Link} to="/history" variant="secondary">
            <span aria-hidden="true">←</span> Back to Scan History
          </CcureButton>
        </div>
      </AppLayout>
    );
  }

  if (!phase1Hosts.length) return null;

  const proceedToNextPhase = () => {
    if (!canExecuteScans) return;
    if (!canProceedToPhase2 || !nextPhase) return;
    navigate(nextPhase.route);
  };

  const stepperCurrent = hasPhase2
    ? phase2Done
      ? pipelineMode === "asset"
        ? 3
        : 2
      : executionMode === "interactive"
        ? 1
        : 2
    : 1;

  const portScanHeadingId = `${idBase}-port-scan`;
  const modeLabelId = `${idBase}-mode`;
  const customPortsId = `${idBase}-custom-ports`;
  const customPortsErrorId = `${idBase}-custom-ports-error`;
  const excludePortsHeadingId = `${idBase}-exclude-ports`;
  const excludePortsId = `${idBase}-exclude-ports-input`;
  const excludeIpsHeadingId = `${idBase}-exclude-ips`;
  const excludeIpsId = `${idBase}-exclude-ips-input`;
  const excludeIpsErrorId = `${idBase}-exclude-ips-error`;

  /* The scanner reports confidence as a word, not a number, so it is never
     converted to a percentage and a missing one is never 0%. */
  const OS_CONFIDENCE_TONE = {
    High: "success",
    Medium: "warning",
    Low: "neutral",
  };

  const hostColumns = [
    ...(showCheckboxes
      ? [
          {
            key: "select",
            className: "p1-col-select",
            header: (
              <input
                type="checkbox"
                className="p1-check"
                aria-label="Select all active hosts for port scan"
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
    /* Host discovery infers an OS from the responses it got. The page showed
       none of it, so a guess and an identification were equally invisible. */
    { key: "os", header: "OS (inferred)" },
    ...(!isBasicScan ? [{ key: "response", header: "Response" }] : []),
    { key: "status", header: "Status" },
  ];

  return (
    <AppLayout pageTitle="Discovery Results" saveStatus={saveStatus}>
      <ScanStepper current={stepperCurrent} />

      <div className="p1-page">
        <header className="p1-header">
          <div>
            <h1 className="p1-title">Discovery Results</h1>
            <p className="p1-subtitle">
              Target: <code className="p1-mono">{target}</code>
              {scanId && (
                <span className="p1-quiet"> · Scan No. {scanNo ?? "—"}</span>
              )}
            </p>
          </div>
          <CcureButton
            as={Link}
            to="/audit-dashboard"
            variant="ghost"
            size="sm"
          >
            <span aria-hidden="true">←</span> New Scan
          </CcureButton>
        </header>

        {error && (
          <CcureAlert variant="danger" className="p1-alert">
            {error}
          </CcureAlert>
        )}

        {isUnreachable && (
          <CcureAlert
            variant="warning"
            live={false}
            title="Host is unavailable/down/unreachable"
            className="p1-alert"
          >
            The discovery scan completed but the target did not respond. Verify
            the IP address and network connectivity before re-scanning.
          </CcureAlert>
        )}

        {phase1Summary && (
          <ul className="p1-summary">
            <li className="p1-summary__item">
              <strong>{phase1Summary.total_hosts}</strong> Total
            </li>
            <li className="p1-summary__item p1-summary__item--accent">
              <strong>{phase1Summary.active_hosts}</strong> Active
            </li>
            <li className="p1-summary__item">
              <strong>{phase1Summary.inactive_hosts}</strong> Inactive
            </li>
            <li className="p1-summary__item">
              <strong>{fmtNumber(phase1Summary.scan_duration)}s</strong>{" "}
              Duration
            </li>
            {isAssetPipeline && phase1Summary.discovery_profile && (
              <li className="p1-summary__item p1-summary__item--plain">
                <CcureBadge
                  variant={
                    phase1Summary.discovery_profile === "FAST"
                      ? "info"
                      : phase1Summary.discovery_profile === "BALANCED"
                        ? "warning"
                        : "success"
                  }
                >
                  {phase1Summary.discovery_profile}
                </CcureBadge>
              </li>
            )}
            {isAssetPipeline &&
              phase1Summary.discovery_intensity === "normal" &&
              phase1Summary.fallback_targets_count != null && (
                <li className="p1-summary__item">
                  Fallback:{" "}
                  <strong>{phase1Summary.fallback_active_hosts}</strong>/
                  {phase1Summary.fallback_targets_count} resolved
                </li>
              )}
          </ul>
        )}

        {hasPhase2 &&
          !isUnreachable &&
          (phase2Done ? (
            <CcureAlert
              variant="success"
              title="Port Scan Complete"
              className="p1-alert"
            >
              <p className="p1-done__text">
                Phase 2 finished successfully. View the full port scan results
                below.
              </p>
              <CcureButton
                as={Link}
                to="/scan/asset-discovery"
                variant="primary"
                size="sm"
              >
                View Port Scan Results <span aria-hidden="true">→</span>
              </CcureButton>
            </CcureAlert>
          ) : executionMode === "interactive" ? (
            <section
              className="p1-portscan"
              aria-labelledby={portScanHeadingId}
            >
              <div className="p1-portscan__head">
                <div>
                  <h2 id={portScanHeadingId} className="p1-portscan__title">
                    Configure &amp; Run Port Scan
                  </h2>
                  <p className="p1-portscan__text">
                    Select hosts below to probe TCP/UDP services.{" "}
                    <span role="status">
                      <strong>{selected.size}</strong> host
                      {selected.size !== 1 ? "s" : ""} selected.
                    </span>
                  </p>
                </div>
                <CcureButton
                  variant="primary"
                  onClick={runPortScan}
                  loading={assetLoading}
                  disabled={
                    selected.size === 0 ||
                    assetLoading ||
                    !canExecuteScans ||
                    (portScanMode === "custom" && !!customPortsError)
                  }
                >
                  {assetLoading ? (
                    "Starting Port Scan..."
                  ) : (
                    <>
                      Run Port Scan on Selected Hosts{" "}
                      <span aria-hidden="true">→</span>
                    </>
                  )}
                </CcureButton>
              </div>

              <div className="p1-portscan__body">
                <div className="p1-field-row">
                  <span id={modeLabelId} className="p1-label">
                    Port Scan Mode:
                  </span>
                  <div
                    className="p1-toggles"
                    role="group"
                    aria-labelledby={modeLabelId}
                  >
                    <CcureButton
                      variant="secondary"
                      size="sm"
                      className="p1-toggle"
                      aria-pressed={portScanMode === "intensity"}
                      onClick={() => {
                        setPortScanMode("intensity");
                        setCustomPortsError("");
                      }}
                    >
                      Intensity Profile
                    </CcureButton>
                    <CcureButton
                      variant="secondary"
                      size="sm"
                      className="p1-toggle"
                      aria-pressed={portScanMode === "custom"}
                      onClick={() => {
                        setPortScanMode("custom");
                        setCustomPortsError("");
                      }}
                    >
                      Custom Ports
                    </CcureButton>
                  </div>
                </div>

                {portScanMode === "intensity" ? (
                  <p className="p1-note">
                    Selected intensity:{" "}
                    <strong>
                      {portScanIntensity?.toUpperCase() || "NORMAL"}
                    </strong>{" "}
                    (change on setup screen)
                  </p>
                ) : (
                  <div className="p1-field">
                    <label htmlFor={customPortsId} className="p1-label">
                      Custom ports
                    </label>
                    <input
                      id={customPortsId}
                      type="text"
                      className="p1-input"
                      value={customPorts || ""}
                      onChange={(e) => {
                        setCustomPorts(e.target.value);
                        const { error: portErr } = parseCustomPortsJS(
                          e.target.value,
                        );
                        setCustomPortsError(portErr);
                      }}
                      placeholder="e.g. 22,80,443,8000-8100"
                      aria-invalid={customPortsError ? "true" : undefined}
                      aria-describedby={
                        customPortsError ? customPortsErrorId : undefined
                      }
                    />
                    <div
                      className="p1-chips"
                      role="group"
                      aria-label="Quick select a port list"
                    >
                      <span className="p1-hint" aria-hidden="true">
                        Quick Select:
                      </span>
                      {Object.entries(PORT_PROFILES)
                        .filter(([k]) => k !== "custom")
                        .map(([k, prof]) => (
                          <button
                            key={k}
                            type="button"
                            className="p1-chip"
                            onClick={() => {
                              setCustomPorts(prof.ports);
                              setCustomPortsError("");
                            }}
                          >
                            {prof.label.split(" ")[0]}
                          </button>
                        ))}
                    </div>
                    {customPortsError && (
                      <p id={customPortsErrorId} className="p1-error">
                        <span aria-hidden="true">⚠</span> {customPortsError}
                      </p>
                    )}
                  </div>
                )}

                <div className="p1-exclusion">
                  <div className="p1-exclusion__head">
                    <div>
                      <h3
                        id={excludePortsHeadingId}
                        className="p1-exclusion__title"
                      >
                        <span aria-hidden="true">🚫</span> Exclude Specific
                        Ports
                      </h3>
                      <p
                        id={`${excludePortsHeadingId}-hint`}
                        className="p1-hint"
                      >
                        Exclude sensitive or firewalled ports from scanning
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      role="switch"
                      className="p1-switch"
                      checked={excludePortsEnabled}
                      onChange={(e) =>
                        handleExcludeToggleChange(e.target.checked)
                      }
                      aria-labelledby={excludePortsHeadingId}
                      aria-describedby={`${excludePortsHeadingId}-hint`}
                    />
                  </div>

                  {excludePortsEnabled && (
                    <div className="p1-exclusion__body">
                      <label htmlFor={excludePortsId} className="p1-label">
                        Ports to exclude
                      </label>
                      <input
                        id={excludePortsId}
                        type="text"
                        className="p1-input"
                        value={excludePorts || ""}
                        onChange={(e) => setExcludePorts(e.target.value)}
                        placeholder="e.g. 2375,2376,6443,10250 or 80-90"
                        disabled={assetLoading || !canExecuteScans}
                      />

                      {excludeTokens.length > 0 && (
                        <ul className="p1-tags" aria-label="Excluded ports">
                          {excludeTokens.map((token, idx) => (
                            <li key={`${token}-${idx}`} className="p1-tag">
                              {token}
                              <button
                                type="button"
                                className="p1-tag__remove"
                                aria-label={`Remove ${token} from excluded ports`}
                                onClick={() => handleRemoveExcludeToken(token)}
                                disabled={assetLoading || !canExecuteScans}
                              >
                                <span aria-hidden="true">×</span>
                              </button>
                            </li>
                          ))}
                        </ul>
                      )}

                      <div className="p1-chips">
                        <span className="p1-hint">Quick:</span>
                        <button
                          type="button"
                          className="p1-chip"
                          onClick={() =>
                            setExcludePorts("2375,2376,6443,10250")
                          }
                          disabled={assetLoading || !canExecuteScans}
                        >
                          Sensitive Ports
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="p1-exclusion">
                  <div className="p1-exclusion__head">
                    <div>
                      <h3
                        id={excludeIpsHeadingId}
                        className="p1-exclusion__title"
                      >
                        <span aria-hidden="true">🚫</span> Exclude Specific IPs
                        / Subnets
                      </h3>
                      <p id={`${excludeIpsHeadingId}-hint`} className="p1-hint">
                        Exclude sensitive target hosts or subnets from scanning
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      role="switch"
                      className="p1-switch"
                      checked={excludeIpsEnabled}
                      onChange={(e) =>
                        handleExcludeIpsToggleChange(e.target.checked)
                      }
                      aria-labelledby={excludeIpsHeadingId}
                      aria-describedby={`${excludeIpsHeadingId}-hint`}
                    />
                  </div>

                  {excludeIpsEnabled && (
                    <div className="p1-exclusion__body">
                      <label htmlFor={excludeIpsId} className="p1-label">
                        IP addresses or subnets to exclude
                      </label>
                      <input
                        id={excludeIpsId}
                        type="text"
                        className="p1-input"
                        value={excludeIps || ""}
                        onChange={(e) => setExcludeIps(e.target.value)}
                        placeholder="e.g. 10.180.12.10,10.190.0.0/16"
                        disabled={assetLoading || !canExecuteScans}
                        aria-invalid={excludeIpsError ? "true" : undefined}
                        aria-describedby={
                          excludeIpsError ? excludeIpsErrorId : undefined
                        }
                      />

                      {excludeIpsError && (
                        <p id={excludeIpsErrorId} className="p1-error">
                          <span aria-hidden="true">⚠</span> {excludeIpsError}
                        </p>
                      )}
                    </div>
                  )}
                </div>

                {sensitivePortsFound && (
                  <CcureAlert
                    variant="warning"
                    title="Sensitive Ports Detected"
                    className="p1-alert"
                  >
                    Your selection includes sensitive ports (Docker API{" "}
                    <code className="p1-mono">2375/2376</code>, Kubernetes{" "}
                    <code className="p1-mono">6443/10250</code>). Scanning them
                    can trigger intrusion detection systems or crash services.
                  </CcureAlert>
                )}
              </div>
            </section>
          ) : (
            <div className="p1-running" role="status">
              <span className="p1-spinner" aria-hidden="true" />
              <div>
                <h2 className="p1-running__title">Port Scan Running…</h2>
                <p className="p1-running__text">
                  Phase 2 is running automatically in the background. This page
                  will update when it completes.
                </p>
              </div>
            </div>
          ))}

        {executionMode === "automatic" && hasPhase2 && (
          <div className="p1-pipeline">
            <div
              className={`p1-pipeline__track p1-pipeline__track--${phase2Done ? "done" : phase2Polling ? "polling" : "pending"}`}
              aria-hidden="true"
            >
              <div className="p1-pipeline__fill" />
            </div>
            <ol className="p1-pipeline__steps">
              <li className="p1-step p1-step--done">✓ Discovery</li>
              <li
                className={`p1-step p1-step--${phase2Polling ? "active" : phase2Done ? "done" : "pending"}`}
              >
                {phase2Done
                  ? "✓ Port Scan"
                  : phase2Polling
                    ? "● Port Scan"
                    : "○ Port Scan"}
              </li>
            </ol>
          </div>
        )}

        {!isAssetPipeline && (
          <div
            className="p1-filters"
            role="group"
            aria-label="Discovered hosts to show"
          >
            {[
              ["active", `Active (${activeHosts.length})`],
              ["all", `All (${phase1Hosts.length})`],
            ].map(([val, lbl]) => (
              <CcureButton
                key={val}
                variant="secondary"
                size="sm"
                className="p1-toggle"
                aria-pressed={filter === val}
                onClick={() => setFilter(val)}
              >
                {lbl}
              </CcureButton>
            ))}
          </div>
        )}

        <div className="p1-card">
          <CcureTable
            caption="Discovered hosts"
            columns={hostColumns}
            density="compact"
          >
            {(isAssetPipeline ? activeHosts : displayHosts).map((h) => {
              let displayHost = h.hostname;
              if (!displayHost || displayHost === "Unknown") {
                if (h.mdns_name) displayHost = h.mdns_name;
                else if (h.netbios_names && h.netbios_names.length)
                  displayHost = h.netbios_names[0]?.name;
              }
              displayHost = textValue(displayHost, "");

              return (
                <tr
                  key={h.ip_address}
                  className={h.is_active ? undefined : "p1-row--inactive"}
                >
                  {showCheckboxes && (
                    <td className="p1-col-select">
                      <input
                        type="checkbox"
                        className="p1-check"
                        aria-label={`Select ${h.ip_address} for port scan`}
                        checked={selected.has(h.ip_address)}
                        onChange={() => toggleHost(h.ip_address)}
                        disabled={!h.is_active || !canExecuteScans}
                      />
                    </td>
                  )}
                  <td>
                    <code className="p1-mono">{h.ip_address}</code>
                  </td>
                  <td>{displayHost || <span className="p1-quiet">—</span>}</td>
                  <td>
                    {textValue(
                      h.mac_address,
                      <span className="p1-quiet">—</span>,
                    )}
                  </td>
                  <td>
                    {textValue(h.vendor, <span className="p1-quiet">—</span>)}
                  </td>
                  <td>
                    {textValue(
                      h.discovery_method,
                      <span className="p1-quiet">—</span>,
                    )}
                  </td>
                  <td>
                    {h.os_guess ? (
                      <>
                        <span>{h.os_guess}</span>
                        {/* The strength of the inference travels with it. An
                            OS guess shown bare reads as an identification. */}
                        {h.os_confidence ? (
                          <CcureBadge
                            variant={
                              OS_CONFIDENCE_TONE[String(h.os_confidence)] ||
                              "neutral"
                            }
                            title="How strongly the scanner holds this inference."
                          >
                            {String(h.os_confidence)}
                          </CcureBadge>
                        ) : (
                          <span className="p1-quiet">
                            {" "}
                            confidence not reported
                          </span>
                        )}
                      </>
                    ) : (
                      <span className="p1-quiet">not inferred</span>
                    )}
                  </td>
                  {!isBasicScan && (
                    <td>
                      {h.response_time_ms != null ? (
                        `${fmtNumber(h.response_time_ms)} ms`
                      ) : (
                        <span className="p1-quiet">—</span>
                      )}
                    </td>
                  )}
                  <td>
                    <span
                      className={`p1-status p1-status--${h.is_active ? "up" : "down"}`}
                    >
                      <span className="p1-status__dot" aria-hidden="true" />
                      {h.is_active ? "Active" : "Inactive"}
                    </span>
                    <button
                      type="button"
                      className="p1-detailtoggle"
                      aria-expanded={openHost === h.ip_address}
                      onClick={() =>
                        setOpenHost(
                          openHost === h.ip_address ? null : h.ip_address,
                        )
                      }
                    >
                      {openHost === h.ip_address ? "Hide detail" : "Detail"}
                    </button>
                  </td>
                </tr>
              );
            })}
            {/* One detail row per open host, carrying the evidence the
                discovery phase recorded and the table has no column for. */}
            {(isAssetPipeline ? activeHosts : displayHosts)
              .filter((h) => h.ip_address === openHost)
              .map((h) => (
                <tr key={`${h.ip_address}-detail`}>
                  <td colSpan={hostColumns.length}>
                    <OsIdentification host={h} />
                    <HostMeasurements host={h} />
                    <TcpFingerprint fingerprint={h.tcp_fingerprint} />
                    <PortStates portStates={h.port_states} />
                  </td>
                </tr>
              ))}
          </CcureTable>
        </div>

        {phase1Summary ? <ScanContext summary={phase1Summary} /> : null}

        {phase1Summary && !canProceedToPhase2 && (
          <>
            <CcureAlert variant="success" live={false} className="p1-alert">
              Scan completed. Export report available below.
            </CcureAlert>
            <ExportPanel
              results={phase1Hosts}
              summary={phase1Summary}
              scanId={scanId}
              scanNo={scanNo}
              target={target}
              pipelineMode={pipelineMode}
            />
          </>
        )}

        {canProceedToPhase2 &&
          !isAssetPipeline &&
          executionMode !== "interactive" &&
          executionMode !== "automatic" && (
            <div className="p1-actions">
              <p className="p1-quiet p1-small">
                Continue to Port Scan to choose hosts and intensity on the same
                page.
              </p>
              <CcureButton
                variant="primary"
                onClick={proceedToNextPhase}
                disabled={!canExecuteScans}
              >
                Continue to Port Scan
              </CcureButton>
            </div>
          )}
      </div>
    </AppLayout>
  );
}
