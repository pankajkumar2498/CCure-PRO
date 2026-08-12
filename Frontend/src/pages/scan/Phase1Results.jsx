/**
 * src/pages/scan/Phase1Results.jsx
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
 */
import React, { useState, useEffect } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";

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
  const canExecuteScans = can(user, "scans", "execute");
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
  const [assetLoading, setAssetLoading] = useState(false);
  const [error, setError] = useState("");
  const [customPortsError, setCustomPortsError] = useState("");

  const [excludePortsEnabled, setExcludePortsEnabled] = useState(
    () => !!excludePorts,
  );
  const [excludePortsError, setExcludePortsError] = useState("");
  const [parsedExcludePortsCount, setParsedExcludePortsCount] = useState(0);
  const [sensitivePortsFound, setSensitivePortsFound] = useState(false);

  const [excludeIpsEnabled, setExcludeIpsEnabled] = useState(
    () => !!excludeIps,
  );
  const [excludeIpsError, setExcludeIpsError] = useState("");

  const parseCustomPortsJS = (portsStr) => {
    if (!portsStr || !portsStr.trim()) {
      return { ports: [], error: "", sensitiveFound: false };
    }
    const clean = portsStr.replace(/\s+/g, "");
    if (!/^[0-9,\-]+$/.test(clean)) {
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
    if (!/^[0-9,\-]+$/.test(clean)) {
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

  const isValidIPv4 = (ip) => {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every((p) => {
      const num = Number(p);
      return (
        p !== "" && !isNaN(num) && num >= 0 && num <= 255 && String(num) === p
      );
    });
  };

  const isValidIPv6 = (ip) => {
    if (!ip.includes(":")) return false;
    return (
      /^[0-9a-fA-F:]+$/.test(ip) &&
      !ip.includes(":::") &&
      (ip.match(/:/g) || []).length <= 7
    );
  };

  const isValidCIDR = (cidr) => {
    if (!cidr.includes("/")) return false;
    const parts = cidr.split("/");
    const [ip, maskStr] = parts;
    const mask = Number(maskStr);
    if (isNaN(mask) || maskStr === "") return false;
    if (isValidIPv4(ip)) return mask >= 0 && mask <= 32;
    if (isValidIPv6(ip)) return mask >= 0 && mask <= 128;
    return false;
  };

  const ipToLong = (ip) => {
    return (
      ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0
    );
  };

  const isValidRange = (range) => {
    if (!range.includes("-")) return false;
    const parts = range.split("-");
    if (parts.length !== 2) return false;
    const [start, end] = parts.map((p) => p.trim());
    if (!isValidIPv4(start)) return false;
    if (isValidIPv4(end)) {
      return ipToLong(start) <= ipToLong(end);
    } else if (/^\d+$/.test(end)) {
      const endOctet = Number(end);
      const startParts = start.split(".");
      const startOctet = Number(startParts[3]);
      return endOctet >= startOctet && endOctet <= 255;
    }
    return false;
  };

  const isValidHostname = (host) => {
    if (host.length > 253) return false;
    return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(
      host,
    );
  };

  const parseExcludeIpsJS = (ipsStr) => {
    if (!ipsStr || !ipsStr.trim()) {
      return { ips: [], error: "" };
    }
    const clean = ipsStr.replace(/\s+/g, "");
    const tokens = clean.split(",");
    const ipsArray = [];
    for (const token of tokens) {
      if (!token) continue;
      const isValid =
        isValidIPv4(token) ||
        isValidIPv6(token) ||
        isValidCIDR(token) ||
        isValidRange(token) ||
        isValidHostname(token);
      if (!isValid) {
        return {
          ips: [],
          error: `Invalid IP, range, or CIDR format: "${token}"`,
        };
      }
      ipsArray.push(token);
    }
    return { ips: ipsArray, error: "" };
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
      const { error, sensitiveFound } = parseCustomPortsJS(customPorts);
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
        <div className="page-inner">
          <p className="page-subtitle">Loading scan results…</p>
        </div>
      </AppLayout>
    );
  }

  if (hydrateError) {
    return (
      <AppLayout pageTitle="Discovery Results">
        <div className="page-inner">
          <div className="alert alert--error" style={{ margin: "16px 0" }}>
            ⚠ {hydrateError}
          </div>
          <button
            className="btn btn--ghost"
            onClick={() => navigate("/history")}
          >
            ← Back to Scan History
          </button>
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

  return (
    <AppLayout pageTitle="Discovery Results" saveStatus={saveStatus}>
      <ScanStepper current={stepperCurrent} />

      <div className="page-inner">
        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Discovery Results</h2>
            <p className="page-subtitle">
              Target: <code className="ip-code">{target}</code>
              {scanId && (
                <span className="muted"> · Scan No. {scanNo ?? "—"}</span>
              )}
            </p>
          </div>
          <button
            className="btn btn--ghost"
            onClick={() => navigate("/dashboard")}
          >
            ← New Scan
          </button>
        </div>

        {error && (
          <div className="alert alert--error" style={{ margin: "16px 0" }}>
            ⚠ {error}
          </div>
        )}

        {/* ── Unreachable Banner ───────────────────────────────────────────── */}
        {isUnreachable && (
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
                The discovery scan completed but the target did not respond.
                Verify the IP address and network connectivity before
                re-scanning.
              </p>
            </div>
          </div>
        )}

        {/* ── Phase 1 summary bar ──────────────────────────────────────────── */}
        {phase1Summary && (
          <div className="summary-bar">
            <span className="summary-item">
              <b>{phase1Summary.total_hosts}</b> Total
            </span>
            <span className="summary-item summary-item--active">
              <b>{phase1Summary.active_hosts}</b> Active
            </span>
            <span className="summary-item">
              <b>{phase1Summary.inactive_hosts}</b> Inactive
            </span>
            <span className="summary-item">
              <b>{fmtNumber(phase1Summary.scan_duration)}s</b> Duration
            </span>
            {isAssetPipeline && phase1Summary.discovery_profile && (
              <span className="summary-item" style={{ gap: 6 }}>
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: 10,
                    background:
                      phase1Summary.discovery_profile === "FAST"
                        ? "rgba(34,211,238,0.12)"
                        : phase1Summary.discovery_profile === "BALANCED"
                          ? "rgba(245,158,11,0.12)"
                          : "rgba(34,197,94,0.12)",
                    color:
                      phase1Summary.discovery_profile === "FAST"
                        ? "#22d3ee"
                        : phase1Summary.discovery_profile === "BALANCED"
                          ? "#f59e0b"
                          : "#22c55e",
                    border:
                      phase1Summary.discovery_profile === "FAST"
                        ? "1px solid rgba(34,211,238,0.3)"
                        : phase1Summary.discovery_profile === "BALANCED"
                          ? "1px solid rgba(245,158,11,0.3)"
                          : "1px solid rgba(34,197,94,0.3)",
                  }}
                >
                  {phase1Summary.discovery_profile}
                </span>
              </span>
            )}
            {isAssetPipeline &&
              phase1Summary.discovery_intensity === "normal" &&
              phase1Summary.fallback_targets_count != null && (
                <span
                  className="summary-item"
                  style={{ fontSize: 12, color: "var(--text-muted)" }}
                >
                  Fallback: <b>{phase1Summary.fallback_active_hosts}</b>/
                  {phase1Summary.fallback_targets_count} resolved
                </span>
              )}
          </div>
        )}

        {/* ── Port Scan Phase Banners & Controls ── */}
        {hasPhase2 && !isUnreachable && (
          <div style={{ margin: "16px 0" }}>
            {phase2Done ? (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  padding: "14px 20px",
                  borderRadius: 8,
                  background: "rgba(34,197,94,0.08)",
                  border: "1px solid rgba(34,197,94,0.3)",
                }}
              >
                <span style={{ fontSize: 22 }}>✅</span>
                <div style={{ flex: 1 }}>
                  <strong style={{ display: "block", color: "#15803d" }}>
                    Port Scan Complete
                  </strong>
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    Phase 2 finished successfully. View the full port scan
                    results below.
                  </span>
                </div>
                <button
                  className="btn btn--primary"
                  onClick={() => navigate("/scan/asset-discovery")}
                >
                  View Port Scan Results →
                </button>
              </div>
            ) : executionMode === "interactive" ? (
              <div
                style={{
                  padding: "20px",
                  borderRadius: 8,
                  background: "var(--bg-card)",
                  border: "1px solid var(--border)",
                  display: "flex",
                  flexDirection: "column",
                  gap: 16,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    gap: 16,
                  }}
                >
                  <div>
                    <strong
                      style={{
                        display: "block",
                        color: "var(--text)",
                        fontSize: "1.1rem",
                      }}
                    >
                      Configure & Run Port Scan
                    </strong>
                    <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                      Select hosts below to probe TCP/UDP services.{" "}
                      <b>{selected.size}</b> host
                      {selected.size !== 1 ? "s" : ""} selected.
                    </span>
                  </div>
                  <button
                    className="btn btn--primary"
                    onClick={runPortScan}
                    disabled={
                      selected.size === 0 ||
                      assetLoading ||
                      !canExecuteScans ||
                      (portScanMode === "custom" && !!customPortsError)
                    }
                    style={{ display: "flex", alignItems: "center", gap: 8 }}
                  >
                    {assetLoading ? (
                      <>
                        <span
                          className="btn-spinner"
                          style={{ width: 14, height: 14, borderWidth: 2 }}
                        />
                        Starting Port Scan...
                      </>
                    ) : (
                      <>Run Port Scan on Selected Hosts →</>
                    )}
                  </button>
                </div>

                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 12,
                    borderTop: "1px solid var(--border)",
                    paddingTop: 16,
                  }}
                >
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 16 }}
                  >
                    <span
                      style={{
                        fontSize: 13,
                        fontWeight: "600",
                        color: "var(--text)",
                      }}
                    >
                      Port Scan Mode:
                    </span>
                    <div
                      style={{
                        display: "flex",
                        background: "rgba(255,255,255,0.05)",
                        borderRadius: "6px",
                        padding: "2px",
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setPortScanMode("intensity");
                          setCustomPortsError("");
                        }}
                        style={{
                          background:
                            portScanMode === "intensity"
                              ? "var(--btn-primary-bg, #3b82f6)"
                              : "transparent",
                          color:
                            portScanMode === "intensity"
                              ? "#ffffff"
                              : "var(--text-muted)",
                          border: "none",
                          borderRadius: "4px",
                          padding: "4px 12px",
                          fontSize: "0.8rem",
                          fontWeight: "600",
                          cursor: "pointer",
                          transition: "all 0.15s ease",
                        }}
                      >
                        Intensity Profile
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setPortScanMode("custom");
                          setCustomPortsError("");
                        }}
                        style={{
                          background:
                            portScanMode === "custom"
                              ? "var(--btn-primary-bg, #3b82f6)"
                              : "transparent",
                          color:
                            portScanMode === "custom"
                              ? "#ffffff"
                              : "var(--text-muted)",
                          border: "none",
                          borderRadius: "4px",
                          padding: "4px 12px",
                          fontSize: "0.8rem",
                          fontWeight: "600",
                          cursor: "pointer",
                          transition: "all 0.15s ease",
                        }}
                      >
                        Custom Ports
                      </button>
                    </div>
                  </div>

                  {portScanMode === "intensity" ? (
                    <div
                      style={{
                        fontSize: 13,
                        color: "var(--text-muted)",
                        background: "rgba(255,255,255,0.02)",
                        padding: "10px 14px",
                        borderRadius: "6px",
                        border: "1px dashed var(--border)",
                      }}
                    >
                      Selected intensity:{" "}
                      <span style={{ fontWeight: "700", color: "var(--text)" }}>
                        {portScanIntensity?.toUpperCase() || "NORMAL"}
                      </span>{" "}
                      (change on setup screen)
                    </div>
                  ) : (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 8,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          gap: 10,
                          alignItems: "center",
                        }}
                      >
                        <input
                          type="text"
                          className="ns-input"
                          style={{
                            flex: 1,
                            padding: "8px 12px",
                            borderRadius: "6px",
                            border: "1px solid var(--border)",
                            background: "rgba(0,0,0,0.2)",
                            color: "var(--text)",
                            fontSize: "0.88rem",
                          }}
                          value={customPorts || ""}
                          onChange={(e) => {
                            setCustomPorts(e.target.value);
                            const { error: portErr } = parseCustomPortsJS(
                              e.target.value,
                            );
                            setCustomPortsError(portErr);
                          }}
                          placeholder="e.g. 22,80,443,8000-8100"
                        />
                      </div>

                      <div
                        className="ns-chips"
                        style={{
                          display: "flex",
                          gap: 8,
                          alignItems: "center",
                        }}
                      >
                        <span
                          style={{
                            fontSize: 12,
                            color: "var(--text-muted)",
                            marginRight: 4,
                          }}
                        >
                          Quick Select:
                        </span>
                        {Object.entries(PORT_PROFILES)
                          .filter(([k]) => k !== "custom")
                          .map(([k, prof]) => (
                            <button
                              key={k}
                              type="button"
                              className="ns-chip"
                              onClick={() => {
                                setCustomPorts(prof.ports);
                                setCustomPortsError("");
                              }}
                              style={{
                                padding: "3px 8px",
                                fontSize: "0.75rem",
                              }}
                            >
                              {prof.label.split(" ")[0]}
                            </button>
                          ))}
                      </div>

                      {customPortsError && (
                        <div
                          style={{
                            color: "#ef4444",
                            fontSize: "0.8rem",
                            marginTop: 4,
                          }}
                        >
                          ⚠ {customPortsError}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Exclude Ports Section */}
                  <div
                    style={{
                      borderTop: "1px solid var(--border)",
                      paddingTop: 16,
                      marginTop: 8,
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                      }}
                    >
                      <div>
                        <strong
                          style={{
                            display: "block",
                            color: "var(--text)",
                            fontSize: "0.9rem",
                          }}
                        >
                          🚫 Exclude Specific Ports
                        </strong>
                        <span
                          style={{ fontSize: 12, color: "var(--text-muted)" }}
                        >
                          Exclude sensitive or firewalled ports from scanning
                        </span>
                      </div>
                      <div className="ns-switch-wrapper">
                        <label className="ns-switch">
                          <input
                            type="checkbox"
                            checked={excludePortsEnabled}
                            onChange={(e) =>
                              handleExcludeToggleChange(e.target.checked)
                            }
                          />
                          <span className="ns-slider round"></span>
                        </label>
                      </div>
                    </div>

                    {excludePortsEnabled && (
                      <div
                        style={{
                          marginTop: "12px",
                          display: "flex",
                          flexDirection: "column",
                          gap: 8,
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            gap: 10,
                            alignItems: "center",
                          }}
                        >
                          <input
                            type="text"
                            className="ns-input"
                            style={{
                              flex: 1,
                              padding: "8px 12px",
                              borderRadius: "6px",
                              border: "1px solid var(--border)",
                              background: "rgba(0,0,0,0.2)",
                              color: "var(--text)",
                              fontSize: "0.88rem",
                            }}
                            value={excludePorts || ""}
                            onChange={(e) => setExcludePorts(e.target.value)}
                            placeholder="e.g. 2375,2376,6443,10250 or 80-90"
                            disabled={assetLoading || !canExecuteScans}
                          />
                        </div>

                        {excludeTokens.length > 0 && (
                          <div
                            className="ns-exclude-tags-wrap"
                            style={{
                              display: "flex",
                              flexWrap: "wrap",
                              gap: "6px",
                            }}
                          >
                            {excludeTokens.map((token, idx) => (
                              <span
                                key={`${token}-${idx}`}
                                className="ns-exclude-tag"
                              >
                                {token}
                                <button
                                  type="button"
                                  className="ns-exclude-tag-remove"
                                  onClick={() =>
                                    handleRemoveExcludeToken(token)
                                  }
                                  disabled={assetLoading || !canExecuteScans}
                                >
                                  ×
                                </button>
                              </span>
                            ))}
                          </div>
                        )}

                        <div
                          className="ns-chips"
                          style={{
                            display: "flex",
                            gap: 8,
                            alignItems: "center",
                          }}
                        >
                          <span
                            style={{
                              fontSize: 12,
                              color: "var(--text-muted)",
                              marginRight: 4,
                            }}
                          >
                            Quick:
                          </span>
                          <button
                            type="button"
                            className="ns-chip"
                            onClick={() =>
                              setExcludePorts("2375,2376,6443,10250")
                            }
                            disabled={assetLoading || !canExecuteScans}
                            style={{ padding: "3px 8px", fontSize: "0.75rem" }}
                          >
                            Sensitive Ports
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Exclude IPs Section */}
                  <div
                    style={{
                      borderTop: "1px solid var(--border)",
                      paddingTop: 16,
                      marginTop: 8,
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                      }}
                    >
                      <div>
                        <strong
                          style={{
                            display: "block",
                            color: "var(--text)",
                            fontSize: "0.9rem",
                          }}
                        >
                          🚫 Exclude Specific IPs / Subnets
                        </strong>
                        <span
                          style={{ fontSize: 12, color: "var(--text-muted)" }}
                        >
                          Exclude sensitive target hosts or subnets from
                          scanning
                        </span>
                      </div>
                      <div className="ns-switch-wrapper">
                        <label className="ns-switch">
                          <input
                            type="checkbox"
                            checked={excludeIpsEnabled}
                            onChange={(e) =>
                              handleExcludeIpsToggleChange(e.target.checked)
                            }
                          />
                          <span className="ns-slider round"></span>
                        </label>
                      </div>
                    </div>

                    {excludeIpsEnabled && (
                      <div
                        style={{
                          marginTop: "12px",
                          display: "flex",
                          flexDirection: "column",
                          gap: 8,
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            gap: 10,
                            alignItems: "center",
                          }}
                        >
                          <input
                            type="text"
                            className="ns-input"
                            style={{
                              flex: 1,
                              padding: "8px 12px",
                              borderRadius: "6px",
                              border: "1px solid var(--border)",
                              background: "rgba(0,0,0,0.2)",
                              color: "var(--text)",
                              fontSize: "0.88rem",
                            }}
                            value={excludeIps || ""}
                            onChange={(e) => setExcludeIps(e.target.value)}
                            placeholder="e.g. 10.180.12.10,10.190.0.0/16"
                            disabled={assetLoading || !canExecuteScans}
                          />
                        </div>

                        {excludeIpsError && (
                          <div
                            style={{
                              color: "#ef4444",
                              fontSize: "0.8rem",
                              marginTop: 4,
                            }}
                          >
                            ⚠ {excludeIpsError}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Sensitive Ports Warning Banner */}
                  {sensitivePortsFound && (
                    <div
                      className="ns-sensitive-banner"
                      style={{
                        marginTop: "12px",
                        background: "rgba(245,158,11,0.08)",
                        borderLeft: "3px solid #f59e0b",
                        color: "#fbbf24",
                        padding: "12px",
                        borderRadius: "8px",
                        fontSize: "0.85rem",
                      }}
                    >
                      <div style={{ fontWeight: "600", marginBottom: "4px" }}>
                        ⚠️ Sensitive Ports Detected
                      </div>
                      <p style={{ margin: 0, color: "#d4d4d8" }}>
                        Your selection includes sensitive ports (Docker API{" "}
                        <code>2375/2376</code>, Kubernetes{" "}
                        <code>6443/10250</code>). Scanning them can trigger
                        intrusion detection systems or crash services.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  padding: "14px 20px",
                  borderRadius: 8,
                  background: "rgba(99,102,241,0.08)",
                  border: "1px solid rgba(99,102,241,0.3)",
                }}
              >
                <span
                  className="btn-spinner"
                  style={{
                    width: 20,
                    height: 20,
                    borderWidth: 3,
                    flexShrink: 0,
                  }}
                />
                <div>
                  <strong style={{ display: "block", color: "#6366f1" }}>
                    Port Scan Running…
                  </strong>
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    Phase 2 is running automatically in the background. This
                    page will update when it completes.
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Sub-progress bar (automatic mode only) ── */}
        {executionMode === "automatic" && hasPhase2 && (
          <div className="asset-pipeline-progress">
            <div className="app-progress-track">
              <div
                className={`app-progress-fill ${phase2Polling ? "app-progress-fill--animated" : ""}`}
                style={{
                  width: phase2Done ? "100%" : phase2Polling ? "65%" : "50%",
                }}
              />
            </div>
            <div className="app-progress-labels">
              <span className="app-progress-label app-progress-label--done">
                ✓ Discovery
              </span>
              <span
                className={`app-progress-label ${phase2Polling ? "app-progress-label--active" : phase2Done ? "app-progress-label--done" : "app-progress-label--pending"}`}
              >
                {phase2Done
                  ? "✓ Port Scan"
                  : phase2Polling
                    ? "● Port Scan"
                    : "○ Port Scan"}
              </span>
            </div>
          </div>
        )}

        {/* ── Filter tabs (non-asset pipelines) ────────────────────────────── */}
        {!isAssetPipeline && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 12,
              flexWrap: "wrap",
            }}
          >
            <div className="filter-tabs">
              {[
                ["active", `Active (${activeHosts.length})`],
                ["all", `All (${phase1Hosts.length})`],
              ].map(([val, lbl]) => (
                <button
                  key={val}
                  className={`filter-tab ${filter === val ? "filter-tab--active" : ""}`}
                  onClick={() => setFilter(val)}
                >
                  {lbl}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ── Discovery hosts table ─────────────────────────────────────────── */}
        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                {showCheckboxes && (
                  <th style={{ width: 40, paddingRight: 0 }}>
                    <input
                      type="checkbox"
                      checked={
                        activeHosts.length > 0 &&
                        activeHosts.every((h) => selected.has(h.ip_address))
                      }
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelected(
                            new Set(activeHosts.map((h) => h.ip_address)),
                          );
                        } else {
                          setSelected(new Set());
                        }
                      }}
                      disabled={!canExecuteScans}
                      style={{ cursor: "pointer" }}
                    />
                  </th>
                )}
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>Method</th>
                {!isBasicScan && <th>Response</th>}
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(isAssetPipeline ? activeHosts : displayHosts).map((h) => {
                let displayHost = h.hostname;
                if (!displayHost || displayHost === "Unknown") {
                  if (h.mdns_name) displayHost = h.mdns_name;
                  else if (h.netbios_names && h.netbios_names.length)
                    displayHost = h.netbios_names[0]?.name;
                }
                displayHost = textValue(displayHost, "");

                return (
                  <React.Fragment key={h.ip_address}>
                    <tr
                      className={h.is_active ? "row--active" : "row--inactive"}
                    >
                      {showCheckboxes && (
                        <td style={{ paddingRight: 0 }}>
                          <input
                            type="checkbox"
                            checked={selected.has(h.ip_address)}
                            onChange={() => toggleHost(h.ip_address)}
                            disabled={!h.is_active || !canExecuteScans}
                            style={{ cursor: "pointer" }}
                          />
                        </td>
                      )}
                      <td>
                        <code className="ip-code">{h.ip_address}</code>
                      </td>
                      <td>{displayHost || <span className="muted">—</span>}</td>
                      <td>
                        {textValue(
                          h.mac_address,
                          <span className="muted">—</span>,
                        )}
                      </td>
                      <td>
                        {textValue(h.vendor, <span className="muted">—</span>)}
                      </td>
                      <td>
                        {textValue(
                          h.discovery_method,
                          <span className="muted">—</span>,
                        )}
                      </td>
                      {!isBasicScan && (
                        <td>
                          {h.response_time_ms != null ? (
                            `${fmtNumber(h.response_time_ms)} ms`
                          ) : (
                            <span className="muted">—</span>
                          )}
                        </td>
                      )}
                      <td>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 6,
                            fontSize: 12,
                            fontWeight: 600,
                            padding: h.is_active ? "2px 8px" : "2px 6px",
                            background: h.is_active
                              ? "rgba(34,197,94,0.1)"
                              : "transparent",
                            color: h.is_active ? "#15803d" : "inherit",
                            borderRadius: 12,
                          }}
                        >
                          <span
                            className={`status-dot ${h.is_active ? "status-dot--up" : "status-dot--down"}`}
                            style={{ margin: 0 }}
                          />
                          {h.is_active ? "Active" : "Inactive"}
                        </span>
                      </td>
                    </tr>
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* ── Basic Scan: completion + export ──────────────────────────────── */}
        {phase1Summary && !canProceedToPhase2 && (
          <>
            <div
              className="alert alert--success"
              style={{ marginTop: 20, marginBottom: 8 }}
            >
              ✓ Scan completed. Export report available below.
            </div>
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

        {/* ── Vulnerability Audit pipeline: proceed button ─────────────────── */}
        {canProceedToPhase2 &&
          !isAssetPipeline &&
          executionMode !== "interactive" &&
          executionMode !== "automatic" && (
            <div className="phase-action-bar">
              <p className="muted" style={{ fontSize: "0.85rem" }}>
                Continue to Port Scan to choose hosts and intensity on the same
                page.
              </p>
              <button
                className="btn btn--primary"
                onClick={proceedToNextPhase}
                disabled={!canExecuteScans}
              >
                Continue to Port Scan
              </button>
            </div>
          )}
      </div>
    </AppLayout>
  );
}
