/**
 * src/pages/scan/NewScan.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Scan setup page — Target input + intensity selectors + Start button.
 *
 * API: POST /scan/host-discovery → { success, data, summary, scan_id }
 *
 * scan_type is always "adaptive" (backend default); pipeline behaviour is
 * fully determined by pipeline_mode (basic | asset | advanced).
 *
 * On success → saves Phase 1 data to ScanContext → navigates to results page.
 */
import "./NewScan.css";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout  from "../../components/layout/AppLayout";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { buildPhasePayload, getScanPipeline } from "../../config/scanConfig";
import api from "../../api/axiosInstance";

/* ── Constants ─────────────────────────────────────────────────────────────── */

const DISCOVERY_INTENSITIES = [
  {
    value:      "light",
    label:      "Light",
    icon:       "⚡",
    desc:       "Fastest — may miss firewalled hosts",
    badge:      "Fastest",
    badgeStyle: { background: "rgba(34,211,238,0.12)", color: "#22d3ee", border: "1px solid rgba(34,211,238,0.3)" },
  },
  {
    value:      "normal",
    label:      "Normal",
    icon:       "⚖",
    desc:       "Fast-first with coverage fallback",
    badge:      "Recommended",
    badgeStyle: { background: "rgba(34,197,94,0.12)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.3)" },
  },
  {
    value:      "deep",
    label:      "Deep",
    icon:       "🔬",
    desc:       "Max coverage — best for firewalled nets",
    badge:      "Thorough",
    badgeStyle: { background: "rgba(245,158,11,0.12)", color: "#d97706", border: "1px solid rgba(245,158,11,0.3)" },
  },
];

const SCAN_INTENSITIES = [
  { value: "light",  label: "Light",  icon: "🏃", desc: "Fast scan, fewer ports" },
  { value: "normal", label: "Normal", icon: "⚖",  desc: "Balanced port coverage" },
  { value: "deep",   label: "Deep",   icon: "🔭", desc: "Full port range scan"   },
];

const QUICK_TARGETS = ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24", "192.168.1.1"];

/* Map pipeline → badge styling */
const PIPELINE_BADGE = {
  basic:    { label: "Basic Scan",   cls: "ns-badge--basic"    },
  asset:    { label: "Asset Discovery", cls: "ns-badge--asset" },
  advanced: { label: "Advanced Scan",   cls: "ns-badge--advanced" },
};

/* ── Component ─────────────────────────────────────────────────────────────── */

export default function NewScan() {
  const navigate = useNavigate();
  const {
    target, setTarget,
    pipelineMode,
    intensity, setIntensity,
    discoveryIntensity, setDiscoveryIntensity,
    setPhase1Hosts, setPhase1Summary,
    setScanId, setScanNo, setSaveStatus,
    setPipelineState,
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");
  const [rateLimit, setRateLimit] = useState("");

  const pipeline  = getScanPipeline(pipelineMode || "basic");
  const badgeMeta = PIPELINE_BADGE[pipelineMode] || PIPELINE_BADGE.basic;

  /* Derived start-button label */
  const btnLabel = (() => {
    if (pipelineMode === "asset") {
      const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
      return `Start Discovery · ${cap(discoveryIntensity || "normal")}`;
    }
    return "Start Scan";
  })();

  const [scanProgress, setScanProgress] = useState(null);
  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");

  const waitForPhase1 = (scanId) => {
    console.log(`[TRACE][FRONTEND][${new Date().toISOString()}] waitForPhase1 started for scan ${scanId}`);
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`${wsPrefix}/scans/${scanId}/progress`);
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log(`[TRACE][FRONTEND][${new Date().toISOString()}] WS Message: phase=${data.phase}, status=${data.progress?.status}`);
          
          const isP1Done = (data.phase === 1 && (data.progress?.status === "complete" || data.progress?.status === "failed"));
          const isLaterPhase = (data.phase > 1);

          if (isP1Done || isLaterPhase) {
            console.log(`[TRACE][FRONTEND][${new Date().toISOString()}] Resolving waitForPhase1: isP1Done=${isP1Done}, isLaterPhase=${isLaterPhase}`);
            ws.close();
            resolve(data.progress || { status: "complete" });
          } else if (data.phase === 1) {
            setScanProgress(data.progress);
          }
        } catch (e) {
          console.error("WS parse error", e);
        }
      };
      ws.onerror = () => {
        ws.close();
        reject(new Error("Progress WebSocket failed"));
      };
      setTimeout(() => {
        ws.close();
        reject(new Error("Phase 1 timed out"));
      }, 180000);
    });
  };

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setSaveStatus("saving");
    setPipelineState(PIPELINE_STATES.DISCOVERY);
    setTarget(target.trim());

    try {
      const payload = buildPhasePayload(pipelineMode || "basic", {
        targets:   target.split(",").map(t => t.trim()).filter(Boolean),
        scan_type: "adaptive",
        ...(pipelineMode === "asset" ? { discovery_intensity: discoveryIntensity } : {}),
        ...(rateLimit ? { rate_limit: parseInt(rateLimit, 10) } : {}),
      });

      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error || "Scan failed");

      setScanId(data.scan_id ?? null);
      setScanNo(data.scan_no ?? data.display_id ?? null);

      // Wait for Phase 1 via WebSocket
      const p1Result = await waitForPhase1(data.scan_id);
      if (p1Result?.status === "failed") {
         throw new Error("Phase 1 background task failed.");
      }

      // Fetch the actual populated scan
      const { data: fullScan } = await api.get(`/scans/${data.scan_id}`);

      setPhase1Hosts(fullScan?.results?.phase1?.data || []);
      setPhase1Summary(fullScan?.results?.phase1?.summary || {});
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
      navigate(pipelineMode === "advanced" ? "/scan/advanced-scan" : "/scan/host-discovery");
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Scan failed");
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setLoading(false);
      setScanProgress(null);
    }
  };

  return (
    <AppLayout pageTitle="New Scan">
      <div className="ns-page">

        {/* ── Hero ──────────────────────────────────────────────────────── */}
        <div className="ns-hero">
          <button className="ns-back" onClick={() => navigate("/dashboard")}>
            ← Back
          </button>
          <div className={`ns-badge ${badgeMeta.cls}`}>
            {badgeMeta.label}
          </div>
          <h1 className="ns-title">{pipeline.label}</h1>
          <p className="ns-sub">{pipeline.description}</p>
        </div>

        {/* ── Card ──────────────────────────────────────────────────────── */}
        <div className="ns-card">

          {/* Target input */}
          <div className="ns-section">
            <div className="ns-label">
              Target
              <span className="ns-label-hint">IP, CIDR, or range</span>
            </div>
            <div className="ns-input-wrap">
              <span className="ns-input-icon" aria-hidden="true">🎯</span>
              <input
                id="ns-target-input"
                className="ns-input"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleScan()}
                placeholder="192.168.1.0/24   ·   10.0.0.1-50   ·   192.168.1.10"
                disabled={loading}
                autoFocus
                autoComplete="off"
                spellCheck={false}
              />
              {loading && (
                <div className="ns-input-scanning" aria-label="Scanning">
                  <span className="ns-pulse-dot" />
                  <span className="ns-pulse-dot" />
                  <span className="ns-pulse-dot" />
                </div>
              )}
            </div>

            {/* Quick targets */}
            <div className="ns-chips">
              <span className="ns-chips-label">Quick:</span>
              {QUICK_TARGETS.map(t => (
                <button
                  key={t}
                  className="ns-chip"
                  onClick={() => setTarget(t)}
                  disabled={loading}
                  title={`Use ${t}`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* ── Discovery Intensity — Asset Discovery only ─────────────── */}
          {pipelineMode === "asset" && (
            <>
              <div className="ns-divider" />
              <div className="ns-section">
                <div className="ns-label">
                  Discovery Intensity
                  <span className="ns-label-hint">Controls Phase 1 speed vs. coverage</span>
                </div>
                <div className="ns-intensity-grid">
                  {DISCOVERY_INTENSITIES.map(di => {
                    const isActive = discoveryIntensity === di.value;
                    return (
                      <button
                        key={di.value}
                        id={`discovery-intensity-${di.value}`}
                        className={[
                          "ns-int-card",
                          `ns-int--${di.value}`,
                          isActive ? "ns-int-card--active" : "",
                        ].join(" ")}
                        onClick={() => setDiscoveryIntensity(di.value)}
                        disabled={loading}
                      >
                        <span className="ns-int-icon">{di.icon}</span>
                        <span className="ns-int-name">{di.label}</span>
                        <span className="ns-int-desc">{di.desc}</span>
                        {isActive && (
                          <span className="ns-int-badge" style={di.badgeStyle}>
                            {di.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* ── Scan Intensity — Advanced Scan only ────────────────────── */}
          {pipelineMode === "advanced" && (
            <>
              <div className="ns-divider" />
              <div className="ns-section">
                <div className="ns-label">Scan Intensity</div>
                <div className="ns-intensity-grid">
                  {SCAN_INTENSITIES.map(si => {
                    const isActive = intensity === si.value;
                    return (
                      <button
                        key={si.value}
                        id={`scan-intensity-${si.value}`}
                        className={[
                          "ns-int-card",
                          `ns-int--${si.value}`,
                          isActive ? "ns-int-card--active" : "",
                        ].join(" ")}
                        onClick={() => setIntensity(si.value)}
                        disabled={loading}
                      >
                        <span className="ns-int-icon">{si.icon}</span>
                        <span className="ns-int-name">{si.label}</span>
                        <span className="ns-int-desc">{si.desc}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </>
          )}


          {/* Rate Limiting */}
          <div className="ns-divider" />
          <div className="ns-section">
            <div className="ns-label">
              Rate Limit (PPS)
              <span className="ns-label-hint">Leave blank for profile default (e.g., fast is 256)</span>
            </div>
            <div className="ns-input-wrap">
              <span className="ns-input-icon" aria-hidden="true">⏱</span>
              <input
                type="number"
                className="ns-input"
                value={rateLimit}
                onChange={e => setRateLimit(e.target.value)}
                placeholder="e.g. 500"
                disabled={loading}
              />
            </div>
          </div>

          {/* ── Basic Scan Notice ────────────────────────────────────── */}
          {pipelineMode === "basic" && (
            <>
              <div className="ns-divider" />
              <div className="ns-info-notice">
                <span className="ns-info-icon">💡</span>
                <p>
                  <strong>Basic Scan Mechanics:</strong> Uses ultra-fast <code>ARP</code> on local subnets. 
                  For routed remote subnets, it falls back to a full TCP handshake on ports 80/443/22 to bypass firewalls, which may be significantly slower.
                </p>
              </div>
            </>
          )}
          {/* Error banner */}
          {error && (
            <div className="ns-error" role="alert">
              <span className="ns-error-icon">⚠</span>
              {error}
            </div>
          )}

          <div className="ns-divider" />

          {/* Start button */}
          <button
            id="ns-start-btn"
            className={`ns-start-btn${loading ? " ns-start-btn--scanning" : ""}`}
            onClick={handleScan}
            disabled={loading || !target.trim()}
          >
            {loading ? (
              <>
                <span className="ns-spinner" />
                Discovering hosts…
              </>
            ) : (
              <>
                {btnLabel}
                <span className="ns-btn-arrow">→</span>
              </>
            )}
          </button>

        </div>{/* /ns-card */}
      </div>{/* /ns-page */}
    </AppLayout>
  );
}
