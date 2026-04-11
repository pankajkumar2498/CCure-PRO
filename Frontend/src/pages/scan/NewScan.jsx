/**
 * src/pages/scan/NewScan.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Target input + scan method selector + Start button.
 *
 * API: POST /scan/host-discovery → { success, data, summary, scan_id }
 *
 * CHANGE: Now reads `pipelineMode` from ScanContext and includes
 * `phases` + `pipeline_mode` in the API payload so the backend knows
 * exactly which phases to queue for this scan session.
 *
 * On success → saves Host Discovery data to ScanContext → navigates to /scan/host-discovery
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout  from "../../components/layout/AppLayout";
import { useScan } from "../../context/ScanContext";
import { buildPhasePayload, getScanPipeline } from "../../config/scanConfig";
import api         from "../../api/axiosInstance";

const SCAN_TYPES = [
  { value: "adaptive", label: "Adaptive",  desc: "Auto-selects best method per host" },
  { value: "ping",     label: "Ping",      desc: "ICMP echo — fast, may be blocked"  },
  { value: "arp",      label: "ARP",       desc: "Layer 2 — LAN only, very accurate" },
  { value: "tcp",      label: "TCP",       desc: "Port-connect — works without root" },
  { value: "full",     label: "Full",      desc: "All methods combined"               },
  { value: "stealth",  label: "Stealth",   desc: "Fragmented packets — evasion mode" },
];

const QUICK_TARGETS = ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24", "192.168.1.1"];

export default function NewScan() {
  const navigate = useNavigate();
  const {
    target, setTarget,
    scanType, setScanType,
    pipelineMode,                             // ← read from context (set by Dashboard)
    setPhase1Hosts, setPhase1Summary,
    setScanId, setSaveStatus, resetScan,
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  // Derive display info from the current pipeline
  const pipeline = getScanPipeline(pipelineMode || "basic");

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setSaveStatus("saving");

    // NOTE: resetScan() was already called in Dashboard.handleCard before
    // navigating here, so we only need to restore target + scanType.
    setTarget(target.trim());
    setScanType(scanType);

    try {
      /**
       * Build the payload with phases array so the backend knows the full
       * pipeline for this scan session.
       *
       * Example payloads:
       *   basic:    { phases: [1],       pipeline_mode: "basic",    targets: [...], scan_type: "..." }
       *   asset:    { phases: [1, 2],    pipeline_mode: "asset",    targets: [...], scan_type: "..." }
       *   advanced: { phases: [1, 2, 3, 4], pipeline_mode: "advanced", targets: [...], scan_type: "..." }
       */
      const payload = buildPhasePayload(pipelineMode || "basic", {
        targets:   target.split(",").map(t => t.trim()).filter(Boolean),
        scan_type: scanType,
      });

      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error || "Scan failed");

      setPhase1Hosts(data.data);
      setPhase1Summary(data.summary);
      setScanId(data.scan_id ?? null);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
      navigate("/scan/host-discovery");
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Scan failed");
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppLayout pageTitle="New Scan">
      <div className="page-inner">
        <div className="new-scan-page">

          {/* Hero */}
          <div className="ns-hero">
            <button className="ns-back-btn" onClick={() => navigate("/dashboard")}>← Back</button>
            <h1 className="ns-title">{pipeline.label}</h1>
            <p className="ns-sub">
              {pipeline.description}
            </p>
          </div>

          {/* Scan card */}
          <div className="ns-card">

            {/* Target input */}
            <div className="field">
              <label>Target</label>
              <div className="target-input-wrap">
                <input
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleScan()}
                  placeholder="192.168.1.0/24   or   10.0.0.1-50   or   192.168.1.10"
                  disabled={loading}
                  autoFocus
                />
                {loading && <div className="input-loader" />}
              </div>

              {/* Quick targets */}
              <div className="quick-targets">
                <span className="qt-label">Quick:</span>
                {QUICK_TARGETS.map(t => (
                  <button key={t} className="qt-chip"
                    onClick={() => setTarget(t)} disabled={loading}>
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Scan type */}
            <div className="field">
              <label>Scan Method</label>
              <div className="scan-type-grid">
                {SCAN_TYPES.map(st => (
                  <button key={st.value}
                    className={`st-card ${scanType === st.value ? "st-card--active" : ""}`}
                    onClick={() => setScanType(st.value)}
                    disabled={loading}>
                    <span className="st-name">{st.label}</span>
                    <span className="st-desc">{st.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {error && <div className="alert alert--error">⚠ {error}</div>}

            <button
              className="btn btn--dark"
              style={{ width: "100%", justifyContent: "center", padding: "12px", fontSize: "0.95rem" }}
              onClick={handleScan}
              disabled={loading || !target.trim()}
            >
              {loading
                ? <><span className="btn-spinner" /> Discovering hosts…</>
                : "▶ Start Discovery Scan"}
            </button>
          </div>

          {/* Info cards — dynamically show only active phases for this pipeline */}
          <div className="ns-info-grid">
            {[
              { phase: 1, icon: "①", title: "Discovery",     desc: "Finds all live hosts using ARP, ICMP, or TCP probes."           },
              { phase: 2, icon: "②", title: "Port Scan",     desc: "Maps open TCP services and grabs banners from selected hosts."   },
              { phase: 3, icon: "③", title: "Vulnerability", desc: "Checks TLS, SSH, HTTP headers, CVE database, and risk scoring."  },
              { phase: 4, icon: "④", title: "Risk Report",   desc: "Aggregates findings into a scored, exportable risk report."      },
            ]
              .filter(c => pipeline.phases.includes(c.phase))
              .map(c => (
                <div key={c.title} className="ns-info-card">
                  <span className="nic-icon">{c.icon}</span>
                  <h3 className="nic-title">{c.title}</h3>
                  <p className="nic-desc">{c.desc}</p>
                </div>
              ))
            }
          </div>

        </div>
      </div>
    </AppLayout>
  );
}
