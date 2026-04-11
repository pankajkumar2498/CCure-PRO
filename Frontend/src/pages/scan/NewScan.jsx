/**
 * src/pages/scan/NewScan.jsx
 * Target input + scan method selector + Start button.
 * API: POST /scan/phase1 → { success, data, summary, scan_id }
 * On success → saves to ScanContext → navigates to /scan/phase1
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout  from "../../components/layout/AppLayout";
import { useScan } from "../../context/ScanContext";
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
    setPhase1Hosts, setPhase1Summary,
    setScanId, setSaveStatus, resetScan,
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true); setError("");
    resetScan();
    setTarget(target.trim());
    setScanType(scanType);
    setSaveStatus("saving");

    try {
      const { data } = await api.post("/scan/phase1", {
        targets:   target.split(",").map(t => t.trim()).filter(Boolean),
        scan_type: scanType,
      });
      if (!data.success) throw new Error(data.error || "Scan failed");

      setPhase1Hosts(data.data);
      setPhase1Summary(data.summary);
      setScanId(data.scan_id ?? null);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
      navigate("/scan/phase1");
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
            <h1 className="ns-title">Network Intelligence Scan</h1>
            <p className="ns-sub">
              Enter a target to begin phase-selective discovery, port mapping, and vulnerability audit.
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

          {/* Info cards */}
          <div className="ns-info-grid">
            {[
              { icon: "①", title: "Discovery",    desc: "Finds all live hosts using ARP, ICMP, or TCP probes."            },
              { icon: "②", title: "Port Scan",    desc: "Maps open TCP services and grabs banners from selected hosts."    },
              { icon: "③", title: "Vulnerability",desc: "Checks TLS, SSH, HTTP headers, CVE database, and risk scoring."  },
            ].map(c => (
              <div key={c.title} className="ns-info-card">
                <span className="nic-icon">{c.icon}</span>
                <h3 className="nic-title">{c.title}</h3>
                <p className="nic-desc">{c.desc}</p>
              </div>
            ))}
          </div>

        </div>
      </div>
    </AppLayout>
  );
}
