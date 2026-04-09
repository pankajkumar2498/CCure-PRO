/**
 * src/components/scan/PhaseThree.jsx
 * Receives hosts + scanId → POST /scan/phase3 → vuln/risk audit.
 * Calls onComplete() when done so Dashboard updates save status.
 */
import { useState } from "react";
import api from "../../api/axiosInstance";
import RiskBadge from "./RiskBadge";

const SEV_COLOR = {
  Critical: "#ff4d4d", High: "#f97316",
  Medium: "#f59e0b", Low: "#22c55e", Info: "#60a5fa",
};

export default function PhaseThree({ hosts, scanId, onBack, onRestart, onComplete, onSaving }) {
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");
  const [results, setResults]   = useState([]);
  const [summary, setSummary]   = useState(null);
  const [expanded, setExpanded] = useState(new Set());

  const runScan = async () => {
    setLoading(true); setError(""); setResults([]); setSummary(null);
    onSaving?.();
    try {
      const { data } = await api.post("/scan/phase3", {
        hosts,
        scan_id: scanId,    // ← backend marks scan complete in DB
      });
      if (!data.success) throw new Error(data.error || "Phase 3 failed");
      setResults(data.data);
      setSummary(data.summary);
      setExpanded(new Set(data.data.filter(h => h.is_active).map(h => h.ip_address)));
      onComplete?.();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Phase 3 failed");
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = ip => {
    const next = new Set(expanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setExpanded(next);
  };

  return (
    <div className="phase-panel">
      <div className="phase-controls">
        <div className="info-pill">
          <span className="muted">Deep auditing</span>
          <b>{hosts.length}</b>
          <span className="muted">host{hosts.length !== 1 ? "s" : ""}</span>
        </div>
        <button className="phase-btn phase-btn--ghost" onClick={onBack}>← Back</button>
        <button className="phase-btn phase-btn--danger" onClick={runScan} disabled={loading}>
          {loading ? <span className="btn-spinner" /> : "⚡ Run Vulnerability Audit"}
        </button>
      </div>

      {loading && (
        <div className="scan-progress">
          <div className="progress-bar"><div className="progress-fill" /></div>
          <p className="muted" style={{ marginTop: 10, fontSize: 13 }}>
            Running CVE checks, TLS inspection, SSH audit… this may take 30–60 seconds per host.
          </p>
        </div>
      )}

      {error && <div className="scan-error">⚠ {error}</div>}

      {summary && (
        <div className="summary-bar">
          <span className="sb-item"><b>{summary.total_hosts}</b> Audited</span>
          <span className="sb-item" style={{ color:"#ff4d4d" }}><b>{summary.critical_hosts}</b> Critical</span>
          <span className="sb-item" style={{ color:"#f97316" }}><b>{summary.high_risk_hosts}</b> High</span>
          <span className="sb-item"><b>{summary.scan_duration?.toFixed(1)}s</b> Duration</span>
          {scanId && (
            <span className="sb-item" style={{ color:"var(--ok)" }}>
              ✓ Scan #{scanId} complete
            </span>
          )}
        </div>
      )}

      {results.filter(h => h.is_active).map(h => (
        <div key={h.ip_address}
          className={`vuln-card risk-border-${h.host_risk_level?.toLowerCase() || "info"}`}>

          <div className="vc-header" onClick={() => toggleExpand(h.ip_address)}>
            <div className="vc-title">
              <code className="ip">{h.ip_address}</code>
              {h.hostname !== "Unknown" && <span className="muted small"> {h.hostname}</span>}
            </div>
            <div className="vc-right">
              <RiskBadge level={h.host_risk_level} score={h.host_risk_score} />
              {h.cves?.length > 0 && (
                <span className="cve-count">{h.cves.length} CVE{h.cves.length > 1 ? "s" : ""}</span>
              )}
            </div>
            <div className="vc-right">
              <RiskBadge level={h.host_risk_level} score={h.host_risk_score} />
              {h.cves?.length > 0 && (
                <span className="cve-count">{h.cves.length} CVE{h.cves.length > 1 ? "s" : ""}</span>
              )}
              <button className="expand-btn">
                {expanded.has(h.ip_address) ? "▲" : "▼"}
              </button>
            </div>
          </div>

          {expanded.has(h.ip_address) && (
            <div className="vc-body">

              {/* ── Risk score bar ── */}
              {h.host_risk_score > 0 && (
                <div className="risk-section">
                  <div className="risk-bar-wrap">
                    <div className="risk-bar-track">
                      <div
                        className="risk-bar-fill"
                        style={{
                          width: `${h.host_risk_score}%`,
                          background: SEV_COLOR[h.host_risk_level] || "#60a5fa",
                        }}
                      />
                    </div>
                    <span className="risk-label">{h.host_risk_score}/100</span>
                  </div>
                </div>
              )}

              {/* ── CVEs ── */}
              {h.cves?.length > 0 && (
                <div className="audit-section">
                  <h4 className="section-title">⚠ CVE Findings</h4>
                  <div className="cve-list">
                    {h.cves.map((cve, i) => (
                      <div key={i} className="cve-row">
                        <span className="cve-id"
                          style={{ color: SEV_COLOR[cve.severity] || "#60a5fa" }}>
                          {cve.cve_id}
                        </span>
                        <span className="cve-sev" style={{ color: SEV_COLOR[cve.severity] }}>
                          {cve.severity}
                        </span>
                        <span className="cve-desc">{cve.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Open ports (re-displayed with risk) ── */}
              {h.open_ports?.length > 0 && (
                <div className="audit-section">
                  <h4 className="section-title">🔌 Open Ports</h4>
                  <div className="mini-ports">
                    {h.open_ports.map((p, i) => (
                      <span key={i} className="port-pill"
                        style={{ borderColor: SEV_COLOR[p.risk] || "#1a2a3a" }}>
                        <code>{p.port}</code> {p.service}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ── TLS ── */}
              {h.tls_info && Object.keys(h.tls_info).length > 0 && h.tls_info.enabled && (
                <div className="audit-section">
                  <h4 className="section-title">🔒 TLS / SSL</h4>
                  <div className="kv-grid">
                    {h.tls_info.version && <KV k="Version" v={h.tls_info.version} />}
                    {h.tls_info.cipher  && <KV k="Cipher"  v={h.tls_info.cipher} />}
                    {h.tls_info.score   && <KV k="Grade"   v={h.tls_info.score} />}
                    {h.tls_info.cert_subject && <KV k="Subject" v={h.tls_info.cert_subject} />}
                    {h.tls_info.cert_expiry  && <KV k="Expiry"  v={h.tls_info.cert_expiry} />}
                    {h.tls_info.cert_expired !== undefined && (
                      <KV k="Expired" v={h.tls_info.cert_expired ? "⚠ YES" : "No"}
                        danger={h.tls_info.cert_expired} />
                    )}
                    {h.tls_info.cert_self_signed !== undefined && (
                      <KV k="Self-signed" v={h.tls_info.cert_self_signed ? "Yes" : "No"}
                        warn={h.tls_info.cert_self_signed} />
                    )}
                    {h.tls_info.weak_cipher && <KV k="Weak cipher" v="⚠ Detected" danger />}
                  </div>
                </div>
              )}

              {/* ── SSH ── */}
              {h.ssh_info && Object.keys(h.ssh_info).length > 0 && (
                <div className="audit-section">
                  <h4 className="section-title">🖥 SSH</h4>
                  <div className="kv-grid">
                    {h.ssh_info.version && <KV k="Version" v={h.ssh_info.version} />}
                    {h.ssh_info.banner  && <KV k="Banner"  v={h.ssh_info.banner} />}
                  </div>
                </div>
              )}

              {/* ── HTTP Audit ── */}
              {h.http_audit && Object.keys(h.http_audit).length > 0 && h.http_audit.status_code > 0 && (
                <div className="audit-section">
                  <h4 className="section-title">🌐 HTTP Security Headers</h4>
                  <div className="kv-grid">
                    <KV k="Status"     v={h.http_audit.status_code} />
                    {h.http_audit.server_header && <KV k="Server" v={h.http_audit.server_header} />}
                    <KV k="HSTS"           v={h.http_audit.hsts ? "✓" : "✗ Missing"} danger={!h.http_audit.hsts} />
                    <KV k="CSP"            v={h.http_audit.csp  ? "✓" : "✗ Missing"} danger={!h.http_audit.csp} />
                    <KV k="X-Frame"        v={h.http_audit.x_frame || "✗ Missing"} danger={!h.http_audit.x_frame} />
                    <KV k="X-Content-Type" v={h.http_audit.x_content_type ? "✓" : "✗ Missing"} danger={!h.http_audit.x_content_type} />
                  </div>
                  {h.http_audit.issues?.length > 0 && (
                    <ul className="issue-list">
                      {h.http_audit.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* ── SNMP ── */}
              {h.snmp_info && Object.keys(h.snmp_info).length > 0 && (
                <div className="audit-section">
                  <h4 className="section-title">📡 SNMP</h4>
                  <div className="kv-grid">
                    {Object.entries(h.snmp_info).map(([k, v]) => (
                      <KV key={k} k={k} v={String(v)} />
                    ))}
                  </div>
                </div>
              )}

              {/* ── SMB ── */}
              {h.smb_info && Object.keys(h.smb_info).length > 0 && (
                <div className="audit-section">
                  <h4 className="section-title">🗂 SMB / NetBIOS</h4>
                  <div className="kv-grid">
                    {Object.entries(h.smb_info).map(([k, v]) => (
                      <KV key={k} k={k} v={String(v)} />
                    ))}
                  </div>
                </div>
              )}

            </div>
          )}
        </div>
      ))}

      {results.length > 0 && (
        <div className="phase-footer">
          <span className="muted">Audit complete</span>
          <button className="phase-btn phase-btn--ghost" onClick={onRestart}>
            ↺ New Scan
          </button>
        </div>
      )}
    </div>
  );
}

function KV({ k, v, danger, warn }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span className="kv-val"
        style={danger ? { color: "#ff4d4d" } : warn ? { color: "#f59e0b" } : {}}>
        {v}
      </span>
    </div>
  );
}
