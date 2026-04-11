/**
 * src/pages/scan/Phase3Results.jsx
 * Runs POST /scan/phase3 on selected hosts.
 * Displays CVEs, risk scores, TLS, SSH, HTTP headers, SNMP, SMB.
 * Bottom: ExportPanel for JSON/CSV/PDF/Copy.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout    from "../../components/layout/AppLayout";
import ScanStepper  from "../../components/layout/ScanStepper";
import RiskBadge    from "../../components/scan/RiskBadge";
import ExportPanel  from "../../components/scan/ExportPanel";
import { useScan }  from "../../context/ScanContext";
import api          from "../../api/axiosInstance";

const SEV_COLOR = {
  Critical: "#ff4d4d",
  High:     "#f97316",
  Medium:   "#f59e0b",
  Low:      "#22c55e",
  Info:     "#60a5fa",
};

function normalizeCve(cve) {
  const cvss = Number(cve.cvss_score ?? cve.cvss ?? 0) || 0;
  const severity = cve.severity || (
    cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : cvss > 0 ? "Low" : "Info"
  );
  return {
    cve_id:      cve.cve_id || cve.cve || "Unknown",
    severity,
    cvss_score:  cvss,
    description: cve.description || cve.desc || "",
  };
}

function KV({ k, v, danger, warn }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span className="kv-val" style={danger ? { color: "#ff4d4d" } : warn ? { color: "#f59e0b" } : {}}>
        {v}
      </span>
    </div>
  );
}

function AuditSection({ title, children }) {
  return (
    <div className="audit-section">
      <h4 className="section-title">{title}</h4>
      {children}
    </div>
  );
}

export default function Phase3Results() {
  const navigate = useNavigate();
  const {
    phase3Results: hosts, scanId, target,
    setPhase3Summary,
    saveStatus, setSaveStatus,
    resetScan,
  } = useScan();

  const [loading,    setLoading]    = useState(false);
  const [results,    setResults]    = useState([]);
  const [summary,    setSummary]    = useState(null);
  const [expanded,   setExpanded]   = useState(new Set());
  const [error,      setError]      = useState("");
  const [hasScanned, setHasScanned] = useState(false);

  if (!hosts.length) {
    navigate("/scan/phase2", { replace: true });
    return null;
  }

  const runScan = async () => {
    setLoading(true);
    setError(""); setResults([]); setSummary(null); setHasScanned(false);
    setSaveStatus("saving");
    try {
      const { data } = await api.post("/scan/phase3", { hosts, scan_id: scanId });
      if (!data.success) throw new Error(data.error || "Phase 3 failed");
      setResults(data.data);
      setSummary(data.summary);
      setPhase3Summary(data.summary);
      setExpanded(new Set(data.data.filter(h => h.is_active).map(h => h.ip_address)));
      setHasScanned(true);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 4000);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Phase 3 failed");
      setSaveStatus("error");
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = ip => {
    const n = new Set(expanded);
    n.has(ip) ? n.delete(ip) : n.add(ip);
    setExpanded(n);
  };

  const activeResults = results.filter(h => h.is_active);

  return (
    <AppLayout pageTitle="Vulnerability Audit" saveStatus={saveStatus}>
      <ScanStepper current={3} />

      <div className="page-inner">

        {/* Page header */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Vulnerability Audit</h2>
            <p className="page-subtitle">
              Deep auditing <b>{hosts.length}</b> host{hosts.length !== 1 ? "s" : ""} from{" "}
              <code className="ip-code">{target}</code>
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn--ghost" onClick={() => navigate("/scan/phase2")}>← Back</button>
            <button className="btn btn--danger" onClick={runScan} disabled={loading}>
              {loading ? <><span className="btn-spinner" /> Auditing…</> : "⚡ Run Vulnerability Audit"}
            </button>
          </div>
        </div>

        {/* Progress */}
        {loading && (
          <div className="progress-wrap">
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
              Running TLS inspection, SSH audit, CVE matching, HTTP header checks… 30–90 seconds per host.
            </p>
          </div>
        )}

        {error && <div className="alert alert--error">⚠ {error}</div>}

        {/* Summary bar */}
        {summary && (
          <div className="summary-bar">
            <span className="summary-item"><b>{summary.total_hosts}</b> Audited</span>
            <span className="summary-item summary-item--danger"><b>{summary.critical_hosts}</b> Critical</span>
            <span className="summary-item summary-item--warn"><b>{summary.high_risk_hosts}</b> High risk</span>
            <span className="summary-item"><b>{summary.scan_duration?.toFixed(1)}s</b> Duration</span>
            {scanId && (
              <span className="summary-item" style={{ color: "var(--ok)" }}>✓ Scan #{scanId} complete</span>
            )}
          </div>
        )}

        {/* Vulnerability cards */}
        {activeResults.map(h => {
          const riskLower = h.host_risk_level?.toLowerCase() || "info";
          const isOpen    = expanded.has(h.ip_address);

          return (
            <div key={h.ip_address} className={`vuln-card vuln-card--${riskLower}`}>

              {/* Card header */}
              <div className="vuln-card-header" onClick={() => toggleExpand(h.ip_address)}>
                <div className="vuln-card-title">
                  <code className="ip-code" style={{ fontSize: "0.9rem", fontWeight: 700 }}>{h.ip_address}</code>
                  {h.hostname && h.hostname !== "Unknown" && (
                    <span className="muted small"> {h.hostname}</span>
                  )}
                  {h.os_guess && h.os_guess !== "Unknown" && (
                    <span style={{ fontSize: 11, color: "var(--text-muted)", background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4, marginLeft: 4 }}>
                      {h.os_guess}
                    </span>
                  )}
                </div>

                <div className="vuln-card-right">
                  <RiskBadge level={h.host_risk_level} score={h.host_risk_score} />
                  {h.cves?.length > 0 && (
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#f97316", background: "rgba(249,115,22,.1)", border: "1px solid rgba(249,115,22,.25)", padding: "2px 8px", borderRadius: 4 }}>
                      {h.cves.length} CVE{h.cves.length > 1 ? "s" : ""}
                    </span>
                  )}
                  <button className="expand-btn">{isOpen ? "▲" : "▼"}</button>
                </div>
              </div>

              {/* Card body */}
              {isOpen && (
                <div className="vuln-card-body">

                  {/* Risk bar */}
                  {h.host_risk_score > 0 && (
                    <div style={{ padding: "12px 0 8px" }}>
                      <div className="risk-bar-wrap">
                        <div className="risk-bar-track">
                          <div
                            className="risk-bar-fill"
                            style={{ width: `${h.host_risk_score}%`, background: SEV_COLOR[h.host_risk_level] || "#60a5fa" }}
                          />
                        </div>
                        <span className="risk-bar-label">{h.host_risk_score}/100</span>
                      </div>
                    </div>
                  )}

                  {/* CVEs */}
                  {h.cves?.length > 0 && (
                    <AuditSection title={`⚠ CVE Findings (${h.cves.length})`}>
                      <div className="cve-list">
                        {h.cves.map((rawCve, i) => {
                          const cve = normalizeCve(rawCve);
                          return (
                            <div key={i} className="cve-row">
                              <span className="cve-id" style={{ color: SEV_COLOR[cve.severity] || "#60a5fa" }}>
                                {cve.cve_id}
                              </span>
                              <span className="cve-sev" style={{ color: SEV_COLOR[cve.severity] }}>
                                {cve.severity}
                              </span>
                              {cve.cvss_score > 0 && (
                                <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>
                                  CVSS {cve.cvss_score}
                                </span>
                              )}
                              <span className="cve-desc">{cve.description}</span>
                            </div>
                          );
                        })}
                      </div>
                    </AuditSection>
                  )}

                  {/* Open ports */}
                  {h.open_ports?.length > 0 && (
                    <AuditSection title="🔌 Open Ports">
                      <div className="port-pills">
                        {h.open_ports.map((p, i) => (
                          <span key={i} className="port-pill" style={{ borderColor: SEV_COLOR[p.risk] || "var(--border)" }}>
                            <code>{p.port}</code>
                            <span>{p.service}</span>
                            <span style={{ color: SEV_COLOR[p.risk] || "var(--text-faint)", fontSize: 10 }}>
                              {p.risk || "Info"}
                            </span>
                          </span>
                        ))}
                      </div>
                    </AuditSection>
                  )}

                  {/* TLS */}
                  {h.tls_info?.enabled && (
                    <AuditSection title="🔒 TLS / SSL Certificate">
                      <div className="kv-grid">
                        {h.tls_info.version      && <KV k="Version"     v={h.tls_info.version} />}
                        {h.tls_info.cipher       && <KV k="Cipher"      v={h.tls_info.cipher} />}
                        {h.tls_info.score        && <KV k="Grade"       v={h.tls_info.score} />}
                        {h.tls_info.cert_subject && <KV k="Subject"     v={h.tls_info.cert_subject} />}
                        {h.tls_info.cert_issuer  && <KV k="Issuer"      v={h.tls_info.cert_issuer} />}
                        {h.tls_info.cert_expiry  && <KV k="Expiry"      v={h.tls_info.cert_expiry} />}
                        {h.tls_info.cert_expired !== undefined && (
                          <KV k="Expired" v={h.tls_info.cert_expired ? "⚠ YES" : "No"} danger={h.tls_info.cert_expired} />
                        )}
                        {h.tls_info.cert_self_signed !== undefined && (
                          <KV k="Self-signed" v={h.tls_info.cert_self_signed ? "Yes" : "No"} warn={h.tls_info.cert_self_signed} />
                        )}
                        {h.tls_info.weak_cipher && <KV k="Weak cipher" v="⚠ Detected" danger />}
                      </div>
                    </AuditSection>
                  )}

                  {/* SSH */}
                  {h.ssh_info && Object.keys(h.ssh_info).length > 0 && (
                    <AuditSection title="🖥 SSH">
                      <div className="kv-grid">
                        {h.ssh_info.version && <KV k="Protocol" v={h.ssh_info.version} />}
                        {h.ssh_info.banner  && <KV k="Banner"   v={h.ssh_info.banner} />}
                      </div>
                    </AuditSection>
                  )}

                  {/* HTTP */}
                  {h.http_audit?.status_code > 0 && (
                    <AuditSection title="🌐 HTTP Security Headers">
                      <div className="kv-grid">
                        <KV k="Status"         v={h.http_audit.status_code} />
                        {h.http_audit.server_header && <KV k="Server" v={h.http_audit.server_header} />}
                        <KV k="HSTS"           v={h.http_audit.hsts ? "✓ Present" : "✗ Missing"} danger={!h.http_audit.hsts} />
                        <KV k="CSP"            v={h.http_audit.csp  ? "✓ Present" : "✗ Missing"} danger={!h.http_audit.csp} />
                        <KV k="X-Frame"        v={h.http_audit.x_frame || "✗ Missing"}            danger={!h.http_audit.x_frame} />
                        <KV k="X-Content-Type" v={h.http_audit.x_content_type ? "✓" : "✗ Missing"} danger={!h.http_audit.x_content_type} />
                        <KV k="X-XSS"         v={h.http_audit.x_xss ? "✓" : "✗ Missing"}         danger={!h.http_audit.x_xss} />
                      </div>
                      {h.http_audit.issues?.length > 0 && (
                        <ul className="issue-list">
                          {h.http_audit.issues.map((iss, i) => <li key={i}>{iss}</li>)}
                        </ul>
                      )}
                    </AuditSection>
                  )}

                  {/* SNMP */}
                  {h.snmp_info && Object.keys(h.snmp_info).length > 0 && (
                    <AuditSection title="📡 SNMP">
                      <div className="kv-grid">
                        {Object.entries(h.snmp_info).map(([k, v]) => <KV key={k} k={k} v={String(v)} />)}
                      </div>
                    </AuditSection>
                  )}

                  {/* SMB */}
                  {h.smb_info && Object.keys(h.smb_info).length > 0 && (
                    <AuditSection title="🗂 SMB / NetBIOS">
                      <div className="kv-grid">
                        {Object.entries(h.smb_info).map(([k, v]) => <KV key={k} k={k} v={String(v)} />)}
                      </div>
                    </AuditSection>
                  )}

                </div>
              )}
            </div>
          );
        })}

        {/* Export + footer */}
        {hasScanned && (
          <>
            <ExportPanel results={results} summary={summary} scanId={scanId} target={target} />
            <div className="phase-footer" style={{ marginTop: 8 }}>
              <span className="muted" style={{ fontSize: 13 }}>
                Audit complete — results saved to history.
              </span>
              <div style={{ display: "flex", gap: 10 }}>
                <button className="btn btn--ghost" onClick={() => navigate("/history")}>
                  View History
                </button>
                <button className="btn btn--primary" onClick={() => { resetScan(); navigate("/scan"); }}>
                  ↺ New Scan
                </button>
              </div>
            </div>
          </>
        )}

      </div>
    </AppLayout>
  );
}
