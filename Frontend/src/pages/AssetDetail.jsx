/**
 * src/pages/AssetDetail.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Asset drill-down page — /assets/:id
 *
 * Tabs:
 *   1. Overview       — Network identity, OS, risk breakdown
 *   2. Vulnerabilities— All findings for this asset, sorted by priority
 *   3. Services       — Open ports with TLS + HTTP detail
 *   4. Change Log     — Differential scan timeline (AssetChangeLog)
 *   5. Notes & Tags   — Analyst workspace
 *
 * All data sourced from real /assets/:id/* endpoints.
 * Inline edit actions gated by assets:update permission.
 */
import { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { canPermission } from "../auth/permissions";
import {
  getAsset, getAssetServices, getAssetFindings,
  getAssetChangelog, updateAsset, addAssetTag,
  removeAssetTag, addAssetNote,
} from "../api/assets";
import { updateFindingStatus } from "../api/findings";
import "../styles/dashboard.css";

// ── Helpers ───────────────────────────────────────────────────────────────────

const ago = (iso) => {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const fmt = (d) => d ? new Date(d).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : "—";

const riskColor = (score) =>
  score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 25 ? "#eab308" : "#22c55e";

const SEV_CLASS = {
  Critical: "db-sev-badge--critical", High: "db-sev-badge--high",
  Medium: "db-sev-badge--medium", Low: "db-sev-badge--low", Info: "db-sev-badge--info",
};

const PRI_CLASS = {
  P0: "db-priority-badge--p0", P1: "db-priority-badge--p1",
  P2: "db-priority-badge--p2", P3: "db-priority-badge--p3", P4: "db-priority-badge--p4",
};

function Skeleton({ h = 14, w = "100%" }) {
  return <div className="db-skeleton" style={{ height: h, width: w, borderRadius: 4, marginBottom: 8 }} />;
}

function InfoRow({ label, value, mono = false }) {
  return (
    <div style={{ display: "flex", gap: 8, padding: "6px 0", borderBottom: "1px solid var(--border)", fontSize: "0.78rem" }}>
      <div style={{ width: 140, color: "var(--text-muted)", flexShrink: 0 }}>{label}</div>
      <div style={{ fontFamily: mono ? "var(--mono)" : "inherit", color: "var(--text)", wordBreak: "break-all" }}>
        {value || "—"}
      </div>
    </div>
  );
}

// ── Tab: Overview ─────────────────────────────────────────────────────────────

function OverviewTab({ asset, loading, canUpdate, onToggleManaged }) {
  if (loading) return (
    <div>
      {[1,2,3,4,5,6,7].map(i => <Skeleton key={i} h={28} />)}
    </div>
  );

  if (!asset) return <div className="db-empty"><div className="db-empty-icon">⚠</div>Asset not found</div>;

  const vc = asset.vuln_counts || {};
  const score = asset.risk_score || 0;
  const color = riskColor(score);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

      {/* Left: Network Identity */}
      <div className="db-card">
        <div className="db-card-title" style={{ marginBottom: 12 }}>🌐 Network Identity</div>
        <InfoRow label="IP Address"    value={asset.ip_address} mono />
        <InfoRow label="MAC Address"   value={asset.mac_address} mono />
        <InfoRow label="Hostname"      value={asset.hostname} />
        <InfoRow label="FQDN"          value={asset.fqdn} mono />
        <InfoRow label="NetBIOS Name"  value={asset.netbios_name} />
        <InfoRow label="Subnet"        value={asset.subnet} mono />
        <InfoRow label="VLAN"          value={asset.vlan_id} />
        <InfoRow label="Vendor"        value={asset.vendor} />
        <InfoRow label="Response Time" value={asset.response_time_ms ? `${asset.response_time_ms}ms` : null} />
        <InfoRow label="Discovery"     value={asset.discovery_method} />
        <InfoRow label="First Seen"    value={fmt(asset.first_seen_at)} />
        <InfoRow label="Last Seen"     value={ago(asset.last_seen_at)} />
      </div>

      {/* Right: Risk + OS + Status */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

        {/* Risk Score */}
        <div className="db-card">
          <div className="db-card-title" style={{ marginBottom: 12 }}>⚠️ Risk Profile</div>
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 14 }}>
            <div style={{
              width: 72, height: 72, borderRadius: "50%", flexShrink: 0,
              background: `conic-gradient(${color} ${score * 3.6}deg, var(--border) 0deg)`,
              display: "flex", alignItems: "center", justifyContent: "center", position: "relative",
            }}>
              <div style={{ position: "absolute", inset: 10, borderRadius: "50%", background: "var(--bg-white)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <div style={{ fontSize: "1rem", fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
                <div style={{ fontSize: "0.55rem", color: "var(--text-muted)", letterSpacing: "0.04em" }}>RISK</div>
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: "0.82rem", fontWeight: 700, color, marginBottom: 4 }}>
                {asset.risk_level?.toUpperCase() || "—"}
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                {[["C", vc.critical, "#f87171"], ["H", vc.high, "#fb923c"], ["M", vc.medium, "#fbbf24"], ["L", vc.low, "#4ade80"]].map(([k, v, c]) => (
                  <div key={k} style={{ textAlign: "center", background: "var(--border)", borderRadius: 5, padding: "4px 8px" }}>
                    <div style={{ fontSize: "0.6rem", color: "var(--text-muted)" }}>{k}</div>
                    <div style={{ fontSize: "0.9rem", fontWeight: 700, color: c }}>{v || 0}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* OS + Device */}
        <div className="db-card">
          <div className="db-card-title" style={{ marginBottom: 12 }}>🖥 OS &amp; Device</div>
          <InfoRow label="OS Name"     value={asset.os_name} />
          <InfoRow label="OS Family"   value={asset.os_family} />
          <InfoRow label="OS Version"  value={asset.os_version} />
          <InfoRow label="Confidence"  value={asset.os_confidence ? `${asset.os_confidence}%` : null} />
          <InfoRow label="Category"    value={asset.device_category} />
          <InfoRow label="Manufacturer" value={asset.manufacturer} />
        </div>

        {/* Management */}
        <div className="db-card">
          <div className="db-card-title" style={{ marginBottom: 12 }}>⚙️ Management</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
            <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>Managed Asset</span>
            {canUpdate ? (
              <button
                className="db-btn"
                onClick={onToggleManaged}
                style={asset.is_managed
                  ? { background: "rgba(34,197,94,0.1)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.2)", padding: "3px 10px", fontSize: "0.72rem" }
                  : { background: "rgba(239,68,68,0.1)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)", padding: "3px 10px", fontSize: "0.72rem" }
                }
              >
                {asset.is_managed ? "✔ Managed" : "✗ Unmanaged"} — click to toggle
              </button>
            ) : (
              <span className="db-tag" style={asset.is_managed
                ? { color: "#4ade80", borderColor: "rgba(34,197,94,0.2)", background: "rgba(34,197,94,0.06)" }
                : { color: "#f87171", borderColor: "rgba(239,68,68,0.2)", background: "rgba(239,68,68,0.06)" }
              }>
                {asset.is_managed ? "Managed" : "Unmanaged"}
              </span>
            )}
          </div>
          <InfoRow label="Owner"       value={asset.owner} />
          <InfoRow label="Last Scan"   value={asset.last_scan_id ? `Scan: ${asset.last_scan_id}` : null} />
        </div>

      </div>
    </div>
  );
}

// ── Tab: Vulnerabilities ──────────────────────────────────────────────────────

function VulnerabilitiesTab({ assetId, canUpdate }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [status, setStatus]     = useState("open");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getAssetFindings(assetId, status || undefined);
      setFindings(r.data?.findings || []);
    } catch { /* silent */ }
    finally { setLoading(false); }
  }, [assetId, status]);

  useEffect(() => { load(); }, [load]);

  const handleAction = async (id, newStatus) => {
    try {
      await updateFindingStatus(id, newStatus);
      setFindings(prev => prev.map(f => f.id === id ? { ...f, status: newStatus } : f));
    } catch { /* silent */ }
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
        {["open", "accepted", "fixed", ""].map((s) => (
          <button key={s || "all"} className={`db-btn ${status === s ? "db-btn--primary" : "db-btn--ghost"}`}
            onClick={() => { setStatus(s); }}
            style={{ fontSize: "0.72rem" }}>
            {s || "All"}
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: "0.72rem", color: "var(--text-muted)" }}>
          {findings.length} findings
        </span>
      </div>

      <div className="db-card" style={{ padding: 0 }}>
        <div className="db-table-wrap">
          <table className="db-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Title</th>
                <th>CVSS</th>
                <th>Priority</th>
                <th>Severity</th>
                <th>Status</th>
                <th>First Found</th>
                {canUpdate && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {loading && Array.from({ length: 6 }).map((_, i) => (
                <tr key={i}>{Array.from({ length: canUpdate ? 8 : 7 }).map((_, j) => (
                  <td key={j}><Skeleton h={12} /></td>
                ))}</tr>
              ))}
              {!loading && findings.length === 0 && (
                <tr><td colSpan={canUpdate ? 8 : 7} style={{ textAlign: "center", padding: 24, color: "var(--text-muted)" }}>
                  No {status} findings for this asset.
                </td></tr>
              )}
              {!loading && findings.map((f) => (
                <tr key={f.id}>
                  <td><span className="cve-id">{f.vuln_id}</span></td>
                  <td style={{ maxWidth: 240 }}>
                    <div style={{ fontSize: "0.72rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</div>
                    {f.in_kev && <span style={{ fontSize: "0.58rem", fontWeight: 700, background: "rgba(239,68,68,0.12)", color: "#f87171", padding: "1px 4px", borderRadius: 3 }}>KEV</span>}
                  </td>
                  <td><span style={{ fontWeight: 700, color: f.cvss_v3_score >= 9 ? "#f87171" : f.cvss_v3_score >= 7 ? "#fb923c" : "#fbbf24" }}>{f.cvss_v3_score?.toFixed(1)}</span></td>
                  <td><span className={`db-priority-badge ${PRI_CLASS[f.priority_label] || ""}`}>{f.priority_label}</span></td>
                  <td><span className={`db-sev-badge ${SEV_CLASS[f.severity] || ""}`}>{f.severity}</span></td>
                  <td>
                    <span className="db-tag" style={
                      f.status === "open" ? { color: "#f87171", background: "rgba(239,68,68,0.06)", borderColor: "rgba(239,68,68,0.2)" } :
                      f.status === "fixed" ? { color: "#4ade80", background: "rgba(34,197,94,0.06)", borderColor: "rgba(34,197,94,0.2)" } :
                      { color: "#fbbf24", background: "rgba(234,179,8,0.06)", borderColor: "rgba(234,179,8,0.2)" }
                    }>{f.status}</span>
                  </td>
                  <td style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>{ago(f.first_found_at)}</td>
                  {canUpdate && (
                    <td>
                      {f.status === "open" && (
                        <div style={{ display: "flex", gap: 4 }}>
                          <button className="db-btn db-btn--ghost" style={{ fontSize: "0.62rem", padding: "2px 7px" }}
                            onClick={() => handleAction(f.id, "accepted")}>Accept</button>
                          <button className="db-btn db-btn--ghost" style={{ fontSize: "0.62rem", padding: "2px 7px", color: "#4ade80", borderColor: "rgba(34,197,94,0.2)" }}
                            onClick={() => handleAction(f.id, "fixed")}>Fixed</button>
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Services ─────────────────────────────────────────────────────────────

function ServicesTab({ assetId }) {
  const [services, setServices] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    getAssetServices(assetId)
      .then(r => setServices(r.data?.services || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [assetId]);

  const HIGH_RISK = new Set([21, 23, 69, 110, 139, 445, 3389, 5900, 5985]);

  const tlsColor = (g) => ({ A: "#22c55e", B: "#4ade80", C: "#eab308", D: "#f97316", F: "#ef4444" }[g] || "var(--text-muted)");

  return (
    <div>
      {loading && [1,2,3,4].map(i => <Skeleton key={i} h={44} />)}
      {!loading && services.length === 0 && (
        <div className="db-empty"><div className="db-empty-icon">🔌</div>No open services found on this asset.</div>
      )}
      {!loading && services.map((svc) => {
        const isRisk = HIGH_RISK.has(svc.port);
        const isOpen = expanded === svc.id;
        return (
          <div key={svc.id} className="db-card" style={{ padding: 0, marginBottom: 8 }}>
            <div
              style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", cursor: "pointer" }}
              onClick={() => setExpanded(isOpen ? null : svc.id)}
            >
              <div style={{
                width: 40, textAlign: "center", fontFamily: "var(--mono)", fontWeight: 700,
                fontSize: "0.82rem", color: isRisk ? "#f87171" : "var(--accent)",
              }}>
                {svc.port}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text)" }}>
                  {svc.service_name || "unknown"}
                  {svc.service_product && ` / ${svc.service_product}`}
                  {svc.service_version && ` ${svc.service_version}`}
                </div>
                <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>
                  {svc.protocol?.toUpperCase()} · {svc.state}
                </div>
              </div>
              {isRisk && <span style={{ fontSize: "0.65rem", background: "rgba(239,68,68,0.1)", color: "#f87171", padding: "2px 7px", borderRadius: 4, fontWeight: 700 }}>HIGH RISK</span>}
              {svc.tls && <span style={{ fontSize: "0.65rem", background: "rgba(34,197,94,0.08)", color: tlsColor(svc.tls.grade), padding: "2px 7px", borderRadius: 4, fontWeight: 700 }}>TLS {svc.tls.grade}</span>}
              <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>{isOpen ? "▲" : "▼"}</span>
            </div>

            {isOpen && (
              <div style={{ borderTop: "1px solid var(--border)", padding: "12px 14px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                {/* Banner */}
                {svc.banner && (
                  <div style={{ gridColumn: "1 / -1" }}>
                    <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 4 }}>Banner</div>
                    <pre style={{ fontFamily: "var(--mono)", fontSize: "0.68rem", background: "var(--border)", padding: "6px 10px", borderRadius: 5, overflow: "auto", maxHeight: 80, whiteSpace: "pre-wrap", color: "var(--text)" }}>
                      {svc.banner}
                    </pre>
                  </div>
                )}

                {/* TLS Detail */}
                {svc.tls && (
                  <div>
                    <div style={{ fontSize: "0.68rem", fontWeight: 700, color: "var(--text-muted)", marginBottom: 8 }}>TLS Details</div>
                    {[
                      ["Protocol", svc.tls.protocol_version],
                      ["Cipher Suite", svc.tls.cipher_suite],
                      ["Grade", svc.tls.grade],
                      ["Weak Cipher", svc.tls.is_weak_cipher ? "⚠ Yes" : "✔ No"],
                      ["Cert Expired", svc.tls.cert_is_expired ? "⚠ Yes" : "✔ No"],
                      ["Self-signed", svc.tls.cert_is_self_signed ? "⚠ Yes" : "✔ No"],
                      ["Cert Subject", svc.tls.cert_subject],
                      ["Not After", svc.tls.cert_not_after ? fmt(svc.tls.cert_not_after) : "—"],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: "flex", gap: 8, fontSize: "0.72rem", padding: "3px 0", borderBottom: "1px solid var(--border)" }}>
                        <div style={{ width: 110, color: "var(--text-muted)", flexShrink: 0 }}>{k}</div>
                        <div style={{ color: "var(--text)", fontFamily: k === "Cipher Suite" || k === "Protocol" ? "var(--mono)" : "inherit" }}>{v || "—"}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* HTTP Security */}
                {svc.http && (
                  <div>
                    <div style={{ fontSize: "0.68rem", fontWeight: 700, color: "var(--text-muted)", marginBottom: 8 }}>HTTP Security Headers</div>
                    {[
                      ["Status Code", svc.http.status_code],
                      ["Security Score", svc.http.security_score],
                      ["HSTS", svc.http.has_hsts ? "✔ Present" : "✗ Missing"],
                      ["CSP", svc.http.has_csp ? "✔ Present" : "✗ Missing"],
                      ["X-Frame-Options", svc.http.x_frame_options || "✗ Missing"],
                      ["X-Content-Type", svc.http.x_content_type ? "✔ Present" : "✗ Missing"],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: "flex", gap: 8, fontSize: "0.72rem", padding: "3px 0", borderBottom: "1px solid var(--border)" }}>
                        <div style={{ width: 110, color: "var(--text-muted)", flexShrink: 0 }}>{k}</div>
                        <div style={{ color: String(v).startsWith("✗") ? "#f87171" : String(v).startsWith("✔") ? "#4ade80" : "var(--text)" }}>{v ?? "—"}</div>
                      </div>
                    ))}
                    {(svc.http.missing_headers || []).length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 4 }}>Missing Headers</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {svc.http.missing_headers.map(h => (
                            <span key={h} className="db-tag" style={{ color: "#f87171", borderColor: "rgba(239,68,68,0.2)" }}>{h}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Tab: Change Log ───────────────────────────────────────────────────────────

function ChangelogTab({ assetId }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAssetChangelog(assetId)
      .then(r => setEntries(r.data?.changelog || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [assetId]);

  const CHANGE_ICON = {
    port_opened:    { icon: "🔓", color: "rgba(239,68,68,0.1)" },
    port_closed:    { icon: "🔒", color: "rgba(34,197,94,0.08)" },
    os_changed:     { icon: "🖥", color: "rgba(59,130,246,0.1)" },
    hostname_changed: { icon: "🌐", color: "rgba(99,102,241,0.1)" },
    vuln_new:       { icon: "🚨", color: "rgba(239,68,68,0.1)" },
    vuln_fixed:     { icon: "✅", color: "rgba(34,197,94,0.08)" },
    risk_changed:   { icon: "📊", color: "rgba(234,179,8,0.1)" },
  };

  return (
    <div>
      <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 12 }}>
        Differential scan log — shows what changed between scans on this asset
      </div>

      {loading && [1,2,3].map(i => <Skeleton key={i} h={44} />)}

      {!loading && entries.length === 0 && (
        <div className="db-empty">
          <div className="db-empty-icon">📋</div>
          No change log entries yet. Run multiple scans to see differentials.
        </div>
      )}

      {!loading && entries.map((e) => {
        const meta = CHANGE_ICON[e.change_type] || { icon: "📌", color: "var(--border)" };
        return (
          <div key={e.id} className="db-scan-row" style={{ alignItems: "flex-start" }}>
            <div className="db-scan-icon" style={{ background: meta.color }}>{meta.icon}</div>
            <div className="db-scan-body">
              <div className="db-scan-title" style={{ textTransform: "none" }}>
                {e.change_type?.replace(/_/g, " ")}
                {e.field_name && <span style={{ color: "var(--text-muted)", fontWeight: 400 }}> — {e.field_name}</span>}
              </div>
              {(e.old_value || e.new_value) && (
                <div style={{ display: "flex", gap: 8, marginTop: 4, fontSize: "0.68rem" }}>
                  {e.old_value && <span style={{ color: "#f87171", fontFamily: "var(--mono)" }}>− {e.old_value}</span>}
                  {e.new_value && <span style={{ color: "#4ade80", fontFamily: "var(--mono)" }}>+ {e.new_value}</span>}
                </div>
              )}
              {e.scan_id && <div style={{ fontSize: "0.62rem", color: "var(--text-faint)", marginTop: 2 }}>Scan: {e.scan_id}</div>}
            </div>
            <div className="db-scan-time">{ago(e.detected_at)}</div>
          </div>
        );
      })}
    </div>
  );
}

// ── Tab: Notes & Tags ─────────────────────────────────────────────────────────

function NotesTagsTab({ asset, assetId, canUpdate, onRefresh }) {
  const [newTag,  setNewTag]  = useState("");
  const [newNote, setNewNote] = useState("");
  const [saving,  setSaving]  = useState(false);
  const [msg,     setMsg]     = useState("");

  const handleAddTag = async () => {
    if (!newTag.trim()) return;
    setSaving(true);
    try {
      await addAssetTag(assetId, newTag.trim());
      setNewTag("");
      setMsg("Tag added");
      onRefresh();
    } catch { setMsg("Failed to add tag"); }
    finally { setSaving(false); }
  };

  const handleRemoveTag = async (tag) => {
    try {
      await removeAssetTag(assetId, tag);
      setMsg("Tag removed");
      onRefresh();
    } catch { setMsg("Failed to remove tag"); }
  };

  const handleAddNote = async () => {
    if (!newNote.trim()) return;
    setSaving(true);
    try {
      await addAssetNote(assetId, newNote.trim());
      setNewNote("");
      setMsg("Note added");
      onRefresh();
    } catch { setMsg("Failed to add note"); }
    finally { setSaving(false); }
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

      {/* Tags */}
      <div className="db-card">
        <div className="db-card-title" style={{ marginBottom: 8 }}>🏷 Asset Tags</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 12, minHeight: 30 }}>
          {(asset?.tags || []).map(tag => (
            <span key={tag} className="db-tag" style={{ display: "flex", alignItems: "center", gap: 4 }}>
              {tag}
              {canUpdate && (
                <button onClick={() => handleRemoveTag(tag)}
                  style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", lineHeight: 1, padding: 0, fontSize: "0.75rem" }}>
                  ×
                </button>
              )}
            </span>
          ))}
          {(asset?.tags || []).length === 0 && <span style={{ fontSize: "0.72rem", color: "var(--text-faint)" }}>No tags yet</span>}
        </div>
        {canUpdate && (
          <div style={{ display: "flex", gap: 6 }}>
            <input
              value={newTag}
              onChange={e => setNewTag(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleAddTag()}
              placeholder="Add tag…"
              style={{ flex: 1, padding: "5px 8px", borderRadius: 5, border: "1px solid var(--border)", fontSize: "0.72rem", background: "var(--bg-white)", color: "var(--text)" }}
            />
            <button className="db-btn db-btn--primary" onClick={handleAddTag} disabled={saving} style={{ fontSize: "0.72rem" }}>
              Add
            </button>
          </div>
        )}
      </div>

      {/* Notes */}
      <div className="db-card">
        <div className="db-card-title" style={{ marginBottom: 8 }}>📝 Analyst Notes</div>
        <div style={{ marginBottom: 12, maxHeight: 160, overflowY: "auto" }}>
          {(asset?.notes || []).map(note => (
            <div key={note.id} style={{ padding: "7px 10px", background: "var(--border)", borderRadius: 6, marginBottom: 6 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text)", lineHeight: 1.5 }}>{note.content}</div>
              <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginTop: 3 }}>{ago(note.created_at)}</div>
            </div>
          ))}
          {(asset?.notes || []).length === 0 && <div style={{ fontSize: "0.72rem", color: "var(--text-faint)" }}>No analyst notes yet</div>}
        </div>
        {canUpdate && (
          <div>
            <textarea
              value={newNote}
              onChange={e => setNewNote(e.target.value)}
              placeholder="Add analyst note…"
              rows={3}
              style={{ width: "100%", padding: "6px 8px", borderRadius: 5, border: "1px solid var(--border)", fontSize: "0.72rem", resize: "vertical", background: "var(--bg-white)", color: "var(--text)", marginBottom: 6 }}
            />
            <button className="db-btn db-btn--primary" onClick={handleAddNote} disabled={saving || !newNote.trim()} style={{ fontSize: "0.72rem" }}>
              {saving ? "Saving…" : "Add Note"}
            </button>
          </div>
        )}
      </div>

      {msg && (
        <div style={{ gridColumn: "1 / -1", fontSize: "0.72rem", color: "#4ade80", textAlign: "center", padding: "6px 0" }}>
          {msg}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════

const TABS = [
  { id: "overview",       label: "Overview" },
  { id: "vulnerabilities",label: "Vulnerabilities" },
  { id: "services",       label: "Services & Ports" },
  { id: "changelog",      label: "Change Log" },
  { id: "notes",          label: "Notes & Tags" },
];

export default function AssetDetail() {
  const { id }       = useParams();
  const navigate     = useNavigate();
  const { user }     = useAuth();
  const canUpdate    = canPermission(user, { resource: "assets", action: "update" });

  const [asset,   setAsset]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab,     setTab]     = useState("overview");

  const loadAsset = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getAsset(id);
      setAsset(r.data);
    } catch { setAsset(null); }
    finally { setLoading(false); }
  }, [id]);

  useEffect(() => { loadAsset(); }, [loadAsset]);

  const handleToggleManaged = async () => {
    if (!asset) return;
    try {
      await updateAsset(id, { is_managed: !asset.is_managed });
      setAsset(a => ({ ...a, is_managed: !a.is_managed }));
    } catch { /* silent */ }
  };

  const vc = asset?.vuln_counts || {};

  return (
    <AppLayout pageTitle="Asset Detail" onNewScan={() => navigate("/scan")}>
      <div className="db-page">

        {/* Header */}
        <div className="db-page-header">
          <div>
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 4 }}>
              <span style={{ cursor: "pointer", color: "var(--accent)" }} onClick={() => navigate("/assets")}>
                Asset Registry
              </span>
              {" › "}
              {loading ? "Loading…" : asset?.ip_address}
            </div>
            <div className="db-page-title" style={{ fontFamily: "var(--mono)" }}>
              {loading ? "—" : asset?.ip_address}
            </div>
            <div className="db-page-subtitle">
              {asset?.hostname && <span>{asset.hostname} · </span>}
              {asset?.os_name && <span>{asset.os_name} · </span>}
              Risk: <span style={{ color: riskColor(asset?.risk_score || 0), fontWeight: 600 }}>{asset?.risk_score || 0}/100</span>
            </div>
          </div>
          <div className="db-header-actions">
            {/* Severity pill summary */}
            {!loading && [
              ["C", vc.critical, "#f87171"],
              ["H", vc.high, "#fb923c"],
              ["M", vc.medium, "#fbbf24"],
            ].map(([k, v, c]) => v > 0 && (
              <div key={k} style={{ textAlign: "center", background: "var(--border)", borderRadius: 7, padding: "5px 10px" }}>
                <div style={{ fontSize: "0.58rem", color: "var(--text-muted)" }}>{k}</div>
                <div style={{ fontSize: "0.9rem", fontWeight: 800, color: c }}>{v}</div>
              </div>
            ))}
            <button className="db-btn db-btn--ghost" onClick={() => navigate("/assets")}>← Back</button>
          </div>
        </div>

        {/* Tabs */}
        <div className="db-tab-bar">
          {TABS.map(t => (
            <button key={t.id} className={`db-tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div style={{ padding: "16px 28px" }}>
          {tab === "overview" && (
            <OverviewTab asset={asset} loading={loading} canUpdate={canUpdate} onToggleManaged={handleToggleManaged} />
          )}
          {tab === "vulnerabilities" && (
            <VulnerabilitiesTab assetId={id} canUpdate={canUpdate} />
          )}
          {tab === "services" && (
            <ServicesTab assetId={id} />
          )}
          {tab === "changelog" && (
            <ChangelogTab assetId={id} />
          )}
          {tab === "notes" && (
            <NotesTagsTab asset={asset} assetId={id} canUpdate={canUpdate} onRefresh={loadAsset} />
          )}
        </div>

      </div>
    </AppLayout>
  );
}
