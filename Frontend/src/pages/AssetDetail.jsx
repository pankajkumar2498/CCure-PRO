/**
 * src/pages/AssetDetail.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Complete, premium Asset Detail page.
 * - Drill down from Asset Registry to see detailed host metadata
 * - Manage asset ownership and toggles (Managed/Unmanaged)
 * - Timeline-based analyst notes and tags manager
 * - Vulnerabilities tab with drawer details (proof, severity, CVSS) and actions (remediate/risk accept)
 * - Services & Open Ports tab with detailed TLS and HTTP security headers inspection
 * - Historical change log audit timeline
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { canPermission } from "../auth/permissions";
import {
  getAsset,
  getAssetServices,
  getAssetFindings,
  getAssetChangelog,
  updateAsset,
  addAssetTag,
  removeAssetTag,
  addAssetNote,
} from "../api/assets";
import {
  getFinding,
  updateFindingStatus,
  updateFindingNotes,
} from "../api/findings";
import CVELink from "../components/common/CVELink";
import AuditTimeline from "../components/assets/AuditTimeline";
import "../styles/dashboard.css";

const ago = (iso) => {
  if (!iso) return "—";
  const d = Math.floor((Date.now() - new Date(iso)) / 86400000);
  if (d === 0) return "Today";
  if (d === 1) return "Yesterday";
  return `${d}d ago`;
};

const formatTime = (iso) => {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
};

const combineTime = (iso) => {
  if (!iso) return "—";
  const relative = ago(iso);
  const absolute = formatTime(iso);
  if (relative === "—" || absolute === "—") return "—";
  return `${relative} (${absolute})`;
};

const cleanVendorName = (name) => {
  if (!name) return "";
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "")
    .replace(/(inc|incorporated|corp|corporation|ltd|limited|co|company|systems|hardware)$/g, "");
};

const SEV_CLASS = {
  Critical: "db-sev-badge--critical",
  High: "db-sev-badge--high",
  Medium: "db-sev-badge--medium",
  Low: "db-sev-badge--low",
  Info: "db-sev-badge--info",
};

const PRI_CLASS = {
  P0: "db-priority-badge--p0",
  P1: "db-priority-badge--p1",
  P2: "db-priority-badge--p2",
  P3: "db-priority-badge--p3",
  P4: "db-priority-badge--p4",
};

const riskColor = (score) =>
  score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 25 ? "#eab308" : "#22c55e";

function SidebarRow({ label, value, mono = false, isTag = false, noBorder = false }) {
  if (value === null || value === undefined || value === "" || value === "—" || value === "Unknown" || value === "unknown") return null;
  return (
    <div style={{ display: "flex", justifyContent: "space-between", borderBottom: noBorder ? "none" : "1px solid var(--border)", paddingBottom: 4 }}>
      <span style={{ color: "var(--text-muted)" }}>{label}</span>
      {isTag ? (
        <span className="db-tag" style={{ margin: 0 }}>{value}</span>
      ) : (
        <span className={mono ? "mono" : ""} style={{ fontWeight: 600, textAlign: "right" }}>{value}</span>
      )}
    </div>
  );
}

// ── Vulnerability Drawer component (similar to VulnerabilityBrowser's finding drawer) ──
function FindingDrawer({ findingId, onClose, canUpdate, onStatusChange }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState(null);
  const [reason, setReason] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  useEffect(() => {
    if (!findingId) return;
    setLoading(true);
    getFinding(findingId)
      .then(r => setDetail(r.data))
      .catch(() => { })
      .finally(() => setLoading(false));
  }, [findingId]);

  const handleStatusSave = async (newStatus) => {
    setSaving(true);
    setSaveMsg("");
    try {
      await updateFindingStatus(findingId, newStatus, reason, notes);
      setSaveMsg(`Status updated to ${newStatus}`);
      setAction(null);
      onStatusChange && onStatusChange(findingId, newStatus);
      const r = await getFinding(findingId);
      setDetail(r.data);
    } catch {
      setSaveMsg("Failed to update status");
    } finally {
      setSaving(false);
    }
  };

  const handleNotesSave = async () => {
    if (!notes.trim()) return;
    setSaving(true);
    try {
      await updateFindingNotes(findingId, notes);
      setSaveMsg("Notes saved");
    } catch {
      setSaveMsg("Failed to save notes");
    } finally {
      setSaving(false);
    }
  };

  const v = detail?.vulnerability;
  const ast = detail?.asset;

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 500,
      display: "flex", alignItems: "stretch",
    }}>
      <div style={{ flex: 1, background: "rgba(0,0,0,0.35)" }} onClick={onClose} />
      <div style={{
        width: 480, background: "var(--bg-white)", boxShadow: "-4px 0 24px rgba(0,0,0,0.12)",
        overflow: "auto", display: "flex", flexDirection: "column",
      }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 4 }}>Finding Detail</div>
            {loading
              ? <div className="db-skeleton" style={{ height: 18, width: 200 }} />
              : <div style={{ fontFamily: "var(--mono)", fontSize: "0.9rem", fontWeight: 700, color: "#3b82f6" }}><CVELink cveId={v?.id} style={{ color: "inherit" }} /></div>
            }
          </div>
          <button onClick={onClose} className="db-btn db-btn--ghost" style={{ padding: "4px 10px" }}>✕</button>
        </div>

        {loading ? (
          <div style={{ padding: 20 }}>
            {[200, 100, 150, 80, 120].map((w, i) => (
              <div key={i} className="db-skeleton" style={{ height: 12, width: w, marginBottom: 12 }} />
            ))}
          </div>
        ) : !detail ? (
          <div className="db-empty"><div className="db-empty-icon">⚠</div>Finding not found</div>
        ) : (
          <div style={{ padding: 20, flex: 1, overflowY: "auto" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
              <span className={`db-sev-badge ${SEV_CLASS[v?.severity] || ""}`}>{v?.severity}</span>
              <span className={`db-priority-badge ${PRI_CLASS[v?.priority_label] || ""}`}>{v?.priority_label}</span>
              {v?.in_kev && <span style={{ fontSize: "0.65rem", fontWeight: 700, background: "rgba(239,68,68,0.12)", color: "#f87171", padding: "2px 6px", borderRadius: 4 }}>KEV</span>}
              {v?.has_exploit && <span style={{ fontSize: "0.65rem", fontWeight: 700, background: "rgba(249,115,22,0.12)", color: "#fb923c", padding: "2px 6px", borderRadius: 4 }}>Exploit</span>}
            </div>

            <div style={{ fontSize: "0.9rem", fontWeight: 600, color: "var(--text)", marginBottom: 8 }}>{v?.title}</div>

            <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
              <div style={{ flex: 1, background: "var(--border)", borderRadius: 7, padding: "8px 12px", textAlign: "center" }}>
                <div style={{ fontSize: "0.6rem", color: "var(--text-muted)", marginBottom: 2 }}>CVSSv3</div>
                <div style={{ fontSize: "1.1rem", fontWeight: 800, color: v?.cvss_v3_score >= 9 ? "#f87171" : v?.cvss_v3_score >= 7 ? "#fb923c" : "#fbbf24" }}>
                  {(v?.cvss_v3_score || 0).toFixed(1)}
                </div>
              </div>
              <div style={{ flex: 1, background: "var(--border)", borderRadius: 7, padding: "8px 12px", textAlign: "center" }}>
                <div style={{ fontSize: "0.6rem", color: "var(--text-muted)", marginBottom: 2 }}>EPSS</div>
                <div style={{ fontSize: "1.1rem", fontWeight: 800, color: "var(--text)" }}>
                  {((v?.epss_score || 0) * 100).toFixed(1)}%
                </div>
              </div>
              <div style={{ flex: 1, background: "var(--border)", borderRadius: 7, padding: "8px 12px", textAlign: "center" }}>
                <div style={{ fontSize: "0.6rem", color: "var(--text-muted)", marginBottom: 2 }}>Priority</div>
                <div style={{ fontSize: "1.1rem", fontWeight: 800, color: "var(--text)" }}>
                  {(v?.priority_score || 0).toFixed(0)}
                </div>
              </div>
            </div>

            <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 14, padding: "10px 12px", background: "var(--border)", borderRadius: 7 }}>
              {v?.description || "No description available."}
            </div>

            {v?.cvss_v3_vector && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 3 }}>CVSS Vector</div>
                <div style={{ fontFamily: "var(--mono)", fontSize: "0.7rem", background: "var(--border)", padding: "6px 10px", borderRadius: 5 }}>
                  {v.cvss_v3_vector}
                </div>
              </div>
            )}

            {(v?.cwe_ids || []).length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 4 }}>CWE IDs</div>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {v.cwe_ids.map(c => <span key={c} className="db-tag">{c}</span>)}
                </div>
              </div>
            )}

            {(detail.proof || detail.plugin_output) && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 4 }}>Evidence / Plugin Output</div>
                <pre style={{ fontFamily: "var(--mono)", fontSize: "0.68rem", background: "var(--border)", padding: "8px 10px", borderRadius: 5, overflow: "auto", maxHeight: 120, whiteSpace: "pre-wrap", color: "var(--text)" }}>
                  {detail.proof || detail.plugin_output}
                </pre>
              </div>
            )}

            <div style={{ display: "flex", gap: 12, marginBottom: 14, fontSize: "0.68rem", color: "var(--text-muted)" }}>
              <span>First: {ago(detail.first_found_at)}</span>
              <span>Last: {ago(detail.last_found_at)}</span>
              {detail.fixed_at && <span style={{ color: "#4ade80" }}>Fixed: {ago(detail.fixed_at)}</span>}
            </div>

            {canUpdate && detail.status === "open" && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 6, fontWeight: 700 }}>Actions</div>
                {!action ? (
                  <div style={{ display: "flex", gap: 8 }}>
                    <button className="db-btn db-btn--ghost" onClick={() => setAction("accepted")} style={{ flex: 1 }}>
                      ✔ Accept Risk
                    </button>
                    <button className="db-btn db-btn--ghost" onClick={() => setAction("fixed")} style={{ flex: 1, color: "#4ade80", borderColor: "rgba(34,197,94,0.2)" }}>
                      🛠 Mark Fixed
                    </button>
                  </div>
                ) : (
                  <div style={{ background: "var(--border)", borderRadius: 7, padding: 12 }}>
                    <div style={{ fontSize: "0.72rem", fontWeight: 600, marginBottom: 8 }}>
                      {action === "accepted" ? "Accept Risk — provide reason:" : "Mark as Fixed:"}
                    </div>
                    {action === "accepted" && (
                      <textarea
                        value={reason}
                        onChange={e => setReason(e.target.value)}
                        placeholder="Reason for accepting this risk…"
                        rows={3}
                        style={{ width: "100%", padding: "6px 8px", borderRadius: 5, border: "1px solid var(--border)", fontSize: "0.72rem", resize: "vertical", marginBottom: 8, background: "var(--bg-white)", color: "var(--text)" }}
                      />
                    )}
                    <textarea
                      value={notes}
                      onChange={e => setNotes(e.target.value)}
                      placeholder="Remediation notes (optional)…"
                      rows={2}
                      style={{ width: "100%", padding: "6px 8px", borderRadius: 5, border: "1px solid var(--border)", fontSize: "0.72rem", resize: "vertical", marginBottom: 8, background: "var(--bg-white)", color: "var(--text)" }}
                    />
                    <div style={{ display: "flex", gap: 8 }}>
                      <button
                        className="db-btn db-btn--primary"
                        disabled={saving}
                        onClick={() => handleStatusSave(action)}
                        style={{ flex: 1 }}
                      >
                        {saving ? "Saving…" : `Confirm ${action === "accepted" ? "Accept" : "Fixed"}`}
                      </button>
                      <button className="db-btn db-btn--ghost" onClick={() => setAction(null)}>Cancel</button>
                    </div>
                    {saveMsg && <div style={{ fontSize: "0.7rem", color: saveMsg.includes("Failed") ? "#f87171" : "#4ade80", marginTop: 6 }}>{saveMsg}</div>}
                  </div>
                )}
              </div>
            )}

            {detail.remediation_notes && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 4 }}>Remediation Notes</div>
                <div style={{ fontSize: "0.72rem", color: "var(--text)", background: "var(--border)", padding: "8px 10px", borderRadius: 5, lineHeight: 1.5 }}>
                  {detail.remediation_notes}
                </div>
              </div>
            )}

            {(v?.references || []).length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 4 }}>References</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {v.references.slice(0, 5).map((ref, i) => (
                    <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: "0.7rem", color: "#3b82f6", textDecoration: "none", wordBreak: "break-all" }}>
                      {ref}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Service Detail Sub-panel component (collapsible details for services) ──
function ServiceDetailRow({ svc, showProduct, showBanner, showAudits, colSpan }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetails = !!svc.tls || !!svc.http;

  return (
    <>
      <tr onClick={() => hasDetails && setExpanded(!expanded)} style={{ cursor: hasDetails ? "pointer" : "default" }}>
        <td>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: "0.65rem", color: "var(--text-faint)", width: "12px", display: "inline-block" }}>
              {hasDetails ? (expanded ? "▼" : "▶") : ""}
            </span>
            <span className="mono" style={{ fontWeight: 700 }}>
              {svc.port} / {svc.protocol}
            </span>
          </div>
        </td>
        <td>
          <span className="db-tag">{svc.service_name || "unknown"}</span>
        </td>
        <td>
          <span className="db-status db-status--complete">{svc.state}</span>
        </td>
        {showProduct && (
          <td>
            <div className="mono" style={{ fontSize: "0.72rem" }}>
              {svc.service_product
                ? `${svc.service_product} ${svc.service_version || ""}`.trim()
                : <span style={{ color: "var(--text-faint)", fontStyle: "italic", fontFamily: "inherit" }}>—</span>}
            </div>
          </td>
        )}
        {showBanner && (
          <td className="mono" style={{ fontSize: "0.7rem", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {svc.banner
              ? svc.banner
              : <span style={{ color: "var(--text-faint)", fontStyle: "italic", fontFamily: "inherit" }}>—</span>}
          </td>
        )}
        {showAudits && (
          <td>
            <div style={{ display: "flex", gap: 4 }}>
              {svc.tls && <span className="db-tag" style={{ background: "rgba(168,85,247,0.12)", color: "#c084fc", fontWeight: 700 }}>TLS</span>}
              {svc.http && <span className="db-tag" style={{ background: "rgba(20,184,166,0.12)", color: "#2dd4bf", fontWeight: 700 }}>HTTP</span>}
              {!svc.tls && !svc.http && <span style={{ color: "var(--text-faint)", fontSize: "0.7rem", fontStyle: "italic" }}>—</span>}
            </div>
          </td>
        )}
      </tr>
      {expanded && hasDetails && (
        <tr>
          <td colSpan={colSpan} style={{ background: "rgba(255,255,255,0.01)", padding: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: svc.tls && svc.http ? "1fr 1fr" : "1fr", gap: 20 }}>
              {/* TLS Details */}
              {svc.tls && (
                <div style={{ borderLeft: "2px solid #a855f7", paddingLeft: 12 }}>
                  <div style={{ fontSize: "0.72rem", fontWeight: 700, color: "#c084fc", marginBottom: 6 }}>🔐 TLS Details</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: "0.72rem" }}>
                    <div><strong>Grade:</strong> <span style={{ fontWeight: 800, color: svc.tls.grade === "A" ? "#22c55e" : "#ef4444" }}>{svc.tls.grade || "Unknown"}</span></div>
                    <div><strong>Protocol:</strong> <span className="mono">{svc.tls.protocol_version}</span></div>
                    <div><strong>Cipher:</strong> <span className="mono" style={{ fontSize: "0.68rem" }}>{svc.tls.cipher_suite}</span></div>
                    <div><strong>Subject:</strong> <span className="mono" style={{ fontSize: "0.68rem" }}>{svc.tls.cert_subject}</span></div>
                    <div><strong>Expires:</strong> {svc.tls.cert_not_after ? formatTime(svc.tls.cert_not_after) : "—"}</div>
                    {svc.tls.cert_is_expired && <span style={{ color: "#ef4444", fontWeight: 700 }}>⚠ Certificate Expired</span>}
                    {svc.tls.cert_is_self_signed && <span style={{ color: "#eab308", fontWeight: 700 }}>⚠ Self-Signed Certificate</span>}
                    {svc.tls.is_weak_cipher && <span style={{ color: "#f97316", fontWeight: 700 }}>⚠ Weak Ciphers Enabled</span>}
                    {(svc.tls.issues || []).length > 0 && (
                      <div style={{ marginTop: 4, color: "#f87171" }}>
                        <strong>Issues:</strong>
                        <ul style={{ margin: 2, paddingLeft: 12 }}>
                          {svc.tls.issues.map((iss, index) => <li key={index}>{iss}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* HTTP Details */}
              {svc.http && (
                <div style={{ borderLeft: "2px solid #2dd4bf", paddingLeft: 12 }}>
                  <div style={{ fontSize: "0.72rem", fontWeight: 700, color: "#2dd4bf", marginBottom: 6 }}>🌐 HTTP Details</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: "0.72rem" }}>
                    <div><strong>Status Code:</strong> <span className="mono">{svc.http.status_code}</span></div>
                    <div><strong>Security Score:</strong> <span style={{ fontWeight: 800 }}>{svc.http.security_score}/100</span></div>
                    <div><strong>HSTS:</strong> {svc.http.has_hsts ? "✅ Configured" : "❌ Missing"}</div>
                    <div><strong>CSP:</strong> {svc.http.has_csp ? "✅ Configured" : "❌ Missing"}</div>
                    <div><strong>X-Frame-Options:</strong> <span className="mono">{svc.http.x_frame_options || "Missing"}</span></div>
                    <div><strong>X-Content-Type:</strong> <span className="mono">{svc.http.x_content_type || "Missing"}</span></div>
                    {(svc.http.missing_headers || []).length > 0 && (
                      <div style={{ marginTop: 4, color: "#fb923c" }}>
                        <strong>Missing Headers:</strong>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 2, marginTop: 2 }}>
                          {svc.http.missing_headers.map(h => <span key={h} className="db-tag" style={{ fontSize: "0.6rem" }}>{h}</span>)}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════
export default function AssetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const canUpdate = canPermission(user, { resource: "assets", action: "update" });

  const [asset, setAsset] = useState(null);
  const [services, setServices] = useState([]);
  const [findings, setFindings] = useState([]);
  const [changelogData, setChangelogData] = useState(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("vulnerabilities");

  // Notes and tag state
  const [newNote, setNewNote] = useState("");
  const [newTag, setNewTag] = useState("");
  const [ownerName, setOwnerName] = useState("");
  const [editingOwner, setEditingOwner] = useState(false);

  // Selected vulnerability for Drawer
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [assetRes, servicesRes, findingsRes, changelogRes] = await Promise.all([
        getAsset(id),
        getAssetServices(id),
        getAssetFindings(id),
        getAssetChangelog(id),
      ]);

      setAsset(assetRes.data);
      setOwnerName(assetRes.data?.owner || "");
      setServices(servicesRes.data?.services || []);
      setFindings(findingsRes.data?.findings || []);
      setChangelogData(changelogRes.data || null);
    } catch {
      setError("Failed to load asset details.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Asset toggle managed
  const handleToggleManaged = async () => {
    if (!canUpdate) return;
    try {
      const newVal = !asset.is_managed;
      await updateAsset(id, { is_managed: newVal });
      setAsset(prev => ({ ...prev, is_managed: newVal }));
    } catch {
      /* silent error */
    }
  };

  // Owner update save
  const handleSaveOwner = async () => {
    try {
      await updateAsset(id, { owner: ownerName });
      setAsset(prev => ({ ...prev, owner: ownerName }));
      setEditingOwner(false);
    } catch {
      /* silent error */
    }
  };

  // Add notes handler
  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      await addAssetNote(id, newNote);
      setNewNote("");
      // Refresh asset details (to load updated note history)
      const assetRes = await getAsset(id);
      setAsset(assetRes.data);
    } catch {
      /* silent error */
    }
  };

  // Add tags handler
  const handleAddTag = async (e) => {
    e.preventDefault();
    const tag = newTag.trim();
    if (!tag) return;
    try {
      await addAssetTag(id, tag);
      setNewTag("");
      // Refresh asset details to see updated tags
      const assetRes = await getAsset(id);
      setAsset(assetRes.data);
    } catch {
      /* silent */
    }
  };

  // Remove tag handler
  const handleRemoveTag = async (tag) => {
    try {
      await removeAssetTag(id, tag);
      setAsset(prev => ({
        ...prev,
        tags: prev.tags.filter(t => t !== tag),
      }));
    } catch {
      /* silent */
    }
  };

  // Callback to update local findings status when drawer action commits
  const handleFindingStatusChange = (findingId, newStatus) => {
    setFindings(prev =>
      prev.map(f => (f.id === findingId ? { ...f, status: newStatus } : f))
    );
  };

  if (loading) {
    return (
      <AppLayout pageTitle="Asset Details" onNewScan={() => navigate("/scan")}>
        <div style={{ padding: 40 }}>
          <div className="db-skeleton" style={{ height: 48, marginBottom: 20 }} />
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 20 }}>
            <div className="db-skeleton" style={{ height: 350 }} />
            <div className="db-skeleton" style={{ height: 350 }} />
          </div>
        </div>
      </AppLayout>
    );
  }

  if (error || !asset) {
    return (
      <AppLayout pageTitle="Asset Details" onNewScan={() => navigate("/scan")}>
        <div style={{ padding: 40 }} className="db-empty">
          <div className="db-empty-icon">⚠</div>
          <h3>Failed to Load Asset</h3>
          <p>{error || "The requested asset does not exist or you do not have permission to view it."}</p>
          <button className="db-btn db-btn--primary" onClick={() => navigate("/assets")}>
            Back to Registry
          </button>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle={`Asset: ${asset.ip_address}`} onNewScan={() => navigate("/scan")}>
      <div className="db-page">
        {/* Back Link */}
        <div style={{ padding: "16px 28px 0" }}>
          <button
            onClick={() => navigate("/assets")}
            className="db-btn db-btn--ghost"
            style={{ padding: "4px 10px", fontSize: "0.72rem" }}
          >
            ← Back to Asset Registry
          </button>
        </div>

        {/* Header Block */}
        <div className="db-page-header" style={{ borderBottom: "none" }}>
          <div>
            <div className="db-page-title" style={{ fontFamily: "var(--mono)", fontSize: "1.6rem" }}>
              {asset.ip_address}
            </div>
            <div className="db-page-subtitle">
              {asset.hostname ? (
                <>
                  <span style={{ fontWeight: 600, color: "var(--text)" }}>{asset.hostname}</span>
                  {asset.fqdn && asset.fqdn !== asset.hostname && (
                    <span style={{ color: "var(--text-faint)" }}> · {asset.fqdn}</span>
                  )}
                </>
              ) : (
                "No Hostname Resolved"
              )}
            </div>

            {/* Managed Toggle / Status Row */}
            <div style={{ display: "flex", gap: 10, marginTop: 12, alignItems: "center" }}>
              <span
                className="db-status"
                style={
                  asset.is_active
                    ? { background: "rgba(34,197,94,0.1)", color: "#4ade80" }
                    : { background: "var(--border)", color: "var(--text-muted)" }
                }
              >
                ● {asset.is_active ? "Online / Active" : "Offline / Inactive"}
              </span>

              <button
                disabled={!canUpdate}
                onClick={handleToggleManaged}
                className="db-tag"
                style={{
                  cursor: canUpdate ? "pointer" : "default",
                  background: asset.is_managed ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)",
                  color: asset.is_managed ? "#4ade80" : "#f87171",
                  borderColor: asset.is_managed ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)",
                  fontWeight: 700,
                  outline: "none",
                }}
              >
                {asset.is_managed ? "✔ Managed Asset" : "✗ Unmanaged Asset"}
              </button>
            </div>
          </div>

          {/* Risk Ring (Radial indicator) */}
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div className="db-risk-ring">
              <svg width="88" height="88">
                <circle cx="44" cy="44" r="38" fill="transparent" stroke="var(--border)" strokeWidth="6" />
                <circle
                  cx="44"
                  cy="44"
                  r="38"
                  fill="transparent"
                  stroke={riskColor(asset.risk_score)}
                  strokeWidth="6"
                  strokeDasharray={`${2 * Math.PI * 38}`}
                  strokeDashoffset={`${2 * Math.PI * 38 * (1 - asset.risk_score / 100)}`}
                />
              </svg>
              <div className="db-risk-ring-center">
                <span className="db-risk-ring-num" style={{ color: riskColor(asset.risk_score) }}>
                  {asset.risk_score}
                </span>
                <span className="db-risk-ring-lbl">RISK</span>
              </div>
            </div>

            <div>
              <div style={{ fontSize: "0.6rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
                Risk Classification
              </div>
              <span
                className={`db-sev-badge ${SEV_CLASS[asset.risk_level?.charAt(0).toUpperCase() + asset.risk_level?.slice(1).toLowerCase()] || "db-sev-badge--info"}`}
                style={{ marginTop: 4, display: "inline-block", fontSize: "0.78rem", padding: "4px 8px" }}
              >
                {asset.risk_level}
              </span>
            </div>
          </div>
        </div>

        {/* Tab Selector */}
        <div className="db-tab-bar" style={{ marginTop: 8 }}>
          <button
            className={`db-tab ${activeTab === "vulnerabilities" ? "active" : ""}`}
            onClick={() => setActiveTab("vulnerabilities")}
          >
            Vulnerabilities ({findings.length})
          </button>
          <button
            className={`db-tab ${activeTab === "services" ? "active" : ""}`}
            onClick={() => setActiveTab("services")}
          >
            Services & Ports ({services.length})
          </button>
          <button
            className={`db-tab ${activeTab === "changelog" ? "active" : ""}`}
            onClick={() => setActiveTab("changelog")}
          >
            Audit & Changelog ({changelogData?.stats?.total_events || 0})
          </button>
        </div>

        {/* Main Content Grid */}
        <div className="db-section" style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>

          {/* Left Column: Tab Data */}
          <div>

            {/* Tab: Vulnerabilities */}
            {activeTab === "vulnerabilities" && (
              <div className="db-card" style={{ padding: 0 }}>
                <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border)" }}>
                  <h4 style={{ margin: 0, fontSize: "0.85rem", color: "var(--text)" }}>Discovered Findings</h4>
                </div>
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th>CVE / Finding</th>
                        <th>CVSS</th>
                        <th>Priority</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Last Detected</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
                            No vulnerabilities identified on this asset. Good work!
                          </td>
                        </tr>
                      ) : (
                        findings.map((f) => (
                          <tr
                            key={f.id}
                            style={{ cursor: "pointer" }}
                            onClick={() => setSelectedFindingId(f.id)}
                          >
                            <td>
                              <div className="cve-id">
                                <CVELink cveId={f.vuln_id} />
                              </div>
                              <div
                                style={{
                                  fontSize: "0.65rem",
                                  color: "var(--text-faint)",
                                  maxWidth: 220,
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {f.title}
                              </div>
                              {f.in_kev && (
                                <span
                                  style={{
                                    fontSize: "0.6rem",
                                    fontWeight: 700,
                                    background: "rgba(239,68,68,0.12)",
                                    color: "#f87171",
                                    padding: "1px 5px",
                                    borderRadius: 3,
                                  }}
                                >
                                  KEV
                                </span>
                              )}
                            </td>
                            <td>
                              <span
                                className="cvss-score"
                                style={{
                                  color:
                                    f.cvss_v3_score >= 9
                                      ? "#f87171"
                                      : f.cvss_v3_score >= 7
                                        ? "#fb923c"
                                        : "#fbbf24",
                                }}
                              >
                                {f.cvss_v3_score ? f.cvss_v3_score.toFixed(1) : "0.0"}
                              </span>
                            </td>
                            <td>
                              <span className={`db-priority-badge ${PRI_CLASS[f.priority_label] || ""}`}>
                                {f.priority_label}
                              </span>
                            </td>
                            <td>
                              <span className={`db-sev-badge ${SEV_CLASS[f.severity] || ""}`}>
                                {f.severity}
                              </span>
                            </td>
                            <td>
                              <span
                                className="db-tag"
                                style={
                                  f.status === "open"
                                    ? { color: "#f87171", borderColor: "rgba(239,68,68,0.2)", background: "rgba(239,68,68,0.06)" }
                                    : f.status === "accepted"
                                      ? { color: "#fbbf24", borderColor: "rgba(234,179,8,0.2)", background: "rgba(234,179,8,0.06)" }
                                      : f.status === "fixed"
                                        ? { color: "#4ade80", borderColor: "rgba(34,197,94,0.2)", background: "rgba(34,197,94,0.06)" }
                                        : {}
                                }
                              >
                                {f.status}
                              </span>
                            </td>
                            <td style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                              {ago(f.last_found_at)}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Tab: Services & Open Ports */}
            {activeTab === "services" && (() => {
              // ── Compute column visibility from actual data ──────────────────
              const showProduct = services.some(s => s.service_product);
              const showBanner = services.some(s => s.banner);
              const showAudits = services.some(s => s.tls || s.http);
              const colCount = 3 + (showProduct ? 1 : 0) + (showBanner ? 1 : 0) + (showAudits ? 1 : 0);
              const missingEnrichment = !showProduct && !showBanner && !showAudits;

              return (
                <div className="db-card" style={{ padding: 0 }}>
                  <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <h4 style={{ margin: 0, fontSize: "0.85rem", color: "var(--text)" }}>Open Ports & Running Services</h4>
                    <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>
                      {services.length} service{services.length !== 1 ? "s" : ""} discovered
                    </span>
                  </div>

                  {/* ── Enrichment hint banner ─────────────────────────────── */}
                  {missingEnrichment && services.length > 0 && (
                    <div style={{
                      margin: "12px 16px 0",
                      padding: "10px 14px",
                      background: "rgba(59,130,246,0.06)",
                      border: "1px solid rgba(59,130,246,0.18)",
                      borderRadius: 8,
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 10,
                    }}>
                      <span style={{ fontSize: "1rem", lineHeight: 1.2 }}>🔬</span>
                      <div>
                        <div style={{ fontSize: "0.72rem", fontWeight: 700, color: "#60a5fa", marginBottom: 4 }}>
                          Service enrichment data not available for this scan type
                        </div>
                        <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                          <strong>Product &amp; Version</strong> and <strong>Banner</strong> data require a{" "}
                          <span style={{ color: "#93c5fd", fontWeight: 600 }}>Service Fingerprinting Scan</span>{" "}
                          (Nmap <code style={{ background: "rgba(255,255,255,0.07)", padding: "0 3px", borderRadius: 3 }}>-sV</code>).
                          &nbsp;<strong>TLS / HTTP Audits</strong> require a{" "}
                          <span style={{ color: "#93c5fd", fontWeight: 600 }}>Vulnerability Assessment</span> or{" "}
                          <span style={{ color: "#93c5fd", fontWeight: 600 }}>Authenticated Deep Inspection</span>.
                          Port discovery and service identification from the current scan are shown below.
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="db-table-wrap" style={{ marginTop: missingEnrichment && services.length > 0 ? 8 : 0 }}>
                    <table className="db-table">
                      <thead>
                        <tr>
                          <th>Port / Protocol</th>
                          <th>Service Name</th>
                          <th>State</th>
                          {showProduct && <th>Product &amp; Version</th>}
                          {showBanner && <th>Banner</th>}
                          {showAudits && <th>Audits</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {services.length === 0 ? (
                          <tr>
                            <td colSpan={colCount} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
                              No open ports detected on this host.
                            </td>
                          </tr>
                        ) : (
                          services.map((svc) => (
                            <ServiceDetailRow
                              key={svc.id}
                              svc={svc}
                              showProduct={showProduct}
                              showBanner={showBanner}
                              showAudits={showAudits}
                              colSpan={colCount}
                            />
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              );
            })()}

            {/* Tab: Changelog */}
            {activeTab === "changelog" && (
              <div className="db-card" style={{ padding: 0 }}>
                <AuditTimeline changelogData={changelogData} />
              </div>
            )}
          </div>

          {/* Right Column: Sidebar Panels */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

            {/* Panel: System Details */}
            <div className="db-card">
              <h4 className="db-card-title">System Information</h4>
              <div className="db-card-sub">Hardware & OS fingerprint profiles</div>

              <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: "0.72rem" }}>
                {/* ── Network Identity ─────────────────────────────── */}
                <SidebarRow label="IP Address:" value={asset.ip_address} mono />
                <SidebarRow label="MAC Address:" value={asset.mac_address} mono />
                <SidebarRow label="Subnet:" value={asset.subnet} mono />
                <SidebarRow label="Hostname:"      value={asset.hostname} mono />
                {asset.fqdn && asset.fqdn !== asset.hostname && (
                  <SidebarRow label="FQDN:"          value={asset.fqdn} mono />
                )}
                {asset.dns_name && asset.dns_name !== asset.hostname && asset.dns_name !== asset.fqdn && (
                  <SidebarRow label="DNS Name:"      value={asset.dns_name} mono />
                )}
                <SidebarRow label="NetBIOS Name:" value={asset.netbios_name} mono />
                <SidebarRow label="Domain:" value={asset.custom_attributes?.credentialed_system_info?.domain} mono />
                {/* ── OS / Hardware ────────────────────────────────── */}
                <SidebarRow label="OS Family:" value={asset.os_family} mono />
                <SidebarRow label="OS Name:" value={asset.os_name} />
                <SidebarRow label="OS Version:" value={asset.os_version} mono />
                <SidebarRow label="OS Build:" value={asset.custom_attributes?.credentialed_system_info?.os_build} mono />
                <SidebarRow label="Kernel Version:" value={asset.custom_attributes?.credentialed_system_info?.kernel_version} mono />
                {(asset.os_name || asset.os_family) && asset.os_confidence && (
                  <SidebarRow label="OS Confidence:" value={`${asset.os_confidence}%`} mono />
                )}
                <SidebarRow label="Device Category:" value={asset.device_category} />
                <SidebarRow label="Vendor:" value={asset.vendor} />
                {asset.manufacturer && cleanVendorName(asset.manufacturer) !== cleanVendorName(asset.vendor) && (
                  <SidebarRow label="Manufacturer:" value={asset.manufacturer} />
                )}
                <SidebarRow label="Hardware Model:" value={asset.custom_attributes?.credentialed_system_info?.hardware_model} />
                <SidebarRow label="CPU Model:" value={asset.custom_attributes?.credentialed_system_info?.cpu_model} />
                <SidebarRow label="CPU Cores:" value={asset.custom_attributes?.credentialed_system_info?.cpu_count} mono />
                <SidebarRow label="VLAN ID:" value={asset.vlan_id} mono />
                <SidebarRow label="Discovery Method:" value={asset.discovery_method || "active"} isTag />
                <SidebarRow label="First Discovered:" value={combineTime(asset.first_seen_at)} />
                <SidebarRow label="Last Activity:" value={combineTime(asset.last_seen_at)} />
                <SidebarRow label="System Uptime:" value={asset.custom_attributes?.credentialed_system_info?.uptime} />
                {asset.response_time_ms !== null && asset.response_time_ms !== undefined && (
                  <SidebarRow label="Response Time:" value={`${asset.response_time_ms} ms`} mono />
                )}
                <SidebarRow label="Last Scan ID:" value={asset.last_scan_id} mono />
                <SidebarRow label="Asset ID:" value={asset.id} mono noBorder />
              </div>
            </div>

            {/* Panel: Owner Details */}
            <div className="db-card">
              <h4 className="db-card-title">Assignee / Owner</h4>
              <div className="db-card-sub">Assign accountability for security remediation</div>

              {!editingOwner ? (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "0.78rem", fontWeight: 700, color: asset.owner ? "var(--text)" : "var(--text-faint)" }}>
                    👤 {asset.owner || "No owner assigned"}
                  </span>
                  {canUpdate && (
                    <button onClick={() => setEditingOwner(true)} className="db-btn db-btn--ghost" style={{ padding: "3px 6px", fontSize: "0.65rem" }}>
                      Edit
                    </button>
                  )}
                </div>
              ) : (
                <div style={{ display: "flex", gap: 6 }}>
                  <input
                    type="text"
                    value={ownerName}
                    onChange={(e) => setOwnerName(e.target.value)}
                    placeholder="Enter owner name…"
                    style={{ flex: 1, padding: "4px 8px", fontSize: "0.72rem", border: "1px solid var(--border)", borderRadius: 5, background: "var(--bg-white)", color: "var(--text)" }}
                  />
                  <button onClick={handleSaveOwner} className="db-btn db-btn--primary" style={{ padding: "4px 8px" }}>Save</button>
                  <button onClick={() => { setOwnerName(asset.owner || ""); setEditingOwner(false); }} className="db-btn db-btn--ghost" style={{ padding: "4px 8px" }}>Cancel</button>
                </div>
              )}
            </div>

            {/* Panel: Tags Manager */}
            <div className="db-card">
              <h4 className="db-card-title">Asset Tags</h4>
              <div className="db-card-sub">Tag hosts to filter reports and group assets</div>

              {/* Tag List */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 12 }}>
                {(asset.tags || []).length === 0 ? (
                  <span style={{ fontSize: "0.72rem", color: "var(--text-faint)" }}>No tags configured</span>
                ) : (
                  asset.tags.map((tag) => (
                    <span key={tag} className="db-tag" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                      {tag}
                      {canUpdate && (
                        <span
                          onClick={() => handleRemoveTag(tag)}
                          style={{ cursor: "pointer", opacity: 0.6, fontSize: "0.6rem", fontWeight: "bold" }}
                          title="Remove Tag"
                        >
                          ✕
                        </span>
                      )}
                    </span>
                  ))
                )}
              </div>

              {/* Tag Add Form */}
              {canUpdate && (
                <form onSubmit={handleAddTag} style={{ display: "flex", gap: 6 }}>
                  <input
                    type="text"
                    placeholder="New tag (e.g. dmz, production)…"
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                    style={{ flex: 1, padding: "5px 8px", fontSize: "0.72rem", border: "1px solid var(--border)", borderRadius: 5, background: "var(--bg-white)", color: "var(--text)" }}
                  />
                  <button type="submit" className="db-btn db-btn--ghost" style={{ padding: "5px 8px" }}>+</button>
                </form>
              )}
            </div>

            {/* Panel: Analyst Notes */}
            <div className="db-card">
              <h4 className="db-card-title">Analyst Log Notes</h4>
              <div className="db-card-sub">Add findings notes, status tracking comments</div>

              {/* Note Submission Form */}
              {canUpdate && (
                <form onSubmit={handleAddNote} style={{ marginBottom: 12 }}>
                  <textarea
                    placeholder="Add comment logs for other SOC analysts…"
                    rows={3}
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    style={{ width: "100%", padding: "6px 8px", fontSize: "0.72rem", border: "1px solid var(--border)", borderRadius: 6, background: "var(--bg-white)", color: "var(--text)", resize: "vertical", marginBottom: 6 }}
                  />
                  <button type="submit" className="db-btn db-btn--primary" style={{ padding: "4px 8px", fontSize: "0.68rem" }}>
                    Log Note
                  </button>
                </form>
              )}

              {/* Notes Timeline List */}
              <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 220, overflowY: "auto", paddingRight: 4 }}>
                {(asset.notes || []).length === 0 ? (
                  <div style={{ fontSize: "0.72rem", color: "var(--text-faint)", textAlign: "center", padding: "10px 0" }}>
                    No analyst notes logged for this host.
                  </div>
                ) : (
                  [...(asset.notes || [])].reverse().map((note) => (
                    <div
                      key={note.id}
                      style={{
                        background: "rgba(255,255,255,0.015)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: 8,
                        fontSize: "0.72rem",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", color: "var(--text-faint)", fontSize: "0.62rem", marginBottom: 4 }}>
                        <span style={{ fontWeight: 600 }}>👤 User ID: {note.user_id?.substring(0, 8)}...</span>
                        <span>{ago(note.created_at)}</span>
                      </div>
                      <div style={{ color: "var(--text)", lineHeight: 1.4, wordBreak: "break-word" }}>
                        {note.content}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* Selected Vulnerability Detail Drawer Modal */}
      {selectedFindingId && (
        <FindingDrawer
          findingId={selectedFindingId}
          canUpdate={canUpdate}
          onClose={() => setSelectedFindingId(null)}
          onStatusChange={handleFindingStatusChange}
        />
      )}
    </AppLayout>
  );
}
