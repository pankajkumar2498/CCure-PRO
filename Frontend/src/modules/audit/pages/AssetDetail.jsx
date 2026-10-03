/**
 * src/modules/audit/pages/AssetDetail.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Complete, premium Asset Detail page.
 * - Drill down from Asset Registry to see detailed host metadata
 * - Manage asset ownership and toggles (Managed/Unmanaged)
 * - Timeline-based analyst notes and tags manager
 * - Vulnerabilities tab with drawer details (proof, severity, CVSS) and actions (remediate/risk accept)
 * - Services & Open Ports tab with detailed TLS and HTTP security headers inspection
 * - Historical change log audit timeline
 *
 * Checkpoint 3C batch 11: presentation moved onto the CCure design system.
 *
 * What did NOT change: the four reads on mount, the six writes (method, path
 * and body), the `assets:update` gate on every write control — including the
 * finding-status actions, whose backend rule is different and is recorded as
 * debt rather than changed here — the tag encoding, the optimistic toggle
 * and its revert, the Confirm step before a status write, the re-read after
 * every successful write, and every field's show/hide rule.
 *
 * Two behaviours changed on purpose, both approved at the batch 11 planning
 * checkpoint:
 *
 *   1. The status-save success message is now rendered in a live region that
 *      outlives the action panel. It used to be set in state and rendered
 *      only inside the panel the same handler closed, so nobody ever saw it.
 *   2. The five writes that swallowed their errors (`catch {}`) now report the
 *      failure in a danger alert. State behaviour is unchanged — the toggle
 *      still reverts, edit mode stays open, the tag stays — and nothing
 *      retries.
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import HostPosturePanel from "@audit/components/assets/HostPosturePanel";
import { useAuth } from "@shell/auth/AuthContext";
import { canPermission } from "@shell/auth/permissions";
import {
  getAsset,
  getAssetServices,
  getAssetFindings,
  getAssetChangelog,
  updateAsset,
  addAssetTag,
  removeAssetTag,
  addAssetNote,
} from "@audit/api/assets";
import { getFinding, updateFindingStatus } from "@audit/api/findings";
import CVELink from "@audit/components/common/CVELink";
import AuditTimeline from "@audit/components/assets/AuditTimeline";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureEmptyState,
  CcureField,
  CcureInput,
  CcureSeverityBadge,
  CcureSkeleton,
  CcureTabPanel,
  CcureTabs,
  useFocusTrap,
} from "../../../design-system";
import "../styles/asset-detail.css";

const ago = (iso) => {
  if (!iso) return "—";
  const date = new Date(iso);
  if (isNaN(date.getTime())) return "—";
  const now = new Date();
  const nowMidnight = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
  );
  const dateMidnight = new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
  );
  const d = Math.round((nowMidnight - dateMidnight) / 86400000);
  if (d <= 0) return "Today";
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
    .replace(
      /(inc|incorporated|corp|corporation|ltd|limited|co|company|systems|hardware)$/g,
      "",
    );
};

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
  return labels[cat] || cat || "—";
};

/* Risk bands, shared by the ring and the CVSS cells: the same thresholds the
   registry uses, resolved to a class rather than a colour literal. */
const riskBand = (score) =>
  score >= 75 ? "crit" : score >= 50 ? "high" : score >= 25 ? "med" : "low";
const cvssBand = (score) => (score >= 9 ? "crit" : score >= 7 ? "high" : "med");

const RISK_LEVEL_VARIANT = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "success",
};
const PRIORITY_VARIANT = {
  P0: "danger",
  P1: "danger",
  P2: "warning",
  P3: "info",
  P4: "neutral",
};
const STATUS_VARIANT = {
  open: "danger",
  accepted: "warning",
  fixed: "success",
};

const RING_R = 38;
const RING_C = 2 * Math.PI * RING_R;

function InfoField({ label, value, mono = false, isTag = false }) {
  if (
    value === null ||
    value === undefined ||
    value === "" ||
    value === "—" ||
    value === "Unknown" ||
    value === "unknown"
  )
    return null;
  return (
    <div className="ad-field">
      <span className="ad-field-label">{label}</span>
      {isTag ? (
        <span>
          <CcureBadge variant="neutral">{value}</CcureBadge>
        </span>
      ) : (
        <span className={`ad-field-value${mono ? " ad-mono" : ""}`}>
          {value}
        </span>
      )}
    </div>
  );
}

function InfoGrid({ children }) {
  return <div className="ad-field-grid">{children}</div>;
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

  /* A real dialog: focus is contained while it is open and restored to the
     opener on close; Escape closes it. */
  const panelRef = useRef(null);
  useFocusTrap(panelRef, true);
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    if (!findingId) return;
    setLoading(true);
    getFinding(findingId)
      .then((r) => setDetail(r.data))
      .catch(() => {})
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

  const v = detail?.vulnerability;
  const saveFailed = saveMsg.includes("Failed");

  return (
    <div className="ad-drawer">
      <div className="ad-drawer-scrim" onClick={onClose} />
      <div
        className="ad-drawer-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ad-drawer-title"
        ref={panelRef}
      >
        <div className="ad-drawer-head">
          <div>
            <div className="ad-kicker">Finding Detail</div>
            <h2 className="ad-drawer-title" id="ad-drawer-title">
              {loading ? (
                <CcureSkeleton width={200} height={18} radius={3} />
              ) : (
                <CVELink cveId={v?.id} className="ad-inherit" />
              )}
            </h2>
          </div>
          <CcureButton
            variant="ghost"
            size="sm"
            aria-label="Close finding details"
            onClick={onClose}
          >
            ✕
          </CcureButton>
        </div>

        {/* Always mounted, so a result written after the action panel closes
            still has somewhere to be announced. (Approved change 1.) */}
        <div
          role="status"
          aria-live="polite"
          className={`ad-savemsg${saveMsg ? (saveFailed ? " ad-savemsg--bad" : " ad-savemsg--ok") : ""}`}
        >
          {saveMsg}
        </div>

        {loading ? (
          <div className="ad-drawer-body">
            {[200, 100, 150, 80, 120].map((w, i) => (
              <CcureSkeleton
                key={i}
                width={w}
                height={12}
                radius={3}
                className="ad-mb-sm"
              />
            ))}
          </div>
        ) : !detail ? (
          <CcureEmptyState icon="⚠" title="Finding not found" />
        ) : (
          <div className="ad-drawer-body">
            <div className="ad-badges ad-mb-sm">
              <CcureSeverityBadge severity={v?.severity} />
              <CcureBadge
                variant={PRIORITY_VARIANT[v?.priority_label] || "neutral"}
                mono
              >
                {v?.priority_label}
              </CcureBadge>
              {v?.in_kev && <CcureBadge variant="danger">KEV</CcureBadge>}
              {v?.has_exploit && (
                <CcureBadge variant="warning">Exploit</CcureBadge>
              )}
            </div>

            <div className="ad-drawer-name">{v?.title}</div>

            <div className="ad-scores">
              <div className="ad-score">
                <div className="ad-score-label">CVSSv3</div>
                <div
                  className={`ad-score-value ad-cvss--${cvssBand(v?.cvss_v3_score || 0)}`}
                >
                  {(v?.cvss_v3_score || 0).toFixed(1)}
                </div>
              </div>
              <div className="ad-score">
                <div className="ad-score-label">EPSS</div>
                <div className="ad-score-value">
                  {((v?.epss_score || 0) * 100).toFixed(1)}%
                </div>
              </div>
              <div className="ad-score">
                <div className="ad-score-label">Priority</div>
                <div className="ad-score-value">
                  {(v?.priority_score || 0).toFixed(0)}
                </div>
              </div>
            </div>

            <div className="ad-description">
              {v?.description || "No description available."}
            </div>

            {v?.cvss_v3_vector && (
              <div className="ad-section">
                <div className="ad-kicker">CVSS Vector</div>
                <div className="ad-code">{v.cvss_v3_vector}</div>
              </div>
            )}

            {(v?.cwe_ids || []).length > 0 && (
              <div className="ad-section">
                <div className="ad-kicker">CWE IDs</div>
                <div className="ad-badges">
                  {v.cwe_ids.map((c) => (
                    <CcureBadge key={c} variant="neutral" mono>
                      {c}
                    </CcureBadge>
                  ))}
                </div>
              </div>
            )}

            {(detail.proof || detail.plugin_output) && (
              <div className="ad-section">
                <div className="ad-kicker">Evidence / Plugin Output</div>
                <pre className="ad-evidence">
                  {detail.proof || detail.plugin_output}
                </pre>
              </div>
            )}

            <div className="ad-dates">
              <span>First: {ago(detail.first_found_at)}</span>
              <span>Last: {ago(detail.last_found_at)}</span>
              {detail.fixed_at && (
                <span className="ad-dates-fixed">
                  Fixed: {ago(detail.fixed_at)}
                </span>
              )}
            </div>

            {canUpdate && detail.status === "open" && (
              <div className="ad-section">
                <div className="ad-kicker ad-kicker--strong">Actions</div>
                {!action ? (
                  <div className="ad-actions">
                    <CcureButton
                      variant="secondary"
                      className="ad-grow"
                      onClick={() => setAction("accepted")}
                    >
                      ✔ Accept Risk
                    </CcureButton>
                    <CcureButton
                      variant="secondary"
                      className="ad-grow ad-btn--ok"
                      onClick={() => setAction("fixed")}
                    >
                      🛠 Mark Fixed
                    </CcureButton>
                  </div>
                ) : (
                  <div className="ad-action-panel">
                    <div className="ad-action-title">
                      {action === "accepted"
                        ? "Accept Risk — provide reason:"
                        : "Mark as Fixed:"}
                    </div>
                    {action === "accepted" && (
                      <CcureField
                        id="ad-reason"
                        label="Reason for accepting this risk"
                      >
                        <textarea
                          id="ad-reason"
                          className="cc-field__control ad-textarea"
                          value={reason}
                          onChange={(e) => setReason(e.target.value)}
                          placeholder="Reason for accepting this risk…"
                          rows={3}
                        />
                      </CcureField>
                    )}
                    <CcureField
                      id="ad-remediation"
                      label="Remediation notes (optional)"
                    >
                      <textarea
                        id="ad-remediation"
                        className="cc-field__control ad-textarea"
                        value={notes}
                        onChange={(e) => setNotes(e.target.value)}
                        placeholder="Remediation notes (optional)…"
                        rows={2}
                      />
                    </CcureField>
                    <div className="ad-actions">
                      <CcureButton
                        variant="primary"
                        className="ad-grow"
                        disabled={saving}
                        onClick={() => handleStatusSave(action)}
                      >
                        {saving
                          ? "Saving…"
                          : `Confirm ${action === "accepted" ? "Accept" : "Fixed"}`}
                      </CcureButton>
                      <CcureButton
                        variant="ghost"
                        onClick={() => setAction(null)}
                      >
                        Cancel
                      </CcureButton>
                    </div>
                  </div>
                )}
              </div>
            )}

            {detail.remediation_notes && (
              <div className="ad-section">
                <div className="ad-kicker">Remediation Notes</div>
                <div className="ad-note-box">{detail.remediation_notes}</div>
              </div>
            )}

            {(v?.references || []).length > 0 && (
              <div className="ad-section">
                <div className="ad-kicker">References</div>
                <div className="ad-refs">
                  {v.references.slice(0, 5).map((ref, i) => (
                    <a
                      key={i}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ad-ref"
                    >
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
function ServiceDetailRow({
  svc,
  showProduct,
  showBanner,
  showAudits,
  colSpan,
}) {
  const [expanded, setExpanded] = useState(false);
  const hasDetails = !!svc.tls || !!svc.http;
  const detailId = `ad-svc-${svc.id ?? `${svc.port}-${svc.protocol}`}`;

  const dash = <span className="ad-faint ad-italic">—</span>;

  return (
    <>
      <tr>
        <td>
          {/* Was a `<tr onClick>` with a glyph: unreachable by keyboard and
              silent about whether it was open. */}
          {hasDetails ? (
            <button
              type="button"
              className="ad-expand"
              aria-expanded={expanded}
              aria-controls={expanded ? detailId : undefined}
              onClick={() => setExpanded(!expanded)}
            >
              <span className="ad-expand-glyph" aria-hidden="true">
                {expanded ? "▼" : "▶"}
              </span>
              {svc.port} / {svc.protocol}
            </button>
          ) : (
            <span className="ad-mono ad-strong">
              {svc.port} / {svc.protocol}
            </span>
          )}
        </td>
        <td>
          <CcureBadge variant="neutral">
            {svc.service_name || "unknown"}
          </CcureBadge>
        </td>
        <td>
          <CcureBadge variant="success">{svc.state}</CcureBadge>
        </td>
        {showProduct && (
          <td className="ad-mono ad-t-xs">
            {svc.service_product
              ? `${svc.service_product} ${svc.service_version || ""}`.trim()
              : dash}
          </td>
        )}
        {showBanner && (
          <td className="ad-mono ad-t-xs ad-truncate">
            {svc.banner ? svc.banner : dash}
          </td>
        )}
        {showAudits && (
          <td>
            <div className="ad-badges">
              {svc.tls && <CcureBadge variant="info">TLS</CcureBadge>}
              {svc.http && <CcureBadge variant="primary">HTTP</CcureBadge>}
              {!svc.tls && !svc.http && dash}
            </div>
          </td>
        )}
      </tr>
      {expanded && hasDetails && (
        <tr id={detailId}>
          <td colSpan={colSpan} className="ad-detail-cell">
            <div
              className={`ad-detail-grid${svc.tls && svc.http ? " ad-detail-grid--two" : ""}`}
            >
              {/* TLS Details */}
              {svc.tls && (
                <div className="ad-detail ad-detail--tls">
                  <div className="ad-detail-title">🔐 TLS Details</div>
                  <div className="ad-detail-rows">
                    <div>
                      <strong>Grade:</strong>{" "}
                      <span
                        className={`ad-grade ad-grade--${svc.tls.grade === "A" ? "good" : "bad"}`}
                      >
                        {svc.tls.grade || "Unknown"}
                      </span>
                    </div>
                    <div>
                      <strong>Protocol:</strong>{" "}
                      <span className="ad-mono">
                        {svc.tls.protocol_version}
                      </span>
                    </div>
                    <div>
                      <strong>Cipher:</strong>{" "}
                      <span className="ad-mono ad-t-xs">
                        {svc.tls.cipher_suite}
                      </span>
                    </div>
                    <div>
                      <strong>Subject:</strong>{" "}
                      <span className="ad-mono ad-t-xs">
                        {typeof svc.tls.cert_subject === "object"
                          ? svc.tls.cert_subject?.common_name || "—"
                          : svc.tls.cert_subject || "—"}
                      </span>
                    </div>
                    <div>
                      <strong>Expires:</strong>{" "}
                      {svc.tls.cert_not_after
                        ? formatTime(svc.tls.cert_not_after)
                        : "—"}
                    </div>
                    {svc.tls.cert_is_expired && (
                      <span className="ad-flag ad-flag--danger">
                        ⚠ Certificate Expired
                      </span>
                    )}
                    {svc.tls.cert_is_self_signed && (
                      <span className="ad-flag ad-flag--warning">
                        ⚠ Self-Signed Certificate
                      </span>
                    )}
                    {svc.tls.is_weak_cipher && (
                      <span className="ad-flag ad-flag--high">
                        ⚠ Weak Ciphers Enabled
                      </span>
                    )}
                    {(svc.tls.issues || []).length > 0 && (
                      <div className="ad-issues">
                        <strong>Issues:</strong>
                        <ul className="ad-issues-list">
                          {svc.tls.issues.map((iss, index) => (
                            <li key={index}>{iss}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* HTTP Details */}
              {svc.http && (
                <div className="ad-detail ad-detail--http">
                  <div className="ad-detail-title">🌐 HTTP Details</div>
                  <div className="ad-detail-rows">
                    <div>
                      <strong>Status Code:</strong>{" "}
                      <span className="ad-mono">{svc.http.status_code}</span>
                    </div>
                    <div>
                      <strong>Security Score:</strong>{" "}
                      <span className="ad-strong">
                        {svc.http.security_score}/100
                      </span>
                    </div>
                    <div>
                      <strong>HSTS:</strong>{" "}
                      {svc.http.has_hsts ? "✅ Configured" : "❌ Missing"}
                    </div>
                    <div>
                      <strong>CSP:</strong>{" "}
                      {svc.http.has_csp ? "✅ Configured" : "❌ Missing"}
                    </div>
                    <div>
                      <strong>X-Frame-Options:</strong>{" "}
                      <span className="ad-mono">
                        {svc.http.x_frame_options || "Missing"}
                      </span>
                    </div>
                    <div>
                      <strong>X-Content-Type:</strong>{" "}
                      <span className="ad-mono">
                        {svc.http.x_content_type || "Missing"}
                      </span>
                    </div>
                    {(svc.http.missing_headers || []).length > 0 && (
                      <div className="ad-missing">
                        <strong>Missing Headers:</strong>
                        <div className="ad-badges ad-mt-2xs">
                          {svc.http.missing_headers.map((h) => (
                            <CcureBadge key={h} variant="warning" mono>
                              {h}
                            </CcureBadge>
                          ))}
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

const TABS_ID = "ad-tabs";

// ═══════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════
export default function AssetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const canUpdate = canPermission(user, "audit.asset.update");

  const [asset, setAsset] = useState(null);
  const [services, setServices] = useState([]);
  const [findings, setFindings] = useState([]);
  const [changelogData, setChangelogData] = useState(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("system_info");

  // Notes and tag state
  const [newNote, setNewNote] = useState("");
  const [newTag, setNewTag] = useState("");
  const [ownerName, setOwnerName] = useState("");
  const [editingOwner, setEditingOwner] = useState(false);

  /* Approved change 2: a failed write is reported, not swallowed. One message
     at a time; a later success clears it. */
  const [writeError, setWriteError] = useState("");

  // Selected vulnerability for Drawer
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [assetRes, servicesRes, findingsRes, changelogRes] =
        await Promise.all([
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
      setAsset((prev) => ({ ...prev, is_managed: newVal }));
      setWriteError("");
    } catch {
      setWriteError(
        "Could not update the managed state. The asset was not changed.",
      );
    }
  };

  // Owner update save
  const handleSaveOwner = async () => {
    try {
      await updateAsset(id, { owner: ownerName });
      setAsset((prev) => ({ ...prev, owner: ownerName }));
      setEditingOwner(false);
      setWriteError("");
    } catch {
      setWriteError(
        "Could not save the owner. The previous owner is still recorded.",
      );
    }
  };

  // Add notes handler
  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      await addAssetNote(id, newNote);
      setNewNote("");
      setWriteError("");
      // Refresh asset details (to load updated note history)
      const assetRes = await getAsset(id);
      setAsset(assetRes.data);
    } catch {
      setWriteError("Could not log the note.");
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
      setWriteError("");
      // Refresh asset details to see updated tags
      const assetRes = await getAsset(id);
      setAsset(assetRes.data);
    } catch {
      setWriteError(`Could not add the tag "${tag}".`);
    }
  };

  // Remove tag handler
  const handleRemoveTag = async (tag) => {
    try {
      await removeAssetTag(id, tag);
      setAsset((prev) => ({
        ...prev,
        tags: prev.tags.filter((t) => t !== tag),
      }));
      setWriteError("");
    } catch {
      setWriteError(`Could not remove the tag "${tag}".`);
    }
  };

  // Callback to update local findings status when drawer action commits
  const handleFindingStatusChange = (findingId, newStatus) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f)),
    );
  };

  const closeDrawer = useCallback(() => setSelectedFindingId(null), []);

  if (loading) {
    return (
      <AppLayout pageTitle="Asset Details" onNewScan={() => navigate("/scan")}>
        <div className="ad-page ad-page--loading" aria-busy="true">
          <CcureSkeleton height={48} className="ad-mb-lg" />
          <div className="ad-body">
            <CcureSkeleton height={350} />
            <CcureSkeleton height={350} />
          </div>
        </div>
      </AppLayout>
    );
  }

  if (error || !asset) {
    return (
      <AppLayout pageTitle="Asset Details" onNewScan={() => navigate("/scan")}>
        <div className="ad-page ad-page--error">
          <CcureAlert variant="danger" title="Failed to Load Asset">
            {error ||
              "The requested asset does not exist or you do not have permission to view it."}
          </CcureAlert>
          <div className="ad-mt-md">
            <CcureButton variant="primary" onClick={() => navigate("/assets")}>
              Back to Registry
            </CcureButton>
          </div>
        </div>
      </AppLayout>
    );
  }

  const band = riskBand(asset.risk_score);
  const riskLevelKey = String(asset.risk_level || "").toLowerCase();
  const changelogCount = changelogData?.stats?.total_events || 0;

  return (
    <AppLayout
      pageTitle={`Asset: ${asset.ip_address}`}
      onNewScan={() => navigate("/scan")}
    >
      <div className="ad-page">
        {/* Back Link */}
        <div className="ad-back">
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() => navigate("/assets")}
          >
            ← Back to Asset Registry
          </CcureButton>
        </div>

        {writeError && (
          <div className="ad-write-error">
            <CcureAlert
              variant="danger"
              onDismiss={() => setWriteError("")}
              dismissLabel="Dismiss this message"
            >
              {writeError}
            </CcureAlert>
          </div>
        )}

        {/* Header Block */}
        <header className="ad-header">
          <div className="ad-header-main">
            <h1 className="ad-address">{asset.ip_address}</h1>
            <p className="ad-hostname">
              {asset.hostname ? (
                <>
                  <span className="ad-hostname-name">{asset.hostname}</span>
                  {asset.fqdn && asset.fqdn !== asset.hostname && (
                    <span className="ad-faint"> · {asset.fqdn}</span>
                  )}
                </>
              ) : (
                "No Hostname Resolved"
              )}
            </p>

            {/* Managed Toggle / Status Row */}
            <div className="ad-status-row">
              <CcureBadge variant={asset.is_active ? "success" : "neutral"} dot>
                {asset.is_active ? "Online / Active" : "Offline / Inactive"}
              </CcureBadge>

              {/* A toggle that says which way it is set. Disabled, not hidden,
                  without the permission — the state is still information. */}
              <button
                type="button"
                disabled={!canUpdate}
                aria-pressed={Boolean(asset.is_managed)}
                onClick={handleToggleManaged}
                className={`ad-toggle ${asset.is_managed ? "ad-toggle--on" : "ad-toggle--off"}`}
              >
                {asset.is_managed ? "✔ Managed Asset" : "✗ Unmanaged Asset"}
              </button>

              <CcureBadge variant="info">
                👤 Owner: {asset.owner || "Unassigned"}
              </CcureBadge>
            </div>
          </div>

          {/* Risk Ring (Radial indicator). The ring's arc and colour are the
              score itself, expressed as SVG attributes and a band class —
              no inline style. */}
          <div className="ad-risk">
            <div
              className={`ad-riskring ad-riskring--${band}`}
              role="img"
              aria-label={`Risk score ${asset.risk_score} out of 100`}
            >
              <svg width="88" height="88" aria-hidden="true" focusable="false">
                <circle
                  className="ad-riskring-track"
                  cx="44"
                  cy="44"
                  r={RING_R}
                  fill="transparent"
                  strokeWidth="6"
                />
                <circle
                  className="ad-riskring-arc"
                  cx="44"
                  cy="44"
                  r={RING_R}
                  fill="transparent"
                  strokeWidth="6"
                  strokeDasharray={`${RING_C}`}
                  strokeDashoffset={`${RING_C * (1 - asset.risk_score / 100)}`}
                />
              </svg>
              <div className="ad-riskring-center">
                <span className="ad-riskring-num">{asset.risk_score}</span>
                <span className="ad-riskring-lbl">RISK</span>
              </div>
            </div>

            <div>
              <div className="ad-kicker">Risk Classification</div>
              <CcureBadge
                variant={RISK_LEVEL_VARIANT[riskLevelKey] || "info"}
                size="md"
              >
                {asset.risk_level}
              </CcureBadge>
            </div>
          </div>
        </header>

        {/* Tab Selector */}
        <CcureTabs
          id={TABS_ID}
          className="ad-tabs"
          label="Asset detail views"
          value={activeTab}
          onChange={setActiveTab}
          tabs={[
            { id: "system_info", label: "Asset Information" },
            { id: "services", label: `Services & Ports (${services.length})` },
            {
              id: "vulnerabilities",
              label: `Vulnerabilities (${findings.length})`,
            },
            { id: "changelog", label: `Audit & Changelog (${changelogCount})` },
          ]}
        />

        {/* Main Content Grid */}
        <div className="ad-body">
          {/* Left Column: Tab Data */}
          <div className="ad-main">
            {/* Tab: Vulnerabilities */}
            <CcureTabPanel
              id="vulnerabilities"
              tabsId={TABS_ID}
              active={activeTab === "vulnerabilities"}
            >
              <CcureCard title="Discovered Findings" headingLevel={2} bodyFlush>
                <div className="cc-table-wrap">
                  <table className="cc-table ad-table">
                    <caption className="cc-sr-only">
                      Findings on this asset, with CVSS score, priority,
                      severity, status and last detection
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">CVE / Finding</th>
                        <th scope="col">CVSS</th>
                        <th scope="col">Priority</th>
                        <th scope="col">Severity</th>
                        <th scope="col">Status</th>
                        <th scope="col">Last Detected</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="ad-empty-cell">
                            <CcureEmptyState
                              title="No vulnerabilities identified on this asset."
                              description={
                                <>
                                  To scan for vulnerabilities, run a{" "}
                                  <strong>Vulnerability Audit Scan</strong> on
                                  this host.
                                </>
                              }
                            />
                          </td>
                        </tr>
                      ) : (
                        findings.map((f) => (
                          <tr key={f.id}>
                            <td>
                              <div className="ad-cve-id">
                                <CVELink
                                  cveId={f.vuln_id}
                                  className="ad-cve-link"
                                />
                              </div>
                              <div className="ad-finding-title" title={f.title}>
                                {f.title}
                              </div>
                              <div className="ad-badges ad-mt-2xs">
                                {f.in_kev && (
                                  <CcureBadge variant="danger">KEV</CcureBadge>
                                )}
                                <CcureButton
                                  variant="ghost"
                                  size="sm"
                                  aria-label={`Details for ${f.vuln_id}`}
                                  onClick={() => setSelectedFindingId(f.id)}
                                >
                                  Details
                                </CcureButton>
                              </div>
                            </td>
                            <td>
                              <span
                                className={`ad-cvss ad-cvss--${cvssBand(f.cvss_v3_score || 0)}`}
                              >
                                {f.cvss_v3_score
                                  ? f.cvss_v3_score.toFixed(1)
                                  : "0.0"}
                              </span>
                            </td>
                            <td>
                              <CcureBadge
                                variant={
                                  PRIORITY_VARIANT[f.priority_label] ||
                                  "neutral"
                                }
                                mono
                              >
                                {f.priority_label}
                              </CcureBadge>
                            </td>
                            <td>
                              <CcureSeverityBadge severity={f.severity} />
                            </td>
                            <td>
                              <CcureBadge
                                variant={STATUS_VARIANT[f.status] || "neutral"}
                              >
                                {f.status}
                              </CcureBadge>
                            </td>
                            <td className="ad-t-xs ad-secondary">
                              {ago(f.last_found_at)}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </CcureCard>
            </CcureTabPanel>

            {/* Tab: Services & Open Ports */}
            <CcureTabPanel
              id="services"
              tabsId={TABS_ID}
              active={activeTab === "services"}
            >
              {(() => {
                // ── Compute column visibility from actual data ──────────────────
                const showProduct = services.some((s) => s.service_product);
                const showBanner = services.some((s) => s.banner);
                const showAudits = services.some((s) => s.tls || s.http);
                const colCount =
                  3 +
                  (showProduct ? 1 : 0) +
                  (showBanner ? 1 : 0) +
                  (showAudits ? 1 : 0);
                const missingEnrichment =
                  !showProduct && !showBanner && !showAudits;

                return (
                  <CcureCard
                    title="Open Ports & Running Services"
                    headingLevel={2}
                    bodyFlush
                    actions={
                      <span className="ad-t-xs ad-secondary">
                        {services.length} service
                        {services.length !== 1 ? "s" : ""} discovered
                      </span>
                    }
                  >
                    {/* ── Enrichment hint banner ─────────────────────────────── */}
                    {missingEnrichment && services.length > 0 && (
                      <div className="ad-hint">
                        <CcureAlert
                          variant="info"
                          live={false}
                          title="Service enrichment data not available for this scan type"
                        >
                          <strong>Product &amp; Version</strong> and{" "}
                          <strong>Banner</strong> data require a{" "}
                          <span className="ad-strong">
                            Service Fingerprinting Scan
                          </span>{" "}
                          (Nmap <code className="ad-code-inline">-sV</code>).{" "}
                          <strong>TLS / HTTP Audits</strong> require a{" "}
                          <span className="ad-strong">
                            Vulnerability Assessment
                          </span>{" "}
                          or{" "}
                          <span className="ad-strong">
                            Authenticated Deep Inspection
                          </span>
                          . Port discovery and service identification from the
                          current scan are shown below.
                        </CcureAlert>
                      </div>
                    )}

                    <div className="cc-table-wrap">
                      <table className="cc-table ad-table">
                        <caption className="cc-sr-only">
                          Open ports and running services on this asset
                        </caption>
                        <thead>
                          <tr>
                            <th scope="col">Port / Protocol</th>
                            <th scope="col">Service Name</th>
                            <th scope="col">State</th>
                            {showProduct && (
                              <th scope="col">Product &amp; Version</th>
                            )}
                            {showBanner && <th scope="col">Banner</th>}
                            {showAudits && <th scope="col">Audits</th>}
                          </tr>
                        </thead>
                        <tbody>
                          {services.length === 0 ? (
                            <tr>
                              <td colSpan={colCount} className="ad-empty-cell">
                                <CcureEmptyState
                                  title="No open ports detected on this host."
                                  description={
                                    <>
                                      To discover active running services, run a{" "}
                                      <strong>
                                        Asset Discovery (Port Scan)
                                      </strong>{" "}
                                      or{" "}
                                      <strong>
                                        Service Fingerprinting Scan
                                      </strong>{" "}
                                      on this host.
                                    </>
                                  }
                                />
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
                  </CcureCard>
                );
              })()}
            </CcureTabPanel>

            {/* Tab: Changelog */}
            <CcureTabPanel
              id="changelog"
              tabsId={TABS_ID}
              active={activeTab === "changelog"}
            >
              <CcureCard>
                <AuditTimeline changelogData={changelogData} headingLevel={2} />
              </CcureCard>
            </CcureTabPanel>

            {/* Tab: System Info */}
            <CcureTabPanel
              id="system_info"
              tabsId={TABS_ID}
              active={activeTab === "system_info"}
            >
              <div className="ad-stack">
                {/* Panel: Owner Details */}
                <CcureCard
                  title="Assignee / Owner"
                  subtitle="Assign accountability for security remediation"
                  headingLevel={2}
                >
                  {!editingOwner ? (
                    <div className="ad-owner-row">
                      <div className="ad-owner">
                        <span
                          className={`ad-owner-name${asset.owner ? "" : " ad-faint"}`}
                        >
                          👤 {asset.owner || "No owner assigned"}
                          {asset.provenance?.owner?.source === "analyst" && (
                            <CcureBadge
                              variant="info"
                              title="Manually set by security analyst. Protected from overwrite."
                            >
                              OVERRIDE
                            </CcureBadge>
                          )}
                          {asset.provenance?.owner?.source === "amt_import" && (
                            <CcureBadge
                              variant="success"
                              title="Verified via AMT inventory synchronization."
                            >
                              ✔ Ccure VERIFIED
                            </CcureBadge>
                          )}
                        </span>
                        {asset.custom_attributes?.owner_employee_id && (
                          <span className="ad-owner-emp">
                            Employee ID:{" "}
                            {asset.custom_attributes.owner_employee_id}
                          </span>
                        )}
                      </div>
                      {canUpdate && (
                        <CcureButton
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditingOwner(true)}
                        >
                          Edit
                        </CcureButton>
                      )}
                    </div>
                  ) : (
                    <div className="ad-owner-edit">
                      <CcureInput
                        id="ad-owner"
                        label="Owner name"
                        type="text"
                        value={ownerName}
                        onChange={(e) => setOwnerName(e.target.value)}
                        placeholder="Enter owner name…"
                        fieldClassName="ad-grow"
                      />
                      <div className="ad-actions">
                        <CcureButton
                          variant="primary"
                          size="sm"
                          onClick={handleSaveOwner}
                        >
                          Save
                        </CcureButton>
                        <CcureButton
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setOwnerName(asset.owner || "");
                            setEditingOwner(false);
                          }}
                        >
                          Cancel
                        </CcureButton>
                      </div>
                    </div>
                  )}
                </CcureCard>

                {/* Panel: Network & Identity */}
                <CcureCard
                  title="🌐 Network & Identity"
                  subtitle="IP details, MAC, hostname, and DNS settings"
                  headingLevel={2}
                >
                  <InfoGrid>
                    <InfoField
                      label="IP Address"
                      value={asset.ip_address}
                      mono
                    />
                    <InfoField
                      label="MAC Address"
                      value={asset.mac_address}
                      mono
                    />
                    <InfoField label="Subnet" value={asset.subnet} mono />
                    <InfoField label="Hostname" value={asset.hostname} mono />
                    {asset.fqdn && asset.fqdn !== asset.hostname && (
                      <InfoField label="FQDN" value={asset.fqdn} mono />
                    )}
                    {asset.dns_name &&
                      asset.dns_name !== asset.hostname &&
                      asset.dns_name !== asset.fqdn && (
                        <InfoField
                          label="DNS Name"
                          value={asset.dns_name}
                          mono
                        />
                      )}
                    <InfoField
                      label="NetBIOS Name"
                      value={asset.netbios_name}
                      mono
                    />
                    <InfoField
                      label="Domain"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.domain
                      }
                      mono
                    />
                    <InfoField label="VLAN ID" value={asset.vlan_id} mono />
                  </InfoGrid>
                </CcureCard>

                {/* Panel: OS & Hardware */}
                <CcureCard
                  title="🖥️ Operating System & Hardware"
                  subtitle="Device category, manufacturer, CPU, and kernel details"
                  headingLevel={2}
                >
                  <InfoGrid>
                    <InfoField label="OS Family" value={asset.os_family} mono />
                    <InfoField label="OS Name" value={asset.os_name} />
                    <InfoField
                      label="OS Version"
                      value={asset.os_version}
                      mono
                    />
                    <InfoField
                      label="OS Build"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.os_build
                      }
                      mono
                    />
                    <InfoField
                      label="Kernel Version"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.kernel_version
                      }
                      mono
                    />
                    {(asset.os_name || asset.os_family) &&
                      asset.os_confidence && (
                        <InfoField
                          label="OS Confidence"
                          value={`${asset.os_confidence}%`}
                          mono
                        />
                      )}
                    <InfoField
                      label="Device Category"
                      value={getCategoryLabel(asset.device_category)}
                    />
                    <InfoField label="Vendor" value={asset.vendor} />
                    {asset.manufacturer &&
                      cleanVendorName(asset.manufacturer) !==
                        cleanVendorName(asset.vendor) && (
                        <InfoField
                          label="Manufacturer"
                          value={asset.manufacturer}
                        />
                      )}
                    <InfoField
                      label="Hardware Model"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.hardware_model
                      }
                    />
                    <InfoField
                      label="CPU Model"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.cpu_model
                      }
                    />
                    <InfoField
                      label="CPU Cores"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.cpu_count
                      }
                      mono
                    />
                    <InfoField
                      label="System Uptime"
                      value={
                        asset.custom_attributes?.credentialed_system_info
                          ?.uptime
                      }
                    />
                  </InfoGrid>
                </CcureCard>

                {/* What an authenticated scan established. Everything in it
                    was already on the asset record and none of it reached the
                    page — the hardening switches, the credentialed status and
                    the collected inventories. */}
                <HostPosturePanel customAttributes={asset.custom_attributes} />

                {/* Panel: CCure AMT Reference */}
                {(asset.custom_attributes?.amt_asset_tag ||
                  asset.custom_attributes?.amt_asset_name ||
                  asset.custom_attributes?.serial_number) && (
                  <CcureCard
                    title="🏢 Corporate (Assets) Details"
                    subtitle="Verified Asset"
                    headingLevel={2}
                  >
                    <InfoGrid>
                      {/* <InfoField label="Asset Tag" value={asset.custom_attributes?.amt_asset_tag} mono /> */}
                      <InfoField
                        label="Asset Name"
                        value={asset.custom_attributes?.amt_asset_name}
                      />
                      <InfoField
                        label="Serial Number"
                        value={asset.custom_attributes?.serial_number}
                        mono
                      />
                      <InfoField
                        label="Asset Type"
                        value={asset.custom_attributes?.amt_asset_type}
                      />
                      <InfoField
                        label="Company"
                        value={asset.custom_attributes?.amt_company_name}
                      />
                      <InfoField
                        label="Office Location"
                        value={asset.custom_attributes?.amt_location}
                      />
                      {/* <InfoField label="Corporate Status" value={asset.custom_attributes?.amt_status} isTag /> */}
                    </InfoGrid>
                  </CcureCard>
                )}

                {/* Panel: Scan & Discovery */}
                <CcureCard
                  title="🔬 Discovery & Scan Metadata"
                  subtitle="Scan identification, activity times, and audit details"
                  headingLevel={2}
                >
                  <InfoGrid>
                    <InfoField
                      label="Discovery Method"
                      value={asset.discovery_method || "active"}
                      isTag
                    />
                    <InfoField
                      label="First Discovered"
                      value={combineTime(asset.first_seen_at)}
                    />
                    <InfoField
                      label="Last Activity"
                      value={combineTime(asset.last_seen_at)}
                    />
                    {asset.response_time_ms !== null &&
                      asset.response_time_ms !== undefined && (
                        <InfoField
                          label="Response Time"
                          value={`${asset.response_time_ms} ms`}
                          mono
                        />
                      )}
                    <InfoField
                      label="Last Scan ID"
                      value={asset.last_scan_id}
                      mono
                    />
                    <InfoField label="Asset ID" value={asset.id} mono />
                  </InfoGrid>
                </CcureCard>
              </div>
            </CcureTabPanel>
          </div>

          {/* Right Column: Sidebar Panels */}
          <aside className="ad-side">
            {/* Panel: Tags Manager */}
            <CcureCard
              title="Asset Tags"
              subtitle="Tag hosts to filter reports and group assets"
              headingLevel={2}
            >
              {/* Tag List */}
              <div className="ad-tags">
                {(asset.tags || []).length === 0 ? (
                  <span className="ad-t-xs ad-faint">No tags configured</span>
                ) : (
                  asset.tags.map((tag) => (
                    <span key={tag} className="ad-tag">
                      {tag}
                      {canUpdate && (
                        <button
                          type="button"
                          className="ad-tag-remove"
                          aria-label={`Remove tag ${tag}`}
                          title="Remove Tag"
                          onClick={() => handleRemoveTag(tag)}
                        >
                          ✕
                        </button>
                      )}
                    </span>
                  ))
                )}
              </div>

              {/* Tag Add Form */}
              {canUpdate && (
                <form onSubmit={handleAddTag} className="ad-inline-form">
                  <CcureInput
                    id="ad-new-tag"
                    label="New tag"
                    type="text"
                    placeholder="New tag (e.g. dmz, production)…"
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                    fieldClassName="ad-grow"
                  />
                  <CcureButton
                    type="submit"
                    variant="secondary"
                    size="sm"
                    aria-label="Add tag"
                  >
                    +
                  </CcureButton>
                </form>
              )}
            </CcureCard>

            {/* Panel: Analyst Notes */}
            <CcureCard
              title="Analyst Log Notes"
              subtitle="Add findings notes, status tracking comments"
              headingLevel={2}
            >
              {/* Note Submission Form */}
              {canUpdate && (
                <form onSubmit={handleAddNote} className="ad-note-form">
                  <CcureField id="ad-new-note" label="Analyst note">
                    <textarea
                      id="ad-new-note"
                      className="cc-field__control ad-textarea"
                      placeholder="Add comment logs for other SOC analysts…"
                      rows={3}
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                    />
                  </CcureField>
                  <CcureButton type="submit" variant="primary" size="sm">
                    Log Note
                  </CcureButton>
                </form>
              )}

              {/* Notes Timeline List */}
              <div className="ad-notes">
                {(asset.notes || []).length === 0 ? (
                  <div className="ad-notes-empty">
                    No analyst notes logged for this host.
                  </div>
                ) : (
                  [...(asset.notes || [])].reverse().map((note) => (
                    <div key={note.id} className="ad-note">
                      <div className="ad-note-meta">
                        <span className="ad-note-author">
                          👤 User ID: {note.user_id?.substring(0, 8)}...
                        </span>
                        <span>{ago(note.created_at)}</span>
                      </div>
                      <div className="ad-note-body">{note.content}</div>
                    </div>
                  ))
                )}
              </div>
            </CcureCard>
          </aside>
        </div>
      </div>

      {/* Selected Vulnerability Detail Drawer Modal */}
      {selectedFindingId && (
        <FindingDrawer
          findingId={selectedFindingId}
          canUpdate={canUpdate}
          onClose={closeDrawer}
          onStatusChange={handleFindingStatusChange}
        />
      )}
    </AppLayout>
  );
}
