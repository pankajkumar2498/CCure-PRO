/**
 * src/pages/Dashboard.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * CAST-themed scan template grid — main landing page after login.
 *
 * SCAN MODE → PHASE PIPELINE MAPPING
 * ────────────────────────────────────
 *  basic             → Phase 1 only   (Host Discovery, then STOPS)
 *  asset             → Phase 1 → 2    (always re-runs Phase 1 fresh, no cache reuse)
 *  vulnerability_audit → Phase 1 → 2 → 3  (full pipeline)
 *
 * The selected mode is stored in ScanContext.pipelineMode so every
 * downstream phase-result page knows whether to show the "Next Phase" CTA.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from "../context/ScanContext";
import { SCAN_PIPELINES, getScanPipeline } from "../config/scanConfig";
import AppLayout from "../components/layout/AppLayout";
import Modal from "../components/layout/Modal";

/* ─── SVG Icons ──────────────────────────────────────────────────────────── */
const Svg = ({ children, size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);
const SvgSearch   = () => <Svg size={14}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></Svg>;

/* Card icons */
const IcoWifi     = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>;
const IcoDatabase = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>;
const IcoLightning= ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>;
const IcoNetwork  = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/><rect x="9" y="16" width="6" height="6" rx="1"/><path d="M5 8v3a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8"/><line x1="12" y1="12" x2="12" y2="16"/></svg>;
const IcoShield   = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>;
const IcoDir      = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="5" r="2"/><circle cx="4" cy="19" r="2"/><circle cx="20" cy="19" r="2"/><line x1="12" y1="7" x2="12" y2="13"/><line x1="12" y1="13" x2="4" y2="17"/><line x1="12" y1="13" x2="20" y2="17"/></svg>;
const IcoWebApp   = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><polyline points="9 9 12 6 15 9"/><line x1="12" y1="6" x2="12" y2="13"/></svg>;
const IcoCloud    = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>;
const IcoPolicy   = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></svg>;
const IcoLock     = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>;
const IcoPatch    = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>;
const IcoAgent    = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>;
const IcoOffline  = ({ c, s=32 }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="1"/><polyline points="16 2 12 6 8 2"/></svg>;

/* ─── Scan template definitions ──────────────────────────────────────────── */
const TEMPLATES = [
  // Row 1 — mapped (active) scans
  {
    id:       "basic",
    title:    "Basic Network Scan",
    desc:     "Identifies Only the Live Hosts in the Network.",
    Icon:     IcoWifi,
    bg:       "#e8fdf0",
    color:    "#22c55e",
    mapped:   true,
    // badge:    "Guided Flow",
    // pipelineMode drives handleCard — links directly to SCAN_PIPELINES["basic"]
    pipelineMode: "basic",
  },
  {
    id:       "asset",
    title:    "Asset Discovery",
    desc:     "Identifies Assets Live in the Network with Basic Information.",
    Icon:     IcoDatabase,
    bg:       "#eff6ff",
    color:    "#3b82f6",
    mapped:   true,
    // badge:    "Phase 1 → 2",
    pipelineMode: "asset",
  },
  {
    id:       "advanced",
    title:    "Vulnerability Audit",
    desc:     "Identifies hosts and performs a deep vulnerability audit.",
    Icon:     IcoLightning,
    bg:       "#fefce8",
    color:    "#eab308",
    mapped:   true,
    // badge:    "Full Pipeline",
    pipelineMode: "vulnerability_audit",
  },
  { id:"network",  title:"Network Based Scanning",     desc:"Test API endpoints and validate response data automatically.",         Icon:IcoNetwork,  bg:"#f5f3ff", color:"#8b5cf6", mapped:false },

  // Row 2
  { id:"malware",  title:"Malware Scan",               desc:"Perform rapid connectivity checks and network availability tests.",    Icon:IcoShield,   bg:"#fff1f2", color:"#ef4444", mapped:false },
  { id:"active",   title:"Active Directory Scan",      desc:"Analyze network traffic suitable for any size infrastructure.",        Icon:IcoDir,      bg:"#eff6ff", color:"#3b82f6", mapped:false },
  { id:"webapp",   title:"Web Application Scanning",   desc:"Configure custom parameters using advanced rule settings.",            Icon:IcoWebApp,   bg:"#fff7ed", color:"#f97316", mapped:false },
  { id:"cloud",    title:"Cloud Scanning",             desc:"Verify that code meets quality standards and best practices.",         Icon:IcoCloud,    bg:"#f0f9ff", color:"#0ea5e9", mapped:false },

  // Row 3
  { id:"policy",   title:"Policy Compliance Scanning", desc:"Monitor for malicious activity across all endpoints and systems.",     Icon:IcoPolicy,   bg:"#f0fdf4", color:"#16a34a", mapped:false },
  {
    id:       "cred",
    title:    "Credential Validation",
    desc:     "Scanning Hosts with Credentials.",
    Icon:     IcoLock,
    bg:       "#fefce8",
    color:    "#ca8a04",
    mapped:   true,
    // badge:    "SSH Auth",
    // Credentialed scan has its own dedicated route — no pipelineMode needed
    directRoute: "/scan/credentialed",
  },
  { id:"patch",   title:"Patch Management",           desc:"Analyze mobile app performance on Android and iOS platforms.",         Icon:IcoPatch,    bg:"#f5f3ff", color:"#7c3aed", mapped:false },
  { id:"agent",   title:"Agent Based Monitoring",     desc:"Automatically optimize system performance and resource utilization.",  Icon:IcoAgent,    bg:"#fdf4ff", color:"#a855f7", mapped:false, beta:true },

  // Row 4
  { id:"offline", title:"Offline Configuration Scan", desc:"Audit the configuration of network devices without connectivity.",     Icon:IcoOffline,  bg:"#f8fafc", color:"#64748b", mapped:false },
];

/* ─── Scan Card ──────────────────────────────────────────────────────────── */
function ScanCard({ tpl, onClick }) {
  const { Icon, title, desc, bg, color, mapped, beta, badge } = tpl;
  return (
    <button
      className={`scan-card ${mapped ? "scan-card--active" : "scan-card--disabled"}`}
      onClick={() => mapped && onClick(tpl)}
      disabled={!mapped}
      title={!mapped ? "Coming soon" : undefined}
    >
      {beta   && <span className="scan-card-badge badge-beta">Beta</span>}
      {!mapped && <span className="scan-card-badge badge-soon">Soon</span>}
      {mapped && badge && <span className="scan-card-badge badge-api">{badge}</span>}

      <div className="scan-card-icon" style={{ background: bg }}>
        <Icon c={color} s={32} />
      </div>
      <h3 className="scan-card-title">{title}</h3>
      <p className="scan-card-desc">{desc}</p>
    </button>
  );
}

/* ─── Dashboard ──────────────────────────────────────────────────────────── */
export default function Dashboard() {
  const navigate = useNavigate();
  const { setPipelineMode, resetScan } = useScan();
  const [search, setSearch] = useState("");
  const [modalOpen, setModalOpen] = useState(false);

  const filtered = TEMPLATES.filter(t =>
    t.title.toLowerCase().includes(search.toLowerCase()) ||
    t.desc.toLowerCase().includes(search.toLowerCase())
  );

  /**
   * handleCard — the single routing handler for all scan cards.
   *
   * Logic:
   *  1. Cards with `directRoute` (e.g. Credential Validation) navigate directly.
   *  2. Cards with `pipelineMode` use the SCAN_PIPELINES config:
   *     - Sets pipelineMode in context so downstream phases know the pipeline.
   *     - Resets scan state (all three modes always start fresh via /scan).
   *     - Navigates to the scan form (/scan/new).
   *
   * NOTE: Asset Discovery no longer skips to /scan/asset-discovery even if phase1 data
   * exists — it always restarts from Host Discovery as required.
   */
  const handleCard = (tpl) => {
    if (!tpl.mapped) return;

    // ── Dedicated route (e.g. SSH / Credentialed) ──
    if (tpl.directRoute) {
      navigate(tpl.directRoute);
      return;
    }

    // ── Pipeline-driven scan ──
    if (tpl.pipelineMode) {
      getScanPipeline(tpl.pipelineMode);

      // Always reset — every scan starts fresh regardless of cached state
      resetScan();

      // Store the chosen pipeline mode in context
      setPipelineMode(tpl.pipelineMode);

      // Open the shared scan form. The selected pipeline mode controls which phases run.
      navigate("/scan/new");
    }
  };

  const onNewScan = () => setModalOpen(true);

  return (
    <>
      <AppLayout pageTitle="Scan Templates" onNewScan={onNewScan}>
        <div className="page-inner">
          <div className="page-title-row">
            <div>
              <h1 className="page-title">Scan Templates</h1>
              <p className="page-subtitle">Choose a scan type to begin your network assessment</p>
            </div>
          </div>

          {/* Search */}
          <div className="search-wrap">
            <span className="search-icon"><SvgSearch /></span>
            <input
              className="search-input"
              placeholder="Search templates…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          {/* Template grid */}
          {filtered.length === 0 ? (
            <div className="empty-state">
              <span className="empty-state-icon">🔍</span>
              <p className="empty-state-title">No templates match "{search}"</p>
            </div>
          ) : (
            <div className="scan-grid">
              {filtered.map(tpl => (
                <ScanCard key={tpl.id} tpl={tpl} onClick={handleCard} />
              ))}
            </div>
          )}
        </div>
      </AppLayout>

      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Start New Scan"
        subtitle="Choose a scan type to begin your next assessment."
      >
        <div className="modal-panel-grid">
          {filtered.map(tpl => (
            <ScanCard key={tpl.id} tpl={tpl} onClick={(tpl) => { handleCard(tpl); setModalOpen(false); }} />
          ))}
        </div>
      </Modal>
    </>
  );
}
