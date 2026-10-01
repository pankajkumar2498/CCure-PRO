/**
 * src/modules/audit/pages/Dashboard.jsx
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
 *
 * Checkpoint 3C batch 11: presentation moved onto the CCure design system.
 * Nothing about template selection changed — `handleCard` is verbatim, and
 * the page still issues no request. What changed is what assistive technology
 * is told: the search control has a name, the picker is a real dialog, the
 * decorative icons are hidden, the badge no longer leads a card's accessible
 * name, and the "coming soon" reason is announced rather than living only in
 * a tooltip. Icon tones come from six semantic classes instead of twenty-two
 * colour literals, so they follow the theme like everything else.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from "@audit/context/ScanContext";
import { getScanPipeline } from "@audit/config/scanConfig";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  CcureBadge,
  CcureEmptyState,
  CcureInput,
  CcureModal,
} from "../../../design-system";
import "../styles/scan-templates.css";

/* ─── SVG Icons ──────────────────────────────────────────────────────────── */
/* Every icon here is decorative: the card's text carries its meaning. They are
   hidden from assistive technology so a reader does not announce fourteen
   unlabelled graphics on the way through the grid. */
const Svg = ({ children, size = 16 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    {children}
  </svg>
);
const SvgSearch = () => (
  <Svg size={14}>
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </Svg>
);

/* Card icons — stroke is `currentColor`, so the tone class on the tile decides
   the colour and the icon needs no colour prop of its own. */
const CardSvg = ({ children, s = 32 }) => (
  <svg
    width={s}
    height={s}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    {children}
  </svg>
);
const IcoWifi = (p) => (
  <CardSvg {...p}>
    <path d="M5 12.55a11 11 0 0 1 14.08 0" />
    <path d="M1.42 9a16 16 0 0 1 21.16 0" />
    <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
    <line x1="12" y1="20" x2="12.01" y2="20" />
  </CardSvg>
);
const IcoDatabase = (p) => (
  <CardSvg {...p}>
    <ellipse cx="12" cy="5" rx="9" ry="3" />
    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
  </CardSvg>
);
const IcoLightning = (p) => (
  <CardSvg {...p}>
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </CardSvg>
);
const IcoNetwork = (p) => (
  <CardSvg {...p}>
    <rect x="2" y="2" width="6" height="6" rx="1" />
    <rect x="16" y="2" width="6" height="6" rx="1" />
    <rect x="9" y="16" width="6" height="6" rx="1" />
    <path d="M5 8v3a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8" />
    <line x1="12" y1="12" x2="12" y2="16" />
  </CardSvg>
);
const IcoShield = (p) => (
  <CardSvg {...p}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </CardSvg>
);
const IcoDir = (p) => (
  <CardSvg {...p}>
    <circle cx="12" cy="5" r="2" />
    <circle cx="4" cy="19" r="2" />
    <circle cx="20" cy="19" r="2" />
    <line x1="12" y1="7" x2="12" y2="13" />
    <line x1="12" y1="13" x2="4" y2="17" />
    <line x1="12" y1="13" x2="20" y2="17" />
  </CardSvg>
);
const IcoWebApp = (p) => (
  <CardSvg {...p}>
    <rect x="2" y="3" width="20" height="14" rx="2" />
    <line x1="8" y1="21" x2="16" y2="21" />
    <line x1="12" y1="17" x2="12" y2="21" />
    <polyline points="9 9 12 6 15 9" />
    <line x1="12" y1="6" x2="12" y2="13" />
  </CardSvg>
);
const IcoCloud = (p) => (
  <CardSvg {...p}>
    <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />
  </CardSvg>
);
const IcoPolicy = (p) => (
  <CardSvg {...p}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="9" y1="13" x2="15" y2="13" />
    <line x1="9" y1="17" x2="15" y2="17" />
  </CardSvg>
);
const IcoLock = (p) => (
  <CardSvg {...p}>
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </CardSvg>
);
const IcoPatch = (p) => (
  <CardSvg {...p}>
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
  </CardSvg>
);
const IcoAgent = (p) => (
  <CardSvg {...p}>
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </CardSvg>
);
const IcoOffline = (p) => (
  <CardSvg {...p}>
    <rect x="2" y="7" width="20" height="14" rx="1" />
    <polyline points="16 2 12 6 8 2" />
  </CardSvg>
);

/* ─── Scan template definitions ──────────────────────────────────────────── */
/* `tone` replaces the per-template `bg` / `color` literal pair. Six semantic
   tones cover the thirteen templates; each resolves to CCure tokens in
   scan-templates.css and therefore follows the theme. */
const TEMPLATES = [
  // Row 1 — mapped (active) scans
  {
    id: "basic",
    title: "Basic Network Scan",
    desc: "Identifies Only the Live Hosts in the Network.",
    Icon: IcoWifi,
    tone: "success",
    mapped: true,
    // badge:    "Guided Flow",
    // pipelineMode drives handleCard — links directly to SCAN_PIPELINES["basic"]
    pipelineMode: "basic",
  },
  {
    id: "asset",
    title: "Asset Discovery",
    desc: "Identifies Assets Live in the Network with Basic Information.",
    Icon: IcoDatabase,
    tone: "info",
    mapped: true,
    // badge:    "Phase 1 → 2",
    pipelineMode: "asset",
  },
  {
    id: "advanced",
    title: "Vulnerability Audit",
    desc: "Identifies hosts and performs a deep vulnerability audit.",
    Icon: IcoLightning,
    tone: "warning",
    mapped: true,
    // badge:    "Full Pipeline",
    pipelineMode: "vulnerability_audit",
  },
  {
    id: "network",
    title: "Network Based Scanning",
    desc: "Test API endpoints and validate response data automatically.",
    Icon: IcoNetwork,
    tone: "primary",
    mapped: false,
  },

  // Row 2
  {
    id: "malware",
    title: "Malware Scan",
    desc: "Perform rapid connectivity checks and network availability tests.",
    Icon: IcoShield,
    tone: "danger",
    mapped: false,
  },
  {
    id: "active",
    title: "Active Directory Scan",
    desc: "Analyze network traffic suitable for any size infrastructure.",
    Icon: IcoDir,
    tone: "info",
    mapped: false,
  },
  {
    id: "webapp",
    title: "Web Application Scanning",
    desc: "Configure custom parameters using advanced rule settings.",
    Icon: IcoWebApp,
    tone: "warning",
    mapped: true,
    directRoute: "/web-scans/dashboard",
  },
  {
    id: "cloud",
    title: "Cloud Scanning",
    desc: "Verify that code meets quality standards and best practices.",
    Icon: IcoCloud,
    tone: "info",
    mapped: false,
  },

  // Row 3
  {
    id: "policy",
    title: "Policy Compliance Scanning",
    desc: "Evaluate hosts against security baseline configurations and standards.",
    Icon: IcoPolicy,
    tone: "success",
    mapped: true,
    directRoute: "/compliance",
  },
  {
    id: "cred",
    title: "Credential Validation",
    desc: "Scanning Hosts with Credentials.",
    Icon: IcoLock,
    tone: "warning",
    mapped: true,
    // badge:    "SSH Auth",
    // Credentialed scan has its own dedicated route — no pipelineMode needed
    directRoute: "/scan/credentialed",
  },
  {
    id: "patch",
    title: "Patch Management",
    desc: "Analyze mobile app performance on Android and iOS platforms.",
    Icon: IcoPatch,
    tone: "primary",
    mapped: false,
  },
  {
    id: "agent",
    title: "Agent Based Monitoring",
    desc: "Automatically optimize system performance and resource utilization.",
    Icon: IcoAgent,
    tone: "primary",
    mapped: false,
    beta: true,
  },

  // Row 4
  {
    id: "offline",
    title: "Offline Configuration Scan",
    desc: "Audit the configuration of network devices without connectivity.",
    Icon: IcoOffline,
    tone: "neutral",
    mapped: false,
  },
];

/* ─── Scan Card ──────────────────────────────────────────────────────────── */
/* The badges are rendered AFTER the title and description and positioned by
   CSS, so a card's accessible name starts with what it is ("Malware Scan …
   Soon, coming soon") rather than with its status ("Soon Malware Scan …").
   The title is a span, not a heading: a <button> may only contain phrasing
   content, and a heading inside a control announces as a heading, not as the
   control's name. */
function ScanCard({ tpl, onClick }) {
  const { Icon, title, desc, tone, mapped, beta, badge } = tpl;
  return (
    <button
      type="button"
      className={`tpl-card ${mapped ? "tpl-card--active" : "tpl-card--disabled"}`}
      onClick={() => mapped && onClick(tpl)}
      disabled={!mapped}
      title={!mapped ? "Coming soon" : undefined}
    >
      <span className={`tpl-icon tpl-icon--${tone}`} aria-hidden="true">
        <Icon s={32} />
      </span>
      <span className="tpl-card-title">{title}</span>
      <span className="tpl-card-desc">{desc}</span>
      <span className="tpl-card-badges">
        {beta && <CcureBadge variant="info">Beta</CcureBadge>}
        {!mapped && (
          <>
            <CcureBadge variant="neutral">Soon</CcureBadge>
            <span className="cc-sr-only">, coming soon</span>
          </>
        )}
        {mapped && badge && <CcureBadge variant="primary">{badge}</CcureBadge>}
      </span>
    </button>
  );
}

/* ─── Dashboard ──────────────────────────────────────────────────────────── */
export default function Dashboard() {
  const navigate = useNavigate();
  const { setPipelineMode, resetScan } = useScan();
  const [search, setSearch] = useState("");
  const [modalOpen, setModalOpen] = useState(false);

  const filtered = TEMPLATES.filter(
    (t) =>
      t.title.toLowerCase().includes(search.toLowerCase()) ||
      t.desc.toLowerCase().includes(search.toLowerCase()),
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
              <p className="page-subtitle">
                Choose a scan type to begin your network assessment
              </p>
            </div>
          </div>

          {/* Search — named, not merely placeholdered. */}
          <div className="tpl-search">
            <CcureInput
              id="tpl-search"
              type="search"
              aria-label="Search templates"
              placeholder="Search templates…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              adornment={<SvgSearch />}
            />
          </div>

          {/* Template grid */}
          {filtered.length === 0 ? (
            /* role="status": the result of a search is announced, not just
               painted, so a keyboard user typing into the box hears that
               nothing matched without leaving it. */
            <div role="status">
              <CcureEmptyState
                icon="🔍"
                title={`No templates match "${search}"`}
              />
            </div>
          ) : (
            <div className="tpl-grid">
              {filtered.map((tpl) => (
                <ScanCard key={tpl.id} tpl={tpl} onClick={handleCard} />
              ))}
            </div>
          )}
        </div>
      </AppLayout>

      {/* The picker the shell's New Scan button opens. CcureModal supplies
          role="dialog", aria-modal, the title as accessible name, the focus
          trap and Escape — the legacy Modal had the Escape and nothing else.
          `closeLabel="Close"` keeps the control's existing accessible name. */}
      <CcureModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Start New Scan"
        subtitle="Choose a scan type to begin your next assessment."
        size="lg"
        closeLabel="Close"
      >
        <div className="tpl-grid tpl-grid--modal">
          {filtered.map((tpl) => (
            <ScanCard
              key={tpl.id}
              tpl={tpl}
              onClick={(tpl) => {
                handleCard(tpl);
                setModalOpen(false);
              }}
            />
          ))}
        </div>
      </CcureModal>
    </>
  );
}
