/**
 * src/components/layout/HelpPanel.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Context-aware Help center panel with:
 *   • FAQ search
 *   • Quick-link cards by topic
 *   • What's New section
 *   • Support contact form
 *
 * Checkpoint 3C batch 12: presentation moved onto the CCure design system.
 * Content and behaviour are unchanged — it still issues no request, and the
 * support form is still client-side only. Added for assistive technology:
 * the section strip is a tab list, the FAQ search is labelled, each FAQ
 * announces whether it is open, the panel closes on Escape and takes focus on
 * open, and the close control is named.
 */

import { useState, useRef, useEffect } from "react";
import {
  CcureButton,
  CcureField,
  CcureInput,
  CcureTabs,
} from "../../design-system";

/* ── Icons (decorative) ──────────────────────────────────────────────────── */
const Icon = ({ d, size = 16 }) => (
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
    <path d={d} />
  </svg>
);

const IcoClose = () => <Icon d="M18 6L6 18M6 6l12 12" />;
const IcoExtLink = () => (
  <Icon
    d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3"
    size={14}
  />
);
const IcoChevron = () => <Icon d="M9 18l6-6-6-6" size={14} />;
const IcoHelp = () => (
  <svg
    width={17}
    height={17}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <circle cx="12" cy="12" r="10" />
    <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

/* ── FAQ data ─────────────────────────────────────────────────────────────── */
const FAQ_DATA = [
  {
    q: "How do I start a new scan?",
    a: "Click the '+ New Scan' button in the top header, or navigate to the Scan Library from the sidebar.",
    tags: ["scan", "start", "new"],
  },
  {
    q: "What is the difference between Host Discovery and Asset Scan?",
    a: "Host Discovery identifies live hosts on the network. Asset Scan goes deeper — port enumeration, service detection, and OS fingerprinting.",
    tags: ["scan", "host", "asset", "discovery"],
  },
  {
    q: "How do I view my past scan results?",
    a: "Go to 'My Scan Jobs' in the sidebar to see all your scans. Click any scan to view its full report.",
    tags: ["scan", "history", "results"],
  },
  {
    q: "How do I change my password?",
    a: "Open the profile menu (top-right), click 'My Account', then go to the 'Security' tab and click 'Change Password'.",
    tags: ["password", "security", "account"],
  },
  {
    q: "What does the vulnerability severity mean?",
    a: "CCure uses the CVSS scale: Critical (9–10), High (7–8.9), Medium (4–6.9), Low (0–3.9). Focus on Critical and High first.",
    tags: ["vulnerability", "severity", "cvss"],
  },
  {
    q: "Can I schedule recurring scans?",
    a: "Scheduled scans are on the roadmap. For now, you can manually re-run past scans from the Scan Library.",
    tags: ["schedule", "recurring", "automation"],
  },
  {
    q: "How do I export a report?",
    a: "Navigate to 'Security Reports', find your report, and click the Download PDF button.",
    tags: ["report", "export", "pdf"],
  },
  {
    q: "How do I add a new user to my organization?",
    a: "As an admin, go to 'User Management' in the sidebar. Click 'Invite User' to add a new member.",
    tags: ["user", "admin", "organization"],
  },
  {
    q: "What is a credentialed scan?",
    a: "A credentialed scan uses SSH/WinRM credentials to log into hosts and detect software versions and patch levels from inside.",
    tags: ["credentialed", "ssh", "winrm", "scan"],
  },
  {
    q: "Why are some sidebar items greyed out?",
    a: "Items marked 'SOON' are features currently under development. They'll be enabled in a future release.",
    tags: ["sidebar", "disabled", "features"],
  },
];

/* ── Quick links ─────────────────────────────────────────────────────────── */
const QUICK_LINKS = [
  { title: "Getting Started Guide", emoji: "🚀", url: "#" },
  { title: "Scan Types Explained", emoji: "🔍", url: "#" },
  { title: "Understanding CVEs", emoji: "🛡", url: "#" },
  { title: "API Documentation", emoji: "📖", url: "#" },
  { title: "Admin Guide", emoji: "⚙", url: "#" },
  { title: "Release Notes", emoji: "📋", url: "#" },
];

/* ── What's New ──────────────────────────────────────────────────────────── */
const WHATS_NEW = [
  {
    version: "v1.5",
    date: "May 2026",
    items: [
      "Profile & Account management modal",
      "In-app notification center",
      "Settings drawer with preferences",
      "Help center with FAQ search",
    ],
  },
  {
    version: "v1.4",
    date: "April 2026",
    items: [
      "Credentialed scan support (SSH & WinRM)",
      "Asset-centric PostgreSQL data model",
      "Recycle bin for deleted scans",
      "Audit log viewer for admins",
    ],
  },
];

const SECTIONS = [
  { id: "faq", label: "FAQ" },
  { id: "links", label: "Quick Links" },
  { id: "new", label: "What's New" },
  { id: "support", label: "Support" },
];

/* ── FAQ Item ─────────────────────────────────────────────────────────────── */
function FaqItem({ q, a, index }) {
  const [open, setOpen] = useState(false);
  const answerId = `shh-faq-a-${index}`;
  return (
    <div className={`shh-faq-item ${open ? "shh-faq-item--open" : ""}`}>
      <button
        type="button"
        className="shh-faq-q"
        aria-expanded={open}
        aria-controls={open ? answerId : undefined}
        onClick={() => setOpen((o) => !o)}
      >
        <span>{q}</span>
        <span
          className={`shh-faq-chevron ${open ? "shh-faq-chevron--open" : ""}`}
          aria-hidden="true"
        >
          <IcoChevron />
        </span>
      </button>
      {open && (
        <div className="shh-faq-a" id={answerId}>
          {a}
        </div>
      )}
    </div>
  );
}

/* ── Support Form ─────────────────────────────────────────────────────────── */
/* Client-side only: nothing is sent anywhere. That was true before the
   migration and is not this batch's to change. */
function SupportForm() {
  const [msg, setMsg] = useState("");
  const [sent, setSent] = useState(false);

  const handleSend = () => {
    if (!msg.trim()) return;
    setSent(true);
    setTimeout(() => {
      setSent(false);
      setMsg("");
    }, 3000);
  };

  return (
    <div className="shh-support">
      <h4 className="shh-section-title">Contact Support</h4>
      {sent ? (
        <div className="shh-support-sent" role="status">
          ✅ Message sent! We&apos;ll get back to you soon.
        </div>
      ) : (
        <>
          <CcureField id="shh-support-msg" label="Your message">
            <textarea
              id="shh-support-msg"
              className="cc-field__control shh-support-textarea"
              placeholder="Describe your issue or question…"
              value={msg}
              onChange={(e) => setMsg(e.target.value)}
              rows={4}
            />
          </CcureField>
          <CcureButton
            variant="primary"
            size="sm"
            onClick={handleSend}
            disabled={!msg.trim()}
          >
            Send Message
          </CcureButton>
        </>
      )}
    </div>
  );
}

/* ── Main ────────────────────────────────────────────────────────────────── */
export default function HelpPanel({ id = "sh-help", onClose }) {
  const [query, setQuery] = useState("");
  const [activeSection, setActiveSection] = useState("faq");
  const panelRef = useRef(null);

  // Escape closes; the owner restores focus to the help button.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    panelRef.current?.focus?.();
  }, []);

  // Click outside to close
  useEffect(() => {
    const h = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        const helpBtn = document.getElementById("header-help-btn");
        if (helpBtn && helpBtn.contains(e.target)) return;
        onClose();
      }
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [onClose]);

  const filteredFaqs = FAQ_DATA.filter(
    (f) =>
      !query ||
      f.q.toLowerCase().includes(query.toLowerCase()) ||
      f.a.toLowerCase().includes(query.toLowerCase()) ||
      f.tags.some((t) => t.includes(query.toLowerCase())),
  );

  return (
    <div
      className="shh-panel"
      ref={panelRef}
      id={id}
      role="dialog"
      aria-label="Help Center"
      tabIndex={-1}
    >
      {/* Header */}
      <div className="shh-header">
        <div className="shh-header-left">
          <IcoHelp />
          <span>Help Center</span>
        </div>
        <button
          type="button"
          className="shh-close"
          onClick={onClose}
          aria-label="Close help"
        >
          <IcoClose />
        </button>
      </div>

      {/* Section tabs */}
      <CcureTabs
        className="shh-tabs"
        label="Help sections"
        tabs={SECTIONS}
        value={activeSection}
        onChange={setActiveSection}
      />

      {/* Body */}
      <div className="shh-body">
        {/* FAQ */}
        {activeSection === "faq" && (
          <div>
            <div className="shh-search-wrap">
              <CcureInput
                id="shh-faq-search"
                type="search"
                aria-label="Search FAQs"
                placeholder="Search FAQs…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            {filteredFaqs.length === 0 ? (
              <div className="shh-empty" role="status">
                No matching questions found.
              </div>
            ) : (
              <div className="shh-faqs">
                {filteredFaqs.map((f, i) => (
                  <FaqItem key={f.q} q={f.q} a={f.a} index={i} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Quick Links */}
        {activeSection === "links" && (
          <div className="shh-links-grid">
            {QUICK_LINKS.map((l) => (
              <a
                key={l.title}
                href={l.url}
                className="shh-link-card"
                target="_blank"
                rel="noreferrer"
              >
                <span className="shh-link-emoji" aria-hidden="true">
                  {l.emoji}
                </span>
                <span className="shh-link-title">{l.title}</span>
                <IcoExtLink />
                <span className="cc-sr-only"> (opens in a new tab)</span>
              </a>
            ))}
          </div>
        )}

        {/* What's New */}
        {activeSection === "new" && (
          <div className="shh-whats-new">
            {WHATS_NEW.map((rel) => (
              <div key={rel.version} className="shh-release">
                <div className="shh-release-header">
                  <span className="shh-release-ver">{rel.version}</span>
                  <span className="shh-release-date">{rel.date}</span>
                </div>
                <ul className="shh-release-items">
                  {rel.items.map((item) => (
                    <li key={item} className="shh-release-item">
                      <span className="shh-release-dot" aria-hidden="true" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}

        {/* Support */}
        {activeSection === "support" && <SupportForm />}
      </div>
    </div>
  );
}
