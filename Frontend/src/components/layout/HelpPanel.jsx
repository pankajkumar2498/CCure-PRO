/**
 * src/components/layout/HelpPanel.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Context-aware Help center panel with:
 *   • FAQ search
 *   • Quick-link cards by topic
 *   • What's New section
 *   • Support contact form
 */

import { useState, useRef, useEffect } from "react";

/* ── Icons ───────────────────────────────────────────────────────────────── */
const Icon = ({ d, size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);
const IcoClose    = () => <Icon d="M18 6L6 18M6 6l12 12" />;
const IcoSearch   = () => <Icon d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />;
const IcoExtLink  = () => <Icon d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3" size={14} />;
const IcoChevron  = () => <Icon d="M9 18l6-6-6-6" size={14} />;
const IcoHelp     = () => (
  <svg width={17} height={17} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
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
  { title: "Scan Types Explained",  emoji: "🔍", url: "#" },
  { title: "Understanding CVEs",    emoji: "🛡",  url: "#" },
  { title: "API Documentation",     emoji: "📖", url: "#" },
  { title: "Admin Guide",           emoji: "⚙",  url: "#" },
  { title: "Release Notes",         emoji: "📋", url: "#" },
];

/* ── What's New ──────────────────────────────────────────────────────────── */
const WHATS_NEW = [
  {
    version: "v1.5",
    date:    "May 2026",
    items:   [
      "Profile & Account management modal",
      "In-app notification center",
      "Settings drawer with preferences",
      "Help center with FAQ search",
    ],
  },
  {
    version: "v1.4",
    date:    "April 2026",
    items:   [
      "Credentialed scan support (SSH & WinRM)",
      "Asset-centric PostgreSQL data model",
      "Recycle bin for deleted scans",
      "Audit log viewer for admins",
    ],
  },
];

/* ── FAQ Item ─────────────────────────────────────────────────────────────── */
function FaqItem({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`hp-faq-item ${open ? "hp-faq-item--open" : ""}`}>
      <button className="hp-faq-q" onClick={() => setOpen(o => !o)}>
        <span>{q}</span>
        <span className={`hp-faq-chevron ${open ? "hp-faq-chevron--open" : ""}`}><IcoChevron /></span>
      </button>
      {open && <div className="hp-faq-a">{a}</div>}
    </div>
  );
}

/* ── Support Form ─────────────────────────────────────────────────────────── */
function SupportForm() {
  const [msg, setMsg]     = useState("");
  const [sent, setSent]   = useState(false);

  const handleSend = () => {
    if (!msg.trim()) return;
    setSent(true);
    setTimeout(() => { setSent(false); setMsg(""); }, 3000);
  };

  return (
    <div className="hp-support">
      <h4 className="hp-section-title">Contact Support</h4>
      {sent ? (
        <div className="hp-support-sent">✅ Message sent! We'll get back to you soon.</div>
      ) : (
        <>
          <textarea
            className="hp-support-textarea"
            placeholder="Describe your issue or question…"
            value={msg}
            onChange={e => setMsg(e.target.value)}
            rows={4}
          />
          <button className="hp-support-btn" onClick={handleSend} disabled={!msg.trim()}>
            Send Message
          </button>
        </>
      )}
    </div>
  );
}

/* ── Main ────────────────────────────────────────────────────────────────── */
export default function HelpPanel({ onClose }) {
  const [query, setQuery]       = useState("");
  const [activeSection, setActiveSection] = useState("faq");
  const panelRef = useRef(null);

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

  const filteredFaqs = FAQ_DATA.filter(f =>
    !query ||
    f.q.toLowerCase().includes(query.toLowerCase()) ||
    f.a.toLowerCase().includes(query.toLowerCase()) ||
    f.tags.some(t => t.includes(query.toLowerCase()))
  );

  const SECTIONS = [
    { id: "faq",      label: "FAQ"         },
    { id: "links",    label: "Quick Links" },
    { id: "new",      label: "What's New"  },
    { id: "support",  label: "Support"     },
  ];

  return (
    <div className="hp-panel" ref={panelRef} role="dialog" aria-label="Help Center">
      {/* Header */}
      <div className="hp-header">
        <div className="hp-header-left">
          <IcoHelp />
          <span>Help Center</span>
        </div>
        <button className="hp-close" onClick={onClose}><IcoClose /></button>
      </div>

      {/* Section tabs */}
      <div className="hp-tabs">
        {SECTIONS.map(s => (
          <button
            key={s.id}
            className={`hp-tab ${activeSection === s.id ? "hp-tab--active" : ""}`}
            onClick={() => setActiveSection(s.id)}
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* Body */}
      <div className="hp-body">
        {/* FAQ */}
        {activeSection === "faq" && (
          <div>
            <div className="hp-search-wrap">
              <IcoSearch />
              <input
                className="hp-search"
                placeholder="Search FAQs…"
                value={query}
                onChange={e => setQuery(e.target.value)}
              />
            </div>
            {filteredFaqs.length === 0 ? (
              <div className="hp-empty">No matching questions found.</div>
            ) : (
              <div className="hp-faqs">
                {filteredFaqs.map(f => (
                  <FaqItem key={f.q} q={f.q} a={f.a} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Quick Links */}
        {activeSection === "links" && (
          <div className="hp-links-grid">
            {QUICK_LINKS.map(l => (
              <a key={l.title} href={l.url} className="hp-link-card" target="_blank" rel="noreferrer">
                <span className="hp-link-emoji">{l.emoji}</span>
                <span className="hp-link-title">{l.title}</span>
                <IcoExtLink />
              </a>
            ))}
          </div>
        )}

        {/* What's New */}
        {activeSection === "new" && (
          <div className="hp-whats-new">
            {WHATS_NEW.map(rel => (
              <div key={rel.version} className="hp-release">
                <div className="hp-release-header">
                  <span className="hp-release-ver">{rel.version}</span>
                  <span className="hp-release-date">{rel.date}</span>
                </div>
                <ul className="hp-release-items">
                  {rel.items.map(item => (
                    <li key={item} className="hp-release-item">
                      <span className="hp-release-dot" />
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
