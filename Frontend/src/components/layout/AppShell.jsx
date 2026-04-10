/**
 * src/components/layout/AppShell.jsx
 *
 * Shared header + page wrapper used by all 5 pages.
 * Accepts optional `saveStatus` to show the saving pill.
 */

import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

// const NAV = [
//   { to: "/scan",    label: "New Scan",  icon: "⊕" },
//   { to: "/history", label: "History",   icon: "◧" },
// ];

const NAV = [
  { to: "/scan",              label: "Network Scan", icon: "⊕",  exact: true  },
  { to: "/scan/credentialed", label: "Credentialed", icon: "🔐", exact: false },
  { to: "/history",           label: "History",      icon: "◧",  exact: false },
];

export default function AppShell({ children, saveStatus = "" }) {
  const { user, logout } = useAuth();
  const { pathname }     = useLocation();

  return (
    <div className="app-shell">
      <header className="shell-header">
        {/* Brand */}
        <Link to="/scan" className="shell-brand">
          <span className="brand-icon">◈</span>
          <span className="brand-name">CCURE AUDIT</span>
          <span className="brand-badge">PRO</span>
        </Link>

        {/* Nav */}
        <nav className="shell-nav">
          {NAV.map(n => (
            <Link
              key={n.to}
              to={n.to}
              className={`shell-nav-link ${
                (n.exact ? (pathname === n.to || pathname.startsWith("/scan/phase")) : pathname.startsWith(n.to))
                  ? "shell-nav-link--active" : ""}`}
            >
              <span className="nav-icon">{n.icon}</span>
              {n.label}
            </Link>
          ))}
        </nav>

        {/* Right side */}
        <div className="shell-right">
          {saveStatus === "saving" && (
            <span className="save-status save-status--saving">
              <span className="btn-spinner" style={{ width: 12, height: 12, borderWidth: 2 }} />
              Saving…
            </span>
          )}
          {saveStatus === "saved" && (
            <span className="save-status save-status--saved">✓ Saved</span>
          )}
          {saveStatus === "error" && (
            <span className="save-status save-status--error">⚠ Save failed</span>
          )}

          <span className="user-chip">
            <span className="user-dot" />
            {user?.username}
          </span>
          <button className="logout-btn" onClick={logout}>Sign out</button>
        </div>
      </header>

      <div className="shell-body">
        {children}
      </div>
    </div>
  );
}
