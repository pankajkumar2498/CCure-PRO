/**
 * src/components/layout/AppLayout.jsx
 *
 * The primary layout shell used by every protected page.
 * Faithfully implements the CAST Dashboard design:
 *   • Dark left sidebar (#1a2332) with nav items + brand
 *   • White top header (52px) with + New Scan, Settings, Profile
 *   • Responsive: sidebar hides on mobile
 */
import { useRef, useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

/* ─── SVG icon set (self-contained, no external deps) ─────────────────── */
const Icon = ({ d, size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);
const IcoGrid    = () => <Icon d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />;
const IcoFile    = () => <Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8" />;
const IcoArchive = () => <Icon d="M21 8v13H3V8M1 3h22v5H1zM10 12h4" />;
const IcoShield  = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />;
const IcoChart   = () => <Icon d="M18 20V10M12 20V4M6 20v-6M2 20h20" />;
const IcoTrash   = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoUser    = () => <Icon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />;
const IcoPlus    = () => (
  <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
  </svg>
);
const IcoBell    = () => (
  <svg width={17} height={17} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
  </svg>
);
const IcoSettings = () => (
  <svg width={17} height={17} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3"/>
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
  </svg>
);
const IcoHelp = () => (
  <svg width={17} height={17} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);
const IcoChevronLeft = () => (
  <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="15 18 9 12 15 6" />
  </svg>
);
const IcoChevronRight = () => (
  <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="9 18 15 12 9 6" />
  </svg>
);

const IcoUsers = () => <Icon d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 7a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />;
const IcoLock  = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 11V7" />;
const IcoList  = () => <Icon d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />;
const IcoOrg   = () => <Icon d="M3 21h18M3 7v1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7M4 21V4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v17" />;

/* ─── Sidebar navigation config ────────────────────────────────────────── */
const NAV_ITEMS = [
  { id: "dashboard", label: "Scan Library",     Icon: IcoGrid,    route: "/dashboard" },
  { id: "history",   label: "My Scan Jobs",     Icon: IcoFile,    route: "/history"   },
  { id: "archived",  label: "Archived Scans",   Icon: IcoArchive, route: "/archived-scans" },
  { id: "policies",  label: "Scan Policies",    Icon: IcoShield,  disabled: true      },
  { id: "reports",   label: "Security Reports", Icon: IcoChart,   route: "/reports"   },
  { id: "recycle",   label: "Recycle Bin",      Icon: IcoTrash,   route: "/recycle-bin" },
];

const ADMIN_NAV_ITEMS = [
  { id: "admin-users", label: "User Management",      Icon: IcoUsers,   route: "/admin/users",         permission: { resource: "users", action: "read" } },
  { id: "admin-orgs",  label: "Organizations",  Icon: IcoOrg,     route: "/admin/organizations", permission: { resource: "organizations", action: "read" } },
  { id: "admin-roles", label: "Roles & Permissions",  Icon: IcoLock,    route: "/admin/roles",         permission: { resource: "roles", action: "read" } },
  { id: "admin-deleted-users", label: "Deleted Users", Icon: IcoTrash, route: "/admin/deleted-users", permission: { resource: "users", action: "delete" } },
  { id: "admin-logs",  label: "Audit Logs",     Icon: IcoList,    route: "/admin/audit-logs",    permission: { resource: "audit", action: "read" } },
];

const hasPermission = (user, resource, action) => {
  if (!user?.role?.permissions) return false;
  return user.role.permissions.some(p => p.resource === resource && (p.action === action || p.action === 'manage'));
};

/* ─── Profile dropdown ──────────────────────────────────────────────────── */
function ProfileDropdown({ user, onClose, onLogout }) {
  const ref = useRef(null);
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose(); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [onClose]);

  return (
    <div className="profile-dropdown" ref={ref}>
      <div className="pd-header">
        <div className="pd-avatar"><IcoUser /></div>
        <div className="pd-info">
          <span className="pd-name">{user?.username || "User"}</span>
          <span className="pd-email">{user?.email || ""}</span>
        </div>
      </div>
      <div className="pd-body">
        <button className="pd-btn pd-btn--primary">My Account</button>
        <button className="pd-btn pd-btn--signout" onClick={onLogout}>
          ↩ Sign Out
        </button>
      </div>
    </div>
  );
}

/* ─── Main AppLayout ────────────────────────────────────────────────────── */
export default function AppLayout({ children, pageTitle = "", saveStatus = "", onNewScan }) {
  const navigate              = useNavigate();
  const { pathname }          = useLocation();
  const { user, logout }      = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(() => {
    return localStorage.getItem("sidebarCollapsed") === "true";
  });

  useEffect(() => {
    localStorage.setItem("sidebarCollapsed", isCollapsed);
  }, [isCollapsed]);

  // Derive active sidebar item from current route
  const activeId = (() => {
    if (pathname.startsWith("/history"))   return "history";
    if (pathname.startsWith("/archived-scans")) return "archived";
    if (pathname.startsWith("/recycle-bin")) return "recycle";
    if (pathname.startsWith("/reports"))     return "reports";
    if (pathname.startsWith("/dashboard"))   return "dashboard";
    if (pathname.startsWith("/scan"))      return "dashboard";
    if (pathname.startsWith("/admin/users")) return "admin-users";
    if (pathname.startsWith("/admin/deleted-users")) return "admin-deleted-users";
    if (pathname.startsWith("/admin/roles")) return "admin-roles";
    if (pathname.startsWith("/admin/organizations")) return "admin-orgs";
    if (pathname.startsWith("/admin/audit-logs")) return "admin-logs";
    return "dashboard";
  })();

  return (
    <div className="app-layout">

      {/* ── SIDEBAR ─────────────────────────────────────────────── */}
      <aside className={`sidebar ${isCollapsed ? "sidebar--collapsed" : ""}`}>
        
        {/* Toggle Button */}
        <button 
          className="sidebar-toggle"
          onClick={() => setIsCollapsed(!isCollapsed)}
          title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        >
          {isCollapsed ? <IcoChevronRight /> : <IcoChevronLeft />}
        </button>

        {/* Nav */}
        <nav className="sidebar-nav">
          {/* Admin Section */}
          {ADMIN_NAV_ITEMS.some(item => hasPermission(user, item.permission.resource, item.permission.action)) && (
            <>
              <span className="sidebar-section-label">Administration</span>
              {ADMIN_NAV_ITEMS.map(({ id, label, Icon, route, permission }) => {
                if (!hasPermission(user, permission.resource, permission.action)) return null;
                return (
                  <button
                    key={id}
                    className={`sidebar-item ${activeId === id ? "sidebar-item--active" : ""}`}
                    onClick={() => {
                      if (isCollapsed) setIsCollapsed(false);
                      if (route) navigate(route);
                    }}
                    title={label}
                  >
                    <span className="sidebar-item-icon">
                      <Icon />
                    </span>
                    <span>{label}</span>
                  </button>
                );
              })}
              <div style={{ height: 16 }} />
            </>
          )}

          <span className="sidebar-section-label">Navigation</span>
          {NAV_ITEMS.map(({ id, label, Icon, route, disabled }) => (
            <button
              key={id}
              className={`sidebar-item ${activeId === id ? "sidebar-item--active" : ""} ${disabled ? "sidebar-item--disabled" : ""}`}
              onClick={() => {
                if (isCollapsed) setIsCollapsed(false);
                if (!disabled && route) navigate(route);
              }}
              title={disabled ? "Coming soon" : label}
            >
              <span className="sidebar-item-icon">
                <Icon />
              </span>
              <span>{label}</span>
              {disabled && (
                <span style={{ marginLeft: "auto", fontSize: "0.6rem", background: "#334155", color: "#64748b", padding: "1px 5px", borderRadius: 3, letterSpacing: "0.05em" }}>
                  SOON
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Footer: user chip */}
        <div className="sidebar-footer">
          <div style={{ padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#334155", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <IcoUser />
            </div>
            <div className="pd-info" style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
              <span style={{ fontSize: "0.78rem", fontWeight: 600, color: "#e2e8f0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {user?.username || "User"}
              </span>
              <span style={{ fontSize: "0.65rem", color: "#64748b", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {user?.email || ""}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* ── MAIN AREA ───────────────────────────────────────────── */}
      <div className="main-area">

        {/* ── TOP HEADER ── */}
        <header className="top-header">
          <div className="header-brand">
            <span className="header-brand-icon">◈</span>
            <span className="header-brand-title">CCure Audit PRO</span>
            {pageTitle && (
              <div className="header-breadcrumb" style={{ marginLeft: 8 }}>
                <span className="header-breadcrumb-sep">/</span>
                <span className="header-breadcrumb-current">{pageTitle}</span>
              </div>
            )}
          </div>

          <div className="header-actions">
            {/* Save status pill */}
            {saveStatus === "saving" && (
              <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.78rem", color: "var(--text-muted)" }}>
                <span className="btn-spinner btn-spinner--dark" />Saving…
              </span>
            )}
            {saveStatus === "saved" && (
              <span style={{ fontSize: "0.78rem", color: "var(--ok)", fontWeight: 600 }}>✓ Saved</span>
            )}
            {saveStatus === "error" && (
              <span style={{ fontSize: "0.78rem", color: "var(--danger)", fontWeight: 600 }}>⚠ Save failed</span>
            )}

            {/* + New Scan */}
            <button className="btn-new-scan" onClick={onNewScan || (() => navigate("/dashboard"))}>
              <IcoPlus />
              New Scan
            </button>

            {/* Settings */}
            <button className="btn-icon" title="Settings"><IcoSettings /><span>Settings</span></button>

            {/* Help */}
            <button className="btn-icon btn-icon--round" title="Help"><IcoHelp /></button>

            {/* Notifications */}
            <button className="btn-icon btn-icon--round" title="Notifications"><IcoBell /></button>

            {/* Profile */}
            <div style={{ position: "relative" }}>
              <button className="profile-btn" onClick={() => setProfileOpen(p => !p)}>
                <div className="profile-avatar"><IcoUser /></div>
                <span className="profile-name">{user?.username || "Profile"}</span>
                <span className="profile-chevron">▾</span>
              </button>
              {profileOpen && (
                <ProfileDropdown
                  user={user}
                  onClose={() => setProfileOpen(false)}
                  onLogout={() => { setProfileOpen(false); logout(); }}
                />
              )}
            </div>
          </div>
        </header>

        {/* ── PAGE CONTENT ── */}
        <main className="page-main">
          {children}
        </main>
      </div>
    </div>
  );
}
