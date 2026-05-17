/**
 * Primary protected app shell.
 * Keeps the original scan navigation while adding the new security dashboard.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { canAny, canPermission } from "../../auth/permissions";
import { getUnreadCount, streamNotificationEvents } from "../../api/notifications";
import { usePreferences } from "../../context/PreferencesContext";
import ProfileModal from "./ProfileModal";
import SettingsDrawer from "./SettingsDrawer";
import NotificationsPanel, { NotificationBell } from "./NotificationsPanel";
import HelpPanel from "./HelpPanel";

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
  >
    <path d={d} />
  </svg>
);

const IcoDashboard = () => <Icon d="M3 13h8V3H3v10zM13 21h8V11h-8v10zM13 3v6h8V3h-8zM3 21h8v-6H3v6z" />;
const IcoGrid = () => <Icon d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />;
const IcoFile = () => <Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8" />;
const IcoArchive = () => <Icon d="M21 8v13H3V8M1 3h22v5H1zM10 12h4" />;
const IcoShield = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />;
const IcoChart = () => <Icon d="M18 20V10M12 20V4M6 20v-6M2 20h20" />;
const IcoTrash = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoUser = () => <Icon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />;
const IcoPlus = () => (
  <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);
const IcoSettings = () => <Icon d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.31.22.65.22 1h.38a2 2 0 1 1 0 4h-.38c0 .35-.08.69-.22 1z" />;
const IcoHelp = () => <Icon d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.09 9a3 3 0 1 1 5.83 1c0 2-3 3-3 3M12 17h.01" />;
const IcoChevronLeft = () => <Icon d="M15 18l-6-6 6-6" size={14} />;
const IcoChevronRight = () => <Icon d="M9 18l6-6-6-6" size={14} />;
const IcoUsers = () => <Icon d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 7a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />;
const IcoLock = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 11V7" />;
const IcoList = () => <Icon d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />;
const IcoOrg = () => <Icon d="M3 21h18M3 7v1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7M4 21V4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v17" />;
const IcoMonitor = () => <Icon d="M2 3h20v14H2zM8 21h8M12 17v4" />;
const IcoAlert = () => <Icon d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" />;

const NAV_ITEMS = [
  { id: "security-dashboard", label: "Security Dashboard", Icon: IcoDashboard, route: "/dashboard" },
  { id: "assets", label: "Asset Registry", Icon: IcoMonitor, route: "/assets", permission: { resource: "assets", action: "read" } },
  { id: "vulnerabilities", label: "Vulnerability Browser", Icon: IcoAlert, route: "/vulnerabilities", permission: { resource: "findings", action: "read" } },
  { id: "scan-library", label: "Scan Library", Icon: IcoGrid, route: "/scan", permission: { resource: "scans", action: "execute" } },
  { id: "history", label: "My Scan Jobs", Icon: IcoFile, route: "/history", permission: { resource: "scans", action: "read" } },
  {
    id: "archived",
    label: "Archived Scans",
    Icon: IcoArchive,
    route: "/archived",
    requiredAny: [
      { resource: "scans", action: "restore" },
      { resource: "scans", action: "recycle" },
    ],
  },
  { id: "policies", label: "Scan Policies", Icon: IcoShield, disabled: true },
  { id: "reports", label: "Security Reports", Icon: IcoChart, route: "/reports", permission: { resource: "reports", action: "read" } },
  {
    id: "recycle",
    label: "Recycle Bin",
    Icon: IcoTrash,
    route: "/recycle-bin",
    requiredAny: [
      { resource: "scans", action: "restore" },
      { resource: "scans", action: "purge" },
    ],
  },
];

const ADMIN_NAV_ITEMS = [
  { id: "admin-users", label: "User Management", Icon: IcoUsers, route: "/admin/users", permission: { resource: "users", action: "read" } },
  { id: "admin-orgs", label: "Organizations", Icon: IcoOrg, route: "/admin/organizations", permission: { resource: "organizations", action: "read" } },
  { id: "admin-roles", label: "Roles & Permissions", Icon: IcoLock, route: "/admin/roles", permission: { resource: "roles", action: "read" } },
  { id: "admin-deleted-users", label: "Deleted Users", Icon: IcoTrash, route: "/admin/users/deleted", permission: { resource: "users", action: "delete" } },
  { id: "admin-logs", label: "Audit Logs", Icon: IcoList, route: "/admin/audit-logs", permission: { resource: "audit", action: "read" } },
];

const hasPermission = (user, permission) => canPermission(user, permission);
const canSeeNavItem = (user, item) => {
  if (item.permission && !hasPermission(user, item.permission)) return false;
  if (item.requiredAny && !canAny(user, item.requiredAny)) return false;
  return true;
};

function ProfileDropdown({ user, onClose, onLogout, onOpenProfile }) {
  const ref = useRef(null);

  useEffect(() => {
    const handleMouseDown = (event) => {
      if (ref.current && !ref.current.contains(event.target)) onClose();
    };
    document.addEventListener("mousedown", handleMouseDown);
    return () => document.removeEventListener("mousedown", handleMouseDown);
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
        <button className="pd-btn pd-btn--primary" onClick={() => { onClose(); onOpenProfile(); }}>
          My Account
        </button>
        <button className="pd-btn pd-btn--signout" onClick={onLogout}>
          Sign Out
        </button>
      </div>
    </div>
  );
}

export default function AppLayout({ children, pageTitle = "", saveStatus = "", onNewScan }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { user, logout } = useAuth();
  const canStartScans = hasPermission(user, { resource: "scans", action: "execute" });

  const [profileOpen, setProfileOpen] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notificationEvent, setNotificationEvent] = useState(null);
  const { preferences, updateLocalPreferences } = usePreferences();
  const [localCollapsed, setLocalCollapsed] = useState(() => localStorage.getItem("sidebarCollapsed") === "true");

  useEffect(() => {
    if (preferences?.sidebar_collapsed !== undefined) {
      setLocalCollapsed(preferences.sidebar_collapsed);
      localStorage.setItem("sidebarCollapsed", preferences.sidebar_collapsed);
    }
  }, [preferences?.sidebar_collapsed]);

  const toggleSidebar = () => {
    const next = !localCollapsed;
    setLocalCollapsed(next);
    localStorage.setItem("sidebarCollapsed", next);
  };

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    const refreshSummary = async () => {
      try {
        const summary = await getUnreadCount();
        if (!stopped) setUnreadCount(summary.total_unread || 0);
      } catch {
        // ignore notification failures in the shell
      }
    };

    const connect = async () => {
      let failures = 0;
      while (!stopped) {
        try {
          await streamNotificationEvents({
            signal: controller.signal,
            onEvent: ({ event, data }) => {
              if (stopped || !data) return;
              if (event === "connected" && data.summary) setUnreadCount(data.summary.total_unread || 0);
              if (event === "notification.created" && data.notification) {
                setNotificationEvent({ type: "created", notification: data.notification, receivedAt: Date.now() });
                if (!data.notification.is_read) setUnreadCount((count) => count + 1);
              }
              if (event === "notifications.summary" && data.summary) setUnreadCount(data.summary.total_unread || 0);
            },
          });
          if (!stopped) throw new Error("Notification stream closed.");
        } catch {
          if (stopped || controller.signal.aborted) return;
          failures += 1;
          if (failures === 1) await refreshSummary();
          await wait(Math.min(30000, 1000 * 2 ** Math.min(failures, 5)));
        }
      }
    };

    connect();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, []);

  const closeAll = useCallback(() => {
    setShowNotifs(false);
    setShowHelp(false);
    setShowSettings(false);
  }, []);

  const activeId = (() => {
    if (pathname === "/" || pathname.startsWith("/dashboard")) return "security-dashboard";
    if (pathname.startsWith("/scan")) return "scan-library";
    if (pathname.startsWith("/history")) return "history";
    if (pathname.startsWith("/archived")) return "archived";
    if (pathname.startsWith("/recycle-bin")) return "recycle";
    if (pathname.startsWith("/reports")) return "reports";
    if (pathname.startsWith("/admin/users/deleted")) return "admin-deleted-users";
    if (pathname.startsWith("/admin/users")) return "admin-users";
    if (pathname.startsWith("/admin/roles")) return "admin-roles";
    if (pathname.startsWith("/admin/organizations")) return "admin-orgs";
    if (pathname.startsWith("/admin/audit-logs")) return "admin-logs";
    return "security-dashboard";
  })();

  const renderNavItem = (item) => {
    const { id, label, Icon: ItemIcon, route, disabled } = item;
    if (!canSeeNavItem(user, item)) return null;

    return (
      <button
        key={id}
        type="button"
        className={`sidebar-item ${activeId === id ? "sidebar-item--active" : ""} ${disabled ? "sidebar-item--disabled" : ""}`}
        onClick={() => {
          if (localCollapsed) toggleSidebar();
          if (!disabled && route) navigate(route);
        }}
        title={disabled ? "Coming soon" : label}
      >
        <span className="sidebar-item-icon"><ItemIcon /></span>
        <span>{label}</span>
        {disabled && (
          <span style={{ marginLeft: "auto", fontSize: "0.6rem", background: "#334155", color: "#64748b", padding: "1px 5px", borderRadius: 3 }}>
            SOON
          </span>
        )}
      </button>
    );
  };

  return (
    <div className="app-layout">
      <aside className={`sidebar ${localCollapsed ? "sidebar--collapsed" : ""}`}>
        <button
          type="button"
          className="sidebar-toggle"
          onClick={toggleSidebar}
          title={localCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        >
          {localCollapsed ? <IcoChevronRight /> : <IcoChevronLeft />}
        </button>

        <div className="sidebar-brand">
          <span className="sidebar-gem">*</span>
          <div className="sidebar-brand-text">
            <span className="sidebar-name">CCure Audit</span>
            <span className="sidebar-sub">PRO</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {ADMIN_NAV_ITEMS.some((item) => canSeeNavItem(user, item)) && (
            <>
              <span className="sidebar-section-label">Administration</span>
              {ADMIN_NAV_ITEMS.map(renderNavItem)}
              <div style={{ height: 16 }} />
            </>
          )}

          <span className="sidebar-section-label">Navigation</span>
          {NAV_ITEMS.map(renderNavItem)}
        </nav>

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

      <div className="main-area">
        <header className="top-header">
          <div className="header-brand">
            <span className="header-brand-icon">*</span>
            <span className="header-brand-title">CCure Audit PRO</span>
            {pageTitle && (
              <div className="header-breadcrumb" style={{ marginLeft: 8 }}>
                <span className="header-breadcrumb-sep">/</span>
                <span className="header-breadcrumb-current">{pageTitle}</span>
              </div>
            )}
          </div>

          <div className="header-actions">
            {saveStatus === "saving" && <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>Saving...</span>}
            {saveStatus === "saved" && <span style={{ fontSize: "0.78rem", color: "var(--ok)", fontWeight: 600 }}>Saved</span>}
            {saveStatus === "error" && <span style={{ fontSize: "0.78rem", color: "var(--danger)", fontWeight: 600 }}>Save failed</span>}

            {canStartScans && (
              <button className="btn-new-scan" onClick={onNewScan || (() => navigate("/scan"))}>
                <IcoPlus />
                New Scan
              </button>
            )}

            <button className={`btn-icon ${showSettings ? "btn-icon--active" : ""}`} title="Settings" onClick={() => { closeAll(); setShowSettings((show) => !show); }}>
              <IcoSettings /><span>Settings</span>
            </button>

            <button className={`btn-icon btn-icon--round ${showHelp ? "btn-icon--active" : ""}`} title="Help" onClick={() => { closeAll(); setShowHelp((show) => !show); }}>
              <IcoHelp />
            </button>

            <div style={{ position: "relative" }}>
              <NotificationBell unreadCount={unreadCount} onClick={() => { closeAll(); setShowNotifs((show) => !show); }} />
              {showNotifs && (
                <div className="np-panel-wrap">
                  <NotificationsPanel
                    onClose={() => setShowNotifs(false)}
                    onUnreadChange={setUnreadCount}
                    liveEvent={notificationEvent}
                  />
                </div>
              )}
            </div>

            {showHelp && (
              <div className="hp-panel-wrap">
                <HelpPanel onClose={() => setShowHelp(false)} />
              </div>
            )}

            <div style={{ position: "relative" }}>
              <button className="profile-btn" onClick={() => setProfileOpen((open) => !open)}>
                <div className="profile-avatar"><IcoUser /></div>
                <span className="profile-name">{user?.username || "Profile"}</span>
                <span className="profile-chevron">v</span>
              </button>
              {profileOpen && (
                <ProfileDropdown
                  user={user}
                  onClose={() => setProfileOpen(false)}
                  onLogout={() => { setProfileOpen(false); logout(); }}
                  onOpenProfile={() => setShowProfile(true)}
                />
              )}
            </div>
          </div>
        </header>

        <main className="page-main">{children}</main>
      </div>

      {showSettings && (
        <SettingsDrawer onClose={() => setShowSettings(false)} onPreferencesUpdated={updateLocalPreferences} />
      )}

      {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
    </div>
  );
}
