import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { canAny, canPermission } from "../../auth/permissions";
import { getUnreadCount, streamNotificationEvents } from "../../api/notifications";
import { usePreferences } from "../../context/PreferencesContext";
import api from "../../api/axiosInstance";
import ProfileModal from "./ProfileModal";
import SettingsDrawer from "./SettingsDrawer";
import NotificationsPanel, { NotificationBell } from "./NotificationsPanel";
import HelpPanel from "./HelpPanel";

// ── Icons ────────────────────────────────────────────────────────────────────
const Icon = ({ d, size = 16, viewBox = "0 0 24 24", fill = "none" }) => (
  <svg width={size} height={size} viewBox={viewBox} fill={fill} stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

const IcoDashboard = () => <Icon d="M3 13h8V3H3v10zM13 21h8V11h-8v10zM13 3v6h8V3h-8zM3 21h8v-6H3v6z" />;
const IcoFileText = () => <Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8" />;
const IcoGrid = () => <Icon d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />;
const IcoPlay = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>;
const IcoFile = () => <Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6" />;
const IcoArchive = () => <Icon d="M21 8v13H3V8M1 3h22v5H1zM10 12h4" />;
const IcoTrash = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoAlert = () => <Icon d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" />;
const IcoMonitor = () => <Icon d="M2 3h20v14H2zM8 21h8M12 17v4" />;
const IcoServer = () => <Icon d="M2 5h20v4H2zm0 10h20v4H2zm6-10v4m8-4v4m-8 10v4m8-4v4" />;
const IcoLock = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 11V7" />;
const IcoChart = () => <Icon d="M18 20V10M12 20V4M6 20v-6M2 20h20" />;
const IcoCheckCircle = () => <Icon d="M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4L12 14.01l-3-3" />;
const IcoTrendUp = () => <Icon d="M23 6l-9.5 9.5-5-5L1 18M17 6h6v6" />;
const IcoUsers = () => <Icon d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 7a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />;
const IcoOrg = () => <Icon d="M3 21h18M3 7v1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7M4 21V4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v17" />;
const IcoShieldKey = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM8 11h8M8 15h6" />;
const IcoList = () => <Icon d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />;
const IcoSettings = () => <Icon d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.31.22.65.22 1h.38a2 2 0 1 1 0 4h-.38c0 .35-.08.69-.22 1z" />;
const IcoHelp = () => <Icon d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.09 9a3 3 0 1 1 5.83 1c0 2-3 3-3 3M12 17h.01" />;
const IcoChevronLeft = () => <Icon d="M15 18l-6-6 6-6" size={14} />;
const IcoChevronRight = () => <Icon d="M9 18l6-6-6-6" size={14} />;
const IcoUser = () => <Icon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />;
const IcoMenu = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>;
const IcoPlus = () => (
  <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);
const IcoInfo = () => <Icon d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01" />;

// ── Sidebar Definition ───────────────────────────────────────────────────────
const SIDEBAR_SECTIONS = [
  {
    label: "Overview",
    items: [
      { id: "security-dashboard", label: "Security Dashboard", Icon: IcoDashboard, route: "/" },
      { id: "executive-report",   label: "Executive Report",   Icon: IcoFileText,  route: "/reports?tab=executive", permission: { resource: "reports", action: "read" } },
    ],
  },
  {
    label: "Scanning",
    items: [
      { id: "scan-templates", label: "Scan Templates", Icon: IcoGrid,    route: "/scan", permission: { resource: "scans", action: "execute" } },
      { id: "scan-monitor",   label: "Active Scans",   Icon: IcoMonitor, route: "/monitor", permission: { resource: "scans", action: "read" }, badgeKey: "runningScans", badgeColor: "info" },
      { id: "scan-history",   label: "Scan History",   Icon: IcoFile,    route: "/history", permission: { resource: "scans", action: "read" } },
      { id: "archived-scans", label: "Archived Scans", Icon: IcoArchive, route: "/archived", requiredAny: [{ resource: "scans", action: "restore" }, { resource: "scans", action: "recycle" }] },
      { id: "recycle-bin",    label: "Recycle Bin",    Icon: IcoTrash,   route: "/recycle-bin", requiredAny: [{ resource: "scans", action: "restore" }, { resource: "scans", action: "purge" }] },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { id: "vulnerabilities", label: "Vulnerabilities", Icon: IcoAlert,   route: "/vulnerabilities", permission: { resource: "findings", action: "read" }, badgeKey: "criticalCount", badgeColor: "danger" },
      { id: "asset-registry",  label: "Asset Registry",  Icon: IcoMonitor, route: "/assets", permission: { resource: "assets", action: "read" } },
      { id: "services-ports",  label: "Services & Ports",Icon: IcoServer,  route: "/assets?tab=services", permission: { resource: "assets", action: "read" } },
      { id: "tls-certs",       label: "TLS / Certificates",Icon: IcoLock,  route: "/assets?tab=tls", permission: { resource: "assets", action: "read" } },
    ],
  },
  {
    label: "Reports",
    items: [
      { id: "security-reports", label: "Security Reports", Icon: IcoChart,       route: "/reports", permission: { resource: "reports", action: "read" } },
      { id: "compliance",       label: "Compliance",       Icon: IcoCheckCircle, route: "/reports?tab=compliance", permission: { resource: "reports", action: "read" } },
      { id: "risk-trends",      label: "Risk Trends",      Icon: IcoTrendUp,     route: "/reports?tab=trends", permission: { resource: "reports", action: "read" } },
    ],
  },
  {
    label: "Administration",
    items: [
      { id: "user-management", label: "User Management", Icon: IcoUsers,     route: "/admin/users", permission: { resource: "users", action: "read" } },
      { id: "deleted-users",   label: "Deleted Users",   Icon: IcoTrash,     route: "/admin/users/deleted", permission: { resource: "users", action: "read" } },
      { id: "organizations",   label: "Organizations",   Icon: IcoOrg,       route: "/admin/organizations", permission: { resource: "organizations", action: "read" } },
      { id: "roles-perms",     label: "Roles & Permissions",Icon: IcoShieldKey,route: "/admin/roles", permission: { resource: "roles", action: "read" } },
      { id: "audit-logs",      label: "Audit Logs",      Icon: IcoList,      route: "/admin/audit-logs", permission: { resource: "audit", action: "read" } },
    ],
  },
];

const hasPermission = (user, permission) => canPermission(user, permission);
const canSeeNavItem = (user, item) => {
  if (item.permission && !hasPermission(user, item.permission)) return false;
  if (item.requiredAny && !canAny(user, item.requiredAny)) return false;
  return true;
};

// ── Profile Dropdown ─────────────────────────────────────────────────────────
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

// ── Main Layout Component ────────────────────────────────────────────────────
export default function AppLayout({ children, pageTitle = "", saveStatus = "", onNewScan }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { pathname, search } = location;
  const { user, logout } = useAuth();
  const canStartScans = hasPermission(user, { resource: "scans", action: "execute" });

  const [profileOpen, setProfileOpen] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState("CDAC RTSG Bangalore");
  const [searchQuery, setSearchQuery] = useState("");
  const [unreadCount, setUnreadCount] = useState(0);
  const [notificationEvent, setNotificationEvent] = useState(null);
  
  const { preferences, updateLocalPreferences } = usePreferences();
  const [localCollapsed, setLocalCollapsed] = useState(() => localStorage.getItem("sidebarCollapsed") === "true");
  const [mobileOpen, setMobileOpen] = useState(false);

  const sidebarNavRef = useRef(null);

  // Restore scroll position on mount
  useEffect(() => {
    const savedScroll = sessionStorage.getItem("sidebarScrollPos");
    if (savedScroll && sidebarNavRef.current) {
      sidebarNavRef.current.scrollTop = parseInt(savedScroll, 10);
    }
  }, []);

  const handleSidebarScroll = (e) => {
    sessionStorage.setItem("sidebarScrollPos", e.target.scrollTop);
  };

  // Live Counts
  const [runningScans, setRunningScans] = useState(0);
  const [criticalCount, setCriticalCount] = useState(0);
  const [quotaUsed, setQuotaUsed] = useState(0);
  const [quotaLimit, setQuotaLimit] = useState(50);
  const [concurrentUsed, setConcurrentUsed] = useState(0);
  const [concurrentLimit, setConcurrentLimit] = useState(5);

  // Poll dashboard summary for sidebar badges & quota
  useEffect(() => {
    const fetchCounts = async () => {
      try {
        const res = await api.get("/dashboard/summary");
        if (res.status === 200 && res.data) {
          const d = res.data;
          setRunningScans(d?.scans?.running ?? 0);
          setCriticalCount(d?.severity?.critical ?? 0);
          setQuotaUsed(d?.scans?.last_24h ?? 0);
          setQuotaLimit(d?.scans?.quota_limit_24h ?? 50);
          setConcurrentUsed(d?.scans?.running ?? 0);
        }
      } catch { /* silent */ }
    };
    fetchCounts();
    const interval = setInterval(fetchCounts, 30_000);
    return () => clearInterval(interval);
  }, []);

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
      } catch {}
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
          if (!stopped) throw new Error("Stream closed.");
        } catch {
          if (stopped || controller.signal.aborted) return;
          failures += 1;
          if (failures === 1) await refreshSummary();
          await wait(Math.min(30000, 1000 * 2 ** Math.min(failures, 5)));
        }
      }
    };
    connect();
    return () => { stopped = true; controller.abort(); };
  }, []);

  const closeAll = useCallback(() => {
    setShowNotifs(false);
    setShowHelp(false);
    setShowSettings(false);
    setShowOrgDropdown(false);
  }, []);

  // Determine active nav item
  const activeId = (() => {
    if (pathname === "/" || pathname === "/dashboard") return "security-dashboard";
    if (pathname.startsWith("/reports") && search.includes("tab=executive")) return "executive-report";
    if (pathname.startsWith("/reports") && search.includes("tab=compliance")) return "compliance";
    if (pathname.startsWith("/reports") && search.includes("tab=trends")) return "risk-trends";
    if (pathname.startsWith("/reports")) return "security-reports";
    if (pathname.startsWith("/monitor")) return "active-scans";
    if (pathname.startsWith("/history")) return "scan-history";
    if (pathname.startsWith("/archived")) return "archived-scans";
    if (pathname.startsWith("/recycle-bin")) return "recycle-bin";
    if (pathname.startsWith("/assets") && search.includes("tab=services")) return "services-ports";
    if (pathname.startsWith("/assets") && search.includes("tab=tls")) return "tls-certs";
    if (pathname.startsWith("/assets")) return "asset-registry";
    if (pathname.startsWith("/vulnerabilities")) return "vulnerabilities";
    if (pathname.startsWith("/scan")) return "scan-templates";
    if (pathname.startsWith("/admin/users/deleted")) return "deleted-users";
    if (pathname.startsWith("/admin/users")) return "user-management";
    if (pathname.startsWith("/admin/roles")) return "roles-perms";
    if (pathname.startsWith("/admin/organizations")) return "organizations";
    if (pathname.startsWith("/admin/audit-logs")) return "audit-logs";
    return "";
  })();

  const renderNavItem = (item) => {
    const { id, label, Icon: ItemIcon, route, disabled, badgeKey, badgeColor } = item;
    if (!canSeeNavItem(user, item)) return null;

    let badgeVal = 0;
    if (badgeKey === "runningScans") badgeVal = runningScans;
    if (badgeKey === "criticalCount") badgeVal = criticalCount;

    return (
      <button
        key={id}
        type="button"
        className={`sidebar-item ${activeId === id ? "sidebar-item--active" : ""} ${disabled ? "sidebar-item--disabled" : ""}`}
        onClick={() => {
          if (!disabled && route) navigate(route);
          setMobileOpen(false);
        }}
        title={localCollapsed && !mobileOpen ? label : ""}
      >
        <span className="sidebar-item-icon"><ItemIcon /></span>
        <span className="sidebar-item-label">{label}</span>
        {disabled && <span className="sidebar-soon-tag">SOON</span>}
        {badgeVal > 0 && !disabled && (
          <span className={`sidebar-badge sidebar-badge--${badgeColor || "neutral"}`}>
            {badgeVal}
          </span>
        )}
      </button>
    );
  };

  const quotaPct = quotaLimit > 0 ? Math.min((quotaUsed / quotaLimit) * 100, 100) : 0;
  const concPct = concurrentLimit > 0 ? Math.min((concurrentUsed / concurrentLimit) * 100, 100) : 0;

  return (
    <div className="app-layout">
      {/* Mobile Backdrop */}
      <div 
        className={`sidebar-backdrop ${mobileOpen ? "sidebar-backdrop--visible" : ""}`}
        onClick={() => setMobileOpen(false)}
      />

      <aside className={`sidebar ${localCollapsed ? "sidebar--collapsed" : ""} ${mobileOpen ? "sidebar--mobile-open" : "sidebar--mobile-hidden"}`}>
        <button
          type="button"
          className="sidebar-toggle"
          onClick={toggleSidebar}
          title={localCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        >
          {localCollapsed ? <IcoChevronRight /> : <IcoChevronLeft />}
        </button>

        <div className="sidebar-brand">
          <span className="sidebar-gem">🛡</span>
          <div className="sidebar-brand-text">
            <span className="sidebar-name">CCure Audit</span>
            <span className="sidebar-sub">PRO</span>
          </div>
        </div>

        <nav className="sidebar-nav" ref={sidebarNavRef} onScroll={handleSidebarScroll}>
          {SIDEBAR_SECTIONS.map((section, idx) => {
            const visibleItems = section.items.filter(item => canSeeNavItem(user, item));
            if (visibleItems.length === 0) return null;

            return (
              <div key={section.label}>
                {idx > 0 && !localCollapsed && <div className="sidebar-divider" />}
                <div className="sidebar-section-label">{section.label}</div>
                {visibleItems.map(renderNavItem)}
              </div>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-footer-quota">
            <div className="quota-row">
              <span>Scan Quota (24h)</span>
              <span>{quotaUsed}/{quotaLimit}</span>
            </div>
            <div className="quota-bar-track">
              <div className="quota-bar-fill" style={{ width: `${quotaPct}%`, background: quotaPct >= 80 ? "#ef4444" : "var(--accent)" }} />
            </div>
            <div className="quota-row" style={{ marginTop: 6 }}>
              <span>Concurrent</span>
              <span>{concurrentUsed}/{concurrentLimit}</span>
            </div>
            <div className="quota-bar-track">
              <div className="quota-bar-fill" style={{ width: `${concPct}%`, background: "var(--accent)" }} />
            </div>
          </div>

          <div className="sidebar-footer-bottom">
            <div className="sidebar-footer-avatar"><IcoUser /></div>
            <div className="sidebar-footer-userinfo">
              <span className="sidebar-footer-username" title={user?.username || "User"}>{user?.username || "User"}</span>
              <span className="sidebar-footer-role" title={user?.role?.name || ""}>{user?.role?.name || "Member"}</span>
            </div>
            <button className="sidebar-settings-btn" onClick={() => { closeAll(); setShowSettings(s => !s); }} title="Settings">
              <IcoSettings />
            </button>
          </div>
        </div>
      </aside>

      <div className="main-area">
        <header className="top-header">
          <div style={{ display: "flex", alignItems: "center", gap: "16px", flex: 1 }}>
            <button className="sidebar-hamburger" onClick={() => setMobileOpen(true)}>
              <IcoMenu />
            </button>
            
            <div style={{ position: "relative" }}>
              <div 
                className="org-dropdown" 
                onClick={() => { closeAll(); setShowOrgDropdown(s => !s); }}
                style={{ display: "flex", alignItems: "center", gap: 6, background: "rgba(255,255,255,0.03)", padding: "6px 12px", borderRadius: 6, cursor: "pointer", border: "1px solid var(--border)", fontSize: "0.78rem", fontWeight: 600, color: "var(--text)", transition: "background 0.2s" }}
              >
                <span>{selectedOrg}</span>
                <span style={{ fontSize: "0.6rem", background: "var(--accent)", color: "#fff", padding: "2px 4px", borderRadius: 4 }}>ENTERPRISE</span>
                <span style={{ marginLeft: 4, color: "var(--text-muted)", fontSize: "0.6rem" }}>▼</span>
              </div>
              {showOrgDropdown && (
                <div style={{ position: "absolute", top: "100%", left: 0, marginTop: 8, width: 220, background: "var(--bg-app)", border: "1px solid var(--border)", borderRadius: 8, boxShadow: "0 10px 25px rgba(0,0,0,0.5)", zIndex: 9999, overflow: "hidden" }}>
                  <div style={{ padding: "8px 12px", fontSize: "0.65rem", fontWeight: 700, color: "var(--text-muted)", letterSpacing: "0.05em", textTransform: "uppercase", borderBottom: "1px solid var(--border)" }}>Switch Organization</div>
                  {["CDAC RTSG Bangalore", "Global Cyber Command", "Demo Organization"].map(org => (
                    <button 
                      key={org}
                      onClick={() => { setSelectedOrg(org); setShowOrgDropdown(false); }}
                      style={{ width: "100%", padding: "10px 12px", textAlign: "left", background: "transparent", border: "none", cursor: "pointer", fontSize: "0.82rem", color: org === selectedOrg ? "var(--accent)" : "var(--text)", display: "flex", alignItems: "center", gap: 8 }}
                    >
                      {org === selectedOrg ? <span style={{ width: 14 }}>✓</span> : <span style={{ width: 14 }} />}
                      {org}
                    </button>
                  ))}
                </div>
              )}
            </div>
            
            <div className="global-search" style={{ position: "relative", width: "300px" }}>
              <div style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
              </div>
              <input 
                type="text" 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search assets, CVEs, scans..." 
                style={{ width: "100%", background: "var(--bg-app)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 12px 8px 32px", fontSize: "0.82rem", color: "var(--text)", outline: "none", transition: "border-color 0.2s" }} 
              />
              <div style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", fontSize: "0.7rem", background: "var(--border)", padding: "2px 4px", borderRadius: 4 }}>
                ⌘K
              </div>
            </div>
          </div>

          <div className="header-actions">
            {saveStatus === "saving" && <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>Saving...</span>}
            {saveStatus === "saved" && <span style={{ fontSize: "0.78rem", color: "var(--ok)", fontWeight: 600 }}>Saved</span>}
            {saveStatus === "error" && <span style={{ fontSize: "0.78rem", color: "var(--danger)", fontWeight: 600 }}>Save failed</span>}

            {canStartScans && (
              <button className="btn-new-scan" onClick={onNewScan || (() => navigate("/scan"))}>
                <IcoPlus />
                <span className="hide-on-mobile">New Scan</span>
              </button>
            )}

            <button className={`btn-icon btn-icon--round`} title="Info">
              <IcoInfo />
            </button>

            <button className={`btn-icon btn-icon--round ${showHelp ? "btn-icon--active" : ""}`} title="Help" onClick={() => { closeAll(); setShowHelp((show) => !show); }}>
              <IcoHelp />
            </button>

            <div style={{ position: "relative" }}>
              <NotificationBell unreadCount={unreadCount} onClick={() => { closeAll(); setShowNotifs((show) => !show); }} />
              {showNotifs && (
                <div className="np-panel-wrap">
                  <NotificationsPanel onClose={() => setShowNotifs(false)} onUnreadChange={setUnreadCount} liveEvent={notificationEvent} />
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
                <span className="profile-name hide-on-mobile">{user?.username || "Profile"}</span>
                <span className="profile-chevron">▼</span>
              </button>
              {profileOpen && (
                <ProfileDropdown user={user} onClose={() => setProfileOpen(false)} onLogout={() => { setProfileOpen(false); logout(); }} onOpenProfile={() => setShowProfile(true)} />
              )}
            </div>
          </div>
        </header>

        <main className="page-main">{children}</main>
      </div>

      {showSettings && <SettingsDrawer onClose={() => setShowSettings(false)} onPreferencesUpdated={updateLocalPreferences} />}
      {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
    </div>
  );
}
