import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@shell/auth/AuthContext";
import CcureHomeLink from "@shell/navigation/CcureHomeLink";
import { canAny, canPermission, isSuperAdmin } from "@shell/auth/permissions";
import {
  CcureAppShell,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureProgress,
} from "../../design-system";
import "../../styles/app-shell.css";
import {
  getUnreadCount,
  streamNotificationEvents,
} from "../../api/notifications";
import { usePreferences } from "../../context/PreferencesContext";
import api from "@shell/api/axiosInstance";
import { listOrganizations } from "../../api/admin";
import ProfileModal from "./ProfileModal";
import SettingsDrawer from "./SettingsDrawer";
import NotificationsPanel, { NotificationBell } from "./NotificationsPanel";
import HelpPanel from "./HelpPanel";

// ── Icons ────────────────────────────────────────────────────────────────────
// Every icon is decorative — the control's text or aria-label carries the
// meaning — so they are hidden from assistive technology.
const Icon = ({ d, size = 16, viewBox = "0 0 24 24", fill = "none" }) => (
  <svg
    width={size}
    height={size}
    viewBox={viewBox}
    fill={fill}
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

const IcoDashboard = () => (
  <Icon d="M3 13h8V3H3v10zM13 21h8V11h-8v10zM13 3v6h8V3h-8zM3 21h8v-6H3v6z" />
);
const IcoFileText = () => (
  <Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8" />
);
const IcoGrid = () => (
  <Icon d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />
);
const IcoFile = () => (
  <Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6" />
);
const IcoArchive = () => <Icon d="M21 8v13H3V8M1 3h22v5H1zM10 12h4" />;
const IcoTrash = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoAlert = () => (
  <Icon d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" />
);
const IcoMonitor = () => <Icon d="M2 3h20v14H2zM8 21h8M12 17v4" />;
const IcoServer = () => (
  <Icon d="M2 5h20v4H2zm0 10h20v4H2zm6-10v4m8-4v4m-8 10v4m8-4v4" />
);
const IcoLock = () => (
  <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 11V7" />
);
const IcoChart = () => <Icon d="M18 20V10M12 20V4M6 20v-6M2 20h20" />;
const IcoCheckCircle = () => (
  <Icon d="M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4L12 14.01l-3-3" />
);
const IcoTrendUp = () => <Icon d="M23 6l-9.5 9.5-5-5L1 18M17 6h6v6" />;
const IcoUsers = () => (
  <Icon d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 7a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
);
const IcoOrg = () => (
  <Icon d="M3 21h18M3 7v1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7m0 1a3 3 0 0 0 6 0V7M4 21V4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v17" />
);
const IcoShieldKey = () => (
  <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM8 11h8M8 15h6" />
);
const IcoMail = () => (
  <Icon d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM22 6l-10 7L2 6" />
);
const IcoList = () => (
  <Icon d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
);
const IcoSettings = () => (
  <Icon d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.31.22.65.22 1h.38a2 2 0 1 1 0 4h-.38c0 .35-.08.69-.22 1z" />
);
const IcoHelp = () => (
  <Icon d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.09 9a3 3 0 1 1 5.83 1c0 2-3 3-3 3M12 17h.01" />
);
const IcoUser = () => (
  <Icon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />
);
const IcoPlus = () => (
  <svg
    width={14}
    height={14}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2.5"
    strokeLinecap="round"
  >
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);
const IcoTopology = () => (
  <Icon d="M12 2a3 3 0 0 0-3 3c0 1.1.6 2 1.5 2.6L9 10l-4 2-2.5-1.5A3 3 0 0 0 0 13a3 3 0 0 0 5 2.2l4-2L12 15l3-1.8 4 2A3 3 0 0 0 24 13a3 3 0 0 0-2.5-2.5L19 12l-4-2-1.5-2.4A3 3 0 0 0 15 5a3 3 0 0 0-3-3z" />
);

// ── Sidebar Definition ───────────────────────────────────────────────────────
const SIDEBAR_SECTIONS = [
  {
    label: "Overview",
    items: [
      {
        id: "security-dashboard",
        label: "Security Dashboard",
        Icon: IcoDashboard,
        route: "/audit-dashboard",
        permission: { resource: "dashboard", action: "read" },
      },
      {
        id: "executive-report",
        label: "Executive Report",
        Icon: IcoFileText,
        route: "/reports?tab=executive",
        permission: { resource: "reports", action: "read" },
      },
    ],
  },
  {
    label: "Scanning",
    items: [
      {
        id: "scan-templates",
        label: "Scan Templates",
        Icon: IcoGrid,
        route: "/scan",
        permission: { resource: "scans", action: "execute" },
      },
      {
        id: "scan-monitor",
        label: "Active Scans",
        Icon: IcoMonitor,
        route: "/monitor",
        permission: { resource: "scans", action: "read" },
        badgeKey: "runningScans",
        badgeColor: "info",
      },
      {
        id: "scan-schedules",
        label: "Scan Schedules",
        Icon: IcoFile,
        route: "/scan-schedules",
        // scan_schedules:read, not scans:read. Seeing what is scheduled to
        // point at a network unattended is its own question, and `viewer`
        // holds this one deliberately.
        permission: { resource: "scan_schedules", action: "read" },
      },
      {
        id: "scan-policies",
        label: "Scan Policies",
        Icon: IcoFile,
        route: "/scan-policies",
        // scan_policies:read, not scans:read. "May this person run a scan" and
        // "may this person decide what every scan assesses" are different
        // authorisations, and the backend keeps them apart.
        permission: { resource: "scan_policies", action: "read" },
      },
      {
        id: "scan-credentials",
        label: "Scan Credentials",
        Icon: IcoFile,
        route: "/scan-credentials",
        // credentials:read, an existing RBAC resource that had no API until
        // Phase 2 wired one.
        permission: { resource: "credentials", action: "read" },
      },
      {
        id: "configuration-checks",
        label: "Configuration Checks",
        Icon: IcoFile,
        route: "/configuration-checks",
        // scans:read, not a new permission. This is a read-only catalogue of
        // what a scan checks, and it describes scan capability rather than
        // granting any.
        permission: { resource: "scans", action: "read" },
      },
      {
        id: "scan-history",
        label: "Scan History",
        Icon: IcoFile,
        route: "/history",
        permission: { resource: "scans", action: "read" },
      },
      {
        id: "archived-scans",
        label: "Archived Scans",
        Icon: IcoArchive,
        route: "/archived",
        requiredAny: [
          { resource: "scans", action: "restore" },
          { resource: "scans", action: "recycle" },
        ],
      },
      {
        id: "recycle-bin",
        label: "Recycle Bin",
        Icon: IcoTrash,
        route: "/recycle-bin",
        requiredAny: [
          { resource: "scans", action: "restore" },
          { resource: "scans", action: "purge" },
        ],
      },
    ],
  },
  {
    label: "Intelligence",
    items: [
      {
        id: "vulnerabilities",
        label: "Vulnerabilities",
        Icon: IcoAlert,
        route: "/vulnerabilities",
        permission: { resource: "findings", action: "read" },
        badgeKey: "criticalCount",
        badgeColor: "danger",
      },
      {
        id: "remediation",
        label: "Remediation",
        Icon: IcoAlert,
        route: "/remediation",
        // findings:read, the same grant the vulnerability browser takes.
        // Assigning and moving work take findings:update, accepting a risk
        // takes findings:accept_risk, and setting the deadlines takes
        // settings:update — all three are enforced inside the page, because
        // an operator who may read the queue should still be able to see it.
        permission: { resource: "findings", action: "read" },
      },
      {
        id: "asset-registry",
        label: "Asset Registry",
        Icon: IcoMonitor,
        route: "/assets",
        permission: { resource: "assets", action: "read" },
      },
      {
        id: "services-ports",
        label: "Services & Ports",
        Icon: IcoServer,
        route: "/assets?tab=services",
        permission: { resource: "assets", action: "read" },
      },
      {
        id: "tls-certs",
        label: "TLS / Certificates",
        Icon: IcoLock,
        route: "/assets?tab=tls",
        permission: { resource: "assets", action: "read" },
      },
      {
        id: "network-topology",
        label: "Network Topology",
        Icon: IcoTopology,
        route: "/topology",
        permission: { resource: "scans", action: "read" },
      },
    ],
  },
  {
    label: "Reports",
    items: [
      {
        id: "security-reports",
        label: "Security Reports",
        Icon: IcoChart,
        route: "/reports",
        permission: { resource: "reports", action: "read" },
      },
      {
        id: "compliance",
        label: "Compliance",
        Icon: IcoCheckCircle,
        route: "/compliance",
        permission: { resource: "reports", action: "read" },
      },
      {
        id: "risk-trends",
        label: "Risk Trends",
        Icon: IcoTrendUp,
        route: "/reports?tab=trends",
        permission: { resource: "reports", action: "read" },
      },
    ],
  },
  {
    label: "Administration",
    items: [
      {
        id: "user-management",
        label: "User Management",
        Icon: IcoUsers,
        route: "/admin/users",
        permission: { resource: "users", action: "read" },
      },
      {
        id: "deleted-users",
        label: "Deleted Users",
        Icon: IcoTrash,
        route: "/admin/users/deleted",
        permission: { resource: "users", action: "read" },
      },
      {
        id: "email-domains",
        label: "Email Domain Rules",
        Icon: IcoMail,
        route: "/admin/email-domains",
        // No `permission`: these rules are platform-wide, so the gate is the
        // superadmin role rather than a permission an org_admin also holds.
        superadminOnly: true,
      },
      {
        id: "organizations",
        label: "Organizations",
        Icon: IcoOrg,
        route: "/admin/organizations",
        permission: { resource: "organizations", action: "read" },
      },
      {
        id: "roles-perms",
        label: "Roles & Permissions",
        Icon: IcoShieldKey,
        route: "/admin/roles",
        permission: { resource: "roles", action: "read" },
      },
      {
        id: "amt-integration",
        label: "AMT Integration",
        Icon: IcoSettings,
        route: "/admin/amt",
        permission: { resource: "settings", action: "update" },
      },
      {
        id: "audit-logs",
        label: "Audit Logs",
        Icon: IcoList,
        route: "/admin/audit-logs",
        permission: { resource: "audit", action: "read" },
      },
    ],
  },
];

const hasPermission = (user, permission) => canPermission(user, permission);
const canSeeNavItem = (user, item) => {
  // Role gate, not a permission gate. Superadmin holds every permission, so
  // permission checks alone cannot express "superadmin only" — any permission
  // an org_admin also has would let them through. Used for platform-wide
  // settings whose blast radius crosses tenants.
  if (item.superadminOnly && !isSuperAdmin(user)) return false;
  if (item.permission && !hasPermission(user, item.permission)) return false;
  if (item.requiredAny && !canAny(user, item.requiredAny)) return false;
  return true;
};

// ── Header pieces ────────────────────────────────────────────────────────────
/* Closes on a pointer-down outside `ref` (the legacy behaviour) AND on Escape,
   restoring focus to `restoreTo` when Escape or an outside click closed it. */
function useDismiss(ref, open, onClose, restoreTo) {
  useEffect(() => {
    if (!open) return undefined;
    const onMouseDown = (event) => {
      if (ref.current && !ref.current.contains(event.target)) {
        if (restoreTo?.current && restoreTo.current.contains(event.target))
          return;
        onClose();
      }
    };
    const onKey = (event) => {
      if (event.key === "Escape") {
        onClose();
        restoreTo?.current?.focus?.();
      }
    };
    document.addEventListener("mousedown", onMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [ref, open, onClose, restoreTo]);
}

function ProfileMenu({ user, onLogout, onOpenProfile }) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef(null);
  const menuRef = useRef(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(menuRef, open, close, btnRef);

  return (
    <div className="sh-menu-anchor">
      <button
        type="button"
        ref={btnRef}
        className="sh-user-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="sh-profile-menu"
        aria-label={`Account menu for ${user?.username || "Profile"}`}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="sh-avatar" aria-hidden="true">
          <IcoUser />
        </span>
        <span className="sh-user-name hide-on-mobile">
          {user?.username || "Profile"}
        </span>
        <span className="sh-chevron" aria-hidden="true">
          ▼
        </span>
      </button>
      {open && (
        <div
          className="sh-menu sh-menu--profile"
          ref={menuRef}
          id="sh-profile-menu"
          role="menu"
          aria-label="Account"
        >
          <div className="sh-menu-head">
            <span className="sh-avatar sh-avatar--lg" aria-hidden="true">
              <IcoUser />
            </span>
            <span className="sh-menu-head-text">
              <span className="sh-menu-name">{user?.username || "User"}</span>
              <span className="sh-menu-email">{user?.email || ""}</span>
            </span>
          </div>
          <div className="sh-menu-body">
            <button
              type="button"
              role="menuitem"
              className="cc-btn cc-btn--primary cc-btn--sm cc-btn--block"
              onClick={() => {
                close();
                onOpenProfile();
              }}
            >
              My Account
            </button>
            <button
              type="button"
              role="menuitem"
              className="cc-btn cc-btn--ghost cc-btn--sm cc-btn--block sh-signout"
              onClick={onLogout}
            >
              Sign Out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* Superadmin only. A real menu button now: the legacy control was a
   `<div onClick>` with no name, no state and no keyboard path. Selection
   semantics are unchanged — write activeOrgId, then reload the document. */
function OrgSwitcher({
  selectedOrg,
  orgs,
  loading,
  open,
  onToggle,
  onClose,
  onSwitch,
}) {
  const btnRef = useRef(null);
  const menuRef = useRef(null);
  useDismiss(menuRef, open, onClose, btnRef);
  return (
    <div className="sh-menu-anchor">
      <button
        type="button"
        ref={btnRef}
        className="sh-org-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="sh-org-menu"
        aria-label={`Switch organization. Current: ${selectedOrg}`}
        onClick={onToggle}
      >
        <span className="sh-org-name">{selectedOrg}</span>
        <CcureBadge variant="primary" size="sm">
          ENTERPRISE
        </CcureBadge>
        <span className="sh-chevron" aria-hidden="true">
          ▼
        </span>
      </button>
      {open && (
        <div
          className="sh-menu sh-menu--org"
          ref={menuRef}
          id="sh-org-menu"
          role="menu"
          aria-label="Switch Organization"
        >
          <div className="sh-menu-title">Switch Organization</div>
          {loading ? (
            <div className="sh-menu-note">Loading...</div>
          ) : orgs.length === 0 ? (
            <div className="sh-menu-note">No organizations found</div>
          ) : (
            orgs.map((org) => (
              <button
                key={org.id}
                type="button"
                role="menuitem"
                className={`sh-menu-item${org.name === selectedOrg ? " sh-menu-item--current" : ""}`}
                aria-current={org.name === selectedOrg ? "true" : undefined}
                onClick={() => onSwitch(org)}
              >
                <span className="sh-menu-check" aria-hidden="true">
                  {org.name === selectedOrg ? "✓" : ""}
                </span>
                {org.name}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

const IcoSearch = () => (
  <Icon d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" size={14} />
);

// ── Main Layout Component ────────────────────────────────────────────────────
export default function AppLayout({ children, saveStatus = "", onNewScan }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { pathname, search } = location;
  const { user, logout } = useAuth();
  const isSuperadmin = isSuperAdmin(user);
  const canStartScans = hasPermission(user, {
    resource: "scans",
    action: "execute",
  });
  const [showProfile, setShowProfile] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState("CDAC RTSG Bangalore");
  const [searchQuery, setSearchQuery] = useState("");
  const [unreadCount, setUnreadCount] = useState(0);
  const [notificationEvent, setNotificationEvent] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [loadingOrgs, setLoadingOrgs] = useState(false);

  // Openers, so a panel closed by keyboard hands focus back where it came from.
  const helpBtnRef = useRef(null);
  const bellRef = useRef(null);
  const settingsBtnRef = useRef(null);
  const notifsRef = useRef(null);
  const helpRef = useRef(null);

  useEffect(() => {
    if (user && isSuperAdmin(user)) {
      setLoadingOrgs(true);
      listOrganizations()
        .then((data) => {
          if (data && data.organizations) {
            setOrgs(data.organizations);
            const activeOrgId = localStorage.getItem("activeOrgId");
            if (activeOrgId) {
              const activeOrg = data.organizations.find(
                (o) => o.id === activeOrgId,
              );
              if (activeOrg) {
                setSelectedOrg(activeOrg.name);
              }
            } else if (user.org_id) {
              const userOrg = data.organizations.find(
                (o) => o.id === user.org_id,
              );
              if (userOrg) {
                setSelectedOrg(userOrg.name);
                localStorage.setItem("activeOrgId", user.org_id);
              }
            }
          }
        })
        .catch(() => {
          /* silent */
        })
        .finally(() => setLoadingOrgs(false));
    }
  }, [user]);

  const handleOrgSwitch = (org) => {
    localStorage.setItem("activeOrgId", org.id);
    setSelectedOrg(org.name);
    setShowOrgDropdown(false);
    window.location.reload();
  };

  const handleSearchKeyDown = (e) => {
    if (e.key === "Enter") {
      const q = searchQuery.trim();
      if (!q) return;
      if (/^cve-\d{4}-\d{4,}/i.test(q)) {
        navigate(`/vulnerabilities?search=${encodeURIComponent(q)}`);
      } else {
        navigate(`/assets?search=${encodeURIComponent(q)}`);
      }
    }
  };

  const searchInputRef = useRef(null);
  useEffect(() => {
    const handleGlobalKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, []);

  const { preferences, updateLocalPreferences } = usePreferences();
  const [localCollapsed, setLocalCollapsed] = useState(
    () => localStorage.getItem("sidebarCollapsed") === "true",
  );

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
  // null means "no limit". Defaulting these to invented numbers made an
  // enterprise plan with unlimited scans read as "30/50", and pinned the
  // concurrency display at 5 when the real ceiling was 20.
  const [quotaLimit, setQuotaLimit] = useState(null);
  const [concurrentUsed, setConcurrentUsed] = useState(0);
  const [concurrentLimit, setConcurrentLimit] = useState(null);

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
          setQuotaLimit(d?.scans?.quota_limit_24h ?? null);
          setConcurrentUsed(d?.scans?.running ?? 0);
        }
        // The summary carries usage but not the plan's ceilings, so the real
        // limits come from the quota endpoint rather than a hardcoded guess.
        try {
          const q = await api.get("/scan/quota");
          if (q.status === 200 && q.data) {
            setQuotaLimit(q.data.scans_limit_24h ?? null);
            setConcurrentLimit(q.data.concurrent_limit ?? null);
            if (typeof q.data.scans_used_24h === "number")
              setQuotaUsed(q.data.scans_used_24h);
            if (typeof q.data.concurrent_running === "number")
              setConcurrentUsed(q.data.concurrent_running);
          }
        } catch {
          /* quota is advisory — never block the sidebar on it */
        }
      } catch {
        /* silent */
      }
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
      } catch {
        // Deliberately swallowed: this polls on a timer, so a transient
        // failure corrects itself on the next tick. Surfacing it would put a
        // toast on screen every time the network blinked.
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
              if (event === "connected" && data.summary)
                setUnreadCount(data.summary.total_unread || 0);
              if (event === "notification.created" && data.notification) {
                setNotificationEvent({
                  type: "created",
                  notification: data.notification,
                  receivedAt: Date.now(),
                });
                if (!data.notification.is_read)
                  setUnreadCount((count) => count + 1);
              }
              if (event === "notifications.summary" && data.summary)
                setUnreadCount(data.summary.total_unread || 0);
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
    return () => {
      stopped = true;
      controller.abort();
    };
  }, []);

  const closeAll = useCallback(() => {
    setShowNotifs(false);
    setShowHelp(false);
    setShowSettings(false);
    setShowOrgDropdown(false);
  }, []);

  // Panel closers that hand focus back to the control that opened them.
  const closeNotifs = useCallback(() => {
    setShowNotifs(false);
    bellRef.current?.focus?.();
  }, []);
  const closeHelp = useCallback(() => {
    setShowHelp(false);
    helpBtnRef.current?.focus?.();
  }, []);
  const closeSettings = useCallback(() => {
    setShowSettings(false);
    settingsBtnRef.current?.focus?.();
  }, []);
  const closeOrg = useCallback(() => setShowOrgDropdown(false), []);

  // Determine active nav item
  const activeId = (() => {
    if (pathname === "/audit-dashboard" || pathname === "/dashboard")
      return "security-dashboard";
    if (pathname.startsWith("/reports") && search.includes("tab=executive"))
      return "executive-report";
    if (pathname.startsWith("/reports") && search.includes("tab=compliance"))
      return "compliance";
    if (pathname.startsWith("/reports") && search.includes("tab=trends"))
      return "risk-trends";
    if (pathname.startsWith("/reports")) return "security-reports";
    if (pathname.startsWith("/monitor")) return "active-scans";
    if (pathname.startsWith("/history")) return "scan-history";
    if (pathname.startsWith("/archived")) return "archived-scans";
    if (pathname.startsWith("/recycle-bin")) return "recycle-bin";
    if (pathname.startsWith("/assets") && search.includes("tab=services"))
      return "services-ports";
    if (pathname.startsWith("/assets") && search.includes("tab=tls"))
      return "tls-certs";
    if (pathname.startsWith("/assets")) return "asset-registry";
    if (pathname.startsWith("/vulnerabilities")) return "vulnerabilities";
    if (pathname.startsWith("/scan")) return "scan-templates";
    if (pathname.startsWith("/admin/email-domains")) return "email-domains";
    if (pathname.startsWith("/admin/users/deleted")) return "deleted-users";
    if (pathname.startsWith("/admin/users")) return "user-management";
    if (pathname.startsWith("/admin/roles")) return "roles-perms";
    if (pathname.startsWith("/admin/organizations")) return "organizations";
    if (pathname.startsWith("/admin/amt")) return "amt-integration";
    if (pathname.startsWith("/admin/audit-logs")) return "audit-logs";
    return "";
  })();

  /* The sections the shell renders: SIDEBAR_SECTIONS filtered by
     canSeeNavItem exactly as before, with the badge values and the active
     item resolved here so the shell stays free of any opinion about them. */
  const BADGE_VARIANT = {
    info: "info",
    danger: "danger",
    warning: "warning",
    success: "success",
  };
  const BADGE_LABEL = { runningScans: "running", criticalCount: "critical" };
  const sections = SIDEBAR_SECTIONS.map((section) => ({
    label: section.label,
    items: section.items
      .filter((item) => canSeeNavItem(user, item))
      .map((item) => {
        const {
          id,
          label,
          Icon: ItemIcon,
          route,
          disabled,
          badgeKey,
          badgeColor,
        } = item;
        let badgeVal = 0;
        if (badgeKey === "runningScans") badgeVal = runningScans;
        if (badgeKey === "criticalCount") badgeVal = criticalCount;
        return {
          id,
          label,
          route,
          disabled,
          icon: <ItemIcon />,
          active: activeId === id,
          badge: badgeVal,
          badgeVariant: BADGE_VARIANT[badgeColor] || "neutral",
          badgeLabel: BADGE_LABEL[badgeKey],
        };
      }),
  })).filter((section) => section.items.length > 0);

  // A null limit is an uncapped plan, not a zero-length bar: show the count
  // and leave the meter empty rather than implying a ceiling that isn't there.
  const fmtLimit = (limit) => (limit > 0 ? limit : "∞");
  const quotaPct =
    quotaLimit > 0 ? Math.min((quotaUsed / quotaLimit) * 100, 100) : 0;

  const sidebarFooter = (
    <>
      <div className="sh-quota">
        <div className="sh-quota-row">
          <span id="sh-quota-label">Scan Quota (24h)</span>
          <span>
            {quotaUsed}/{fmtLimit(quotaLimit)}
          </span>
        </div>
        <CcureProgress
          value={quotaLimit > 0 ? quotaUsed : null}
          max={quotaLimit > 0 ? quotaLimit : 100}
          animated={false}
          showValue={false}
          variant={quotaPct >= 80 ? "danger" : "primary"}
          className="sh-quota-bar"
          label="Scan quota used in the last 24 hours"
        />
        <div className="sh-quota-row">
          <span>Concurrent</span>
          <span>
            {concurrentUsed}/{fmtLimit(concurrentLimit)}
          </span>
        </div>
        <CcureProgress
          value={concurrentLimit > 0 ? concurrentUsed : null}
          max={concurrentLimit > 0 ? concurrentLimit : 100}
          animated={false}
          showValue={false}
          className="sh-quota-bar"
          label="Concurrent scans running"
        />
      </div>
      <div className="sh-user">
        <span className="sh-avatar" aria-hidden="true">
          <IcoUser />
        </span>
        <span className="sh-user-info">
          <span className="sh-user-info-name" title={user?.username || "User"}>
            {user?.username || "User"}
          </span>
          <span className="sh-user-info-role" title={user?.role?.name || ""}>
            {user?.role?.name || "Member"}
          </span>
        </span>
        <button
          type="button"
          ref={settingsBtnRef}
          className="cc-btn cc-btn--ghost cc-btn--sm sh-iconbtn"
          aria-label="Settings"
          aria-expanded={showSettings}
          aria-controls="sh-settings"
          onClick={() => {
            closeAll();
            setShowSettings((s) => !s);
          }}
        >
          <IcoSettings />
        </button>
      </div>
    </>
  );

  const headerLeft = isSuperadmin ? (
    <>
      <OrgSwitcher
        selectedOrg={selectedOrg}
        orgs={orgs}
        loading={loadingOrgs}
        open={showOrgDropdown}
        onToggle={() => {
          const next = !showOrgDropdown;
          closeAll();
          setShowOrgDropdown(next);
        }}
        onClose={closeOrg}
        onSwitch={handleOrgSwitch}
      />
      <div className="sh-search">
        <CcureInput
          ref={searchInputRef}
          id="sh-global-search"
          type="search"
          aria-label="Search assets, CVEs, scans..."
          placeholder="Search assets, CVEs, scans..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={handleSearchKeyDown}
          adornment={
            <kbd className="sh-kbd" aria-hidden="true">
              ⌘K
            </kbd>
          }
        />
        <span className="sh-search-icon" aria-hidden="true">
          <IcoSearch />
        </span>
      </div>
    </>
  ) : null;

  const headerActions = (
    <>
      <span
        role="status"
        className={`sh-savestatus${saveStatus === "saved" ? " sh-savestatus--ok" : ""}${saveStatus === "error" ? " sh-savestatus--bad" : ""}`}
      >
        {saveStatus === "saving" && "Saving..."}
        {saveStatus === "saved" && "Saved"}
        {saveStatus === "error" && "Save failed"}
      </span>
      {/* The way back to the platform's Product Hub (Phase 12, D12-8) — the
          shell's shared link, in Audit's header classes. */}
      <CcureHomeLink className="sh-home" labelClassName="hide-on-mobile" />
      {canStartScans && (
        <CcureButton
          variant="primary"
          size="sm"
          className="sh-newscan"
          aria-label="New Scan"
          onClick={onNewScan || (() => navigate("/scan"))}
        >
          <IcoPlus />
          <span className="hide-on-mobile">New Scan</span>
        </CcureButton>
      )}
      <button
        type="button"
        ref={helpBtnRef}
        id="header-help-btn"
        className={`cc-btn cc-btn--ghost cc-btn--sm sh-iconbtn${showHelp ? " sh-iconbtn--active" : ""}`}
        aria-label="Help"
        aria-expanded={showHelp}
        aria-controls="sh-help"
        onClick={() => {
          const next = !showHelp;
          closeAll();
          setShowHelp(next);
        }}
      >
        <IcoHelp />
      </button>
      <div className="sh-menu-anchor">
        <NotificationBell
          ref={bellRef}
          unreadCount={unreadCount}
          expanded={showNotifs}
          onClick={() => {
            const next = !showNotifs;
            closeAll();
            setShowNotifs(next);
          }}
        />
        {showNotifs && (
          <div className="sh-popover" ref={notifsRef}>
            <NotificationsPanel
              id="sh-notifications"
              onClose={closeNotifs}
              onUnreadChange={setUnreadCount}
              liveEvent={notificationEvent}
            />
          </div>
        )}
      </div>
      {showHelp && (
        <div className="sh-popover sh-popover--help" ref={helpRef}>
          <HelpPanel id="sh-help" onClose={closeHelp} />
        </div>
      )}
      <ProfileMenu
        user={user}
        onLogout={() => logout()}
        onOpenProfile={() => setShowProfile(true)}
      />
    </>
  );

  return (
    <>
      <CcureAppShell
        brand={{ name: "CCure Audit", sub: "PRO", mark: "🛡" }}
        sections={sections}
        currentPath={pathname}
        onNavigate={(route) => navigate(route)}
        headerLeft={headerLeft}
        headerActions={headerActions}
        sidebarFooter={sidebarFooter}
        collapsed={localCollapsed}
        onToggleCollapsed={toggleSidebar}
        navRef={sidebarNavRef}
        onNavScroll={handleSidebarScroll}
        mainClassName="page-main"
        className="sh-shell"
      >
        {children}
      </CcureAppShell>
      {showSettings && (
        <SettingsDrawer
          id="sh-settings"
          onClose={closeSettings}
          onPreferencesUpdated={updateLocalPreferences}
        />
      )}
      {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
    </>
  );
}
