import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@shell/auth/AuthContext";
import CcureHomeLink from "@shell/navigation/CcureHomeLink";
import { canPermission, canSwitchOrganisation } from "@shell/auth/permissions";
import { canSeeNavItem } from "@shell/auth/navVisibility";
import {
  CcureAppShell,
  CcureButton,
  CcureInput,
  CcureProgress,
  CcureIconButton,
} from "../../../../design-system";
import "../../styles/app-shell.css";
// The platform's shared header pieces (Phase 12 navigation refactor). Imported
// after app-shell.css so their stylesheets keep their place after it.
import AccountMenu from "@shell/navigation/AccountMenu";
import OrgSwitcher from "@shell/navigation/OrgSwitcher";
import UserCard from "@shell/navigation/UserCard";
import useOrganizationSwitcher from "@shell/navigation/useOrganizationSwitcher";
import useNotificationFeed from "@shell/notifications/useNotificationFeed";
import { usePreferences } from "@shell/preferences/PreferencesContext";
import api from "@shell/api/axiosInstance";
import ProfileModal from "@shell/account/ProfileModal";
import SettingsDrawer from "@shell/account/SettingsDrawer";
import NotificationsPanel, {
  NotificationBell,
} from "@shell/notifications/NotificationsPanel";
import HelpPanel from "./HelpPanel";
import renderAuditSettings from "./auditSettings";
import { AMT_PERMISSION } from "../../config/permissions";

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
const IcoSettings = () => (
  <Icon d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.31.22.65.22 1h.38a2 2 0 1 1 0 4h-.38c0 .35-.08.69-.22 1z" />
);
const IcoHelp = () => (
  <Icon d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.09 9a3 3 0 1 1 5.83 1c0 2-3 3-3 3M12 17h.01" />
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
        permission: "audit.dashboard.read",
      },
      {
        id: "executive-report",
        label: "Executive Report",
        Icon: IcoFileText,
        route: "/reports?tab=executive",
        permission: "audit.report.read",
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
        permission: "audit.scan.run",
      },
      {
        id: "scan-monitor",
        label: "Active Scans",
        Icon: IcoMonitor,
        route: "/monitor",
        permission: "audit.scan.read",
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
        permission: "audit.scan_schedule.read",
      },
      {
        id: "scan-policies",
        label: "Scan Policies",
        Icon: IcoFile,
        route: "/scan-policies",
        // scan_policies:read, not scans:read. "May this person run a scan" and
        // "may this person decide what every scan assesses" are different
        // authorisations, and the backend keeps them apart.
        permission: "audit.scan_policy.read",
      },
      {
        id: "scan-credentials",
        label: "Scan Credentials",
        Icon: IcoFile,
        route: "/scan-credentials",
        // credentials:read, an existing RBAC resource that had no API until
        // Phase 2 wired one.
        permission: "audit.credential.read",
      },
      {
        id: "configuration-checks",
        label: "Configuration Checks",
        Icon: IcoFile,
        route: "/configuration-checks",
        // scans:read, not a new permission. This is a read-only catalogue of
        // what a scan checks, and it describes scan capability rather than
        // granting any.
        permission: "audit.scan.read",
      },
      {
        id: "scan-history",
        label: "Scan History",
        Icon: IcoFile,
        route: "/history",
        permission: "audit.scan.read",
      },
      {
        id: "archived-scans",
        label: "Archived Scans",
        Icon: IcoArchive,
        route: "/archived",
        requiredAny: ["audit.scan.lifecycle", "audit.scan.lifecycle"],
      },
      {
        id: "recycle-bin",
        label: "Recycle Bin",
        Icon: IcoTrash,
        route: "/recycle-bin",
        requiredAny: ["audit.scan.lifecycle", "audit.scan.purge"],
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
        permission: "audit.finding.read",
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
        permission: "audit.finding.read",
      },
      {
        id: "asset-registry",
        label: "Asset Registry",
        Icon: IcoMonitor,
        route: "/assets",
        permission: "audit.asset.read",
      },
      {
        id: "services-ports",
        label: "Services & Ports",
        Icon: IcoServer,
        route: "/assets?tab=services",
        permission: "audit.asset.read",
      },
      {
        id: "tls-certs",
        label: "TLS / Certificates",
        Icon: IcoLock,
        route: "/assets?tab=tls",
        permission: "audit.asset.read",
      },
      {
        id: "network-topology",
        label: "Network Topology",
        Icon: IcoTopology,
        route: "/topology",
        permission: "audit.scan.read",
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
        permission: "audit.report.read",
      },
      {
        id: "compliance",
        label: "Compliance",
        Icon: IcoCheckCircle,
        route: "/compliance",
        permission: "audit.report.read",
      },
      {
        id: "risk-trends",
        label: "Risk Trends",
        Icon: IcoTrendUp,
        route: "/reports?tab=trends",
        permission: "audit.report.read",
      },
    ],
  },
  {
    // Audit's own configuration only. User, organisation, role, email-domain
    // and audit-log administration are the platform's: they live in the
    // platform shell's sidebar, never in a product's.
    label: "Audit Settings",
    items: [
      {
        id: "amt-integration",
        label: "AMT Integration",
        Icon: IcoSettings,
        route: "/admin/amt",
        permission: AMT_PERMISSION,
      },
    ],
  },
];

const hasPermission = (user, permission) => canPermission(user, permission);

// ── Header pieces ────────────────────────────────────────────────────────────
const IcoSearch = () => (
  <Icon d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" size={14} />
);

// ── Main Layout Component ────────────────────────────────────────────────────
export default function AppLayout({ children, saveStatus = "", onNewScan }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { pathname, search } = location;
  const { user, logout } = useAuth();
  const isSuperadmin = canSwitchOrganisation(user);
  const canStartScans = hasPermission(user, "audit.scan.run");
  const [showProfile, setShowProfile] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Openers, so a panel closed by keyboard hands focus back where it came from.
  const helpBtnRef = useRef(null);
  const bellRef = useRef(null);
  const settingsBtnRef = useRef(null);
  const notifsRef = useRef(null);
  const helpRef = useRef(null);

  // Tenancy is the platform's: the shell lists organisations and switches.
  const { orgs, loadingOrgs, selectedOrg, switchOrg } =
    useOrganizationSwitcher(user);

  const handleOrgSwitch = (org) => {
    setShowOrgDropdown(false);
    switchOrg(org);
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

  // The platform's notification feed: unread count and live stream.
  const { unreadCount, setUnreadCount, notificationEvent } =
    useNotificationFeed();

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
      <UserCard user={user}>
        <CcureIconButton
          variant="ghost"
          size="sm"
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
        </CcureIconButton>
      </UserCard>
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
      <CcureIconButton
        variant="ghost"
        size="sm"
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
      </CcureIconButton>
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
      <AccountMenu
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
        className={`sh-shell${isSuperadmin ? " sh-shell--organization" : ""}`}
      >
        {children}
      </CcureAppShell>
      {showSettings && (
        <SettingsDrawer
          id="sh-settings"
          onClose={closeSettings}
          onPreferencesUpdated={updateLocalPreferences}
          productSettings={renderAuditSettings}
        />
      )}
      {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
    </>
  );
}
