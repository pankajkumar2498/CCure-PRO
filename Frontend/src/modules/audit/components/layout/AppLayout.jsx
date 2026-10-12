import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@shell/auth/AuthContext";
import CcureHomeLink from "@shell/navigation/CcureHomeLink";
import { canSwitchOrganisation } from "@shell/auth/permissions";
import { canSeeNavItem } from "@shell/auth/navVisibility";
import {
  CcureAppShell,
  CcureInput,
  CcureIconButton,
  CcureIcon,
} from "../../../../design-system";
import "../../styles/app-shell.css";
// The platform's shared header pieces (Phase 12 navigation refactor). Imported
// after app-shell.css so their stylesheets keep their place after it.
import AccountMenu from "@shell/navigation/AccountMenu";
import ThemeToggle from "@shell/navigation/ThemeToggle";
import OrgSwitcher from "@shell/navigation/OrgSwitcher";
import UserCard from "@shell/navigation/UserCard";
import useOrganizationSwitcher from "@shell/navigation/useOrganizationSwitcher";
import { usePreferences } from "@shell/preferences/PreferencesContext";
import api from "@shell/api/axiosInstance";
import ProfileModal from "@shell/account/ProfileModal";
import SettingsDrawer from "@shell/account/SettingsDrawer";
import renderAuditSettings from "./auditSettings";
import { AMT_PERMISSION } from "../../config/permissions";

// ── Icons ────────────────────────────────────────────────────────────────────
// The application's shared icon set (design-system CcureIcon). Every icon is
// decorative — the control's text or aria-label carries the meaning.
const nav = (name) => {
  const NavIcon = () => <CcureIcon name={name} size={16} />;
  return NavIcon;
};
const IcoDashboard = nav("dashboard");
const IcoGrid = nav("grid");
const IcoFile = nav("file");
const IcoArchive = nav("archive");
const IcoTrash = nav("trash");
const IcoAlert = nav("alert-triangle");
const IcoMonitor = nav("monitor");
const IcoServer = nav("server");
const IcoLock = nav("lock");
const IcoChart = nav("bar-chart");
const IcoCheckCircle = nav("check-circle");
const IcoTrendUp = nav("trending-up");
const IcoSettings = nav("settings");
const IcoTopology = nav("topology");

// ── Sidebar Definition ───────────────────────────────────────────────────────

const SIDEBAR_SECTIONS = [
  {
    label: "Overview",
    items: [
      {
        id: "security-dashboard",
        label: "Audit Dashboard",
        Icon: IcoDashboard,
        route: "/audit-dashboard",
        permission: "audit.dashboard.read",
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

// ── Header pieces ────────────────────────────────────────────────────────────
const IcoSearch = () => <CcureIcon name="search" size={14} />;

// ── Main Layout Component ────────────────────────────────────────────────────
export default function AppLayout({ children, saveStatus = "" }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { pathname, search } = location;
  const { user, logout } = useAuth();
  const isSuperadmin = canSwitchOrganisation(user);
  const [showProfile, setShowProfile] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Openers, so a panel closed by keyboard hands focus back where it came from.
  const settingsBtnRef = useRef(null);

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
  // Poll dashboard summary for sidebar badges.
  useEffect(() => {
    const fetchCounts = async () => {
      try {
        const res = await api.get("/dashboard/summary");
        if (res.status === 200 && res.data) {
          const d = res.data;
          setRunningScans(d?.scans?.running ?? 0);
          setCriticalCount(d?.severity?.critical ?? 0);
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

  const closeAll = useCallback(() => {
    setShowSettings(false);
    setShowOrgDropdown(false);
  }, []);

  // Panel closers that hand focus back to the control that opened them.
  const closeSettings = useCallback(() => {
    setShowSettings(false);
    settingsBtnRef.current?.focus?.();
  }, []);
  const closeOrg = useCallback(() => setShowOrgDropdown(false), []);

  // Determine active nav item
  const activeId = (() => {
    if (pathname === "/audit-dashboard" || pathname === "/dashboard")
      return "security-dashboard";
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

  const sidebarFooter = (
    <>
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
      <ThemeToggle />
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
        brand={{ name: "CCure Audit", sub: "PRO" }}
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
