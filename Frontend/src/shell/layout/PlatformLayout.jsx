/**
 * src/shell/layout/PlatformLayout.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * The CCure Platform Shell — the frame of CCure Home, the product entry pages
 * and the shared administration screens. It is the platform's own and no
 * product's: it never renders a product's navigation, and no product renders
 * this one.
 *
 *   LEFT SIDEBAR   "Which CCure product do I want to use?" — CCure Home, every
 *                  product from the platform registry (fetched, never copied),
 *                  and Administration (the /admin/* screens, by permission).
 *   HEADER         organisation switcher (superadmin) · notifications ·
 *                  settings (platform preferences only) · account menu ·
 *                  sign out
 *
 * Choosing a product navigates to its entry address, which mounts that
 * product's own layout with its own sidebar. Nothing here names or imports a
 * product.
 */
import { useCallback, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { CcureAppShell, CcureButton } from "../../design-system";
import { useAuth } from "../auth/AuthContext";
import { isSuperAdmin } from "../auth/permissions";
import { usePreferences } from "../preferences/PreferencesContext";
import { SHARED_ADMIN_NAV } from "../admin/adminNav";
import { canSeeNavItem } from "../auth/navVisibility";
import useProductList, {
  ProductListProvider,
} from "../products/useProductList";
import AccountMenu from "../navigation/AccountMenu";
import OrgSwitcher from "../navigation/OrgSwitcher";
import useOrganizationSwitcher from "../navigation/useOrganizationSwitcher";
import { IcoSettings } from "../navigation/navIcons";
import NotificationsPanel, {
  NotificationBell,
} from "../notifications/NotificationsPanel";
import useNotificationFeed from "../notifications/useNotificationFeed";
import ProfileModal from "../account/ProfileModal";
import SettingsDrawer from "../account/SettingsDrawer";
import "./platform-layout.css";

// The sidebar's sections. Products come from the registry; a failed or pending
// request is said so in the sidebar rather than rendered as "no products".
function platformSections(user, productList) {
  const { status, products } = productList;
  const productItems =
    status === "ready"
      ? products
          .filter((p) => p.entryPath)
          .map((p) => ({
            id: `product-${p.key || p.entryPath}`,
            label: p.title || "Unnamed product",
            route: p.entryPath,
          }))
      : [
          {
            id: "products-status",
            label:
              status === "loading"
                ? "Loading products…"
                : "Products could not be loaded",
            route: "/",
            disabled: true,
          },
        ];
  const admin = SHARED_ADMIN_NAV.filter((item) => canSeeNavItem(user, item));
  return [
    {
      label: "CCure Platform",
      items: [{ id: "home", label: "Home", route: "/" }, ...productItems],
    },
    ...(admin.length ? [{ label: "Administration", items: admin }] : []),
  ];
}

export default function PlatformLayout({ children }) {
  return (
    <ProductListProvider>
      <PlatformFrame>{children}</PlatformFrame>
    </ProductListProvider>
  );
}

function PlatformFrame({ children }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const productList = useProductList();
  const { user, logout } = useAuth();
  const { updateLocalPreferences } = usePreferences();
  const superadmin = isSuperAdmin(user);

  const [showNotifs, setShowNotifs] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showOrgMenu, setShowOrgMenu] = useState(false);
  const bellRef = useRef(null);
  const settingsBtnRef = useRef(null);

  const { orgs, loadingOrgs, selectedOrg, switchOrg } =
    useOrganizationSwitcher(user);
  const { unreadCount, setUnreadCount, notificationEvent } =
    useNotificationFeed();

  const closeAll = useCallback(() => {
    setShowNotifs(false);
    setShowSettings(false);
    setShowOrgMenu(false);
  }, []);
  const closeNotifs = useCallback(() => {
    setShowNotifs(false);
    bellRef.current?.focus?.();
  }, []);
  const closeSettings = useCallback(() => {
    setShowSettings(false);
    settingsBtnRef.current?.focus?.();
  }, []);
  const closeOrg = useCallback(() => setShowOrgMenu(false), []);

  const headerActions = (
    <>
      {superadmin ? (
        <OrgSwitcher
          selectedOrg={selectedOrg}
          orgs={orgs}
          loading={loadingOrgs}
          open={showOrgMenu}
          onToggle={() => {
            const next = !showOrgMenu;
            closeAll();
            setShowOrgMenu(next);
          }}
          onClose={closeOrg}
          onSwitch={(org) => {
            setShowOrgMenu(false);
            switchOrg(org);
          }}
        />
      ) : null}
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
          <div className="pl-popover">
            <NotificationsPanel
              id="sh-notifications"
              onClose={closeNotifs}
              onUnreadChange={setUnreadCount}
              liveEvent={notificationEvent}
            />
          </div>
        )}
      </div>
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
      <AccountMenu
        user={user}
        onLogout={() => logout()}
        onOpenProfile={() => setShowProfile(true)}
      />
      <CcureButton
        variant="ghost"
        size="sm"
        className="pl-signout"
        onClick={() => logout()}
      >
        Sign out
      </CcureButton>
    </>
  );

  return (
    <>
      <CcureAppShell
        brand={{ name: "CCure", sub: "Platform", mark: "◈" }}
        sections={platformSections(user, productList)}
        currentPath={pathname}
        onNavigate={(route) => navigate(route)}
        headerActions={headerActions}
        mainClassName="pl-main"
        className="pl-shell"
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
