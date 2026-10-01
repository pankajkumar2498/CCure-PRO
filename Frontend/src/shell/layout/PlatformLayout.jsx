/**
 * src/shell/layout/PlatformLayout.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * The platform's own page frame — CCure Home, the product entry pages, and any
 * shared screen rendered without a product's layout. After sign-in a person
 * lands here, so it carries the whole shared platform navigation:
 *
 *   CCure Home · Administration (the /admin/* screens the user may see) ·
 *   organisation switcher (superadmin) · notifications · settings (platform
 *   preferences only) · account menu (My Account, Sign Out) · Sign out
 *
 * Every piece is the shell's own — the same components a product's layout
 * composes — so there is one implementation of each. Nothing here names or
 * imports a product: a product's own settings, actions and navigation belong
 * in that product's layout, never in this one.
 */
import { useCallback, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CcureButton } from "../../design-system";
import { useAuth } from "../auth/AuthContext";
import { isSuperAdmin } from "../auth/permissions";
import { usePreferences } from "../preferences/PreferencesContext";
import AdminMenu from "../navigation/AdminMenu";
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

export default function PlatformLayout({ children }) {
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

  return (
    <div className="pl-frame">
      <header className="pl-header">
        <Link to="/" className="pl-brand" aria-label="CCure Home">
          <span className="pl-brand__name">CCure</span>
          <span className="pl-brand__sub">Home</span>
        </Link>
        <div className="pl-header__actions">
          <AdminMenu user={user} />
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
          <CcureButton variant="ghost" size="sm" onClick={() => logout()}>
            Sign out
          </CcureButton>
        </div>
      </header>
      <main className="pl-main" id="main-content">
        {children}
      </main>
      {showSettings && (
        <SettingsDrawer
          id="sh-settings"
          onClose={closeSettings}
          onPreferencesUpdated={updateLocalPreferences}
        />
      )}
      {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
    </div>
  );
}
