/**
 * src/shell/navigation/useOrganizationSwitcher.js — the superadmin's tenant.
 * ─────────────────────────────────────────────────────────────────────────────
 * Lists the organisations, names the active one (`activeOrgId` in
 * localStorage, else the user's own), and switches by writing `activeOrgId`
 * and reloading — the shell's HTTP client then sends it as `org_id` on every
 * request. Moved from Audit's AppLayout with its behaviour unchanged, the
 * initial label included.
 */
import { useEffect, useState } from "react";
import { isSuperAdmin } from "../auth/permissions";
import { listOrganizations } from "../api/admin";

export default function useOrganizationSwitcher(user) {
  const [selectedOrg, setSelectedOrg] = useState("CDAC RTSG Bangalore");
  const [orgs, setOrgs] = useState([]);
  const [loadingOrgs, setLoadingOrgs] = useState(false);

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

  const switchOrg = (org) => {
    localStorage.setItem("activeOrgId", org.id);
    setSelectedOrg(org.name);
    window.location.reload();
  };

  return { orgs, loadingOrgs, selectedOrg, switchOrg };
}
