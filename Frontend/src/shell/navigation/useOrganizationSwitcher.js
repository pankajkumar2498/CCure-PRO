/**
 * src/shell/navigation/useOrganizationSwitcher.js — entering another organisation.
 * ─────────────────────────────────────────────────────────────────────────────
 * RBAC-6. Whether the switcher exists, and which organisation is active, come
 * from the backend's authorization payload (`canSwitchOrganisation`,
 * `activeOrganisationId`) — never from a role name or from `activeOrgId` in
 * localStorage, which is only the hint the HTTP client sends.
 *
 * Switching is a backend operation (`AuthContext.switchOrganisation`): the
 * server validates the target against the account's grants and the
 * organisation's state, audits the entry and answers with the permissions that
 * apply there. Only after it accepts does the document reload, so nothing derived
 * from the previous organisation's permissions survives. A refusal changes
 * nothing and is reported.
 */
import { useEffect, useState } from "react";
import { useAuth } from "../auth/AuthContext";
import {
  activeOrganisationId,
  canSwitchOrganisation,
} from "../auth/permissions";
import { listOrganizations } from "../api/admin";

export default function useOrganizationSwitcher(user) {
  const { switchOrganisation } = useAuth();
  const [selectedOrg, setSelectedOrg] = useState("CDAC RTSG Bangalore");
  const [orgs, setOrgs] = useState([]);
  const [loadingOrgs, setLoadingOrgs] = useState(false);
  const [switchError, setSwitchError] = useState("");
  const active = activeOrganisationId(user);
  const reach = canSwitchOrganisation(user);

  useEffect(() => {
    if (!user || !reach) return;
    setLoadingOrgs(true);
    listOrganizations()
      .then((data) => {
        if (data && data.organizations) {
          setOrgs(data.organizations);
          const activeOrg = data.organizations.find((o) => o.id === active);
          if (activeOrg) setSelectedOrg(activeOrg.name);
        }
      })
      .catch(() => {
        /* silent */
      })
      .finally(() => setLoadingOrgs(false));
  }, [user, reach, active]);

  const switchOrg = async (org) => {
    setSwitchError("");
    try {
      await switchOrganisation(org.id);
    } catch {
      setSwitchError("That organisation could not be entered.");
      return false;
    }
    setSelectedOrg(org.name);
    window.location.reload();
    return true;
  };

  return { orgs, loadingOrgs, selectedOrg, switchOrg, switchError };
}
