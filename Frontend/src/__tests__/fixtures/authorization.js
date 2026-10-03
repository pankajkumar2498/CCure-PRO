/**
 * Test personas for RBAC-6: users carry the backend's `authorization` payload, as
 * AuthContext hands them out. The vocabulary is a generated fixture
 * (authorizationVocabulary.json); production code holds none of it.
 *
 * `personaFrom(user)` keeps the older test shape readable: a user whose
 * `role.permissions` list legacy atoms gets a payload granting exactly those atoms'
 * keys. A user named "superadmin" gets what the backend would send an account that
 * holds everything and may switch organisation — a fixture convention in test code
 * only; the application never infers anything from a role name.
 */
import vocabulary from "./authorizationVocabulary.json";

const atomOf = (p) => (typeof p === "string" ? p : `${p.resource}:${p.action}`);

export const payload = ({
  atoms = [],
  keys = [],
  reach = false,
  active = "org_test",
  home = "org_test",
} = {}) => {
  const held = new Set(keys);
  for (const atom of atoms) {
    for (const key of vocabulary.atoms[atom] || []) held.add(key);
  }
  const platform = [];
  const organization = [];
  for (const key of [...held].sort()) {
    (vocabulary.keys[key] === "platform" ? platform : organization).push(key);
  }
  return {
    contract: 1,
    source: "platform",
    home_org_id: home,
    active_org_id: active,
    permissions: { platform, organization },
    can_switch_organisation: reach,
    assignments: [],
    atoms: vocabulary.atoms,
  };
};

export const everything = () =>
  payload({ keys: Object.keys(vocabulary.keys), reach: true });

export const personaFrom = (user) => {
  if (!user) return user;
  if (user.authorization) return user;
  const label = String(user.role?.name || "").toLowerCase();
  const org = user.org_id ?? "org_test";
  const base = { active: org, home: org };
  if (label === "superadmin") {
    return {
      ...user,
      authorization: { ...everything(), home_org_id: org, active_org_id: org },
    };
  }
  const atoms = (user.role?.permissions || [])
    .map(atomOf)
    .filter((a) => vocabulary.atoms[a]);
  return { ...user, authorization: payload({ atoms, ...base }) };
};
