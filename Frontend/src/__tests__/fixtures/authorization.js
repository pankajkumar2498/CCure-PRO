/** Native authorization payloads for test users, with explicit grants and reach. */
import vocabulary from "./authorizationVocabulary.json";

export const payload = ({
  keys = [],
  reach = false,
  active = "org_test",
  home = "org_test",
} = {}) => {
  const platform = [];
  const organization = [];
  for (const key of [...new Set(keys)].sort()) {
    (vocabulary.keys[key] === "platform" ? platform : organization).push(key);
  }
  return {
    contract: 1,
    home_org_id: home,
    active_org_id: active,
    permissions: { platform, organization },
    can_switch_organisation: reach,
    assignments: [],
  };
};

export const everything = (scope = {}) =>
  payload({ keys: Object.keys(vocabulary.keys), reach: true, ...scope });

export const personaFrom = (user) => {
  if (!user || user.authorization) return user;
  const org = user.org_id ?? "org_test";
  return {
    ...user,
    authorization: payload({
      keys: user.permissionKeys ?? [],
      reach: user.platformReach ?? false,
      active: org,
      home: org,
    }),
  };
};

export const keySetHolds = (keys, permission) =>
  typeof permission === "string" && keys.has(permission);
