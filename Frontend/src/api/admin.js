import axiosInstance from "./axiosInstance";

const normalizeEmail = (email) =>
  String(email || "")
    .trim()
    .toLowerCase();
const withNormalizedEmail = (payload, key = "email") => {
  if (!payload || payload[key] == null) return payload;
  return { ...payload, [key]: normalizeEmail(payload[key]) };
};

export const listUsers = async (params) => {
  const response = await axiosInstance.get("/admin/users/", { params });
  return response.data;
};

// Self-registered accounts awaiting approval (approved_at IS NULL). These
// cannot sign in until approveUser runs, so nothing here is a live account yet.
export const listPendingUsers = async () => {
  const response = await axiosInstance.get("/admin/users/pending");
  return response.data;
};

// Enables sign-in. The backend refuses if the account's email is not verified —
// approving an unverified address would activate a login for a mailbox nobody
// has demonstrated control of. It also emails the user, since they cannot see
// an in-app notification until they can log in.
//
// `allowlistDomain` is a second, much wider decision and defaults to false:
// approving the account clears that one account, while allowlisting adds its
// email domain to the platform-wide ALLOW list for everyone, permanently. They
// are separate arguments because they are separate judgements — an admin
// admitting one colleague whose employer a blocklist got wrong must not
// accidentally open the door to a throwaway mail service.
export const approveUser = async (
  userId,
  { allowlistDomain = false, reason } = {},
) => {
  const response = await axiosInstance.post(`/admin/users/${userId}/approve`, {
    allowlist_domain: allowlistDomain,
    reason: reason ?? null,
  });
  return response.data;
};

export const createUser = async (userData) => {
  const response = await axiosInstance.post(
    "/admin/users/",
    withNormalizedEmail(userData),
  );
  return response.data;
};

export const updateUser = async (userId, userData) => {
  const response = await axiosInstance.put(
    `/admin/users/${userId}/`,
    withNormalizedEmail(userData),
  );
  return response.data;
};

export const changeUserRole = async (userId, roleId) => {
  const response = await axiosInstance.patch(`/admin/users/${userId}/role/`, {
    role_id: roleId,
  });
  return response.data;
};

export const moveUserOrganization = async (userId, orgId) => {
  const response = await axiosInstance.patch(
    `/admin/users/${userId}/organization/`,
    { organization_id: orgId },
  );
  return response.data;
};

export const changeUserStatus = async (userId, statusData) => {
  const response = await axiosInstance.patch(
    `/admin/users/${userId}/status/`,
    statusData,
  );
  return response.data;
};

export const deleteUser = async (userId) => {
  const response = await axiosInstance.delete(`/admin/users/${userId}/`);
  return response.data;
};

export const restoreUser = async (userId) => {
  const response = await axiosInstance.post(`/admin/users/${userId}/restore/`);
  return response.data;
};

export const purgeUser = async (userId) => {
  const response = await axiosInstance.delete(`/admin/users/${userId}/purge/`);
  return response.data;
};

export const resetUserPassword = async (userId, password) => {
  const response = await axiosInstance.post(
    `/admin/users/${userId}/reset-password/`,
    { password },
  );
  return response.data;
};

export const resetUserMfa = async (userId) => {
  const response = await axiosInstance.post(
    `/admin/users/${userId}/reset-mfa/`,
  );
  return response.data;
};

export const listRoles = async () => {
  const response = await axiosInstance.get("/admin/roles/");
  return response.data;
};

export const listRolePermissions = async (roleId) => {
  const response = await axiosInstance.get(
    `/admin/roles/${roleId}/permissions/`,
  );
  return response.data;
};

export const listOrganizations = async () => {
  const response = await axiosInstance.get("/admin/organizations/");
  return response.data;
};

export const createOrganization = async (orgData) => {
  const response = await axiosInstance.post(
    "/admin/organizations/",
    withNormalizedEmail(orgData, "admin_email"),
  );
  return response.data;
};

export const updateOrganization = async (orgId, orgData) => {
  const response = await axiosInstance.put(
    `/admin/organizations/${orgId}/`,
    orgData,
  );
  return response.data;
};

export const changeOrganizationStatus = async (orgId, statusData) => {
  const response = await axiosInstance.patch(
    `/admin/organizations/${orgId}/status/`,
    statusData,
  );
  return response.data;
};

export const deleteOrganization = async (orgId) => {
  const response = await axiosInstance.delete(`/admin/organizations/${orgId}/`);
  return response.data;
};

export const listAuditLogs = async (params) => {
  const response = await axiosInstance.get("/admin/audit-logs/", { params });
  return response.data;
};

// One audit event in full. The list response is deliberately lean, so the
// detail view fetches the fields it needs (session id, timezone, org) rather
// than the table carrying them for every row it renders.
export const getAuditLogDetail = async (eventId) => {
  const response = await axiosInstance.get(
    `/admin/audit-logs/${encodeURIComponent(eventId)}`,
  );
  return response.data;
};
