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

// Replaces the account's role with another RBAC role; the id is an RBAC role id
// (from the assignable-roles list), checked again by the backend.
export const changeUserRole = async (userId, rbacRoleId) => {
  const response = await axiosInstance.patch(`/admin/users/${userId}/role/`, {
    rbac_role_id: rbacRoleId,
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

// Download the audit trail as CSV or PDF.
//
// Fetched with the access token rather than opened as a plain link: the
// endpoint is bearer-authenticated, so a bare <a href> would be an
// unauthenticated request and answer 403. The response comes back as a blob and
// is saved with the filename the server chose, which is where the
// INTEGRITY-FAILURE marker lives on a failed export.
//
// `verify` defaults to true and should stay that way. It is what makes the file
// evidence rather than a copy: with it off, no stored hash is recomputed and the
// export says so in its own header.
// Phase 6a. What audit retention would remove, and everything standing in its
// way — holds, the backup precondition, whether retention is enabled at all.
//
// Read-only. There is deliberately no counterpart that deletes: a purge runs
// from the beat schedule or the CLI, so destroying audit history needs shell
// access to the host as well as the permission. A deletion a session cookie
// can reach is a deletion an XSS can reach.
export const previewAuditRetention = async () => {
  const response = await axiosInstance.get(
    "/admin/audit-logs/retention/preview",
  );
  return response.data;
};

export const exportAuditLogs = async (params = {}, format = "csv") => {
  const response = await axiosInstance.get("/admin/audit-logs/export", {
    params: { ...params, format },
    responseType: "blob",
  });

  const disposition = response.headers?.["content-disposition"] || "";
  const match =
    /filename\*=UTF-8''([^;]+)/i.exec(disposition) ||
    /filename="?([^";]+)"?/i.exec(disposition);
  const filename = match
    ? decodeURIComponent(match[1].trim())
    : `ccure-audit-log.${format === "pdf" ? "pdf" : "csv"}`;

  const url = window.URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);

  return {
    filename,
    rows: Number(response.headers?.["x-audit-export-rows"] || 0),
    // "FAILED" means at least one exported row's stored hash did not reproduce.
    // Surfaced to the caller so the UI can say so rather than reporting a
    // routine download.
    integrity: response.headers?.["x-audit-integrity"] || "NOT_VERIFIED",
    verificationMode:
      response.headers?.["x-audit-verification-mode"] || "unavailable",
  };
};
