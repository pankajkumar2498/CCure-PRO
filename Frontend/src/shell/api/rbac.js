/**
 * src/shell/api/rbac.js — the Platform RBAC administration API (RBAC-7).
 * ─────────────────────────────────────────────────────────────────────────────
 * One client for `/platform/rbac/*`. It speaks permission keys, labels and states —
 * never a legacy atom — and every answer is the backend's: the UI renders what it is
 * told is assignable, editable or retirable, and the backend checks it again.
 *
 * A sensitive operation may be answered 403 `reauth_required`; the caller prompts for
 * an authenticator code and repeats the call with `reauthCode` (sent as the
 * `X-Reauth-Code` header, never stored or logged here).
 */
import axiosInstance from "./axiosInstance";

const headers = (reauthCode) =>
  reauthCode ? { headers: { "X-Reauth-Code": reauthCode } } : {};

export const listPermissionCatalogue = async () =>
  (await axiosInstance.get("/platform/rbac/permissions")).data;

export const listRbacRoles = async ({ orgId, includeRetired } = {}) =>
  (
    await axiosInstance.get("/platform/rbac/roles", {
      params: { org_id: orgId, include_retired: includeRetired || undefined },
    })
  ).data;

export const getRbacRole = async (roleId) =>
  (await axiosInstance.get(`/platform/rbac/roles/${roleId}`)).data;

export const createRbacRole = async (body, { reauthCode } = {}) =>
  (await axiosInstance.post("/platform/rbac/roles", body, headers(reauthCode)))
    .data;

export const updateRbacRole = async (roleId, body, { reauthCode } = {}) =>
  (
    await axiosInstance.patch(
      `/platform/rbac/roles/${roleId}`,
      body,
      headers(reauthCode),
    )
  ).data;

export const setRbacRolePermissions = async (
  roleId,
  permissionKeys,
  { reauthCode } = {},
) =>
  (
    await axiosInstance.put(
      `/platform/rbac/roles/${roleId}/permissions`,
      { permission_keys: permissionKeys },
      headers(reauthCode),
    )
  ).data;

export const transitionRbacRole = async (roleId, body, { reauthCode } = {}) =>
  (
    await axiosInstance.post(
      `/platform/rbac/roles/${roleId}/transition`,
      body,
      headers(reauthCode),
    )
  ).data;

export const replaceRbacRole = async (roleId, toRoleId, { reauthCode } = {}) =>
  (
    await axiosInstance.post(
      `/platform/rbac/roles/${roleId}/replace`,
      { to_role_id: toRoleId },
      headers(reauthCode),
    )
  ).data;

export const listAssignableRoles = async ({ userId, orgId } = {}) =>
  (
    await axiosInstance.get("/platform/rbac/assignable-roles", {
      params: { user_id: userId, org_id: orgId },
    })
  ).data;

export const getUserAssignments = async (userId) =>
  (await axiosInstance.get(`/platform/rbac/users/${userId}/assignments`)).data;

export const assignRbacRole = async (userId, roleId, { reauthCode } = {}) =>
  (
    await axiosInstance.post(
      `/platform/rbac/users/${userId}/assignments`,
      { role_id: roleId },
      headers(reauthCode),
    )
  ).data;

export const revokeRbacAssignment = async (assignmentId, { reauthCode } = {}) =>
  (
    await axiosInstance.delete(
      `/platform/rbac/assignments/${assignmentId}`,
      headers(reauthCode),
    )
  ).data;

/** The step-up the backend asked for, or null. */
export const reauthRequired = (error) =>
  error?.response?.status === 403 &&
  error?.response?.data?.detail?.code === "reauth_required";

/** Governance refusals as readable lines. */
export const refusalMessages = (error) => {
  const detail = error?.response?.data?.detail;
  if (detail?.code === "governance_refused") {
    return detail.violations.map((v) => v.message);
  }
  if (typeof detail === "string") return [detail];
  if (detail?.message) return [detail.message];
  return ["The request was refused."];
};
