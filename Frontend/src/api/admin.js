import axiosInstance from "./axiosInstance";

export const listUsers = async (params) => {
  const response = await axiosInstance.get("/admin/users", { params });
  return response.data;
};

export const createUser = async (userData) => {
  const response = await axiosInstance.post("/admin/users", userData);
  return response.data;
};

export const updateUser = async (userId, userData) => {
  const response = await axiosInstance.put(`/admin/users/${userId}`, userData);
  return response.data;
};

export const changeUserRole = async (userId, roleId) => {
  const response = await axiosInstance.patch(`/admin/users/${userId}/role`, { role_id: roleId });
  return response.data;
};

export const changeUserStatus = async (userId, statusData) => {
  const response = await axiosInstance.patch(`/admin/users/${userId}/status`, statusData);
  return response.data;
};

export const deleteUser = async (userId) => {
  const response = await axiosInstance.delete(`/admin/users/${userId}`);
  return response.data;
};

export const listRoles = async () => {
  const response = await axiosInstance.get("/admin/roles");
  return response.data;
};

export const listRolePermissions = async (roleId) => {
  const response = await axiosInstance.get(`/admin/roles/${roleId}/permissions`);
  return response.data;
};

export const listOrganizations = async () => {
  const response = await axiosInstance.get("/admin/organizations");
  return response.data;
};

export const createOrganization = async (orgData) => {
  const response = await axiosInstance.post("/admin/organizations", orgData);
  return response.data;
};

export const updateOrganization = async (orgId, orgData) => {
  const response = await axiosInstance.put(`/admin/organizations/${orgId}`, orgData);
  return response.data;
};

export const listAuditLogs = async (params) => {
  const response = await axiosInstance.get("/admin/audit-logs", { params });
  return response.data;
};
