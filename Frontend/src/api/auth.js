import axiosInstance, { authSession } from "./axiosInstance";

export const login = async (credentials) => {
  const response = await axiosInstance.post("/auth/login", credentials);
  authSession.setTokens(response.data || {});
  return response.data;
};

export const register = async (userData) => {
  const response = await axiosInstance.post("/auth/register", userData);
  authSession.setTokens(response.data || {});
  return response.data;
};

export const getCurrentUser = async () => {
  const response = await axiosInstance.get("/auth/me");
  return response.data;
};

export const refreshSession = async () => {
  const response = await axiosInstance.post("/auth/refresh", {});
  authSession.setTokens(response.data || {});
  return response.data;
};

export const logout = async () => {
  try {
    await axiosInstance.post("/auth/logout", {});
  } finally {
    authSession.clear();
    window.dispatchEvent(new CustomEvent("auth:logout", { detail: { reason: "logout" } }));
  }
};
