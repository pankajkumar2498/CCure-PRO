import axiosInstance, { authSession } from "./axiosInstance";

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

export const login = async (credentials) => {
  const response = await axiosInstance.post("/auth/login", {
    ...credentials,
    email: normalizeEmail(credentials?.email),
  });
  authSession.setTokens(response.data || {});
  return response.data;
};

export const register = async (userData) => {
  const response = await axiosInstance.post("/auth/register", {
    ...userData,
    email: normalizeEmail(userData?.email),
  });
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

export const checkUsername = async (username) => {
  const response = await axiosInstance.get(`/auth/check-username?q=${encodeURIComponent(username)}`);
  return response.data;
};

export const checkEmail = async (email) => {
  const response = await axiosInstance.get(`/auth/check-email?q=${encodeURIComponent(normalizeEmail(email))}`);
  return response.data;
};

export const forgotPassword = async (email) => {
  const response = await axiosInstance.post("/auth/forgot-password", {
    email: normalizeEmail(email),
  });
  return response.data;
};

export const resetPassword = async (token, password) => {
  const response = await axiosInstance.post("/auth/reset-password", {
    token,
    password,
  });
  return response.data;
};
