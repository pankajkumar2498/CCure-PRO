import axiosInstance, { authSession } from "./axiosInstance";

const normalizeEmail = (email) =>
  String(email || "")
    .trim()
    .toLowerCase();

export const login = async (credentials) => {
  const identifier = String(
    credentials?.email_or_username ||
      credentials?.email ||
      credentials?.username ||
      "",
  ).trim();
  const response = await axiosInstance.post("/auth/login", {
    ...credentials,
    email_or_username: identifier,
  });
  if (response.data?.access_token) {
    authSession.setTokens(response.data || {});
  }
  return response.data;
};

export const verifyMfa = async (mfaToken, code) => {
  const response = await axiosInstance.post("/auth/login/verify-mfa", {
    mfa_token: mfaToken,
    code,
  });
  if (response.data?.access_token) {
    authSession.setTokens(response.data || {});
  }
  return response.data;
};

export const sendEmailOtp = async (mfaToken) => {
  const response = await axiosInstance.post("/auth/login/send-email-otp", {
    mfa_token: mfaToken,
  });
  return response.data;
};

export const enableMfa = async () => {
  const response = await axiosInstance.post("/auth/mfa/enable");
  return response.data;
};

export const confirmMfa = async (code) => {
  const response = await axiosInstance.post("/auth/mfa/confirm", {
    code,
  });
  return response.data;
};

export const disableMfa = async (password) => {
  const response = await axiosInstance.post("/auth/mfa/disable", {
    password,
  });
  return response.data;
};

// Registration no longer returns a session. The backend replies 202 with
// {detail, status: "pending_verification"} and the account stays inert until
// the mailbox is confirmed and an administrator approves it, so calling
// authSession.setTokens() here would store an empty token set and leave the
// app believing it was signed in.
export const register = async (userData) => {
  const response = await axiosInstance.post("/auth/register", {
    ...userData,
    email: normalizeEmail(userData?.email),
  });
  return response.data;
};

export const verifyEmail = async (token) => {
  const response = await axiosInstance.post("/auth/verify-email", { token });
  return response.data;
};

export const resendVerification = async (email) => {
  const response = await axiosInstance.post("/auth/resend-verification", {
    email: normalizeEmail(email),
  });
  return response.data;
};

// True when the deployment has ALLOW_SELF_REGISTRATION enabled. The backend
// returns 404 for every self-service route when it does not, so the signup
// page can hide itself rather than presenting a form that cannot succeed.
export const isSelfRegistrationEnabled = async () => {
  try {
    await axiosInstance.get("/auth/check-email?q=probe@example.com");
    return true;
  } catch (err) {
    if (err?.response?.status === 404) return false;
    // Any other failure (network, 429) is not evidence the feature is off.
    return true;
  }
};

// `orgId` is a *request*: the backend validates it (and audits an organisation
// switch) and answers with the organisation it accepted as active, plus the
// effective permission keys for it (`user.authorization`, RBAC-6). `undefined`
// sends the stored organisation hint like every other request; `null` sends none.
export const getCurrentUser = async (orgId) => {
  const response = await axiosInstance.get(
    "/auth/me",
    orgId === undefined ? undefined : { params: { org_id: orgId } },
  );
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
    window.dispatchEvent(
      new CustomEvent("auth:logout", { detail: { reason: "logout" } }),
    );
  }
};

export const checkUsername = async (username) => {
  const response = await axiosInstance.get(
    `/auth/check-username?q=${encodeURIComponent(username)}`,
  );
  return response.data;
};

export const checkEmail = async (email) => {
  const response = await axiosInstance.get(
    `/auth/check-email?q=${encodeURIComponent(normalizeEmail(email))}`,
  );
  return response.data;
};

export const forgotPassword = async (identifier) => {
  const cleaned = String(identifier || "").trim();
  const response = await axiosInstance.post("/auth/forgot-password", {
    email_or_username: cleaned,
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
