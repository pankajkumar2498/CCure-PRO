import axios from "axios";
import { clearAuthTokens, getAccessToken, setAuthTokens } from "./tokenStorage";

const baseURL = import.meta.env.VITE_API_BASE_URL || "";

const axiosInstance = axios.create({
  baseURL,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

const refreshClient = axios.create({
  baseURL,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

let isRefreshing = false;
let refreshSubscribers = [];

const subscribeTokenRefresh = (callback) => {
  refreshSubscribers.push(callback);
};

const notifyRefreshSubscribers = (newAccessToken) => {
  refreshSubscribers.forEach((callback) => callback(newAccessToken));
  refreshSubscribers = [];
};

const forceLogout = (reason = "expired") => {
  if (reason === "expired" && window.location.pathname !== "/login") {
    sessionStorage.setItem(
      "postLoginRedirect",
      `${window.location.pathname}${window.location.search}${window.location.hash}`
    );
  }
  clearAuthTokens();
  localStorage.removeItem("activeOrgId");
  window.dispatchEvent(new CustomEvent("auth:logout", { detail: { reason } }));
};

axiosInstance.interceptors.request.use(
  (config) => {
    const token = getAccessToken();

    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }

    const activeOrgId = localStorage.getItem("activeOrgId");
    if (activeOrgId) {
      config.params = config.params || {};
      if (config.params.org_id === undefined) {
        config.params.org_id = activeOrgId;
      }
    }

    return config;
  },
  (error) => Promise.reject(error)
);

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (!error.response || !originalRequest) {
      return Promise.reject(error);
    }

    // Do not attempt automatic token refresh for login, refresh, registration, or password reset endpoints.
    // If these return a 401 Unauthorized, we should propagate the error directly to display the correct message.
    const bypassUrls = [
      "/auth/login",
      "/auth/refresh",
      "/auth/register",
      "/auth/forgot-password",
      "/auth/reset-password"
    ];
    const isBypassUrl = bypassUrls.some((url) => originalRequest.url?.includes(url));

    if (error.response.status !== 401 || originalRequest._retry || isBypassUrl) {
      return Promise.reject(error);
    }

    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        subscribeTokenRefresh((newAccessToken) => {
          if (!newAccessToken) {
            reject(error);
            return;
          }

          originalRequest.headers = originalRequest.headers || {};
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
          resolve(axiosInstance(originalRequest));
        });
      });
    }

    originalRequest._retry = true;
    isRefreshing = true;

    try {
      const response = await refreshClient.post("/auth/refresh", {});

      const newAccessToken = response.data?.access_token;

      if (!newAccessToken) {
        throw new Error("Missing access token in refresh response");
      }

      setAuthTokens({
        access_token: newAccessToken,
      });

      notifyRefreshSubscribers(newAccessToken);

      originalRequest.headers = originalRequest.headers || {};
      originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;

      return axiosInstance(originalRequest);
    } catch (refreshError) {
      notifyRefreshSubscribers(null);
      forceLogout("expired");
      return Promise.reject(refreshError);
    } finally {
      isRefreshing = false;
    }
  }
);

export const authSession = {
  clear: clearAuthTokens,
  getAccessToken,
  setTokens: setAuthTokens,
};

export default axiosInstance;
