/**
 * src/api/auth.js
 * Thin wrappers for POST /auth/register, /auth/login, /auth/logout,
 * GET /auth/me, POST /auth/refresh
 */
import api from "./axiosInstance";

export const registerUser  = (username, email, password) =>
  api.post("/auth/register", { username, email, password });

export const loginUser     = (email, password) =>
  api.post("/auth/login", { email, password });

export const logoutUser    = () =>
  api.post("/auth/logout");

export const getCurrentUser = () =>
  api.get("/auth/me");

export const refreshToken  = (refresh_token) =>
  api.post("/auth/refresh", { refresh_token });
