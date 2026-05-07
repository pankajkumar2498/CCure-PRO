/**
 * src/api/user.js
 * ─────────────────────────────────────────────────────────────────────────────
 * API functions for user profile, preferences, password, and session management.
 */

import axiosInstance from "./axiosInstance";

// ── Profile ───────────────────────────────────────────────────────────────────

/** Get current user's profile */
export const getProfile = () =>
  axiosInstance.get("/user/profile").then((r) => r.data);

/** Update user profile (full_name, email) */
export const updateProfile = (data) =>
  axiosInstance.put("/user/profile", data).then((r) => r.data);

// ── Preferences ───────────────────────────────────────────────────────────────

/** Get user preferences */
export const getPreferences = () =>
  axiosInstance.get("/user/preferences").then((r) => r.data);

/** Update user preferences (partial) */
export const updatePreferences = (data) =>
  axiosInstance.put("/user/preferences", data).then((r) => r.data);

// ── Password ──────────────────────────────────────────────────────────────────

/** Change the current user's password */
export const changePassword = (current_password, new_password) =>
  axiosInstance
    .post("/user/change-password", { current_password, new_password })
    .then((r) => r.data);

// ── Sessions ──────────────────────────────────────────────────────────────────

/** List active sessions */
export const getSessions = () =>
  axiosInstance.get("/user/sessions").then((r) => r.data);

/** Revoke a specific session by ID */
export const revokeSession = (session_id) =>
  axiosInstance.delete(`/user/sessions/${session_id}`).then((r) => r.data);
