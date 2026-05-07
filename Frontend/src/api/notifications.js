/**
 * src/api/notifications.js
 * ─────────────────────────────────────────────────────────────────────────────
 * API functions for the notification center.
 */

import axiosInstance from "./axiosInstance";

/** Get notifications list (supports filtering & pagination) */
export const getNotifications = ({ category, unread_only = false, limit = 50, offset = 0 } = {}) => {
  const params = { unread_only, limit, offset };
  if (category) params.category = category;
  return axiosInstance.get("/notifications", { params }).then((r) => r.data);
};

/** Get unread notification summary by category */
export const getUnreadCount = () =>
  axiosInstance.get("/notifications/summary").then((r) => r.data);

/** Mark a single notification as read */
export const markAsRead = (id) =>
  axiosInstance.patch(`/notifications/${id}/read`).then((r) => r.data);

/** Mark all notifications as read */
export const markAllAsRead = () =>
  axiosInstance.patch("/notifications/read-all").then((r) => r.data);

/** Delete a single notification */
export const deleteNotification = (id) =>
  axiosInstance.delete(`/notifications/${id}`).then((r) => r.data);

/** Delete all notifications */
export const deleteAllNotifications = () =>
  axiosInstance.delete("/notifications").then((r) => r.data);
