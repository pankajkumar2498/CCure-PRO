/**
 * src/api/notifications.js
 * ─────────────────────────────────────────────────────────────────────────────
 * API functions for the notification center.
 */

import axiosInstance from "./axiosInstance";
import { authSession } from "./axiosInstance";

/** Get notifications list (supports filtering & pagination) */
export const getNotifications = ({
  category,
  unread_only = false,
  limit = 50,
  offset = 0,
} = {}) => {
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

const streamUrl = () => {
  const baseURL = axiosInstance.defaults.baseURL || "";
  const prefix = baseURL.endsWith("/") ? baseURL.slice(0, -1) : baseURL;
  return `${prefix}/notifications/stream`;
};

const parseSseMessage = (message) => {
  let event = "message";
  const data = [];

  message.split(/\r?\n/).forEach((line) => {
    if (line.startsWith("event:")) {
      event = line.slice(6).trim() || "message";
      return;
    }
    if (line.startsWith("data:")) {
      data.push(line.slice(5).trimStart());
    }
  });

  return {
    event,
    data: data.length ? JSON.parse(data.join("\n")) : null,
  };
};

export const streamNotificationEvents = async ({ signal, onEvent } = {}) => {
  const headers = { Accept: "text/event-stream" };
  const token = authSession.getAccessToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(streamUrl(), {
    headers,
    credentials: "include",
    signal,
  });

  if (!response.ok || !response.body) {
    throw new Error(`Notification stream failed (${response.status})`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (!signal?.aborted) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const messages = buffer.split(/\r?\n\r?\n/);
    buffer = messages.pop() || "";

    messages
      .filter(Boolean)
      .map(parseSseMessage)
      .forEach((payload) => onEvent?.(payload));
  }
};
