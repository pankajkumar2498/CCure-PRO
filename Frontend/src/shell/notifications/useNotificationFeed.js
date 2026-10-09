/**
 * src/shell/notifications/useNotificationFeed.js — the unread count and the
 * live notification stream every product's header shows.
 * ─────────────────────────────────────────────────────────────────────────────
 * Opens the SSE stream once, takes the unread count from its `connected`
 * event, counts `notification.created` events, and on a dropped stream falls
 * back to one GET /notifications/summary and retries on a backoff. Moved from
 * Audit's AppLayout with its behaviour unchanged.
 */
import { useEffect, useState } from "react";
import { getUnreadCount, streamNotificationEvents } from "../api/notifications";

export default function useNotificationFeed() {
  const [unreadCount, setUnreadCount] = useState(0);
  const [notificationEvent, setNotificationEvent] = useState(null);

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    const refreshSummary = async () => {
      try {
        const summary = await getUnreadCount();
        if (!stopped) setUnreadCount(summary.total_unread || 0);
      } catch {
        // Deliberately swallowed: this polls on a timer, so a transient
        // failure corrects itself on the next tick. Surfacing it would put a
        // toast on screen every time the network blinked.
      }
    };

    const connect = async () => {
      let failures = 0;
      while (!stopped) {
        try {
          await streamNotificationEvents({
            signal: controller.signal,
            onEvent: ({ event, data }) => {
              if (stopped || !data) return;
              if (event === "connected" && data.summary)
                setUnreadCount(data.summary.total_unread || 0);
              if (event === "notification.created" && data.notification) {
                setNotificationEvent({
                  type: "created",
                  notification: data.notification,
                  receivedAt: Date.now(),
                });
                if (!data.notification.is_read)
                  setUnreadCount((count) => count + 1);
              }
              if (event === "notifications.summary" && data.summary)
                setUnreadCount(data.summary.total_unread || 0);
            },
          });
          if (!stopped) throw new Error("Stream closed.");
        } catch {
          if (stopped || controller.signal.aborted) return;
          failures += 1;
          if (failures === 1) await refreshSummary();
          await wait(Math.min(30000, 1000 * 2 ** Math.min(failures, 5)));
        }
      }
    };
    connect();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, []);

  return { unreadCount, setUnreadCount, notificationEvent };
}
