/**
 * src/shell/notifications/NotificationsPanel.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Dropdown notification center with:
 *   • Real-time unread badge on the bell icon
 *   • Category filter tabs (All, then each product's and the platform's)
 *   • Mark individual / all as read
 *   • Delete individual notifications
 *   • Auto-polling every 30 seconds
 *
 * Checkpoint 3C batch 12: presentation moved onto the CCure design system.
 * The reads and writes are unchanged (GET /notifications with the same
 * params, PATCH …/read, PATCH read-all, DELETE …/{id}, GET summary after a
 * change; click-outside closes with the bell exempt). Added for assistive
 * technology: the category strip is a tab list, every item action is named
 * after its notification, the panel closes on Escape and takes focus on open,
 * the bell announces its unread count and whether the panel is open, and the
 * type colours come from tokens instead of six literals.
 */

import { useState, useEffect, useRef, useCallback, forwardRef } from "react";
import {
  getNotifications,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  deleteNotification,
} from "../api/notifications";
import { CcureTabs } from "../../design-system";
import { useNotificationPresentation } from "./notificationPresentation";
import "../navigation/navigation.css";
import "./notifications.css";

/* ── Icons (decorative) ──────────────────────────────────────────────────── */
const Icon = ({ d, size = 16 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path d={d} />
  </svg>
);

const IcoBell = ({ size = 17 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
    <path d="M13.73 21a2 2 0 0 1-3.46 0" />
  </svg>
);
const IcoClose = () => <Icon d="M18 6L6 18M6 6l12 12" />;
const IcoTrash = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoCheck = () => <Icon d="M20 6L9 17l-5-5" />;
const IcoChecks = () => <Icon d="M4 12l4 4L20 6M9 17l4-4" />;

function timeAgo(iso) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/* ── Single notification item ────────────────────────────────────────────── */
function NotifItem({ notif, onRead, onDelete }) {
  const meta = useNotificationPresentation().typeMeta(notif.type);
  return (
    <div
      className={`shn-item ${!notif.is_read ? "shn-item--unread" : ""}`}
      onClick={() => !notif.is_read && onRead(notif.id)}
    >
      <div
        className={`shn-item-icon shn-item-icon--${meta.tone}`}
        aria-hidden="true"
      >
        {meta.emoji}
      </div>
      <div className="shn-item-body">
        <div className="shn-item-title">{notif.title}</div>
        <div className="shn-item-msg">{notif.message}</div>
        <div className="shn-item-time">{timeAgo(notif.created_at)}</div>
      </div>
      <div className="shn-item-actions">
        {!notif.is_read && (
          <button
            type="button"
            className="shn-action-btn shn-action-btn--read"
            title="Mark as read"
            aria-label={`Mark "${notif.title}" as read`}
            onClick={(e) => {
              e.stopPropagation();
              onRead(notif.id);
            }}
          >
            <IcoCheck />
          </button>
        )}
        <button
          type="button"
          className="shn-action-btn shn-action-btn--delete"
          title="Delete"
          aria-label={`Delete "${notif.title}"`}
          onClick={(e) => {
            e.stopPropagation();
            onDelete(notif.id);
          }}
        >
          <IcoTrash />
        </button>
      </div>
    </div>
  );
}

/* ── Bell button (exported for use in AppLayout) ─────────────────────────── */
export const NotificationBell = forwardRef(function NotificationBell(
  { onClick, unreadCount, expanded = false },
  ref,
) {
  const shown = unreadCount > 99 ? "99+" : unreadCount;
  return (
    <button
      type="button"
      ref={ref}
      id="header-notifications-btn"
      className="cc-btn cc-btn--ghost cc-btn--sm sh-iconbtn shn-bell-btn"
      title="Notifications"
      aria-label={`Notifications, ${unreadCount > 0 ? `${shown} unread` : "no unread"}`}
      aria-expanded={expanded}
      aria-controls="sh-notifications"
      onClick={onClick}
    >
      <IcoBell />
      {unreadCount > 0 && (
        <span className="shn-badge" aria-hidden="true">
          {shown}
        </span>
      )}
    </button>
  );
});

/* ── Main panel ──────────────────────────────────────────────────────────── */
export default function NotificationsPanel({
  id = "sh-notifications",
  onClose,
  onUnreadChange,
  liveEvent,
}) {
  const { categories: CATEGORIES } = useNotificationPresentation();
  const [category, setCategory] = useState("all");
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const panelRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const data = await getNotifications({
        category: category === "all" ? undefined : category,
        limit: 50,
      });
      setItems(data);
    } catch {
      setError("Failed to load notifications");
    } finally {
      setLoading(false);
    }
  }, [category]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (liveEvent?.type !== "created" || !liveEvent.notification) return;
    const notif = liveEvent.notification;
    if (category !== "all" && notif.category !== category) return;
    setItems((prev) => {
      if (prev.some((item) => item.id === notif.id)) return prev;
      return [notif, ...prev].slice(0, 50);
    });
  }, [category, liveEvent]);

  const refreshUnreadCount = useCallback(async () => {
    if (!onUnreadChange) return;
    try {
      const summary = await getUnreadCount();
      onUnreadChange(summary.total_unread || 0);
    } catch {
      /* ignore */
    }
  }, [onUnreadChange]);

  // Escape closes; the owner restores focus to the bell.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Focus lands in the panel on open so a keyboard user is inside it.
  useEffect(() => {
    panelRef.current?.focus?.();
  }, []);

  // Click-outside to close
  useEffect(() => {
    const h = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        const bell = document.getElementById("header-notifications-btn");
        if (bell && bell.contains(e.target)) return;
        onClose();
      }
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [onClose]);

  const handleRead = async (id) => {
    try {
      await markAsRead(id);
      setItems((prev) =>
        prev.map((n) =>
          n.id === id
            ? { ...n, is_read: true, read_at: new Date().toISOString() }
            : n,
        ),
      );
      refreshUnreadCount();
    } catch {
      /* ignore */
    }
  };

  const handleDelete = async (id) => {
    try {
      await deleteNotification(id);
      const next = items.filter((n) => n.id !== id);
      setItems(next);
      refreshUnreadCount();
    } catch {
      /* ignore */
    }
  };

  const handleMarkAll = async () => {
    try {
      await markAllAsRead();
      setItems((prev) => prev.map((n) => ({ ...n, is_read: true })));
      if (onUnreadChange) onUnreadChange(0);
    } catch {
      /* ignore */
    }
  };

  const unread = items.filter((n) => !n.is_read).length;

  const getEmptyMessage = () => {
    if (category === "all") {
      return "No notifications available.";
    }
    const catObj = CATEGORIES.find((c) => c.id === category);
    const label = catObj ? catObj.label : category;
    const displayLabel = label.endsWith("s") ? label.slice(0, -1) : label;
    return `No ${displayLabel} notifications found.`;
  };

  /* A disclosure popover, not a modal. The bell carries aria-expanded and
     aria-controls, there is no scrim, the page behind stays interactive, and an
     outside click or Escape closes it. `role="dialog"` promised modal semantics
     this panel does not implement — a focus trap and an inert background — so
     it names a group instead, which keeps the name without the false promise. */
  return (
    <div
      className="shn-panel"
      ref={panelRef}
      id={id}
      role="group"
      aria-label="Notifications"
      tabIndex={-1}
    >
      {/* Header */}
      <div className="shn-header">
        <div className="shn-header-left">
          <IcoBell />
          <span>Notifications</span>
          {unread > 0 && (
            <span className="shn-header-badge">
              {unread}
              <span className="cc-sr-only"> unread</span>
            </span>
          )}
        </div>
        <div className="shn-header-actions">
          {unread > 0 && (
            <button
              type="button"
              className="shn-text-btn"
              onClick={handleMarkAll}
              title="Mark all as read"
            >
              <IcoChecks /> Mark all read
            </button>
          )}
          <button
            type="button"
            className="shn-close"
            onClick={onClose}
            aria-label="Close notifications"
          >
            <IcoClose />
          </button>
        </div>
      </div>

      {/* Category tabs */}
      <CcureTabs
        className="shn-tabs"
        label="Notification categories"
        tabs={CATEGORIES}
        value={category}
        onChange={(next) => {
          setCategory(next);
          setLoading(true);
        }}
      />

      {/* Body */}
      <div className="shn-body">
        {error && (
          <div className="shn-error" role="alert">
            {error}
          </div>
        )}
        {loading ? (
          <div className="shn-loading" role="status" aria-live="polite">
            <div className="shn-spinner" aria-hidden="true" />
            <span className="cc-sr-only">Loading notifications</span>
          </div>
        ) : items.length === 0 ? (
          <div className="shn-empty">
            <div className="shn-empty-icon" aria-hidden="true">
              🔔
            </div>
            <p>{getEmptyMessage()}</p>
          </div>
        ) : (
          <div className="shn-list">
            {items.map((n) => (
              <NotifItem
                key={n.id}
                notif={n}
                onRead={handleRead}
                onDelete={handleDelete}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
