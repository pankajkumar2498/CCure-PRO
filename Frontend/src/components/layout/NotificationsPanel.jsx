/**
 * src/components/layout/NotificationsPanel.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Dropdown notification center with:
 *   • Real-time unread badge on the bell icon
 *   • Category filter tabs (All / Scan / Security / System)
 *   • Mark individual / all as read
 *   • Delete individual notifications
 *   • Auto-polling every 30 seconds
 */

import { useState, useEffect, useRef, useCallback } from "react";
import {
  getNotifications,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  deleteNotification,
} from "../../api/notifications";

/* ── Icons ───────────────────────────────────────────────────────────────── */
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
  >
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
    <path d="M13.73 21a2 2 0 0 1-3.46 0" />
  </svg>
);
const IcoClose = () => <Icon d="M18 6L6 18M6 6l12 12" />;
const IcoTrash = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoCheck = () => <Icon d="M20 6L9 17l-5-5" />;
const IcoChecks = () => <Icon d="M4 12l4 4L20 6M9 17l4-4" />;

/* ── Category config ─────────────────────────────────────────────────────── */
const CATEGORIES = [
  { id: "all", label: "All" },
  { id: "scan", label: "Scans" },
  { id: "security", label: "Security" },
  { id: "system", label: "System" },
  { id: "admin", label: "Admin" },
];

/* ── Type icons / colors ─────────────────────────────────────────────────── */
const TYPE_META = {
  scan_completed: { emoji: "✅", color: "#22c55e", bg: "rgba(34,197,94,.12)" },
  scan_failed: { emoji: "❌", color: "#ef4444", bg: "rgba(239,68,68,.12)" },
  scan_paused: { emoji: "⏸", color: "#f59e0b", bg: "rgba(245,158,11,.12)" },
  vulnerability_found: {
    emoji: "🚨",
    color: "#ef4444",
    bg: "rgba(239,68,68,.12)",
  },
  system_message: { emoji: "ℹ️", color: "#60a5fa", bg: "rgba(96,165,250,.12)" },
  admin_notice: { emoji: "🔔", color: "#a78bfa", bg: "rgba(167,139,250,.12)" },
};

function getTypeMeta(type) {
  return (
    TYPE_META[type] || {
      emoji: "📢",
      color: "#64748b",
      bg: "rgba(100,116,139,.12)",
    }
  );
}

function timeAgo(iso) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/* ── Single notification item ────────────────────────────────────────────── */
function NotifItem({ notif, onRead, onDelete }) {
  const meta = getTypeMeta(notif.type);
  return (
    <div
      className={`np-item ${!notif.is_read ? "np-item--unread" : ""}`}
      onClick={() => !notif.is_read && onRead(notif.id)}
    >
      <div
        className="np-item-icon"
        style={{ background: meta.bg, color: meta.color }}
      >
        {meta.emoji}
      </div>
      <div className="np-item-body">
        <div className="np-item-title">{notif.title}</div>
        <div className="np-item-msg">{notif.message}</div>
        <div className="np-item-time">{timeAgo(notif.created_at)}</div>
      </div>
      <div className="np-item-actions">
        {!notif.is_read && (
          <button
            className="np-action-btn np-action-btn--read"
            title="Mark as read"
            onClick={(e) => {
              e.stopPropagation();
              onRead(notif.id);
            }}
          >
            <IcoCheck />
          </button>
        )}
        <button
          className="np-action-btn np-action-btn--delete"
          title="Delete"
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
export function NotificationBell({ onClick, unreadCount }) {
  return (
    <button
      id="header-notifications-btn"
      className="btn-icon btn-icon--round np-bell-btn"
      title="Notifications"
      onClick={onClick}
    >
      <IcoBell />
      {unreadCount > 0 && (
        <span className="np-badge">
          {unreadCount > 99 ? "99+" : unreadCount}
        </span>
      )}
    </button>
  );
}

/* ── Main panel ──────────────────────────────────────────────────────────── */
export default function NotificationsPanel({
  onClose,
  onUnreadChange,
  liveEvent,
}) {
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

  return (
    <div
      className="np-panel"
      ref={panelRef}
      role="dialog"
      aria-label="Notifications"
    >
      {/* Header */}
      <div className="np-header">
        <div className="np-header-left">
          <IcoBell />
          <span>Notifications</span>
          {unread > 0 && <span className="np-header-badge">{unread}</span>}
        </div>
        <div className="np-header-actions">
          {unread > 0 && (
            <button
              className="np-text-btn"
              onClick={handleMarkAll}
              title="Mark all as read"
            >
              <IcoChecks /> Mark all read
            </button>
          )}
          <button className="np-close" onClick={onClose}>
            <IcoClose />
          </button>
        </div>
      </div>

      {/* Category tabs */}
      <div className="np-tabs">
        {CATEGORIES.map((cat) => (
          <button
            key={cat.id}
            className={`np-tab ${category === cat.id ? "np-tab--active" : ""}`}
            onClick={() => {
              setCategory(cat.id);
              setLoading(true);
            }}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Body */}
      <div className="np-body">
        {error && <div className="np-error">{error}</div>}
        {loading ? (
          <div className="np-loading">
            <div className="np-spinner" />
          </div>
        ) : items.length === 0 ? (
          <div className="np-empty">
            <div className="np-empty-icon">🔔</div>
            <p>{getEmptyMessage()}</p>
          </div>
        ) : (
          <div className="np-list">
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
