/**
 * src/shell/notifications/notificationPresentation.jsx — how a notification looks.
 * ─────────────────────────────────────────────────────────────────────────────
 * The notification panel is the platform's and shows every product's
 * notifications. What it knows by itself is the platform's own vocabulary:
 * `system_message`, `admin_notice`, and the `security`, `system` and `admin`
 * categories. A product describes the types and categories it raises — an icon
 * and a tone per type, a tab per category — and the composition root hands them
 * to the shell here (the same pattern as `accessFallback.jsx`), so the shell
 * never names a product's vocabulary and never imports one.
 *
 * An unknown type renders with a neutral icon, not an error: a notification
 * from a product (or a later version) the build does not describe is still shown.
 */
import { createContext, useContext, useMemo } from "react";

/** `tone` resolves to a token pair in app-shell.css (shn-item-icon--<tone>). */
const PLATFORM_TYPES = {
  system_message: { icon: "info", tone: "info" },
  admin_notice: { icon: "bell", tone: "primary" },
};

const UNKNOWN_TYPE = { icon: "message-square", tone: "neutral" };

const ALL = { id: "all", label: "All" };
const PLATFORM_CATEGORIES = [
  { id: "security", label: "Security" },
  { id: "system", label: "System" },
  { id: "admin", label: "Admin" },
];

const DEFAULT = Object.freeze({
  typeMeta: (type) => PLATFORM_TYPES[type] || UNKNOWN_TYPE,
  categories: [ALL, ...PLATFORM_CATEGORIES],
});

const NotificationPresentationContext = createContext(DEFAULT);

/**
 * `types`: `{ <type>: { icon, tone } }`, `icon` a CcureIcon name. `categories`: `[{ id, label }]`, shown
 * after "All" and before the platform's own, in the order given. Platform
 * entries win a clash: a product cannot restyle the platform's notifications.
 */
export function NotificationPresentationProvider({
  types,
  categories,
  children,
}) {
  const value = useMemo(() => {
    const merged = { ...types, ...PLATFORM_TYPES };
    const own = new Set(PLATFORM_CATEGORIES.map((c) => c.id));
    return {
      typeMeta: (type) => merged[type] || UNKNOWN_TYPE,
      categories: [
        ALL,
        ...(categories || []).filter((c) => c.id !== "all" && !own.has(c.id)),
        ...PLATFORM_CATEGORIES,
      ],
    };
  }, [types, categories]);
  return (
    <NotificationPresentationContext.Provider value={value}>
      {children}
    </NotificationPresentationContext.Provider>
  );
}

export const useNotificationPresentation = () =>
  useContext(NotificationPresentationContext);
