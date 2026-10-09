/**
 * Some Audit endpoints describe an item with an emoji (`icon: "🌐"`): the
 * dashboard's insight cards and the asset timeline's categories. The API is
 * unchanged; the page draws the application's icon for that meaning instead, so
 * the same mark appears in every module and on every platform.
 *
 * A glyph this table does not know falls back to the caller's choice rather
 * than being printed, because an unknown emoji is exactly the inconsistency the
 * icon set exists to remove.
 */

const GLYPH_ICON = {
  "🌐": "globe",
  "⏰": "clock",
  "🔓": "unlock",
  "📡": "radio",
  "🔥": "alert-octagon",
  "🖥": "monitor",
  "💻": "monitor",
  "🛡": "shield",
  "♻": "refresh-cw",
  "🔗": "link",
  "🏷": "tag",
  "🏭": "settings",
  "📛": "tag",
  "🔐": "lock",
  "🔒": "lock",
  "⚠": "alert-triangle",
  "🚨": "alert-octagon",
  "👤": "user",
  "📦": "package",
  "🔌": "link",
};

/** The asset timeline's five categories (core/audit_event_translator.py). */
export const TIMELINE_CATEGORY_ICON = {
  asset_identification: "monitor",
  operating_system: "layers",
  network: "globe",
  security: "shield",
  lifecycle: "refresh-cw",
};

export function iconForBackendGlyph(glyph, fallback = "flag") {
  if (typeof glyph !== "string") return fallback;
  return GLYPH_ICON[glyph.replace(/️/g, "")] || fallback;
}
