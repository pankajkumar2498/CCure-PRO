export function parseDate(value) {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;

  let text = String(value).trim();
  if (!text || text.toLowerCase() === "invalid date") return null;

  // Repair older API values such as 2026-04-28T10:30:00+00:00Z.
  text = text.replace(/([+-]\d{2}:\d{2})Z$/, "$1");

  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function formatDateTime(value, options = {}) {
  const date = parseDate(value);
  if (!date) return "—";
  return date.toLocaleString(undefined, options);
}

export function dateTimeMs(value) {
  const date = parseDate(value);
  return date ? date.getTime() : 0;
}
