// Cache the confirmed account preference so a reload uses it before API startup.
// The account preferences API remains authoritative after sign-in.
export const THEME_STORAGE_KEY = "ccure.theme";

export function readTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) === "dark"
      ? "dark"
      : "light";
  } catch {
    return "light";
  }
}

/**
 * Set `data-theme` on <html>. Called before the first render and, after that,
 * only from PreferencesProvider's layout effect, never from a network callback.
 *
 * WebKit keeps the old theme on a subtree that holds a <select> when the theme
 * changes between React building that subtree (detached) and the browser first
 * styling it: the subtree's root stays light inside a dark page, with dark-theme
 * text on it (cr-report, Browser Matrix webkit). Chromium and Firefox do not.
 * A subtree WebKit has already styled follows the change correctly. Hence two
 * rules: the change happens inside a React commit, which never yields, so no
 * subtree built under one theme is inserted after the flip; and pending style
 * is settled first, so what the same commit inserted is styled under the theme
 * it was built for and then follows the flip like anything else on the page.
 */
export function applyTheme(theme) {
  const root = document.documentElement;
  const next = theme === "dark" ? "dark" : null;
  if (root.getAttribute("data-theme") === next) return;
  void root.offsetHeight;
  if (next) root.setAttribute("data-theme", next);
  else root.removeAttribute("data-theme");
}

export function rememberTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Account persistence still works when browser storage is unavailable.
  }
}
