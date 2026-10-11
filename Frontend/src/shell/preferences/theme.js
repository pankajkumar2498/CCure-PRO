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

export function applyTheme(theme) {
  if (theme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

export function rememberTheme(theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Account persistence still works when browser storage is unavailable.
  }
}
