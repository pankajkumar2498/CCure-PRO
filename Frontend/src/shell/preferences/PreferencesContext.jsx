import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useRef,
} from "react";
import { getPreferences, updatePreferences } from "../api/user";
import { useAuth } from "../auth/AuthContext";
import { readTheme, rememberTheme } from "./theme";

const PreferencesContext = createContext(null);

export function PreferencesProvider({ children }) {
  const { isAuthenticated } = useAuth();
  const [preferences, setPreferences] = useState(null);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme] = useState(readTheme);
  const [savingTheme, setSavingTheme] = useState(false);
  const themeRequest = useRef(false);
  const requestVersion = useRef(null);

  const updateLocalPreferences = useCallback((newPrefs) => {
    setPreferences(newPrefs);
    if (newPrefs.theme === "light" || newPrefs.theme === "dark") {
      setTheme(newPrefs.theme);
      rememberTheme(newPrefs.theme);
    }
    if (newPrefs.sidebar_collapsed !== undefined) {
      try {
        localStorage.setItem("sidebarCollapsed", newPrefs.sidebar_collapsed);
      } catch {
        // The server preference remains available without a browser cache.
      }
    }
  }, []);

  const loadPreferences = useCallback(async () => {
    const version = Symbol();
    requestVersion.current = version;
    if (!isAuthenticated) {
      setPreferences(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const prefs = await getPreferences();
      if (version === requestVersion.current) updateLocalPreferences(prefs);
    } catch {
      if (version === requestVersion.current) setPreferences(null);
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  }, [isAuthenticated, updateLocalPreferences]);

  useEffect(() => {
    loadPreferences();
    return () => {
      requestVersion.current = null;
    };
  }, [loadPreferences]);

  const toggleTheme = useCallback(async () => {
    if (!isAuthenticated || loading || themeRequest.current) return;
    themeRequest.current = true;
    setSavingTheme(true);
    const version = requestVersion.current;
    try {
      // Send only this preference; keep product and notification settings intact.
      const updated = await updatePreferences({
        theme: theme === "dark" ? "light" : "dark",
      });
      if (version === requestVersion.current) updateLocalPreferences(updated);
    } finally {
      themeRequest.current = false;
      setSavingTheme(false);
    }
  }, [isAuthenticated, loading, theme, updateLocalPreferences]);

  return (
    <PreferencesContext.Provider
      value={{
        preferences,
        loading,
        theme,
        savingTheme,
        toggleTheme,
        updateLocalPreferences,
        refreshPreferences: loadPreferences,
      }}
    >
      {children}
    </PreferencesContext.Provider>
  );
}

export function usePreferences() {
  const ctx = useContext(PreferencesContext);
  if (!ctx) {
    throw new Error("usePreferences must be used within a PreferencesProvider");
  }
  return ctx;
}
