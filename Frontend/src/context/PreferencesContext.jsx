import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
} from "react";
import { getPreferences } from "../api/user";
import { useAuth } from "@shell/auth/AuthContext";

const PreferencesContext = createContext(null);

export function PreferencesProvider({ children }) {
  const { isAuthenticated } = useAuth();
  const [preferences, setPreferences] = useState(null);
  const [loading, setLoading] = useState(true);

  const applyTheme = (theme) => {
    if (theme === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  };

  const loadPreferences = useCallback(async () => {
    if (!isAuthenticated) {
      setPreferences(null);
      setLoading(false);
      return;
    }

    try {
      const prefs = await getPreferences();
      setPreferences(prefs);
      applyTheme(prefs.theme);
      // We can also sync sidebarCollapsed with localStorage as fallback
      if (prefs.sidebar_collapsed !== undefined) {
        localStorage.setItem("sidebarCollapsed", prefs.sidebar_collapsed);
      }
    } catch {
      setPreferences(null);
    } finally {
      setLoading(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    loadPreferences();
  }, [loadPreferences]);

  const updateLocalPreferences = useCallback((newPrefs) => {
    setPreferences(newPrefs);
    applyTheme(newPrefs.theme);
    if (newPrefs.sidebar_collapsed !== undefined) {
      localStorage.setItem("sidebarCollapsed", newPrefs.sidebar_collapsed);
    }
  }, []);

  return (
    <PreferencesContext.Provider
      value={{
        preferences,
        loading,
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
