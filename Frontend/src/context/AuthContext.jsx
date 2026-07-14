import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useNavigate } from "react-router-dom";
import {
  getCurrentUser,
  login as loginRequest,
  logout as logoutRequest,
  refreshSession,
  register as registerRequest,
} from "../api/auth";
import { authSession } from "../api/axiosInstance";

const AuthContext = createContext(null);

const syncActiveOrgId = (user) => {
  if (!user) {
    localStorage.removeItem("activeOrgId");
    return;
  }
  const roleName = (user.role?.name || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");
  if (roleName === "superadmin") {
    if (!localStorage.getItem("activeOrgId") && user.org_id) {
      localStorage.setItem("activeOrgId", user.org_id);
    }
  } else {
    if (user.org_id) {
      localStorage.setItem("activeOrgId", user.org_id);
    } else {
      localStorage.removeItem("activeOrgId");
    }
  }
};

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [authState, setAuthState] = useState("loading");
  const [authMessage, setAuthMessage] = useState("");
  const lastSessionRefreshRef = useRef(0);

  const syncCurrentUser = useCallback(async (quiet = false) => {
    const hadAccessToken = !!authSession.getAccessToken();
    let hadRecoverableSession = hadAccessToken;

    if (!quiet) {
      setAuthState("loading");
    }

    if (!hadAccessToken) {
      try {
        await refreshSession();
        hadRecoverableSession = true;
      } catch (error) {
        setUser(null);
        setAuthState("anonymous");
        setAuthMessage("");
        return null;
      }
    }

    try {
      const currentUser = await getCurrentUser();
      syncActiveOrgId(currentUser);
      setUser(currentUser);
      setAuthState("authenticated");
      setAuthMessage("");
      lastSessionRefreshRef.current = Date.now();
      return currentUser;
    } catch (error) {
      authSession.clear();
      setUser(null);

      if (hadRecoverableSession) {
        setAuthState("expired");
        setAuthMessage("Your session expired. Please sign in again.");
      } else {
        setAuthState("anonymous");
        setAuthMessage("");
      }

      return null;
    }
  }, []);

  useEffect(() => {
    syncCurrentUser();

    const handleForcedLogout = (event) => {
      localStorage.removeItem("activeOrgId");
      setUser(null);

      if (event?.detail?.reason === "expired") {
        setAuthState("expired");
        setAuthMessage("Your session expired. Please sign in again.");
        return;
      }

      setAuthState("anonymous");
      setAuthMessage("");
    };

    window.addEventListener("auth:logout", handleForcedLogout);

    return () => {
      window.removeEventListener("auth:logout", handleForcedLogout);
    };
  }, [syncCurrentUser]);

  useEffect(() => {
    if (authState !== "authenticated") return undefined;

    const refreshActiveSession = async () => {
      try {
        await refreshSession();
        lastSessionRefreshRef.current = Date.now();
      } catch {
        // The axios interceptor owns forced logout when the refresh token is no longer valid.
      }
    };

    const intervalId = window.setInterval(refreshActiveSession, 20 * 60 * 1000);

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        const elapsedSinceRefresh = Date.now() - lastSessionRefreshRef.current;
        if (elapsedSinceRefresh > 10 * 60 * 1000) {
          refreshActiveSession();
        }
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [authState]);

  const login = useCallback(async (credentials) => {
    const data = await loginRequest(credentials);
    if (data?.status === "mfa_required") {
      return data;
    }
    if (data.user) {
      syncActiveOrgId(data.user);
    }
    setUser(data.user || null);
    setAuthState("authenticated");
    setAuthMessage("");
    lastSessionRefreshRef.current = Date.now();
    return data;
  }, []);

  const register = useCallback(async (payload) => {
    const data = await registerRequest(payload);
    if (data.user) {
      syncActiveOrgId(data.user);
    }
    setUser(data.user || null);
    setAuthState("authenticated");
    setAuthMessage("");
    lastSessionRefreshRef.current = Date.now();
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await logoutRequest();
    } finally {
      localStorage.removeItem("activeOrgId");
      sessionStorage.removeItem("postLoginRedirect");
      navigate("/login", { replace: true });
      setUser(null);
      setAuthState("anonymous");
      setAuthMessage("");
    }
  }, [navigate]);

  const value = useMemo(
    () => ({
      user,
      authState,
      authMessage,
      loading: authState === "loading",
      isAuthenticated: !!user,
      login,
      register,
      logout,
      refreshUser: syncCurrentUser,
    }),
    [user, authState, authMessage, login, register, logout, syncCurrentUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside <AuthProvider>");
  }
  return ctx;
};

export default AuthContext;
