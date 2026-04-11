import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  getCurrentUser,
  login as loginRequest,
  logout as logoutRequest,
  refreshSession,
  register as registerRequest,
} from "../api/auth";
import { authSession } from "../api/axiosInstance";

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [authState, setAuthState] = useState("loading");
  const [authMessage, setAuthMessage] = useState("");

  const syncCurrentUser = useCallback(async () => {
    const hadAccessToken = !!authSession.getAccessToken();
    let hadRecoverableSession = hadAccessToken;

    setAuthState("loading");

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
      setUser(currentUser);
      setAuthState("authenticated");
      setAuthMessage("");
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

  const login = useCallback(async (credentials) => {
    const data = await loginRequest(credentials);
    setUser(data.user || null);
    setAuthState("authenticated");
    setAuthMessage("");
    return data;
  }, []);

  const register = useCallback(async (payload) => {
    const data = await registerRequest(payload);
    setUser(data.user || null);
    setAuthState("authenticated");
    setAuthMessage("");
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await logoutRequest();
    } finally {
      setUser(null);
      setAuthState("anonymous");
      setAuthMessage("");
    }
  }, []);

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
    [user, authState, authMessage, login, register, logout, syncCurrentUser]
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
