/**
 * src/context/AuthContext.jsx
 * Provides: user, loading, login(), register(), logout()
 * Tokens are stored in localStorage; auto-restored on mount.
 */
import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser, registerUser, logoutUser, getCurrentUser } from "../api/auth";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate              = useNavigate();

  // Restore session on mount
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) { setLoading(false); return; }
    getCurrentUser()
      .then(({ data }) => setUser(data))
      .catch(() => {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
      })
      .finally(() => setLoading(false));
  }, []);

  const _saveTokens = ({ access_token, refresh_token, user: u }) => {
    localStorage.setItem("access_token",  access_token);
    localStorage.setItem("refresh_token", refresh_token);
    setUser(u);
  };

  const login = useCallback(async (email, password, redirectTo = "/dashboard") => {
    const { data } = await loginUser(email, password);
    _saveTokens(data);
    navigate(redirectTo, { replace: true });
  }, [navigate]);

  const register = useCallback(async (username, email, password, redirectTo = "/dashboard") => {
    const { data } = await registerUser(username, email, password);
    _saveTokens(data);
    navigate(redirectTo, { replace: true });
  }, [navigate]);

  const logout = useCallback(async () => {
    try { await logoutUser(); } catch (_) {}
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    setUser(null);
    navigate("/login");
  }, [navigate]);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
};
