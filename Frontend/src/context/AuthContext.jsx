/**
 * src/context/AuthContext.jsx
 *
 * Global auth state. Wrap your app in <AuthProvider>.
 * Use the useAuth() hook anywhere to access:
 *   - user          → current user object or null
 *   - loading       → true while we verify the stored token on mount
 *   - login()       → async (email, password) → throws on failure
 *   - register()    → async (username, email, password) → throws on failure
 *   - logout()      → clears tokens + redirects to /login
 */

import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser, registerUser, logoutUser, getCurrentUser } from "../api/auth";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate              = useNavigate();

  // ── On mount: check if we already have a valid access token ───────────────
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) {
      setLoading(false);
      return;
    }
    getCurrentUser()
      .then(({ data }) => setUser(data))
      .catch(() => {
        // Token invalid / expired and refresh also failed (axiosInstance handles that)
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
      })
      .finally(() => setLoading(false));
  }, []);

  // ── Persist tokens returned by login / register ───────────────────────────
  const _saveTokens = ({ access_token, refresh_token, user: u }) => {
    localStorage.setItem("access_token",  access_token);
    localStorage.setItem("refresh_token", refresh_token);
    setUser(u);
  };

  // ── login ─────────────────────────────────────────────────────────────────
  const login = useCallback(async (email, password, redirectTo = "/scan") => {
    const { data } = await loginUser(email, password);
    _saveTokens(data);
    navigate(redirectTo, { replace: true });
  }, [navigate]);

  // ── register ──────────────────────────────────────────────────────────────
  const register = useCallback(async (username, email, password, redirectTo = "/scan") => {
    const { data } = await registerUser(username, email, password);
    _saveTokens(data);
    navigate(redirectTo, { replace: true });
  }, [navigate]);

  // ── logout ────────────────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    try { await logoutUser(); } catch (_) { /* fire and forget */ }
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
