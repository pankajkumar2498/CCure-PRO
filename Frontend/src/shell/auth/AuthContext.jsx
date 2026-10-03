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
import { activeOrganisationId, authorizationOf } from "./authorization";

const AuthContext = createContext(null);

// `activeOrgId` in localStorage is only the *hint* the HTTP client sends as `org_id`
// on every request; it is never evidence. What the backend accepted as the active
// organisation is `user.authorization.active_org_id`, and that — not the previous
// hint, not a role — is what is stored. A forged or stale hint is therefore
// overwritten with the backend's answer on the next sync.
const syncActiveOrgId = (user) => {
  const active = user ? activeOrganisationId(user) : null;
  if (active) {
    localStorage.setItem("activeOrgId", active);
  } else {
    localStorage.removeItem("activeOrgId");
  }
};

// The signed-in account with its authorization. A stored organisation the backend
// refuses (403/404: inactive, gone, no longer reachable) is dropped and the account
// is fetched again without it, rather than signing the person out.
const fetchCurrentUser = async () => {
  try {
    return await getCurrentUser();
  } catch (error) {
    const status = error?.response?.status;
    if (
      (status === 403 || status === 404) &&
      localStorage.getItem("activeOrgId")
    ) {
      localStorage.removeItem("activeOrgId");
      return getCurrentUser(null);
    }
    throw error;
  }
};

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [authState, setAuthState] = useState("loading");
  const [authMessage, setAuthMessage] = useState("");
  // Bumped when the organisation context changes, so anything derived from the
  // previous organisation's permissions can be discarded.
  const [contextVersion, setContextVersion] = useState(0);
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
      const currentUser = await fetchCurrentUser();
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
    // The login response carries the profile only; the authorization payload comes
    // from /auth/me, so the UI never holds a user without the backend's answer.
    let signedIn = data.user || null;
    try {
      signedIn = await fetchCurrentUser();
    } catch {
      // keep the login response's profile; it carries no authorization, so the UI
      // grants nothing beyond the legacy atoms until the next sync
    }
    if (signedIn) {
      syncActiveOrgId(signedIn);
    }
    setUser(signedIn);
    setAuthState("authenticated");
    setAuthMessage("");
    lastSessionRefreshRef.current = Date.now();
    return data;
  }, []);

  // Registration does not sign anyone in. The backend returns 202 with
  // {detail, status: "pending_verification"} and no tokens: the account is
  // created unverified, inactive and unapproved, and cannot log in until the
  // mailbox is confirmed and an administrator approves it.
  //
  // This previously set authState to "authenticated" from the register
  // response, which is why it must not simply be left alone — with no tokens
  // in the response the app would have believed it held a session it did not
  // have, and every subsequent request would 401.
  const register = useCallback(async (payload) => {
    return registerRequest(payload);
  }, []);

  // Switching organisation is a backend operation. The requested id goes to the
  // backend, which validates it against the account's grants and the
  // organisation's state, audits the switch, and answers with the organisation it
  // accepted and the permissions that apply there. Only that answer is stored; a
  // refusal leaves everything as it was.
  const switchOrganisation = useCallback(async (orgId) => {
    const next = await getCurrentUser(orgId);
    const authorization = authorizationOf(next);
    if (!authorization || authorization.active_org_id !== orgId) {
      throw new Error("The organisation was not accepted by the server.");
    }
    syncActiveOrgId(next);
    setUser(next);
    setContextVersion((version) => version + 1);
    return next;
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
      switchOrganisation,
      contextVersion,
    }),
    [
      user,
      authState,
      authMessage,
      login,
      register,
      logout,
      syncCurrentUser,
      switchOrganisation,
      contextVersion,
    ],
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
