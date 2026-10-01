import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import PrivateRoute from "@shell/auth/PrivateRoute";
import AuthContext from "@shell/auth/AuthContext";
import { AccessFallbackProvider } from "@shell/auth/accessFallback";

describe("PrivateRoute Component", () => {
  const renderWithAuth = (authValue, route = "/dashboard") => {
    return render(
      <AuthContext.Provider value={authValue}>
        <MemoryRouter initialEntries={[route]}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/dashboard"
              element={
                <PrivateRoute
                  requiredPermission={{ resource: "scans", action: "execute" }}
                >
                  <div>Dashboard Area</div>
                </PrivateRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>,
    );
  };

  it("shows a loading spinner when auth state is loading", () => {
    renderWithAuth({ loading: true });
    expect(document.querySelector(".spinner")).toBeInTheDocument();
  });

  it("redirects to login if user is not authenticated", () => {
    renderWithAuth({ loading: false, user: null, authState: "anonymous" });
    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });

  it("renders children if user is authenticated and authorized", () => {
    const user = { role: { name: "admin", permissions: ["scans:execute"] } };
    renderWithAuth({ loading: false, user, authState: "authenticated" });
    expect(screen.getByText("Dashboard Area")).toBeInTheDocument();
  });

  it("redirects unauthorized users away from protected routes", () => {
    // User without scans:execute permission
    const user = { role: { name: "viewer", permissions: [] } };
    renderWithAuth({ loading: false, user, authState: "authenticated" });
    expect(screen.queryByText("Dashboard Area")).not.toBeInTheDocument();
  });

  /* ── Phase 12.3: the shell holds the fallback rule; a product names the
     pages. Behaviour with Audit's list is pinned in AppRoutes.test.jsx. ── */
  const refused = (candidates, permissions) =>
    render(
      <AuthContext.Provider
        value={{
          loading: false,
          authState: "authenticated",
          user: { role: { name: "analyst", permissions } },
        }}
      >
        <AccessFallbackProvider candidates={candidates}>
          <MemoryRouter initialEntries={["/locked"]}>
            <Routes>
              <Route
                path="/locked"
                element={
                  <PrivateRoute
                    requiredPermission={{ resource: "roles", action: "read" }}
                  >
                    <div>Locked page</div>
                  </PrivateRoute>
                }
              />
              <Route path="/first" element={<div>First fallback</div>} />
              <Route path="/second" element={<div>Second fallback</div>} />
              <Route path="/login" element={<div>Login Page</div>} />
            </Routes>
          </MemoryRouter>
        </AccessFallbackProvider>
      </AuthContext.Provider>,
    );
  const CANDIDATES = [
    { path: "/first", permission: { resource: "scans", action: "execute" } },
    { path: "/second", permission: { resource: "scans", action: "read" } },
  ];

  it("a refusal goes to the first candidate the user may open", () => {
    refused(CANDIDATES, ["scans:read"]);
    expect(screen.getByText("Second fallback")).toBeInTheDocument();
  });

  it("with no product candidates a refusal goes to sign-in, never to CCure Home", () => {
    refused([], ["scans:read", "scans:execute"]);
    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });
});
