import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import PrivateRoute from "@shell/auth/PrivateRoute";
import AuthContext from "@shell/auth/AuthContext";
import { AccessFallbackProvider } from "@shell/auth/accessFallback";
import { payload } from "../../fixtures/authorization";

const holder = (...keys) => ({ authorization: payload({ keys }) });

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
                <PrivateRoute requiredPermission="audit.scan.run">
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
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Loading account");
  });

  it("redirects to login if user is not authenticated", () => {
    renderWithAuth({ loading: false, user: null, authState: "anonymous" });
    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });

  it("renders children if user is authenticated and authorized", () => {
    const user = holder("audit.scan.run");
    renderWithAuth({ loading: false, user, authState: "authenticated" });
    expect(screen.getByText("Dashboard Area")).toBeInTheDocument();
  });

  it("redirects unauthorized users away from protected routes", () => {
    // User without scans:execute permission
    const user = holder("audit.scan.read");
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
          user: holder(...permissions),
        }}
      >
        <AccessFallbackProvider candidates={candidates}>
          <MemoryRouter initialEntries={["/locked"]}>
            <Routes>
              <Route
                path="/locked"
                element={
                  <PrivateRoute requiredPermission="platform.role.read">
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
    { path: "/first", permission: "audit.scan.run" },
    { path: "/second", permission: "audit.scan.read" },
  ];

  it("a refusal goes to the first candidate the user may open", () => {
    refused(CANDIDATES, ["audit.scan.read"]);
    expect(screen.getByText("Second fallback")).toBeInTheDocument();
  });

  it("with no product candidates a refusal goes to sign-in, never to CCure Home", () => {
    refused([], ["audit.scan.read", "audit.scan.run"]);
    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });

  it("an incompatible backend is reported plainly, never guessed around", () => {
    renderWithAuth({
      loading: false,
      user: null,
      authState: "incompatible",
      authMessage: "This server does not provide the authorization contract",
    });
    expect(screen.getByRole("alert")).toHaveTextContent(
      "does not provide the authorization contract",
    );
    expect(screen.queryByText("Login Page")).not.toBeInTheDocument();
  });
});
