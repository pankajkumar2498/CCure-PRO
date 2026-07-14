import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import PrivateRoute from "../../components/PrivateRoute";
import AuthContext from "../../context/AuthContext";

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
});
