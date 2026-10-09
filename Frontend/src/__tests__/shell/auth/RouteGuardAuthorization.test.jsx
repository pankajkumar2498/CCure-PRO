import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import PrivateRoute from "@shell/auth/PrivateRoute";
import AuthContext from "@shell/auth/AuthContext";

const authz = (platform = [], organization = []) => ({
  contract: 1,
  source: "platform",
  home_org_id: "o",
  active_org_id: "o",
  permissions: { platform, organization },
  can_switch_organisation: false,
  assignments: [],
  atoms: {},
});

const renderAt = (user, element, authState = "authenticated") =>
  render(
    <AuthContext.Provider value={{ loading: false, user, authState }}>
      <MemoryRouter initialEntries={["/x"]}>
        <Routes>
          <Route path="/login" element={<div>Login</div>} />
          <Route path="/x" element={element} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );

const guard = (props, text = "Secret") => (
  <PrivateRoute deniedElement={<div>Denied</div>} {...props}>
    <div>{text}</div>
  </PrivateRoute>
);

describe("route guards are permission-based", () => {
  it("lets a holder of the key in", () => {
    renderAt(
      { authorization: authz(["platform.email_domain.read"]) },
      guard({ requiredPermission: "platform.email_domain.read" }),
    );
    expect(screen.getByText("Secret")).toBeInTheDocument();
  });

  it("refuses a user without the key, whatever their role says", () => {
    renderAt(
      { role: { name: "superadmin", permissions: [] }, authorization: authz() },
      guard({ requiredPermission: "platform.email_domain.read" }),
    );
    expect(screen.getByText("Denied")).toBeInTheDocument();
  });

  it("keeps the three outcomes distinct: unauthenticated, unauthorized, authorized", () => {
    renderAt(
      null,
      guard({ requiredPermission: "audit.scan.read" }),
      "anonymous",
    );
    expect(screen.getByText("Login")).toBeInTheDocument();
  });

  it("requiredAny and requiredAll read the same payload", () => {
    const u = { authorization: authz([], ["audit.scan.read"]) };
    renderAt(
      u,
      guard({ requiredAny: ["audit.scan.purge", "audit.scan.read"] }),
    );
    expect(screen.getByText("Secret")).toBeInTheDocument();
  });

  it("a forged role or stored organisation cannot open a guarded route", () => {
    localStorage.setItem("activeOrgId", "other");
    renderAt(
      {
        role: { name: "superadmin", permissions: ["audit:read"] },
        authorization: authz([], []),
      },
      guard({ requiredPermission: { resource: "audit", action: "read" } }),
    );
    expect(screen.getByText("Denied")).toBeInTheDocument();
    localStorage.removeItem("activeOrgId");
  });

  it("an organisation key is not honoured for another organisation", () => {
    const u = { authorization: authz([], ["audit.scan.read"]) };
    renderAt(u, guard({ requiredPermission: "audit.scan.read" }));
    expect(screen.getByText("Secret")).toBeInTheDocument();
  });
});
