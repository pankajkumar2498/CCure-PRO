import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const api = vi.hoisted(() => ({
  getCurrentUser: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  refreshSession: vi.fn(),
  register: vi.fn(),
}));
vi.mock("@shell/api/auth", () => api);
vi.mock("@shell/api/axiosInstance", () => ({
  authSession: {
    getAccessToken: () => "token",
    clear: vi.fn(),
    setTokens: vi.fn(),
  },
}));

import { AuthProvider, useAuth } from "@shell/auth/AuthContext";
import { can, activeOrganisationId } from "@shell/auth/authorization";

const payload = (active, keys, canSwitch = true) => ({
  id: "u1",
  org_id: "org_a",
  username: "u",
  role: { name: "Anything", permissions: [] },
  authorization: {
    contract: 1,
    source: "platform",
    home_org_id: "org_a",
    active_org_id: active,
    permissions: { platform: [], organization: keys },
    can_switch_organisation: canSwitch,
    assignments: [],
    atoms: {},
  },
});

let ctx;
function Probe() {
  ctx = useAuth();
  return (
    <div>
      <span data-testid="active">
        {activeOrganisationId(ctx.user) || "none"}
      </span>
      <span data-testid="state">{ctx.authState}</span>
      <span data-testid="read">{String(can(ctx.user, "audit.scan.read"))}</span>
      <span data-testid="purge">
        {String(can(ctx.user, "audit.scan.purge"))}
      </span>
      <span data-testid="version">{ctx.contextVersion}</span>
    </div>
  );
}
const mount = () =>
  render(
    <MemoryRouter>
      <AuthProvider>
        <Probe />
      </AuthProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

describe("organisation context comes from the backend", () => {
  it("stores the organisation the backend accepted, not the previous hint", async () => {
    localStorage.setItem("activeOrgId", "org_forged");
    api.getCurrentUser.mockResolvedValue(
      payload("org_a", ["audit.scan.read"], false),
    );
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("state")).toHaveTextContent("authenticated"),
    );
    expect(localStorage.getItem("activeOrgId")).toBe("org_a");
    expect(screen.getByTestId("active")).toHaveTextContent("org_a");
  });

  it("drops a refused stored organisation and re-fetches without it, rather than signing out", async () => {
    localStorage.setItem("activeOrgId", "org_gone");
    api.getCurrentUser
      .mockRejectedValueOnce({ response: { status: 404 } })
      .mockResolvedValueOnce(payload("org_a", ["audit.scan.read"], false));
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("state")).toHaveTextContent("authenticated"),
    );
    expect(api.getCurrentUser).toHaveBeenLastCalledWith(null);
    expect(localStorage.getItem("activeOrgId")).toBe("org_a");
  });
});

describe("switching is a backend operation", () => {
  it("applies only what the backend returns and refreshes the permissions", async () => {
    api.getCurrentUser.mockResolvedValueOnce(
      payload("org_a", ["audit.scan.read", "audit.scan.purge"]),
    );
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("purge")).toHaveTextContent("true"),
    );

    api.getCurrentUser.mockResolvedValueOnce(
      payload("org_b", ["audit.scan.read"]),
    );
    await act(async () => {
      await ctx.switchOrganisation("org_b");
    });
    expect(api.getCurrentUser).toHaveBeenLastCalledWith("org_b");
    expect(localStorage.getItem("activeOrgId")).toBe("org_b");
    expect(screen.getByTestId("active")).toHaveTextContent("org_b");
    // the previous organisation's permission is gone — no stale authorization
    expect(screen.getByTestId("purge")).toHaveTextContent("false");
    expect(screen.getByTestId("version")).toHaveTextContent("1");
  });

  it("a refusal changes nothing", async () => {
    api.getCurrentUser.mockResolvedValueOnce(
      payload("org_a", ["audit.scan.read"]),
    );
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("read")).toHaveTextContent("true"),
    );
    api.getCurrentUser.mockRejectedValueOnce({ response: { status: 403 } });
    await act(async () => {
      await expect(ctx.switchOrganisation("org_b")).rejects.toBeDefined();
    });
    expect(localStorage.getItem("activeOrgId")).toBe("org_a");
    expect(screen.getByTestId("active")).toHaveTextContent("org_a");
    expect(screen.getByTestId("version")).toHaveTextContent("0");
  });

  it("a backend that answers with a different organisation is not trusted to have switched", async () => {
    api.getCurrentUser.mockResolvedValueOnce(
      payload("org_a", ["audit.scan.read"], false),
    );
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("read")).toHaveTextContent("true"),
    );
    api.getCurrentUser.mockResolvedValueOnce(
      payload("org_a", ["audit.scan.read"], false),
    ); // ignored the request
    await act(async () => {
      await expect(ctx.switchOrganisation("org_b")).rejects.toThrow();
    });
    expect(localStorage.getItem("activeOrgId")).toBe("org_a");
    expect(screen.getByTestId("version")).toHaveTextContent("0");
  });

  it("an authorization payload the UI does not understand grants nothing", async () => {
    const bad = payload("org_a", ["audit.scan.read"]);
    bad.authorization.contract = 7;
    api.getCurrentUser.mockResolvedValueOnce(bad);
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("state")).toHaveTextContent("authenticated"),
    );
    expect(screen.getByTestId("read")).toHaveTextContent("false");
  });
});
