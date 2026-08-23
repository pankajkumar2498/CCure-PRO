import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";

import WebScanningRoutes from "../../../modules/web-scanning/WebScanningRoutes";

/**
 * Route resolution for the web-scanning module.
 *
 * Written to pin the behaviour that actually exists, measured by rendering the
 * real component, rather than the behaviour anyone assumed it had. That
 * distinction cost a round of analysis: `/web-scans/<anything>` looks like it
 * should hit the `path="*"` fallback, and it does not — `<Route path=":id">`
 * matches any single segment first, so an unknown one-segment path renders
 * ScanDetail. The fallback only sees paths of two segments or more.
 *
 * The value of the file is as an upgrade guard. React Router 7 turns on
 * `v7_relativeSplatPath` by default, which changes how a relative target
 * resolves inside a splat route — and WebScanningRoutes redirects relatively
 * (`<Navigate to="dashboard">`) from inside `/web-scans/*`. Asserting the
 * destination of every branch means a router upgrade that silently moves any
 * of them fails here instead of in front of a user.
 */

vi.mock("../../../modules/web-scanning/pages/WebDashboard", () => ({
  default: () => <div>web-dashboard-page</div>,
}));
vi.mock("../../../modules/web-scanning/pages/ScanList", () => ({
  default: () => <div>scan-list-page</div>,
}));
vi.mock("../../../modules/web-scanning/pages/NewWebScan", () => ({
  default: () => <div>new-web-scan-page</div>,
}));
vi.mock("../../../modules/web-scanning/pages/ScanDetail", () => ({
  default: () => <div>scan-detail-page</div>,
}));
vi.mock("../../../modules/web-scanning/pages/FindingsExplorer", () => ({
  default: () => <div>findings-explorer-page</div>,
}));
vi.mock("../../../modules/web-scanning/pages/AssetInventory", () => ({
  default: () => <div>asset-inventory-page</div>,
}));

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="pathname">{location.pathname}</div>;
}

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <LocationProbe />
      <Routes>
        {/* Mounted exactly as App.jsx mounts it, splat included. The splat is
            the point: relative resolution inside one is what React Router 7
            changes the default for. */}
        <Route path="/web-scans/*" element={<WebScanningRoutes />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("WebScanningRoutes", () => {
  describe("named child routes resolve without redirecting", () => {
    const cases = [
      ["/web-scans/dashboard", "web-dashboard-page"],
      ["/web-scans/list", "scan-list-page"],
      ["/web-scans/new", "new-web-scan-page"],
      ["/web-scans/abc123/findings", "findings-explorer-page"],
      ["/web-scans/abc123/assets", "asset-inventory-page"],
    ];

    for (const [path, expected] of cases) {
      it(`${path} renders ${expected}`, () => {
        renderAt(path);
        expect(screen.getByText(expected)).toBeInTheDocument();
        expect(screen.getByTestId("pathname")).toHaveTextContent(path);
      });
    }
  });

  it("treats an unknown single segment as a scan id, not a miss", () => {
    // `:id` is declared before the splat and matches any one segment, so this
    // is ScanDetail rather than the fallback. Asserted because it is the
    // opposite of what the route table suggests at a glance, and because a
    // reordering of those two routes would silently change it.
    renderAt("/web-scans/this-is-not-a-known-page");

    expect(screen.getByText("scan-detail-page")).toBeInTheDocument();
    expect(screen.getByTestId("pathname")).toHaveTextContent(
      "/web-scans/this-is-not-a-known-page",
    );
  });

  describe("the splat fallback redirects to the module dashboard", () => {
    // Awaited rather than read straight after render: <Navigate> performs the
    // redirect from an effect, so the first commit still shows the original
    // path and a synchronous assertion measures the render before the redirect.
    const cases = ["/web-scans/deep/unknown/path", "/web-scans/"];

    for (const path of cases) {
      it(`${path} lands on /web-scans/dashboard`, async () => {
        renderAt(path);

        await waitFor(() =>
          expect(screen.getByTestId("pathname")).toHaveTextContent(
            "/web-scans/dashboard",
          ),
        );
        expect(screen.getByText("web-dashboard-page")).toBeInTheDocument();
      });
    }
  });
});
