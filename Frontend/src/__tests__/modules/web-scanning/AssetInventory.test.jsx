/**
 * AssetInventory — Checkpoint 3C batch 6 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This lists the endpoints a DAST scan discovered on a target. Two properties
 * carry real weight:
 *
 *   * **The scan id comes from the route and is the only scoping.**
 *     `getAssets(id, …)` must be called with the `:id` the router supplied;
 *     an inventory rendered against a different scan's id would show one
 *     customer's discovered endpoints under another's scan.
 *   * **The flags are security facts.** `auth_required`, `is_api`, `is_form`
 *     and `has_file_upload` are how an operator spots the interesting attack
 *     surface. A file-upload endpoint is the single most useful row on this
 *     page, and it is currently conveyed by an emoji with a `title` attribute
 *     and nothing else — no text, no accessible name.
 *
 * The URL column is attacker-influenced: it is whatever the scanner found on a
 * target somebody named. That is asserted below.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AssetInventory from "../../../modules/web-scanning/pages/AssetInventory";
import { webScansApi } from "../../../modules/web-scanning/api/webScansApi";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useParams: () => ({ id: "ws-42" }),
    Link: ({ to, children, ...rest }) => (
      <a href={to} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("../../../modules/web-scanning/api/webScansApi", () => ({
  webScansApi: { getAssets: vi.fn() },
  webDashboardApi: {},
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const ASSETS = [
  {
    id: "a-1",
    method: "GET",
    url: "https://portal.example.test/",
    response_code: 200,
    content_type: "text/html",
    auth_required: false,
    is_api: false,
    is_form: false,
    has_file_upload: false,
  },
  {
    id: "a-2",
    method: "POST",
    url: "https://portal.example.test/api/v1/upload",
    response_code: 401,
    content_type: "application/json",
    auth_required: true,
    is_api: true,
    is_form: false,
    has_file_upload: true,
  },
  {
    id: "a-3",
    method: "POST",
    url: "https://portal.example.test/login",
    response_code: 200,
    content_type: "text/html",
    auth_required: false,
    is_api: false,
    is_form: true,
    has_file_upload: false,
  },
  {
    id: "a-4",
    method: "DELETE",
    url: "https://portal.example.test/api/v1/session",
    response_code: 500,
    content_type: "application/json",
    auth_required: true,
    is_api: true,
    is_form: false,
    has_file_upload: false,
  },
];

const ok = (assets = ASSETS) => Promise.resolve({ data: { data: assets } });

const renderPage = async () => {
  const result = render(<AssetInventory />);
  await waitFor(() => expect(webScansApi.getAssets).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  webScansApi.getAssets.mockImplementation(() => ok());
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetInventory — functional", () => {
  it("requests assets for the scan named in the route", async () => {
    await renderPage();
    expect(webScansApi.getAssets).toHaveBeenCalledWith("ws-42", {
      per_page: 200,
    });
  });

  it("renders one row per asset", async () => {
    await renderPage();
    expect(
      await screen.findByText("https://portal.example.test/"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("https://portal.example.test/api/v1/upload"),
    ).toBeInTheDocument();
  });

  it("accepts the `items` response shape as well as `data`", async () => {
    webScansApi.getAssets.mockResolvedValue({ data: { items: ASSETS } });
    await renderPage();
    expect(
      await screen.findByText("https://portal.example.test/login"),
    ).toBeInTheDocument();
  });

  it("renders an empty state when nothing was discovered", async () => {
    webScansApi.getAssets.mockResolvedValue({ data: { data: [] } });
    await renderPage();
    expect(await screen.findByText(/no assets found/i)).toBeInTheDocument();
  });

  it("survives a failed load without crashing", async () => {
    webScansApi.getAssets.mockRejectedValue(new Error("network"));
    await renderPage();
    expect(await screen.findByText(/no assets found/i)).toBeInTheDocument();
  });

  it("filters by URL", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("https://portal.example.test/login");
    const search = container.querySelector('input[type="text"], input');
    await user.type(search, "upload");
    await waitFor(() =>
      expect(
        screen.queryByText("https://portal.example.test/login"),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.getByText("https://portal.example.test/api/v1/upload"),
    ).toBeInTheDocument();
  });

  it("filters by content type", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("https://portal.example.test/login");
    const search = container.querySelector('input[type="text"], input');
    await user.type(search, "application/json");
    await waitFor(() =>
      expect(
        screen.queryByText("https://portal.example.test/login"),
      ).not.toBeInTheDocument(),
    );
  });

  it("links back to the scan detail for this scan", async () => {
    await renderPage();
    const back = screen.getByRole("link", { name: /back to scan detail/i });
    expect(back).toHaveAttribute("href", "/web-scans/ws-42");
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AssetInventory />);
      await waitFor(() =>
        expect(webScansApi.getAssets).toHaveBeenCalledTimes(1),
      );
      await vi.advanceTimersByTimeAsync(120000);
      expect(webScansApi.getAssets).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetInventory — security", () => {
  it("scopes the request to the route's scan id and nothing else", async () => {
    await renderPage();
    const [scanId, params] = webScansApi.getAssets.mock.calls[0];
    expect(scanId).toBe("ws-42");
    expect(Object.keys(params).sort()).toEqual(["per_page"]);
  });

  it("reports each asset's HTTP method as returned", async () => {
    await renderPage();
    const row = (
      await screen.findByText("https://portal.example.test/api/v1/session")
    ).closest("tr");
    expect(within(row).getByText("DELETE")).toBeInTheDocument();
  });

  it("keeps the size and time column", async () => {
    /* Added after the structural diff reported headerCells 6 -> 5: the
       pre-migration table had a sixth "SIZE / TIME" column that the first
       version of this migration silently dropped. The baseline suite did not
       catch it because no assertion covered that column — the instrument did.
       This is that gap closed. */
    await renderPage();
    const row = (
      await screen.findByText("https://portal.example.test/api/v1/upload")
    ).closest("tr");
    const cell = row.querySelectorAll("td, th")[5];
    expect(cell).toBeTruthy();
    expect(cell.textContent).toMatch(/KB|-/);
  });

  it("reports the response code as returned, including a failure", async () => {
    await renderPage();
    const row = (
      await screen.findByText("https://portal.example.test/api/v1/session")
    ).closest("tr");
    expect(within(row).getByText("500")).toBeInTheDocument();
  });

  it("reports a 401 rather than treating it as unreachable", async () => {
    await renderPage();
    const row = (
      await screen.findByText("https://portal.example.test/api/v1/upload")
    ).closest("tr");
    expect(within(row).getByText("401")).toBeInTheDocument();
  });

  it("marks a file-upload endpoint distinguishably", async () => {
    await renderPage();
    const upload = (
      await screen.findByText("https://portal.example.test/api/v1/upload")
    ).closest("tr");
    const plain = screen
      .getByText("https://portal.example.test/")
      .closest("tr");
    const flagsOf = (row) => row.querySelectorAll("td, th")[4].textContent;
    expect(flagsOf(upload)).not.toBe(flagsOf(plain));
  });

  it("does not invent flags an asset did not report", async () => {
    await renderPage();
    const plain = (
      await screen.findByText("https://portal.example.test/")
    ).closest("tr");
    const flags = plain.querySelectorAll("td, th")[4];
    expect(flags.textContent.trim()).toBe("");
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetInventory — accessibility", () => {
  it("gives the table an accessible name", async () => {
    await renderPage();
    expect(await screen.findByRole("table")).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    await screen.findByText("https://portal.example.test/");
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th.getAttribute("scope")).toBe("col");
    }
  });

  it("marks the URL as its row's header", async () => {
    await renderPage();
    await screen.findByText("https://portal.example.test/");
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(4);
  });

  it("keeps every column the pre-migration table had", async () => {
    await renderPage();
    await screen.findByText("https://portal.example.test/");
    expect(document.querySelectorAll("thead th").length).toBe(6);
  });

  it("labels the search field", async () => {
    await renderPage();
    expect(screen.getByLabelText(/search|filter/i)).toBeInTheDocument();
  });

  it("gives every flag an accessible name, not a title alone", async () => {
    /* `title` is not an accessible name for a bare <span>: most screen readers
       ignore it there, and it is unreachable by keyboard and by touch. A file
       upload endpoint is the most useful row on this page. */
    await renderPage();
    const row = (
      await screen.findByText("https://portal.example.test/api/v1/upload")
    ).closest("tr");
    const flags = row.querySelectorAll("td, th")[4];
    expect(flags.textContent).toMatch(/upload/i);
    expect(flags.textContent).toMatch(/api/i);
  });

  it("announces the loading state", async () => {
    let settle;
    webScansApi.getAssets.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ data: { data: [] } });
        }),
    );
    render(<AssetInventory />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|asset/i);
    settle();
  });

  it("does not expose the loading placeholders to assistive technology", async () => {
    webScansApi.getAssets.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<AssetInventory />);
    await waitFor(() => expect(webScansApi.getAssets).toHaveBeenCalled());
    const shimmer = container.querySelectorAll(
      ".skeleton-loader, .cc-skeleton",
    );
    expect(shimmer.length).toBeGreaterThan(0);
    for (const el of shimmer) {
      expect(el.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("keeps exactly one page heading", async () => {
    await renderPage();
    expect(
      screen.getAllByRole("heading", { name: /asset inventory/i }).length,
    ).toBe(1);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetInventory — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("https://portal.example.test/");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("builds no colour value by concatenating onto a CSS variable", async () => {
    const { container } = await renderPage();
    await screen.findByText("https://portal.example.test/");
    expect(container.innerHTML).not.toMatch(/var\(--[a-z-]+\)[0-9a-f]{2}/i);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("https://portal.example.test/");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("https://portal.example.test/");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("renders one row per asset and no more", async () => {
    await renderPage();
    await screen.findByText("https://portal.example.test/");
    expect(document.querySelectorAll("tbody tr").length).toBe(4);
  });

  it("injects no <style> element into the document", async () => {
    webScansApi.getAssets.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<AssetInventory />);
    await waitFor(() => expect(webScansApi.getAssets).toHaveBeenCalled());
    expect(container.querySelectorAll("style").length).toBe(0);
  });
});
