/**
 * CCurePRO Home — the Product Hub at `/` (Phase 12.2, design §3.3).
 *
 * Every row of §3.3's two tables has a test here: the three card states, and
 * the loading and failed page states. The response is the live :443 body
 * recorded at the 12.1 activation, so these assert against what the platform
 * actually says rather than against a copy of it.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import real from "../fixtures/platformModules.real.json";
import api from "@shell/api/axiosInstance";
import CcureHome from "../../shell/pages/CcureHome";
import { personaFrom } from "../fixtures/authorization";

// The platform header composes the shell's shared pieces (Phase 12 platform
// navigation): preferences come from the provider main.jsx mounts, and the
// notification feed opens a stream — both stubbed here, as in AppLayout's suite.
vi.mock("@shell/preferences/PreferencesContext", () => ({
  usePreferences: () => ({ preferences: {}, updateLocalPreferences: vi.fn() }),
}));
vi.mock("@shell/api/notifications", () => ({
  getUnreadCount: vi.fn().mockResolvedValue({ total_unread: 0 }),
  streamNotificationEvents: vi.fn(() => new Promise(() => {})),
  getNotifications: vi.fn().mockResolvedValue([]),
  markAsRead: vi.fn(),
  markAllAsRead: vi.fn(),
  deleteNotification: vi.fn(),
  deleteAllNotifications: vi.fn(),
}));

vi.mock("@shell/api/axiosInstance", () => ({ default: { get: vi.fn() } }));

const logout = vi.fn();
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom({ username: "analyst" }), logout }),
}));

const clone = (o) => JSON.parse(JSON.stringify(o));
const respond = (body) => api.get.mockResolvedValueOnce({ data: body });
const fail = (status) =>
  api.get.mockRejectedValueOnce(
    Object.assign(new Error("Request failed"), {
      response: status ? { status } : undefined,
    }),
  );

const renderHome = () =>
  render(
    <MemoryRouter>
      <CcureHome />
    </MemoryRouter>,
  );

const cards = async () => {
  const list = await screen.findByRole("list", { name: "CCurePRO products" });
  return within(list).getAllByRole("listitem");
};

beforeEach(() => {
  api.get.mockReset();
  logout.mockReset();
});

describe("CCurePRO Home — the four products", () => {
  it("reads GET /platform/modules once", async () => {
    respond(real);
    renderHome();
    await cards();
    expect(api.get).toHaveBeenCalledTimes(1);
    expect(api.get).toHaveBeenCalledWith("/platform/modules");
  });

  it("shows every product in the registry's order", async () => {
    respond(real);
    renderHome();
    const items = await cards();
    expect(items).toHaveLength(4);
    expect(
      items.map(
        (li) => within(li).getByRole("heading", { level: 2 }).textContent,
      ),
    ).toEqual(["CCure Policy Pro", "CCure Audit", "CCure Rank", "CCure IR"]);
  });

  it("renders each registry title, description and entry address", async () => {
    respond(real);
    renderHome();
    const items = await cards();
    real.modules.forEach((m, i) => {
      const card = within(items[i]);
      expect(card.getByRole("heading", { name: m.title })).toBeInTheDocument();
      expect(card.getByText(m.description)).toBeInTheDocument();
      expect(card.getByRole("link")).toHaveAttribute("href", m.entry_path);
    });
  });

  it("follows the registry's order, not its own", async () => {
    const body = clone(real);
    body.modules.reverse();
    respond(body);
    renderHome();
    const items = await cards();
    expect(
      items.map((li) => within(li).getByRole("heading").textContent),
    ).toEqual(["CCure IR", "CCure Rank", "CCure Audit", "CCure Policy Pro"]);
  });

  it("shows the signed-in user and signs out", async () => {
    respond(real);
    renderHome();
    await cards();
    expect(screen.getByText("analyst")).toBeInTheDocument();
    const u = userEvent.setup();
    await u.click(
      screen.getByRole("button", { name: "Account menu for analyst" }),
    );
    await u.click(screen.getByRole("menuitem", { name: "Sign Out" }));
    expect(logout).toHaveBeenCalledTimes(1);
  });
});

describe("CCurePRO Home — availability", () => {
  it("available → Available, and Open dashboard", async () => {
    respond(real);
    renderHome();
    const audit = within((await cards())[1]);
    expect(audit.getByText("Available")).toBeInTheDocument();
    const link = audit.getByRole("link", {
      name: "Open dashboard, CCure Audit",
    });
    expect(link).toHaveAttribute("href", "/audit-dashboard");
  });

  it("not_yet_available → Not yet available, and About this product — never a dashboard", async () => {
    respond(real);
    renderHome();
    const items = await cards();
    for (const i of [0, 2, 3]) {
      const card = within(items[i]);
      expect(card.getByText("Not yet available")).toBeInTheDocument();
      expect(card.getByRole("link")).toHaveTextContent("About this product");
      expect(card.queryByText(/dashboard/i)).toBeNull();
      expect(card.queryByText("Available")).toBeNull();
    }
  });

  it("a state outside the vocabulary → Status unknown, never Available", async () => {
    const body = clone(real);
    body.modules[2].tile_state = "beta";
    respond(body);
    renderHome();
    const rank = within((await cards())[2]);
    expect(rank.getByText("Status unknown")).toBeInTheDocument();
    expect(rank.queryByText("Available")).toBeNull();
    expect(rank.getByRole("link")).toHaveTextContent("About this product");
    expect(rank.getByRole("link")).toHaveAttribute("href", "/rank-dashboard");
  });

  it("an available product with no vocabulary is Status unknown", async () => {
    const body = clone(real);
    delete body.tile_states;
    respond(body);
    renderHome();
    const items = await cards();
    expect(items).toHaveLength(4);
    for (const li of items) {
      expect(within(li).getByText("Status unknown")).toBeInTheDocument();
    }
    expect(screen.queryByText("Open dashboard")).toBeNull();
  });

  it("a product is shown even with no entry address, and offers none", async () => {
    const body = clone(real);
    body.modules[3].entry_path = "https://elsewhere.example/";
    respond(body);
    renderHome();
    const ir = within((await cards())[3]);
    expect(ir.getByRole("heading", { name: "CCure IR" })).toBeInTheDocument();
    expect(ir.queryByRole("link")).toBeNull();
    expect(
      ir.getByText("No entry address was provided for this product."),
    ).toBeInTheDocument();
  });
});

describe("CCurePRO Home — page states", () => {
  it("loading shows a loader and no card", async () => {
    let resolve;
    api.get.mockReturnValueOnce(new Promise((r) => (resolve = r)));
    renderHome();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading the CCurePRO products…",
    );
    expect(
      screen.queryByRole("list", { name: "CCurePRO products" }),
    ).toBeNull();
    resolve({ data: real });
    await cards();
  });

  it.each([
    [403, "The server answered HTTP 403."],
    [401, "The server answered HTTP 401."],
    [500, "The server answered HTTP 500."],
    [undefined, "The server could not be reached."],
  ])(
    "a failed request (%s) is an error with a retry, not zero products",
    async (status, text) => {
      fail(status);
      renderHome();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(
        "The CCurePRO product list could not be loaded",
      );
      expect(alert).toHaveTextContent(text);
      expect(
        screen.queryByRole("list", { name: "CCurePRO products" }),
      ).toBeNull();
      expect(screen.queryByRole("heading", { level: 2 })).toBeNull();
      expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    },
  );

  it("retry fetches again and then shows the products", async () => {
    fail(503);
    respond(real);
    renderHome();
    await screen.findByRole("alert");
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Retry" }));
    expect(await cards()).toHaveLength(4);
    expect(api.get).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("an unreadable body is an error, not an empty list", async () => {
    respond("<html>gateway error</html>");
    renderHome();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The response carried no product list.",
    );
    expect(
      screen.queryByRole("list", { name: "CCurePRO products" }),
    ).toBeNull();
  });

  it("an empty list is said, not rendered as a blank page", async () => {
    respond({ tile_states: ["available"], modules: [] });
    renderHome();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "No products were listed",
    );
  });

  it("offers nothing data-shaped: no table, chart, figure or disabled control", async () => {
    respond(real);
    const { container } = renderHome();
    await cards();
    expect(
      container.querySelector("table, canvas, figure, progress"),
    ).toBeNull();
    // The header's icons (bell, settings, avatar) are decorative navigation
    // since the platform header gained the shared navigation; the hub itself,
    // the page's <main>, still draws nothing chart-like.
    expect(container.querySelector("main svg")).toBeNull();
    expect(
      container.querySelector("[disabled], [aria-disabled='true']"),
    ).toBeNull();
  });
});
