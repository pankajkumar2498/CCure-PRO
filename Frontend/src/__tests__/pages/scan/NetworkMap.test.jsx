/**
 * NetworkMap (`/topology`, `/scan/topology-map`, `/scan/:scanId/topology-map`)
 * — Checkpoint 3C batch 21 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 21 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The page makes one kind of request: GET /topology/map (org-wide, with a
 * 30-day freshness window by default) or GET /topology/map/{scanId}, with
 * `subnet_mask` and, when a window is set, `active_within_days`. It writes
 * nothing. Everything else is the graph: which nodes and edges reach
 * vis-network, how the operator filters, expands and inspects them, and the
 * two overlays that explain a subnet's evidence and its recommended actions.
 *
 * vis-network is replaced by an in-memory stand-in that keeps what the page
 * hands it — the DataSets and the Network's options and click handler — so
 * the graph is asserted as data. The canvas itself is never drawn under jsdom.
 *
 * The routes sit behind the base sign-in check in App.jsx and nothing more;
 * `scans:read` is enforced by the backend, and a refusal reaches the page as a
 * failed load.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import NetworkMap from "../../../pages/scan/NetworkMap";
import PrivateRoute from "../../../components/auth/PrivateRoute";
import AuthContext from "../../../context/AuthContext";
import api from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div data-testid="app-layout">{children}</div>,
}));

/* A stand-in for vis-network that behaves like the parts the page relies on:
   DataSet.add() throws on a duplicate id, exactly as the real one does, and
   the Network keeps its options and event handlers for inspection. */
const vis = vi.hoisted(() => {
  const state = { networks: [], failNextNetwork: false };
  class DataSet {
    constructor(items = []) {
      this.items = new Map();
      this.add(items);
    }
    add(items) {
      for (const item of [].concat(items)) {
        if (this.items.has(item.id)) {
          throw new Error(
            `Cannot add item: item with id ${item.id} already exists`,
          );
        }
        this.items.set(item.id, item);
      }
    }
    clear() {
      this.items.clear();
    }
    get(id) {
      return id === undefined
        ? [...this.items.values()]
        : this.items.get(id) ?? null;
    }
    getIds() {
      return [...this.items.keys()];
    }
    get length() {
      return this.items.size;
    }
  }
  class Network {
    constructor(container, data, options) {
      if (state.failNextNetwork) {
        state.failNextNetwork = false;
        throw new Error("canvas unavailable");
      }
      this.container = container;
      this.data = data;
      this.options = options;
      this.handlers = {};
      this.destroyed = 0;
      this.fits = [];
      state.networks.push(this);
    }
    on(event, handler) {
      this.handlers[event] = handler;
    }
    once() {}
    fit(options) {
      this.fits.push(options);
    }
    destroy() {
      this.destroyed += 1;
    }
  }
  return { state, DataSet, Network };
});

vi.mock("vis-network/standalone", () => ({
  DataSet: vis.DataSet,
  Network: vis.Network,
}));

const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

/* ── Fixture ─────────────────────────────────────────────────────────────────
   Field names follow core.topology.engine.get_topology_graph (graph_version
   3): canonical endpoint ids, host evidence, typed links. Subnet B holds 60
   hosts so the 50-host graph cap and the 50-row evidence pages both apply. */
const SUBNET_A = "10.0.1.0/24";
const SUBNET_B = "10.0.2.0/24";
const MAC_ONLY = "MAC-Only / FDB";

const ALL_ACTIONS = [
  "Run ARP-enabled scan",
  "Add gateway/router SNMP target",
  "Enable ARP table collection",
  "Enable LLDP/CDP on infrastructure devices",
  "Correlate with asset inventory",
];

const pad = (n) => String(n).padStart(2, "0");

const HOSTS_A = [
  {
    id: "00:11:22:33:44:01",
    label: "files-a",
    group: "workstation",
    tier: "host",
    ip: "10.0.1.11",
    mac: "00:11:22:33:44:01",
    vendor: "Acme",
    subnet: SUBNET_A,
    source_key: "ip:10.0.0.2",
    source_port: "Gi0/1",
    source_port_desc: "uplink to files",
    link_type: "arp",
    vlan_id: 10,
    speed_bps: 1_000_000_000,
    asset_id: "ast-h1",
    asset_match_status: "matched",
  },
  {
    id: "00:11:22:33:44:02",
    label: "10.0.1.12",
    group: "endpoint",
    tier: "host",
    ip: "10.0.1.12",
    mac: "00:11:22:33:44:02",
    vendor: "",
    subnet: SUBNET_A,
    source_key: "ip:10.0.0.2",
    source_port: "",
    link_type: "arp",
    asset_id: null,
    asset_match_status: "unmatched",
  },
];

const HOSTS_B = Array.from({ length: 60 }, (_, i) => {
  const n = i + 1;
  return {
    id: `00:22:00:00:00:${pad(n)}`,
    label: `host-${n}`,
    group: "desktop",
    tier: "host",
    ip: `10.0.2.${n}`,
    mac: `00:22:00:00:00:${pad(n)}`,
    vendor: n === 7 ? "Globex" : "Initech",
    subnet: SUBNET_B,
    source_key: "ip:10.0.0.2",
    source_port: `Gi1/${n}`,
    link_type: "lldp",
    speed_bps: 100_000_000,
    asset_id: n % 10 === 0 ? `ast-b${n}` : null,
    asset_match_status: n % 10 === 0 ? "matched" : "unmatched",
  };
});

const HOSTS_MAC = [1, 2, 3].map((n) => ({
  id: `aa:bb:cc:00:00:0${n}`,
  label: `aa:bb:cc:00:00:0${n}`,
  group: "unknown",
  tier: "host",
  ip: "",
  mac: `aa:bb:cc:00:00:0${n}`,
  subnet: MAC_ONLY,
  source_key: "mac:aa",
  link_type: "fdb",
}));

const subnetNode = (subnet, hostCount, extra = {}) => ({
  id: `subnet:${subnet}`,
  label: subnet,
  group: "subnet",
  tier: "subnet",
  subnet,
  host_count: hostCount,
  data_quality: {
    ip_resolved: hostCount,
    mac_only: 0,
    asset_matches: 1,
    source_count: 1,
  },
  recommended_actions: [],
  ...extra,
});

const TOPOLOGY = {
  success: true,
  graph_version: 3,
  nodes: [
    {
      id: "ip:10.0.0.1",
      label: "core-rtr",
      group: "router",
      tier: "infra",
      ip: "10.0.0.1",
      mac: "00:AA:00:00:00:01",
      asset_id: "ast-r1",
    },
    {
      id: "ip:10.0.0.2",
      label: "access-sw",
      group: "switch",
      tier: "infra",
      ip: "10.0.0.2",
      mac: "",
      asset_id: null,
    },
    {
      id: "ip:10.0.0.3",
      label: "files-srv",
      group: "server",
      tier: "infra",
      ip: "10.0.0.3",
      mac: "",
      asset_id: null,
    },
    subnetNode(SUBNET_A, 2, {
      data_quality: {
        ip_resolved: 2,
        mac_only: 0,
        asset_matches: 1,
        source_count: 1,
      },
      recommended_actions: [...ALL_ACTIONS, "Reboot everything"],
    }),
    subnetNode(SUBNET_B, 60, {
      data_quality: {
        ip_resolved: 60,
        mac_only: 0,
        asset_matches: 6,
        source_count: 1,
      },
    }),
    subnetNode(MAC_ONLY, 3, {
      data_quality: {
        ip_resolved: 0,
        mac_only: 3,
        asset_matches: 0,
        source_count: 1,
      },
    }),
    ...HOSTS_A,
    ...HOSTS_B,
    ...HOSTS_MAC,
  ],
  edges: [
    {
      id: "edge-core",
      from: "ip:10.0.0.1",
      to: "ip:10.0.0.2",
      tier: "infra",
      label: "uplink",
      link_type: "lldp",
      source_port_desc: "Gi0/48",
      target_port: "24",
      vlan_id: 10,
      speed_bps: 1_000_000_000,
    },
    {
      id: "edge-slow",
      from: "ip:10.0.0.2",
      to: "ip:10.0.0.3",
      tier: "infra",
      link_type: "cdp",
      source_port: "Fa0/1",
      speed_bps: 10_000_000,
    },
    {
      id: "edge-a",
      from: "ip:10.0.0.2",
      to: `subnet:${SUBNET_A}`,
      tier: "subnet",
      link_type: "arp",
      host_count: 2,
      source_port: "Gi0/1, Gi0/2",
      link_details: {
        type_counts: { arp: 2 },
        summary: "arp: 2",
        ports: ["Gi0/1", "Gi0/2"],
      },
    },
    {
      id: "edge-b",
      from: "ip:10.0.0.2",
      to: `subnet:${SUBNET_B}`,
      tier: "subnet",
      link_type: "edp",
      host_count: 60,
      source_port: "Gi1/1-60",
      link_details: { type_counts: { edp: 60 }, summary: "edp: 60" },
    },
    {
      id: "edge-mac",
      from: "ip:10.0.0.2",
      to: `subnet:${MAC_ONLY}`,
      tier: "subnet",
      link_type: "fdb",
      host_count: 3,
    },
    // Dropped: an endpoint the payload does not contain, and a repeated id.
    { id: "edge-orphan", from: "ip:10.0.0.2", to: "ip:10.9.9.9" },
    {
      id: "edge-core",
      from: "ip:10.0.0.2",
      to: "ip:10.0.0.1",
      link_type: "lldp",
    },
  ],
  subnets: [SUBNET_A, SUBNET_B, MAC_ONLY],
  stats: { infrastructure: 3, subnets: 3, hosts: 65, mac_only: 3 },
};

/* ── Harness ─────────────────────────────────────────────────────────────── */
const ANALYST = {
  id: 7,
  role: { name: "analyst", permissions: ["scans:read", "assets:read"] },
};

let reply;

function LocationProbe() {
  const location = useLocation();
  return (
    <output data-testid="location">{`${location.pathname}${location.search}`}</output>
  );
}

const renderAt = (entry = "/topology", { user = ANALYST } = {}) =>
  render(
    <AuthContext.Provider
      value={{
        user,
        loading: false,
        authState: user ? "authenticated" : "anonymous",
      }}
    >
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route element={<PrivateRoute />}>
            <Route path="/scan/topology-map" element={<NetworkMap />} />
            <Route path="/scan/:scanId/topology-map" element={<NetworkMap />} />
            <Route path="/topology" element={<NetworkMap />} />
            <Route path="/assets/:id" element={<p>Asset detail page</p>} />
            <Route path="/assets" element={<p>Asset registry page</p>} />
            <Route path="/scan/new" element={<p>New scan page</p>} />
          </Route>
          <Route path="/login" element={<p>Login page</p>} />
        </Routes>
        <LocationProbe />
      </MemoryRouter>
    </AuthContext.Provider>,
  );

const flush = () => act(async () => {});
const settle = async () => {
  for (let i = 0; i < 4; i += 1) await flush();
};

const network = () => vis.state.networks[vis.state.networks.length - 1];
const nodes = () => network().data.nodes;
const edges = () => network().data.edges;
const node = (id) => nodes().get(id);
const edge = (id) => edges().get(id);
const hostIds = () =>
  nodes()
    .get()
    .filter((n) => n._data.tier === "host")
    .map((n) => n.id);

const topologyUrls = () => api.get.mock.calls.map(([url]) => url);
const location = () => screen.getByTestId("location").textContent;
const squash = (el) => (el.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);

const loaded = async (entry = "/topology", options) => {
  const view = renderAt(entry, options);
  await settle();
  return view;
};

const buttonNamed = (re) => {
  const match = screen.getAllByRole("button").find((b) => re.test(squash(b)));
  if (!match) throw new Error(`No button whose text matches ${re}`);
  return match;
};

const selectWithOption = (label) =>
  screen
    .getAllByRole("combobox")
    .find((s) => [...s.options].some((o) => o.textContent === label));

const checkboxFor = (subnet) =>
  screen
    .getAllByRole("checkbox")
    .find((c) => squash(c.closest("label")).includes(subnet));

const clickNode = async (id) => {
  await act(async () => {
    network().handlers.click({ nodes: id ? [id] : [] });
  });
  await settle();
};

const visibleNodes = () =>
  Number(bodyText().match(/(\d+) Visible Nodes/)?.[1] ?? NaN);
const totalHosts = () =>
  Number(bodyText().match(/(\d+) Total Hosts/)?.[1] ?? NaN);

const sidebar = () => screen.getByRole("complementary", { name: /sidebar/i });

const openEvidence = async (subnetId) => {
  await clickNode(subnetId);
  fireEvent.click(buttonNamed(/View Endpoint Evidence/));
  await settle();
  return screen.getByRole("dialog", { name: /Endpoint Evidence/ });
};

const dataRows = (dialog) => within(dialog).getAllByRole("row").slice(1);

beforeEach(() => {
  vis.state.networks.length = 0;
  vis.state.failNextNetwork = false;
  reply = () => Promise.resolve({ data: TOPOLOGY });
  api.get.mockReset();
  api.get.mockImplementation((url) => reply(url));
  for (const verb of ["post", "put", "patch", "delete"]) api[verb].mockReset();
  vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  // The page reads topology and writes nothing, whatever the test did.
  expect(api.post).not.toHaveBeenCalled();
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const url of topologyUrls()) {
    expect(url).toMatch(/^\/topology\/map(\/[^?/]+)?\?/);
  }
  vi.restoreAllMocks();
  document.documentElement.removeAttribute("data-theme");
  document.head
    .querySelectorAll("style[data-nmap-test]")
    .forEach((s) => s.remove());
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */

describe("NetworkMap — contract", () => {
  describe("requests", () => {
    it("loads the org-wide map once, with a 30-day window and a /24 mask", async () => {
      await loaded("/topology");
      expect(topologyUrls()).toEqual([
        "/topology/map?subnet_mask=24&active_within_days=30",
      ]);
    });

    it("serves the same org-wide map at /scan/topology-map", async () => {
      await loaded("/scan/topology-map");
      expect(topologyUrls()).toEqual([
        "/topology/map?subnet_mask=24&active_within_days=30",
      ]);
      expect(bodyText()).toContain("Corporate network architecture");
    });

    it("loads a scan's map from the route parameter, with no window and no window control", async () => {
      await loaded("/scan/s-42/topology-map");
      expect(topologyUrls()).toEqual(["/topology/map/s-42?subnet_mask=24"]);
      expect(bodyText()).toContain("Scan ID: s-42");
      expect(selectWithOption("Last 30 days")).toBeUndefined();
    });

    it("loads a scan's map from the scan_id query string", async () => {
      await loaded("/scan/topology-map?scan_id=s-43");
      expect(topologyUrls()).toEqual(["/topology/map/s-43?subnet_mask=24"]);
      expect(bodyText()).toContain("Scan ID: s-43");
    });

    it("refetches when the mask changes, keeping the window", async () => {
      await loaded();
      const mask = selectWithOption("Class B (/16)");
      expect([...mask.options].map((o) => [o.value, o.textContent])).toEqual([
        ["16", "Class B (/16)"],
        ["22", "Class C Extended (/22)"],
        ["23", "Class C Extended (/23)"],
        ["24", "Class C (/24)"],
      ]);
      expect(mask.value).toBe("24");
      fireEvent.change(mask, { target: { value: "16" } });
      await settle();
      expect(topologyUrls().at(-1)).toBe(
        "/topology/map?subnet_mask=16&active_within_days=30",
      );
    });

    it("refetches when the window changes, and sends no window for all history", async () => {
      await loaded();
      const windowSelect = selectWithOption("Last 30 days");
      expect(
        [...windowSelect.options].map((o) => [o.value, o.textContent]),
      ).toEqual([
        ["7", "Last 7 days"],
        ["30", "Last 30 days"],
        ["90", "Last 90 days"],
        ["0", "All recorded history"],
      ]);
      fireEvent.change(windowSelect, { target: { value: "7" } });
      await settle();
      expect(topologyUrls().at(-1)).toBe(
        "/topology/map?subnet_mask=24&active_within_days=7",
      );
      fireEvent.change(windowSelect, { target: { value: "0" } });
      await settle();
      expect(topologyUrls().at(-1)).toBe("/topology/map?subnet_mask=24");
    });

    it("refreshes on request, and cannot be refreshed while a load is in flight", async () => {
      let resolve;
      reply = () =>
        new Promise((r) => {
          resolve = () => r({ data: TOPOLOGY });
        });
      renderAt();
      await flush();
      expect(buttonNamed(/Syncing\.\.\./)).toBeDisabled();
      await act(async () => resolve());
      await settle();
      const refresh = buttonNamed(/Refresh/);
      expect(refresh).toBeEnabled();
      fireEvent.click(refresh);
      await flush();
      expect(topologyUrls()).toHaveLength(2);
      expect(buttonNamed(/Syncing\.\.\./)).toBeDisabled();
      await act(async () => resolve());
      await settle();
    });

    it("a new load clears hidden subnets and the selection", async () => {
      await loaded();
      fireEvent.click(checkboxFor(SUBNET_A));
      await clickNode(`subnet:${SUBNET_B}`);
      expect(checkboxFor(SUBNET_A)).not.toBeChecked();
      expect(within(sidebar()).queryByText("Total Hosts")).not.toBeNull();
      fireEvent.change(selectWithOption("Class B (/16)"), {
        target: { value: "16" },
      });
      await settle();
      expect(checkboxFor(SUBNET_A)).toBeChecked();
      expect(within(sidebar()).queryByText("Total Hosts")).toBeNull();
    });
  });

  describe("load states", () => {
    it("shows the loading state until the map arrives", async () => {
      reply = () => new Promise(() => {});
      renderAt();
      await flush();
      expect(screen.getByText("Loading topology nodes...")).toBeInTheDocument();
      expect(vis.state.networks).toHaveLength(0);
    });

    it("reports success:false as a failed load", async () => {
      reply = () => Promise.resolve({ data: { success: false } });
      await loaded();
      expect(bodyText()).toContain("Failed to load topology data");
      expect(vis.state.networks).toHaveLength(0);
    });

    it("reports the API's detail, or the error's message, and retries on request", async () => {
      reply = () =>
        Promise.reject({
          response: { data: { detail: "Topology engine unavailable" } },
        });
      await loaded();
      expect(bodyText()).toContain("Topology engine unavailable");

      reply = () => Promise.reject(new Error("socket hang up"));
      fireEvent.click(buttonNamed(/^Retry$/));
      await settle();
      expect(bodyText()).toContain("socket hang up");
      expect(topologyUrls()).toHaveLength(2);

      reply = () => Promise.resolve({ data: TOPOLOGY });
      fireEvent.click(buttonNamed(/^Retry$/));
      await settle();
      expect(bodyText()).not.toContain("socket hang up");
      expect(vis.state.networks).toHaveLength(1);
    });

    it("shows the empty state for a map with no nodes", async () => {
      reply = () =>
        Promise.resolve({
          data: { success: true, nodes: [], edges: [], subnets: [] },
        });
      await loaded();
      expect(bodyText()).toContain("No Network Nodes Discovered");
      expect(bodyText()).toContain(
        "Run a network scan configured with SNMP to view the device hierarchy.",
      );
      expect(vis.state.networks).toHaveLength(0);
    });

    it("reports a graph engine that cannot start", async () => {
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      vis.state.failNextNetwork = true;
      await loaded();
      expect(bodyText()).toContain("Failed to load network engine.");
      expect(error).toHaveBeenCalledWith(
        "Failed to load vis-network:",
        expect.any(Error),
      );
    });
  });

  describe("statistics and summary", () => {
    it("counts visible nodes and total hosts", async () => {
      await loaded();
      expect(visibleNodes()).toBe(6);
      expect(totalHosts()).toBe(65);
      await clickNode(`subnet:${SUBNET_B}`);
      expect(visibleNodes()).toBe(56);
      expect(totalHosts()).toBe(65);
    });

    it("summarises the quality of the topology evidence", async () => {
      await loaded();
      const value = (label) =>
        squash(screen.getByText(label).parentElement).replace(label, "").trim();
      expect(value("MAC-only endpoints")).toBe("3");
      expect(value("IPs resolved")).toBe("62");
      // Two observers: the switch, and the FDB source of the MAC-only hosts.
      expect(value("Topology sources")).toBe("2");
      expect(bodyText()).toContain("ARP present");
      expect(bodyText()).toContain("Neighbour discovery present");
    });

    it("says so when ARP and neighbour discovery are both missing", async () => {
      reply = () =>
        Promise.resolve({
          data: {
            ...TOPOLOGY,
            edges: TOPOLOGY.edges.map((e) => ({
              ...e,
              link_type: "fdb",
              link_details: undefined,
            })),
          },
        });
      await loaded();
      expect(bodyText()).toContain("ARP missing");
      expect(bodyText()).toContain("No neighbour discovery (LLDP/CDP/EDP)");
    });

    it("names the map region and the data quality summary", async () => {
      await loaded();
      expect(
        screen.getByRole("region", { name: "Interactive Topology Map View" }),
      ).toContainElement(network().container);
      expect(
        screen.getByRole("status", { name: "Topology data quality summary" }),
      ).toBeInTheDocument();
    });

    it("lists the device types present, sorted by label", async () => {
      await loaded();
      const legend = screen.getByText("Device Types").parentElement;
      for (const label of [
        "Desktop PC",
        "Endpoint",
        "Router",
        "Server",
        "Switch",
        "Unknown Device",
        "Workstation",
      ]) {
        expect(squash(legend)).toContain(label);
      }
      const text = squash(legend);
      expect(text.indexOf("Desktop PC")).toBeLessThan(
        text.indexOf("Workstation"),
      );
    });
  });

  describe("the graph", () => {
    it("builds the collapsed graph: infrastructure and subnets, no hosts, no orphan or repeated edges", async () => {
      await loaded();
      expect(nodes().getIds()).toEqual([
        "ip:10.0.0.1",
        "ip:10.0.0.2",
        "ip:10.0.0.3",
        `subnet:${SUBNET_A}`,
        `subnet:${SUBNET_B}`,
        `subnet:${MAC_ONLY}`,
      ]);
      expect(edges().getIds()).toEqual([
        "edge-core",
        "edge-slow",
        "edge-a",
        "edge-b",
        "edge-mac",
      ]);
    });

    it("formats each tier's nodes as before", async () => {
      await loaded();
      const shape = (id) => {
        const n = node(id);
        return {
          label: n.label,
          shape: n.shape,
          size: n.size,
          level: n.level,
          font: {
            size: n.font.size,
            face: n.font.face,
            bold: n.font.bold,
            strokeWidth: n.font.strokeWidth,
            vadjust: n.font.vadjust,
          },
          image: n.image.startsWith("data:image/svg+xml;base64,"),
        };
      };
      expect(shape("ip:10.0.0.1")).toEqual({
        label: "core-rtr",
        shape: "image",
        size: 42,
        level: 0,
        font: {
          size: 13,
          face: "Inter, sans-serif",
          bold: true,
          strokeWidth: 3,
          vadjust: 36,
        },
        image: true,
      });
      expect(shape("ip:10.0.0.2")).toMatchObject({ size: 38, level: 1 });
      expect(shape("ip:10.0.0.3")).toMatchObject({ size: 34, level: 2 });
      expect(shape(`subnet:${SUBNET_B}`)).toEqual({
        label: `${SUBNET_B}\n(60 hosts)`,
        shape: "image",
        size: 36,
        level: 2,
        font: {
          size: 11,
          face: "Inter, sans-serif",
          bold: true,
          strokeWidth: 3,
          vadjust: 34,
        },
        image: true,
      });
      expect(shape(`subnet:${MAC_ONLY}`)).toMatchObject({
        label: "MAC-only endpoints\n3 devices",
        size: 42,
      });

      await clickNode(`subnet:${SUBNET_A}`);
      expect(node(`subnet:${SUBNET_A}`).label).toBe(SUBNET_A);
      expect(shape(HOSTS_A[0].id)).toEqual({
        label: "files-a",
        shape: "image",
        size: 26,
        level: 3,
        font: {
          size: 9,
          face: "Inter, sans-serif",
          bold: undefined,
          strokeWidth: 2,
          vadjust: 26,
        },
        image: true,
      });
    });

    it("draws each device type with its own image", async () => {
      await loaded();
      const images = new Set(
        ["ip:10.0.0.1", "ip:10.0.0.2", "ip:10.0.0.3", `subnet:${SUBNET_A}`].map(
          (id) => node(id).image,
        ),
      );
      expect(images.size).toBe(4);
      for (const image of images) {
        const svg = atob(image.replace("data:image/svg+xml;base64,", ""));
        expect(svg).toMatch(/^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
      }
    });

    it("gives nodes and edges plain-text tooltips", async () => {
      await loaded();
      expect(node("ip:10.0.0.1").title).toBe(
        "core-rtr\nIP: 10.0.0.1\nMAC: 00:AA:00:00:00:01\nType: router",
      );
      expect(node("ip:10.0.0.2").title).toBe(
        "access-sw\nIP: 10.0.0.2\nMAC: —\nType: switch",
      );
      expect(node(`subnet:${SUBNET_B}`).title).toBe(
        `${SUBNET_B}\nHosts: 60\nClick node to expand`,
      );
      expect(node(`subnet:${MAC_ONLY}`).title).toBe(
        "MAC-only endpoint cluster\nDevices: 3\nClick to inspect evidence",
      );
      expect(edge("edge-core").title).toBe(
        "Link Type: lldp\nSource: Gi0/48\nTarget Port: 24\nVLAN: 10\nSpeed: 1 Gbps",
      );
      expect(edge("edge-slow").title).toBe(
        "Link Type: cdp\nSource Port: Fa0/1\nSpeed: 10 Mbps",
      );
      expect(edge("edge-a").title).toBe(
        "Subnet Edge Details:\n• Hosts: 2\n• Distribution: arp: 2\n• Source Ports: Gi0/1, Gi0/2",
      );
      expect(edge("edge-mac").title).toBe("Link Type: fdb");

      await clickNode(`subnet:${SUBNET_A}`);
      expect(node(`subnet:${SUBNET_A}`).title).toBe(
        `${SUBNET_A}\nHosts: 2\nClick node to collapse`,
      );
      expect(node(HOSTS_A[0].id).title).toBe(
        "Host: files-a\nIP: 10.0.1.11\nMAC: 00:11:22:33:44:01\nSubnet: 10.0.1.0/24\nType: workstation",
      );
      for (const item of nodes().get()) {
        expect(typeof item.title).toBe("string");
      }
      // Links from a subnet to its hosts carry no tooltip; every other edge does.
      for (const item of edges().get()) {
        expect(typeof item.title).toBe(
          String(item.id).startsWith("edge:host:") ? "undefined" : "string",
        );
      }
    });

    it("sizes and dashes edges by speed and host count", async () => {
      await loaded();
      const shape = (id) => {
        const e = edge(id);
        return {
          width: Number(e.width.toFixed(4)),
          dashes: e.dashes,
          smooth: e.smooth,
          label: e.label,
          fontSize: e.font.size,
          strokeWidth: e.font.strokeWidth,
        };
      };
      expect(shape("edge-core")).toEqual({
        width: 4.6035,
        dashes: false,
        smooth: { type: "continuous" },
        label: "uplink",
        fontSize: 9,
        strokeWidth: 0,
      });
      expect(shape("edge-slow")).toMatchObject({
        width: 2.1035,
        dashes: [5, 5],
      });
      expect(shape("edge-a")).toMatchObject({ width: 1.9775, label: "" });
      expect(shape("edge-b")).toMatchObject({ width: 7.3996 });
      expect(shape("edge-mac")).toMatchObject({ width: 2.4953 });
    });

    it("drops duplicate node ids rather than failing the whole map", async () => {
      reply = () =>
        Promise.resolve({
          data: { ...TOPOLOGY, nodes: [...TOPOLOGY.nodes, TOPOLOGY.nodes[0]] },
        });
      await loaded();
      expect(console.warn).toHaveBeenCalledWith(
        "NetworkMap: dropped 1 duplicate/invalid node(s) from the topology payload",
      );
      expect(nodes().getIds()).toHaveLength(6);
      expect(bodyText()).not.toContain("Failed to load network engine");
      expect(bodyText()).not.toContain("Failed to render the topology view");
    });

    it("builds the network with the same layout, physics and interaction options", async () => {
      await loaded();
      const { options, container } = network();
      expect(container).toBeInstanceOf(HTMLElement);
      expect(options.nodes).toMatchObject({
        borderWidth: 2,
        borderWidthSelected: 3,
        shadow: { enabled: true, size: 6, x: 0, y: 4 },
      });
      expect(options.layout).toEqual({
        hierarchical: {
          enabled: true,
          direction: "UD",
          sortMethod: "directed",
          levelSeparation: 150,
          nodeSpacing: 140,
          treeSpacing: 220,
          blockShifting: true,
          edgeMinimization: true,
          parentCentralization: true,
        },
      });
      expect(options.physics).toEqual({
        enabled: false,
        barnesHut: {
          gravitationalConstant: -1800,
          centralGravity: 0.25,
          springLength: 90,
          springConstant: 0.04,
          damping: 0.09,
          avoidOverlap: 1,
        },
        stabilization: { enabled: true, iterations: 150, updateInterval: 25 },
      });
      expect(options.interaction).toEqual({
        hover: true,
        tooltipDelay: 150,
        zoomView: true,
        dragView: true,
        navigationButtons: true,
      });
    });

    it("fits the view shortly after building it, and on request", async () => {
      await loaded();
      expect(network().fits).toEqual([]);
      await act(() => new Promise((r) => setTimeout(r, 350)));
      expect(network().fits).toEqual([
        { animation: { duration: 400, easingFunction: "easeInOutQuad" } },
      ]);
      fireEvent.click(buttonNamed(/Fit Screen/));
      expect(network().fits.at(-1)).toEqual({ animation: { duration: 400 } });
    });

    it("rebuilds the network when the layout changes", async () => {
      await loaded();
      const first = network();
      const layout = selectWithOption("Force-Directed");
      expect([...layout.options].map((o) => [o.value, o.textContent])).toEqual([
        ["hierarchical", "Hierarchy"],
        ["force", "Force-Directed"],
      ]);
      fireEvent.change(layout, { target: { value: "force" } });
      await settle();
      expect(first.destroyed).toBeGreaterThan(0);
      expect(vis.state.networks).toHaveLength(2);
      expect(network().options.layout.hierarchical.enabled).toBe(false);
      expect(network().options.physics.enabled).toBe(true);
      expect(nodes().getIds()).toHaveLength(6);
      expect(topologyUrls()).toHaveLength(1);
    });

    it("destroys the network on unmount", async () => {
      const { unmount } = await loaded();
      const current = network();
      unmount();
      expect(current.destroyed).toBeGreaterThan(0);
    });
  });

  describe("subnet filters, search, expand and collapse", () => {
    it("lists every subnet as a checked checkbox", async () => {
      await loaded();
      expect(screen.getAllByRole("checkbox")).toHaveLength(3);
      for (const subnet of TOPOLOGY.subnets) {
        expect(checkboxFor(subnet)).toBeChecked();
      }
      expect(bodyText()).toContain("Subnets (3)");
    });

    it("hides a subnet and its hosts, and shows it again collapsed", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      expect(hostIds()).toHaveLength(2);
      fireEvent.click(checkboxFor(SUBNET_A));
      await settle();
      expect(checkboxFor(SUBNET_A)).not.toBeChecked();
      expect(nodes().get(`subnet:${SUBNET_A}`)).toBeNull();
      expect(hostIds()).toHaveLength(0);
      expect(edges().get("edge-a")).toBeNull();
      fireEvent.click(checkboxFor(SUBNET_A));
      await settle();
      expect(checkboxFor(SUBNET_A)).toBeChecked();
      expect(nodes().get(`subnet:${SUBNET_A}`)).not.toBeNull();
      expect(hostIds()).toHaveLength(0);
    });

    it("clears and selects every subnet", async () => {
      await loaded();
      fireEvent.click(buttonNamed(/^Clear$/));
      await settle();
      for (const subnet of TOPOLOGY.subnets) {
        expect(checkboxFor(subnet)).not.toBeChecked();
      }
      expect(nodes().getIds()).toEqual([
        "ip:10.0.0.1",
        "ip:10.0.0.2",
        "ip:10.0.0.3",
      ]);
      fireEvent.click(buttonNamed(/^Select All$/));
      await settle();
      for (const subnet of TOPOLOGY.subnets) {
        expect(checkboxFor(subnet)).toBeChecked();
      }
      expect(nodes().getIds()).toHaveLength(6);
    });

    it("searches hosts by address, name or MAC, expanding the subnets that match, without rebuilding the network", async () => {
      await loaded();
      const search = screen.getByPlaceholderText("Search IP, Hostname, MAC...");
      fireEvent.change(search, { target: { value: "10.0.2.7" } });
      await settle();
      expect(hostIds()).toEqual([HOSTS_B[6].id]);
      expect(node(`subnet:${SUBNET_B}`).label).toBe(SUBNET_B);

      fireEvent.change(search, { target: { value: "44:02" } });
      await settle();
      expect(hostIds()).toEqual(expect.arrayContaining([HOSTS_A[1].id]));
      expect(hostIds()).not.toContain(HOSTS_A[0].id);

      // MAC-only endpoints are never expanded onto the graph.
      fireEvent.change(search, { target: { value: "aa:bb:cc" } });
      await settle();
      expect(hostIds()).toEqual([]);

      fireEvent.change(search, { target: { value: "FILES-A" } });
      await settle();
      expect(hostIds()).toEqual([HOSTS_A[0].id]);
      expect(vis.state.networks).toHaveLength(1);
      expect(network().destroyed).toBe(0);
    });

    it("expands every visible subnet except MAC-only, capped at 50 hosts each, without asking below 16", async () => {
      await loaded();
      fireEvent.click(checkboxFor(SUBNET_A));
      await settle();
      fireEvent.click(buttonNamed(/Expand All/));
      await settle();
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(hostIds()).toHaveLength(50);
      expect(hostIds()).toEqual(HOSTS_B.slice(0, 50).map((h) => h.id));
      expect(edges().get(`edge:host:${HOSTS_B[0].id}`)).toMatchObject({
        from: `subnet:${SUBNET_B}`,
        to: HOSTS_B[0].id,
        width: 1,
        smooth: { type: "continuous" },
      });

      fireEvent.click(checkboxFor(SUBNET_A));
      await settle();
      fireEvent.click(buttonNamed(/Expand All/));
      await settle();
      expect(hostIds()).toHaveLength(52);

      fireEvent.click(buttonNamed(/Collapse All/));
      await settle();
      expect(hostIds()).toHaveLength(0);
      expect(visibleNodes()).toBe(6);
    });

    describe("more than 15 subnets", () => {
      const many = Array.from({ length: 16 }, (_, i) => `10.9.${i}.0/24`);
      const WIDE = {
        success: true,
        nodes: [
          { id: "ip:10.9.0.1", label: "wan", group: "router", tier: "infra" },
          ...many.map((s) => subnetNode(s, 1)),
          ...many.map((s, i) => ({
            id: `h-${i}`,
            label: `h-${i}`,
            group: "endpoint",
            tier: "host",
            ip: `10.9.${i}.5`,
            subnet: s,
          })),
        ],
        edges: [],
        subnets: many,
        stats: { hosts: 16 },
      };

      it("asks first, with the same words, and does nothing when declined", async () => {
        reply = () => Promise.resolve({ data: WIDE });
        await loaded();
        fireEvent.click(buttonNamed(/Expand All/));
        await settle();
        const dlg = screen.getByRole("dialog");
        expect(
          within(dlg).getByText(
            "Expanding more than 15 subnets simultaneously may slow down the view. Continue?",
          ),
        ).toBeInTheDocument();
        expect(hostIds()).toHaveLength(0);

        fireEvent.click(within(dlg).getByRole("button", { name: /^cancel$/i }));
        await settle();
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
        expect(hostIds()).toHaveLength(0);
      });

      it("expands them all when confirmed", async () => {
        reply = () => Promise.resolve({ data: WIDE });
        await loaded();
        fireEvent.click(buttonNamed(/Expand All/));
        await settle();
        fireEvent.click(
          within(screen.getByRole("dialog")).getByRole("button", {
            name: /^expand all$/i,
          }),
        );
        await settle();
        expect(hostIds()).toHaveLength(16);
      });

      it("does not ask when hidden subnets bring the count to 15", async () => {
        reply = () => Promise.resolve({ data: WIDE });
        await loaded();
        fireEvent.click(checkboxFor(many[0]));
        await settle();
        fireEvent.click(buttonNamed(/Expand All/));
        await settle();
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
        expect(hostIds()).toHaveLength(15);
      });
    });
  });

  describe("selecting a node", () => {
    it("a subnet click selects it and toggles its hosts; MAC-only subnets never expand", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_B}`);
      expect(hostIds()).toHaveLength(50);
      expect(squash(sidebar())).toContain(SUBNET_B);
      await clickNode(`subnet:${SUBNET_B}`);
      expect(hostIds()).toHaveLength(0);
      expect(squash(sidebar())).toContain(SUBNET_B);

      await clickNode(`subnet:${MAC_ONLY}`);
      expect(hostIds()).toHaveLength(0);
      expect(squash(sidebar())).toContain("View Endpoint Evidence (3 devices)");
    });

    it("shows a subnet's details, its cap warning and its evidence quality", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_B}`);
      const text = squash(sidebar());
      expect(text).toContain("Tier");
      expect(text).toContain("subnet");
      expect(text).toContain("Total Hosts");
      expect(text).toMatch(/Total Hosts\s*60/);
      expect(text).toContain(
        "Capped at 50 hosts on graph for layout visibility. Use the search bar to locate specific hosts in this subnet.",
      );
      for (const [value, label] of [
        ["60", "IP resolved"],
        ["6", "asset matches"],
        ["1", "sources"],
      ]) {
        expect(text).toMatch(new RegExp(`${value}\\s*${label}`));
      }
      expect(
        buttonNamed(/View Endpoint Evidence \(60 devices\)/),
      ).toBeEnabled();

      await clickNode(`subnet:${SUBNET_A}`);
      expect(squash(sidebar())).not.toContain("Capped at 50 hosts");
    });

    it("shows an infrastructure node's details with a link to its asset", async () => {
      await loaded();
      await clickNode("ip:10.0.0.1");
      const text = squash(sidebar());
      expect(text).toContain("core-rtr");
      expect(text).toMatch(/IP\s*10\.0\.0\.1/);
      expect(text).toMatch(/MAC\s*00:AA:00:00:00:01/);
      expect(text).toMatch(/Tier\s*infra/);
      expect(hostIds()).toHaveLength(0);
      fireEvent.click(buttonNamed(/View Asset Details/));
      await settle();
      expect(location()).toBe("/assets/ast-r1");
      expect(screen.getByText("Asset detail page")).toBeInTheDocument();
    });

    it("shows a host's details, and no asset link when it has no asset", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      await clickNode(HOSTS_A[1].id);
      const text = squash(sidebar());
      expect(text).toMatch(/Subnet\s*10\.0\.1\.0\/24/);
      expect(text).toMatch(/Tier\s*host/);
      expect(
        screen
          .queryAllByRole("button")
          .some((b) => /View Asset Details/.test(squash(b))),
      ).toBe(false);
    });

    it("clears the selection when the click hits no node, and ignores unknown ids", async () => {
      await loaded();
      await clickNode("ip:10.0.0.2");
      expect(squash(sidebar())).toContain("access-sw");
      await clickNode("ip:not-on-graph");
      expect(squash(sidebar())).toContain("access-sw");
      await clickNode(null);
      expect(squash(sidebar())).not.toContain("access-sw");
    });
  });

  describe("endpoint evidence", () => {
    it("pages through a subnet's endpoints fifty at a time", async () => {
      await loaded();
      const dialog = await openEvidence(`subnet:${SUBNET_B}`);
      expect(squash(dialog)).toContain("Subnet Device List");
      expect(squash(dialog)).toContain("Showing 1-50 of 60");
      expect(squash(dialog)).toMatch(/Total Devices:\s*60/);
      expect(squash(dialog)).toMatch(/IPs Resolved:\s*60/);
      expect(squash(dialog)).toMatch(/Asset Matches:\s*6/);
      expect(dataRows(dialog)).toHaveLength(50);
      const previous = within(dialog).getByRole("button", { name: "Previous" });
      const next = within(dialog).getByRole("button", { name: "Show next 50" });
      expect(previous).toBeDisabled();
      fireEvent.click(next);
      expect(squash(dialog)).toContain("Showing 51-60 of 60");
      expect(dataRows(dialog)).toHaveLength(10);
      expect(next).toBeDisabled();
      expect(previous).toBeEnabled();
      fireEvent.click(previous);
      expect(squash(dialog)).toContain("Showing 1-50 of 60");
    });

    it("searches every evidence field from page one, and says when nothing matches", async () => {
      await loaded();
      const dialog = await openEvidence(`subnet:${SUBNET_B}`);
      fireEvent.click(
        within(dialog).getByRole("button", { name: "Show next 50" }),
      );
      const search = within(dialog).getByRole("textbox", {
        name: "Search endpoint evidence",
      });
      expect(search).toHaveAttribute(
        "placeholder",
        "Search MAC, vendor, port, description, speed, VLAN...",
      );
      fireEvent.change(search, { target: { value: "GLOBEX" } });
      expect(squash(dialog)).toContain("Showing 1-1 of 1");
      expect(squash(dataRows(dialog)[0])).toContain("host-7");
      fireEvent.change(search, { target: { value: "100 mbps" } });
      expect(squash(dialog)).toContain("Showing 1-50 of 60");
      fireEvent.change(search, { target: { value: "no-such-device" } });
      expect(squash(dialog)).toContain("Showing 0-0 of 0");
      expect(squash(dialog)).toContain("No endpoints match this filter.");
    });

    it("lists each endpoint's evidence, linking matched assets in a new tab", async () => {
      await loaded();
      const dialog = await openEvidence(`subnet:${SUBNET_A}`);
      const [first, second] = dataRows(dialog);
      expect(squash(first)).toMatch(
        /00:11:22:33:44:01.*10\.0\.1\.11.*files-a.*Acme.*Gi0\/1.*uplink to files.*10.*1 Gbps.*arp.*Matched/,
      );
      const link = within(first).getByRole("link", { name: /Matched/ });
      expect(link).toHaveAttribute("href", "/assets/ast-h1");
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
      // A label that is only the address is not a hostname.
      expect(squash(second)).toMatch(
        /00:11:22:33:44:02.*10\.0\.1\.12.*—.*Unknown.*—.*—.*—.*—.*arp.*Unmatched/,
      );
      expect(within(second).queryByRole("link")).toBeNull();
    });

    it("titles the MAC-only cluster, and closes on Escape or the close button", async () => {
      await loaded();
      let dialog = await openEvidence(`subnet:${MAC_ONLY}`);
      expect(dialog).toHaveAccessibleName(
        /Endpoint Evidence — MAC-Only \/ FDB Cluster/,
      );
      fireEvent.keyDown(document, { key: "Escape" });
      await settle();
      expect(screen.queryByRole("dialog")).toBeNull();

      fireEvent.click(buttonNamed(/View Endpoint Evidence/));
      await settle();
      dialog = screen.getByRole("dialog", { name: /Endpoint Evidence/ });
      fireEvent.click(within(dialog).getByRole("button", { name: /^Close/ }));
      await settle();
      expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("reopens on page one with an empty search", async () => {
      await loaded();
      let dialog = await openEvidence(`subnet:${SUBNET_B}`);
      fireEvent.click(
        within(dialog).getByRole("button", { name: "Show next 50" }),
      );
      fireEvent.keyDown(document, { key: "Escape" });
      await settle();
      fireEvent.click(buttonNamed(/View Endpoint Evidence/));
      await settle();
      dialog = screen.getByRole("dialog", { name: /Endpoint Evidence/ });
      expect(squash(dialog)).toContain("Showing 1-50 of 60");
      expect(
        within(dialog).getByRole("textbox", {
          name: "Search endpoint evidence",
        }),
      ).toHaveValue("");
    });
  });

  describe("recommended actions", () => {
    const actionButton = (action) =>
      screen.getAllByRole("button").find((b) => squash(b) === action);

    it.each([
      [
        "Run ARP-enabled scan",
        /Run ARP-enabled Scan/,
        "SNMP enabled",
        "Configure Scan Now",
        "/scan/new",
      ],
      [
        "Add gateway/router SNMP target",
        /Add SNMP target/,
        "ARP table to",
        "Go to Scan Setup",
        "/scan/new",
      ],
      [
        "Correlate with asset inventory",
        /Correlate with Asset Inventory/,
        "listed as MAC-only",
        "View Asset Registry",
        "/assets",
      ],
    ])(
      "“%s” explains the fix and navigates on request",
      async (action, title, excerpt, proceed, target) => {
        await loaded();
        await clickNode(`subnet:${SUBNET_A}`);
        expect(squash(sidebar())).toContain("Recommended Next Actions");
        fireEvent.click(actionButton(action));
        await settle();
        const dialog = screen.getByRole("dialog", { name: title });
        expect(squash(dialog)).toContain(excerpt);
        fireEvent.click(within(dialog).getByRole("button", { name: proceed }));
        await settle();
        expect(location()).toBe(target);
        expect(screen.queryByRole("dialog")).toBeNull();
      },
    );

    it.each([
      [
        "Enable ARP table collection",
        /Enable ARP Table Collection/,
        "1.3.6.1.2.1.4.22",
      ],
      [
        "Enable LLDP/CDP on infrastructure devices",
        /Enable LLDP\/CDP Link Discovery/,
        "cdp run",
      ],
    ])(
      "“%s” explains the fix and closes without navigating",
      async (action, title, excerpt) => {
        await loaded();
        await clickNode(`subnet:${SUBNET_A}`);
        fireEvent.click(actionButton(action));
        await settle();
        const dialog = screen.getByRole("dialog", { name: title });
        expect(squash(dialog)).toContain(excerpt);
        fireEvent.click(within(dialog).getByRole("button", { name: "Got it" }));
        await settle();
        expect(screen.queryByRole("dialog")).toBeNull();
        expect(location()).toBe("/topology");
      },
    );

    it("an action the page has no guidance for opens nothing", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      fireEvent.click(actionButton("Reboot everything"));
      await settle();
      expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("offers no actions for a subnet without recommendations", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_B}`);
      expect(squash(sidebar())).not.toContain("Recommended Next Actions");
    });
  });

  describe("routes and permission", () => {
    it("App.jsx mounts the page on three routes behind the base sign-in check only", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const base = app.indexOf("<Route element={<PrivateRoute />}>");
      const firstGate = app.indexOf("requiredPermission", base);
      const routes = [
        ...app.matchAll(
          /<Route\s+path="([^"]+)"\s+element=\{<NetworkMap\s*\/>\}\s*\/>/g,
        ),
      ];
      expect(routes.map((m) => m[1])).toEqual([
        "/scan/topology-map",
        "/scan/:scanId/topology-map",
        "/topology",
      ]);
      expect(base).toBeGreaterThan(-1);
      for (const m of routes) {
        expect(m.index).toBeGreaterThan(base);
        expect(m.index).toBeLessThan(firstGate);
      }
      expect(app.match(/<NetworkMap\b/g)).toHaveLength(3);
    });

    it("a visitor who is not signed in is sent to the login page and nothing is requested", async () => {
      await loaded("/topology", { user: null });
      expect(screen.getByText("Login page")).toBeInTheDocument();
      expect(api.get).not.toHaveBeenCalled();
    });

    it("without scans:read the page still mounts, and shows the backend's refusal", async () => {
      reply = () =>
        Promise.reject({
          response: {
            status: 403,
            data: {
              detail:
                "Insufficient privileges. Your role 'viewer' does not have 'scans:read' permission.",
            },
          },
        });
      await loaded("/topology", {
        user: { id: 8, role: { name: "viewer", permissions: ["assets:read"] } },
      });
      expect(topologyUrls()).toEqual([
        "/topology/map?subnet_mask=24&active_within_days=30",
      ]);
      expect(bodyText()).toContain(
        "Insufficient privileges. Your role 'viewer' does not have 'scans:read' permission.",
      );
      expect(vis.state.networks).toHaveLength(0);
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 21 — the specification. Every test here fails on the legacy page.
   ════════════════════════════════════════════════════════════════════════════ */

/* Every colour the canvas receives is named by one of these, defined in
   NetworkMap.css from a --ccure-* token. */
const CANVAS_TOKENS = [
  "--nmap-canvas",
  "--nmap-label-muted",
  "--nmap-edge",
  "--nmap-edge-highlight",
  "--nmap-link-lldp",
  "--nmap-link-cdp",
  "--nmap-link-edp",
  "--nmap-link-arp",
  "--nmap-status-ok",
  "--nmap-status-alert",
  "--nmap-status-info",
  "--nmap-danger-ink",
  "--nmap-danger-fill",
  "--nmap-warning-ink",
  "--nmap-warning-fill",
  "--nmap-success-ink",
  "--nmap-success-fill",
  "--nmap-info-ink",
  "--nmap-info-fill",
  "--nmap-primary-ink",
  "--nmap-primary-fill",
  "--nmap-neutral-ink",
  "--nmap-neutral-fill",
];

const SYSTEM_COLOURS = ["Canvas", "CanvasText", "GrayText", "Highlight"];

const palette = (green) =>
  Object.fromEntries(
    CANVAS_TOKENS.map((token, i) => [token, `rgb(${i + 1}, ${green}, 9)`]),
  );
const LIGHT = palette(10);
const DARK = palette(200);

const injectTokens = () => {
  const block = (values) =>
    Object.entries(values)
      .map(([k, v]) => `${k}: ${v};`)
      .join(" ");
  const style = document.createElement("style");
  style.setAttribute("data-nmap-test", "");
  style.textContent = `.nmap-page { ${block(LIGHT)} } :root[data-theme="dark"] .nmap-page { ${block(DARK)} }`;
  document.head.appendChild(style);
};

const svgOf = (n) => atob(n.image.replace("data:image/svg+xml;base64,", ""));
const svgColours = (n) =>
  [...svgOf(n).matchAll(/\b(?:fill|stroke|stop-color)="([^"]+)"/g)]
    .map((m) => m[1])
    .filter((v) => v !== "none");

describe("NetworkMap — batch 21", () => {
  describe("structure and names", () => {
    it("has one level-one heading, without its glyph", async () => {
      await loaded();
      const h1 = screen.getAllByRole("heading", { level: 1 });
      expect(h1).toHaveLength(1);
      expect(h1[0]).toHaveAccessibleName("Network Topology Map");
    });

    it("gives the sidebar sections and the selected node level-two headings", async () => {
      await loaded();
      expect(
        screen.getByRole("heading", { level: 2, name: "Subnets (3)" }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("heading", { level: 2, name: "Device Types" }),
      ).toBeInTheDocument();
      await clickNode(`subnet:${SUBNET_A}`);
      expect(
        screen.getByRole("heading", { level: 2, name: SUBNET_A }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("heading", {
          level: 3,
          name: "Recommended Next Actions",
        }),
      ).toBeInTheDocument();
    });

    it("labels every map control and names its buttons without glyphs", async () => {
      await loaded();
      expect(screen.getByRole("combobox", { name: "Subnet mask" })).toHaveValue(
        "24",
      );
      expect(screen.getByRole("combobox", { name: "Seen within" })).toHaveValue(
        "30",
      );
      expect(screen.getByRole("combobox", { name: "Layout" })).toHaveValue(
        "hierarchical",
      );
      expect(
        screen.getByRole("textbox", { name: "Search hosts" }),
      ).toHaveAttribute("placeholder", "Search IP, Hostname, MAC...");
      for (const name of [
        "Refresh",
        "Fit Screen",
        "Expand All",
        "Collapse All",
        "Select All",
        "Clear",
      ]) {
        expect(screen.getByRole("button", { name })).toBeEnabled();
      }
    });

    it("groups the subnet checkboxes, each named by its subnet", async () => {
      await loaded();
      const group = screen.getByRole("group", { name: "Visible subnets" });
      expect(
        within(group)
          .getAllByRole("checkbox")
          .map(
            (c) => c.getAttribute("aria-label") ?? squash(c.closest("label")),
          ),
      ).toEqual(TOPOLOGY.subnets);
      for (const subnet of TOPOLOGY.subnets) {
        expect(
          within(group).getByRole("checkbox", { name: subnet }),
        ).toBeChecked();
      }
    });

    it("announces loading, and a failed load as an alert beside its Retry button", async () => {
      reply = () => new Promise(() => {});
      const view = renderAt();
      await flush();
      expect(
        screen
          .getAllByRole("status")
          .some((s) => /Loading topology nodes\.\.\./.test(s.textContent)),
      ).toBe(true);
      view.unmount();

      reply = () => Promise.resolve({ data: { success: false } });
      await loaded();
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Failed to load topology data",
      );
      expect(screen.getByRole("button", { name: "Retry" })).toBeEnabled();
    });

    it("announces the selected node", async () => {
      await loaded();
      const announcement = () =>
        screen
          .getAllByRole("status")
          .map((s) => squash(s))
          .find((t) => /^Selected /.test(t));
      await clickNode(`subnet:${SUBNET_B}`);
      expect(announcement()).toBe(`Selected subnet ${SUBNET_B}`);
      await clickNode("ip:10.0.0.1");
      expect(announcement()).toBe("Selected infra core-rtr");
      await clickNode(null);
      expect(announcement()).toBeUndefined();
    });

    it("names the asset link and its new tab", async () => {
      await loaded();
      await clickNode("ip:10.0.0.1");
      expect(
        screen.getByRole("button", { name: "View Asset Details for core-rtr" }),
      ).toBeEnabled();
      const dialog = await openEvidence(`subnet:${SUBNET_A}`);
      expect(
        within(dialog).getByRole("link", {
          name: "Matched (opens in a new tab)",
        }),
      ).toHaveAttribute("href", "/assets/ast-h1");
    });
  });

  describe("dialogs", () => {
    it("shows endpoint evidence in a design-system dialog with a captioned, scoped table", async () => {
      await loaded();
      const dialog = await openEvidence(`subnet:${SUBNET_B}`);
      expect(dialog).toHaveClass("cc-modal");
      expect(dialog).toHaveAccessibleName(`Endpoint Evidence — ${SUBNET_B}`);
      const table = within(dialog).getByRole("table", {
        name: `Endpoints in ${SUBNET_B}`,
      });
      const headers = within(table).getAllByRole("columnheader");
      expect(headers.map(squash)).toEqual([
        "MAC",
        "IP",
        "Hostname",
        "Vendor",
        "Port",
        "Port Description",
        "VLAN",
        "Speed",
        "Source",
        "Asset",
      ]);
      for (const th of headers) expect(th).toHaveAttribute("scope", "col");
      expect(
        within(dialog).getByRole("navigation", { name: "Endpoint pages" }),
      ).toBeInTheDocument();
    });

    it("shows action guidance in a design-system dialog named without its glyph", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      fireEvent.click(
        screen.getByRole("button", { name: "Run ARP-enabled scan" }),
      );
      await settle();
      const dialog = screen.getByRole("dialog", {
        name: "Run ARP-enabled Scan",
      });
      expect(dialog).toHaveClass("cc-modal");
    });
  });

  describe("presentation", () => {
    it("hides decorative glyphs from assistive technology", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_B}`);
      await openEvidence(`subnet:${SUBNET_A}`);
      const glyphs = /[🗺🔍📂📁📊🔗⚠↻→🚀🔌🌐📋]/u;
      const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
      );
      const exposed = [];
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (
          glyphs.test(n.textContent) &&
          !n.parentElement.closest("[aria-hidden=true]")
        ) {
          exposed.push(n.textContent.trim());
        }
      }
      expect(exposed).toEqual([]);
    });

    it("renders no inline style", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_B}`);
      await openEvidence(`subnet:${SUBNET_A}`);
      expect(document.body.querySelectorAll("[style]")).toHaveLength(0);
    });

    it("carries no colour literals, legacy classes or legacy modal in its source", () => {
      const source = readFileSync(
        path.join(SRC, "pages/scan/NetworkMap.jsx"),
        "utf8",
      );
      expect(source).toMatch(
        /import\s+["']\.\.\/\.\.\/styles\/NetworkMap\.css["']/,
      );
      expect(source).toMatch(/from\s+["']\.\.\/\.\.\/design-system["']/);
      expect(source).not.toMatch(/components\/layout\/Modal/);
      expect(source).not.toMatch(/style=\{\{/);
      expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
      expect(source).not.toMatch(/\b(?:rgba?|hsla?)\(\s*\d/);
      expect(source).not.toMatch(/["'`]var\(--/);
      const classes = [
        ...source.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g),
      ].flatMap((m) => (m[1] ?? m[2]).split(/\s+/));
      expect(
        classes.filter((c) =>
          ["btn", "btn--primary", "btn--secondary", "nmap-stat"].includes(c),
        ),
      ).toEqual([]);
    });

    it("styles the page from tokens only, and defines every canvas token from a CCure token", () => {
      const css = readFileSync(path.join(SRC, "styles/NetworkMap.css"), "utf8");
      expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
      expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
      expect(css.match(/var\(--(?!ccure-|nmap-)/g) || []).toEqual([]);
      expect(css).toMatch(/:focus-visible/);

      const page = css.match(/\.nmap-page\s*\{([\s\S]*?)\n\}/);
      expect(page).not.toBeNull();
      const defined = Object.fromEntries(
        [...page[1].matchAll(/(--nmap-[a-z0-9-]+)\s*:\s*([^;]+);/g)].map(
          (m) => [m[1], m[2].trim()],
        ),
      );
      expect(Object.keys(defined).sort()).toEqual([...CANVAS_TOKENS].sort());
      for (const value of Object.values(defined)) {
        expect(value).toMatch(/^var\(--ccure-[a-z0-9-]+\)$/);
      }

      const source = readFileSync(
        path.join(SRC, "pages/scan/NetworkMap.jsx"),
        "utf8",
      );
      const referenced = new Set(source.match(/--nmap-[a-z0-9-]+/g) || []);
      expect([...referenced].sort()).toEqual([...CANVAS_TOKENS].sort());
    });
  });

  describe("canvas colours", () => {
    it("falls back to system colours when the tokens cannot be read", async () => {
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      const colours = [];
      for (const n of nodes().get()) {
        colours.push(n.font.color, n.font.strokeColor, ...svgColours(n));
      }
      for (const e of edges().get()) {
        colours.push(
          e.color.color,
          ...(e.color.highlight ? [e.color.highlight] : []),
        );
        if (e.font) colours.push(e.font.color);
      }
      expect(colours.length).toBeGreaterThan(20);
      expect(
        [...new Set(colours)].filter((c) => !SYSTEM_COLOURS.includes(c)),
      ).toEqual([]);
    });

    it("paints nodes, labels, icons and edges from the page's tokens", async () => {
      injectTokens();
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      const L = LIGHT;
      const router = node("ip:10.0.0.1");
      expect(router.font.color).toBe(L["--nmap-danger-ink"]);
      expect(router.font.strokeColor).toBe(L["--nmap-canvas"]);
      expect(new Set(svgColours(router))).toEqual(
        new Set([
          L["--nmap-danger-ink"],
          L["--nmap-danger-fill"],
          L["--nmap-canvas"],
        ]),
      );
      const sw = node("ip:10.0.0.2");
      expect(sw.font.color).toBe(L["--nmap-primary-ink"]);
      expect(svgColours(sw)).toEqual(
        expect.arrayContaining([
          L["--nmap-status-ok"],
          L["--nmap-status-alert"],
        ]),
      );
      expect(node("ip:10.0.0.3").font.color).toBe(L["--nmap-neutral-ink"]);
      const subnet = node(`subnet:${SUBNET_A}`);
      expect(subnet.font.color).toBe(L["--nmap-info-ink"]);
      expect(new Set(svgColours(subnet))).toEqual(
        new Set([
          L["--nmap-info-ink"],
          L["--nmap-info-fill"],
          L["--nmap-canvas"],
        ]),
      );
      const host = node(HOSTS_A[0].id);
      expect(host.font.color).toBe(L["--nmap-label-muted"]);
      expect(host.font.strokeColor).toBe(L["--nmap-canvas"]);
      expect(svgColours(host)).toContain(L["--nmap-primary-ink"]);

      expect(edge("edge-core").color).toEqual({
        color: L["--nmap-link-lldp"],
        highlight: L["--nmap-edge-highlight"],
      });
      expect(edge("edge-core").font.color).toBe(L["--nmap-label-muted"]);
      expect(edge("edge-slow").color.color).toBe(L["--nmap-link-cdp"]);
      expect(edge("edge-a").color.color).toBe(L["--nmap-link-arp"]);
      expect(edge("edge-b").color.color).toBe(L["--nmap-link-edp"]);
      expect(edge("edge-mac").color.color).toBe(L["--nmap-edge"]);
      expect(edge(`edge:host:${HOSTS_A[0].id}`).color).toEqual({
        color: L["--nmap-edge"],
      });
      // The shadow keeps vis-network's own colour; the page passes none.
      expect(network().options.nodes.shadow.color).toBeUndefined();
    });

    it("repaints the same network when the theme changes, in both directions", async () => {
      injectTokens();
      await loaded();
      await clickNode(`subnet:${SUBNET_A}`);
      const first = network();
      expect(node("ip:10.0.0.1").font.color).toBe(LIGHT["--nmap-danger-ink"]);

      await act(async () => {
        document.documentElement.setAttribute("data-theme", "dark");
      });
      await settle();
      expect(node("ip:10.0.0.1").font.color).toBe(DARK["--nmap-danger-ink"]);
      expect(node(HOSTS_A[0].id).font.color).toBe(DARK["--nmap-label-muted"]);
      expect(svgColours(node(`subnet:${SUBNET_A}`))).toContain(
        DARK["--nmap-info-fill"],
      );
      expect(edge("edge-core").color.color).toBe(DARK["--nmap-link-lldp"]);
      // Repainted in place: the operator's zoom and pan survive.
      expect(vis.state.networks).toEqual([first]);
      expect(first.destroyed).toBe(0);
      expect(hostIds()).toHaveLength(2);

      await act(async () => {
        document.documentElement.removeAttribute("data-theme");
      });
      await settle();
      expect(node("ip:10.0.0.1").font.color).toBe(LIGHT["--nmap-danger-ink"]);
      expect(topologyUrls()).toHaveLength(1);
    });
  });

  describe("canvas contrast, measured from the real tokens", () => {
    const TOKENS_DIR = path.join(SRC, "design-system", "tokens");
    const declarations = (block) => {
      const out = {};
      for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+)/g)) {
        out[m[1]] = m[2].trim();
      }
      return out;
    };

    const themes = () => {
      const ux4g = readFileSync(
        path.join(TOKENS_DIR, "ux4g.generated.css"),
        "utf8",
      );
      const ccure = readFileSync(
        path.join(TOKENS_DIR, "ccure-tokens.css"),
        "utf8",
      );
      const css = readFileSync(path.join(SRC, "styles/NetworkMap.css"), "utf8");
      let uLight = {};
      for (const m of ux4g.matchAll(/:root\{([\s\S]*?)\}/g)) {
        uLight = { ...uLight, ...declarations(m[1]) };
      }
      let uDark = {};
      for (const m of ux4g.matchAll(
        /:root\[data-theme=dark\]\{([\s\S]*?)\}/g,
      )) {
        uDark = { ...uDark, ...declarations(m[1]) };
      }
      let cLight = {};
      for (const m of ccure.matchAll(/(?:^|\n):root\s*\{([\s\S]*?)\n\}/g)) {
        cLight = { ...cLight, ...declarations(m[1]) };
      }
      const cDark = declarations(
        ccure.match(/:root\[data-theme="dark"\]\s*\{([\s\S]*?)\n\}/)?.[1] ?? "",
      );
      const page = declarations(
        css.match(/\.nmap-page\s*\{([\s\S]*?)\n\}/)?.[1] ?? "",
      );
      const light = { ...uLight, ...cLight, ...page };
      return { light, dark: { ...light, ...uDark, ...cDark, ...page } };
    };

    const resolve = (name, table, depth = 0) => {
      if (depth > 12) return null;
      const raw = table[name];
      if (!raw) return null;
      const m = raw.match(/^var\(\s*(--[a-z0-9-]+)/);
      return m ? resolve(m[1], table, depth + 1) : raw;
    };
    const rgb = (value) => {
      const h = value?.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
      if (!h) return null;
      const s =
        h[1].length === 3
          ? h[1]
              .split("")
              .map((c) => c + c)
              .join("")
          : h[1];
      return [0, 2, 4].map((i) => parseInt(s.slice(i, i + 2), 16));
    };
    const luminance = ([r, g, b]) => {
      const f = (c) => {
        const s = c / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const ratio = (fg, bg, table) => {
      const a = rgb(resolve(fg, table));
      const b = rgb(resolve(bg, table));
      if (!a || !b) return null;
      const [x, y] = [luminance(a), luminance(b)];
      return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
    };

    const FAMILIES = [
      "danger",
      "warning",
      "success",
      "info",
      "primary",
      "neutral",
    ];

    it.each(["light", "dark"])(
      "every label on the canvas halo reaches 4.5:1, and every line and icon 3:1 (%s)",
      (theme) => {
        const table = themes()[theme];
        const failures = [];
        const check = (fg, bg, floor) => {
          const r = ratio(fg, bg, table);
          if (r === null || r < floor) failures.push(`${fg} on ${bg}: ${r}`);
        };
        // Labels: 9–13 px text, drawn over a halo of the canvas colour.
        check("--nmap-label-muted", "--nmap-canvas", 4.5);
        for (const f of FAMILIES)
          check(`--nmap-${f}-ink`, "--nmap-canvas", 4.5);
        // Lines and icon outlines against the canvas; icon detail on its fill.
        for (const t of [
          "--nmap-edge",
          "--nmap-edge-highlight",
          "--nmap-link-lldp",
          "--nmap-link-cdp",
          "--nmap-link-edp",
          "--nmap-link-arp",
        ]) {
          check(t, "--nmap-canvas", 3);
        }
        for (const f of FAMILIES)
          check(`--nmap-${f}-ink`, `--nmap-${f}-fill`, 3);
        for (const s of ["ok", "alert", "info"]) {
          for (const f of ["primary", "success", "neutral"]) {
            check(`--nmap-status-${s}`, `--nmap-${f}-fill`, 3);
          }
        }
        expect(failures).toEqual([]);
      },
    );

    it("paints the graph background with the canvas token", () => {
      const css = readFileSync(path.join(SRC, "styles/NetworkMap.css"), "utf8");
      expect(css).toMatch(
        /\.nmap-canvas\s*\{[^}]*background(?:-color)?:\s*var\(--nmap-canvas\)/,
      );
    });
  });
});
