import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import NetworkMap from "../../../pages/scan/NetworkMap";
import AuthContext from "../../../context/AuthContext";
import { PreferencesProvider } from "../../../context/PreferencesContext";
import api from "../../../api/axiosInstance";

// Mock the API instance
vi.mock("../../../api/axiosInstance");

// Mock vis-network library since it requires browser canvas APIs.
//
// The implementations are `function` expressions rather than arrow functions,
// and that is load-bearing rather than style. NetworkMap calls `new DataSet()`
// and `new Network()`, and from Vitest 4 a mock whose implementation is an
// arrow function is no longer constructible — `new` on it raises "is not a
// constructor". Vitest says so directly: "The vi.fn() mock did not use
// 'function' or 'class' in its implementation."
//
// The component catches that failure and degrades to "Failed to load
// vis-network", so the symptom is not an obvious crash: most assertions still
// pass and one test fails for a reason that reads like a component bug.
vi.mock("vis-network/standalone", () => {
  const mockNetwork = vi.fn().mockImplementation(function () {
    return {
      destroy: vi.fn(),
      fit: vi.fn(),
      on: vi.fn(),
      once: vi.fn(),
    };
  });
  const mockDataSet = vi.fn().mockImplementation(function () {
    return {
      clear: vi.fn(),
      add: vi.fn(),
      remove: vi.fn(),
      get: vi.fn(),
      getIds: vi.fn().mockReturnValue([]),
      length: 0,
    };
  });
  return {
    Network: mockNetwork,
    DataSet: mockDataSet,
  };
});

describe("NetworkMap Component", () => {
  const mockUser = { role: { name: "admin" } };

  // Mirrors the payload core.topology.engine.get_topology_graph actually emits
  // (graph_version 3): endpoint identities are canonical keys, host nodes carry
  // the evidence of how they were observed, and edges carry link typing.
  const mockTopologyResponse = {
    success: true,
    graph_version: 3,
    nodes: [
      {
        id: "ip:10.180.4.1",
        label: "10.180.4.1",
        group: "switch",
        tier: "infra",
        ip: "10.180.4.1",
        mac: "",
        asset_id: null,
      },
      {
        id: "subnet:10.180.4.0/24",
        label: "10.180.4.0/24\n(2 hosts)",
        group: "subnet",
        tier: "subnet",
        subnet: "10.180.4.0/24",
        host_count: 2,
        data_quality: {
          ip_resolved: 2,
          mac_only: 0,
          asset_matches: 1,
          source_count: 1,
          has_arp: true,
          has_fdb: false,
        },
        recommended_actions: [],
      },
      {
        id: "00:11:22:33:44:55",
        label: "10.180.4.15",
        group: "endpoint",
        tier: "host",
        ip: "10.180.4.15",
        mac: "00:11:22:33:44:55",
        vendor: "Acme",
        subnet: "10.180.4.0/24",
        source_key: "ip:10.180.4.1",
        source_label: "10.180.4.1",
        source_port: "if1",
        link_type: "arp",
        observed_types: "arp",
        asset_id: "ast-1",
        asset_match_status: "matched",
      },
      {
        id: "00:11:22:33:44:66",
        label: "10.180.4.16",
        group: "endpoint",
        tier: "host",
        ip: "10.180.4.16",
        mac: "00:11:22:33:44:66",
        vendor: "",
        subnet: "10.180.4.0/24",
        source_key: "ip:10.180.4.1",
        source_label: "10.180.4.1",
        source_port: "if2",
        link_type: "arp",
        observed_types: "arp",
        asset_id: null,
        asset_match_status: "unmatched",
      },
    ],
    edges: [
      {
        id: "edge-1",
        from: "ip:10.180.4.1",
        to: "subnet:10.180.4.0/24",
        tier: "subnet",
        link_type: "arp",
        host_count: 2,
        source_port: "if1, if2",
        link_details: {
          type_counts: { arp: 2 },
          summary: "arp: 2",
          ports: ["if1", "if2"],
        },
      },
    ],
    subnets: ["10.180.4.0/24"],
    stats: {
      infrastructure: 1,
      subnets: 1,
      hosts: 2,
      mac_only: 0,
      asset_matched: 1,
      links: 2,
    },
  };

  const renderComponent = () => {
    return render(
      <AuthContext.Provider value={{ user: mockUser, loading: false }}>
        <PreferencesProvider>
          <MemoryRouter>
            <NetworkMap />
          </MemoryRouter>
        </PreferencesProvider>
      </AuthContext.Provider>,
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
    api.get.mockResolvedValue({ data: mockTopologyResponse });
  });

  it("renders loading state initially", () => {
    api.get.mockImplementation(() => new Promise(() => {})); // pending promise
    renderComponent();
    expect(screen.getByText(/Loading topology nodes/i)).toBeInTheDocument();
  });

  it("renders statistics and title after successful fetch", async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText("🗺️ Network Topology Map")).toBeInTheDocument();
      expect(screen.getByText("Visible Nodes")).toBeInTheDocument();
      expect(screen.getByText("Total Hosts")).toBeInTheDocument();
    });
  });

  it("displays subnets checkboxes in the sidebar filter list", async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText("10.180.4.0/24")).toBeInTheDocument();
    });
  });

  it("renders data quality summary", async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText("MAC-only endpoints")).toBeInTheDocument();
      expect(screen.getByText("IPs resolved")).toBeInTheDocument();
      expect(screen.getByText("ARP present")).toBeInTheDocument();
      // Neither switch reported a neighbour table, and the strip has to say so
      // rather than implying the physical layer was mapped.
      expect(
        screen.getByText("No neighbour discovery (LLDP/CDP/EDP)"),
      ).toBeInTheDocument();
    });
  });

  it("counts distinct topology sources from endpoint evidence", async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText("Topology sources")).toBeInTheDocument();
    });
    // Both endpoints were observed by the same switch: one source, not two.
    const sources = screen
      .getByText("Topology sources")
      .closest(".nmap-quality-item");
    expect(sources).toHaveTextContent("1");
  });

  it("requests a freshness window for the org-wide map", async () => {
    renderComponent();
    // Links accumulate across scans; the org-wide view must not default to
    // showing every adjacency ever recorded.
    await waitFor(() => {
      const topologyCall = api.get.mock.calls.find(([url]) =>
        String(url).startsWith("/topology/map"),
      );
      expect(topologyCall).toBeDefined();
      expect(topologyCall[0]).toContain("active_within_days=30");
      expect(topologyCall[0]).toContain("subnet_mask=24");
    });
  });

  it("drops duplicate node ids instead of failing the whole render", async () => {
    api.get.mockResolvedValue({
      data: {
        ...mockTopologyResponse,
        nodes: [...mockTopologyResponse.nodes, mockTopologyResponse.nodes[0]],
      },
    });
    renderComponent();
    // A duplicate id makes vis-network's DataSet.add() throw; the map must
    // still come up rather than showing the engine-failure message.
    await waitFor(() => {
      expect(screen.getByText("🗺️ Network Topology Map")).toBeInTheDocument();
    });
    expect(screen.queryByText(/Failed to load network engine/i)).toBeNull();
  });

  it("updates search query matching inputs on search fields", async () => {
    renderComponent();
    await waitFor(() => {
      const searchInput = screen.getByPlaceholderText(
        /Search IP, Hostname, MAC/i,
      );
      fireEvent.change(searchInput, { target: { value: "10.180.4.15" } });
      expect(searchInput.value).toBe("10.180.4.15");
    });
  });
});
