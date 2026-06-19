import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import NetworkMap from "../../../pages/scan/NetworkMap";
import AuthContext from "../../../context/AuthContext";
import { PreferencesProvider } from "../../../context/PreferencesContext";
import api from "../../../api/axiosInstance";

// Mock the API instance
vi.mock("../../../api/axiosInstance");

// Mock vis-network library since it requires browser canvas APIs
vi.mock("vis-network/standalone", () => {
  const mockNetwork = vi.fn().mockImplementation(() => ({
    destroy: vi.fn(),
    fit: vi.fn(),
    on: vi.fn(),
    once: vi.fn()
  }));
  const mockDataSet = vi.fn().mockImplementation(() => ({
    clear: vi.fn(),
    add: vi.fn(),
    remove: vi.fn(),
    get: vi.fn(),
    getIds: vi.fn().mockReturnValue([]),
    length: 0
  }));
  return {
    Network: mockNetwork,
    DataSet: mockDataSet
  };
});

describe("NetworkMap Component", () => {
  const mockUser = { role: { name: "admin" } };
  
  const mockTopologyResponse = {
    success: true,
    graph_version: 2,
    nodes: [
      { id: "sw:10:180:4:1", label: "10.180.4.1", group: "switch", tier: "infra" },
      {
        id: "subnet:10.180.4.0/24",
        label: "10.180.4.0/24\n(2 hosts)",
        group: "subnet",
        tier: "subnet",
        subnet: "10.180.4.0/24",
        host_count: 2,
        data_quality: { ip_resolved: 2, mac_only: 0, asset_matches: 1, source_count: 1, has_arp: true, has_fdb: false },
        recommended_actions: []
      },
      { id: "host:1", label: "10.180.4.15", group: "host", tier: "host", ip: "10.180.4.15", mac: "00:11:22:33:44:55", vendor: "Acme", subnet: "10.180.4.0/24", source_port: "if1", asset_match_status: "matched" },
      { id: "host:2", label: "10.180.4.16", group: "host", tier: "host", ip: "10.180.4.16", mac: "00:11:22:33:44:66", vendor: "", subnet: "10.180.4.0/24", source_port: "if2", asset_match_status: "unmatched" }
    ],
    edges: [
      { id: "edge-1", from: "sw:10:180:4:1", to: "subnet:10.180.4.0/24", tier: "subnet", host_count: 2 }
    ],
    subnets: ["10.180.4.0/24"],
    stats: { infrastructure: 1, subnets: 1, hosts: 2, mac_only: 0 }
  };

  const renderComponent = () => {
    return render(
      <AuthContext.Provider value={{ user: mockUser, loading: false }}>
        <PreferencesProvider>
          <MemoryRouter>
            <NetworkMap />
          </MemoryRouter>
        </PreferencesProvider>
      </AuthContext.Provider>
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
    });
  });

  it("updates search query matching inputs on search fields", async () => {
    renderComponent();
    await waitFor(() => {
      const searchInput = screen.getByPlaceholderText(/Search IP, Hostname, MAC/i);
      fireEvent.change(searchInput, { target: { value: "10.180.4.15" } });
      expect(searchInput.value).toBe("10.180.4.15");
    });
  });
});
