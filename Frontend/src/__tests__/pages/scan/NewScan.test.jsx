import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import NewScan from "../../../pages/scan/NewScan";
import { ScanProvider } from "../../../context/ScanContext";
import AuthContext from "../../../context/AuthContext";
import { PreferencesProvider } from "../../../context/PreferencesContext";
import api from "../../../api/axiosInstance";

// Mock the API and Toasts
vi.mock("../../../api/axiosInstance");
vi.mock("../../../components/common/Toast", () => ({
  useToasts: () => ({ pushes: vi.fn(), dismiss: vi.fn() }),
  ToastContainer: () => <div>ToastContainer</div>
}));

// Mock user api for PreferencesContext
vi.mock("../../../api/user", () => ({
  getPreferences: vi.fn().mockResolvedValue({ theme: "light" })
}));

// Mock the quota bar
vi.mock("../../../components/scan/ScanQuotaBar", () => ({
  default: ({ onQuotaChange }) => <div data-testid="quota-bar" />
}));

describe("NewScan Component", () => {
  const userWithPermission = { role: { name: "admin", permissions: ["scans:execute"] } };
  
  const renderComponent = (user = userWithPermission) => {
    return render(
      <AuthContext.Provider value={{ user, loading: false, authState: "authenticated", isAuthenticated: true }}>
        <PreferencesProvider>
          <ScanProvider>
            <MemoryRouter>
              <NewScan />
            </MemoryRouter>
          </ScanProvider>
        </PreferencesProvider>
      </AuthContext.Provider>
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the scan wizard correctly", () => {
    renderComponent();
    expect(screen.getByPlaceholderText(/192.168.1.0\/24/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Start Scan/i })).toBeInTheDocument();
  });

  it("handles input target change", () => {
    renderComponent();
    const input = screen.getByPlaceholderText(/192.168.1.0\/24/i);
    fireEvent.change(input, { target: { value: "10.0.0.1" } });
    expect(input.value).toBe("10.0.0.1");
  });

  it("shows an error state if API request fails", async () => {
    api.post.mockRejectedValueOnce({
      response: { data: { detail: "Invalid target specified" } }
    });

    renderComponent();
    
    const input = screen.getByPlaceholderText(/192.168.1.0\/24/i);
    fireEvent.change(input, { target: { value: "invalid-target" } });
    
    const startButton = screen.getByRole("button", { name: /Start Scan/i });
    fireEvent.click(startButton);
    
    await waitFor(() => {
      expect(screen.getByText("Invalid target specified")).toBeInTheDocument();
    });
  });

  it("prevents execution if user lacks permission", () => {
    const userWithoutPermission = { role: { name: "viewer", permissions: [] } };
    renderComponent(userWithoutPermission);
    
    const input = screen.getByPlaceholderText(/192.168.1.0\/24/i);
    expect(input).toBeDisabled();
    
    const startButton = screen.getByRole("button", { name: /Start Scan/i });
    expect(startButton).toBeDisabled();
  });
});
