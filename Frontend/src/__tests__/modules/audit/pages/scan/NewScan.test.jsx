import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import NewScan from "@audit/pages/scan/NewScan";
import { ScanProvider } from "@audit/context/ScanContext";
import AuthContext from "@shell/auth/AuthContext";
import { PreferencesProvider } from "@shell/preferences/PreferencesContext";
import api from "@shell/api/axiosInstance";

// Mock the API and Toasts
vi.mock("@shell/api/axiosInstance");
vi.mock("@shell/feedback/Toast", () => ({
  useToasts: () => ({ pushes: vi.fn(), dismiss: vi.fn() }),
  ToastContainer: () => <div>ToastContainer</div>,
}));

// Mock user api for PreferencesContext
vi.mock("@shell/api/user", () => ({
  getPreferences: vi.fn().mockResolvedValue({ theme: "light" }),
}));

// Mock the quota bar
vi.mock("@audit/components/scan/ScanQuotaBar", () => ({
  default: ({ onQuotaChange: _onQuotaChange }) => (
    <div data-testid="quota-bar" />
  ),
}));

// The target input carries no id, name or aria-label, so its placeholder is the
// only handle a query can reach it by. That placeholder changed from
// "192.168.1.0/24" to the current value and these four tests kept looking for
// the old one — which nothing caught, because the frontend suite was never run
// by CI. Keep the pattern here, in one place, so the next copy change breaks a
// single line rather than four.
const TARGET_PLACEHOLDER = /10\.180\.6\.0\/24/i;

describe("NewScan Component", () => {
  const userWithPermission = {
    role: { name: "admin", permissions: ["scans:execute"] },
  };

  const renderComponent = (user = userWithPermission) => {
    return render(
      <AuthContext.Provider
        value={{
          user,
          loading: false,
          authState: "authenticated",
          isAuthenticated: true,
        }}
      >
        <PreferencesProvider>
          <ScanProvider>
            <MemoryRouter>
              <NewScan />
            </MemoryRouter>
          </ScanProvider>
        </PreferencesProvider>
      </AuthContext.Provider>,
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the scan wizard correctly", () => {
    renderComponent();
    expect(screen.getByPlaceholderText(TARGET_PLACEHOLDER)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Start Scan/i }),
    ).toBeInTheDocument();
  });

  it("handles input target change", () => {
    renderComponent();
    const input = screen.getByPlaceholderText(TARGET_PLACEHOLDER);
    fireEvent.change(input, { target: { value: "10.0.0.1" } });
    expect(input.value).toBe("10.0.0.1");
  });

  it("shows an error state if API request fails", async () => {
    api.post.mockRejectedValueOnce({
      message: "Invalid target specified",
    });

    renderComponent();

    const input = screen.getByPlaceholderText(TARGET_PLACEHOLDER);
    fireEvent.change(input, { target: { value: "invalid-target" } });

    const startButton = screen.getByRole("button", { name: /Start Scan/i });
    fireEvent.click(startButton);

    await waitFor(() => {
      expect(screen.getByText(/Invalid target specified/i)).toBeInTheDocument();
    });
  });

  it("prevents execution if user lacks permission", () => {
    const userWithoutPermission = { role: { name: "viewer", permissions: [] } };
    renderComponent(userWithoutPermission);

    const input = screen.getByPlaceholderText(TARGET_PLACEHOLDER);
    expect(input).toBeDisabled();

    const startButton = screen.getByRole("button", { name: /Start Scan/i });
    expect(startButton).toBeDisabled();
  });
});
