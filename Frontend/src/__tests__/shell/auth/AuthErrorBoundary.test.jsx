import { expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import AuthErrorBoundary from "@shell/auth/components/AuthErrorBoundary";

function RenderingFailure() {
  throw new Error("SYNTHETIC_PRIVATE_TOKEN: render failure");
}

it("keeps Authentication rendering errors within CCure without exposing diagnostics or scan claims", () => {
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    const { container } = render(
      <MemoryRouter initialEntries={["/login"]}>
        <AuthErrorBoundary>
          <RenderingFailure />
        </AuthErrorBoundary>
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "Authentication page unavailable",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "This authentication page could not be displayed.",
    );
    expect(
      screen.getByRole("link", { name: "Return to sign in" }),
    ).toHaveAttribute("href", "/login");
    expect(container).not.toHaveTextContent(
      /audit|scan result|saved|SYNTHETIC_PRIVATE_TOKEN/i,
    );
    expect(document.title).toBe(
      "Authentication page unavailable | CCure PRO Platform",
    );
    expect(errors).toHaveBeenCalled();
  } finally {
    errors.mockRestore();
  }
});

it("clears the rendering failure when the Authentication route changes", async () => {
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <Link to="/forgot-password">Recovery route</Link>
        <Routes>
          <Route element={<AuthErrorBoundary />}>
            <Route path="/login" element={<RenderingFailure />} />
            <Route path="/forgot-password" element={<h1>Recover account</h1>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole("link", { name: "Recovery route" }));
    expect(
      screen.getByRole("heading", { name: "Recover account" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Authentication page unavailable"),
    ).not.toBeInTheDocument();
  } finally {
    errors.mockRestore();
  }
});
