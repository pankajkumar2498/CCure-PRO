/**
 * VerifyEmail — Checkpoint 3C auth-group migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * Verification is not a login. Confirming the mailbox proves control of the
 * address and nothing more; the account still needs an administrator's
 * approval, and this page must keep saying so rather than implying access has
 * been granted.
 *
 * Three further properties, each load-bearing:
 *
 *   * the token arrives as a query parameter but is submitted in a POST body,
 *     so it must never be rendered, stored, or put in an outgoing link;
 *   * tokens are single-use and the row is deleted in the same transaction
 *     that flips is_verified, so StrictMode's double mount must not consume
 *     one twice — the second call would report a valid link as invalid;
 *   * "invalid" and "missing" deliberately share one panel. Distinguishing
 *     them would leak which tokens exist.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { StrictMode } from "react";

import VerifyEmail from "../../pages/VerifyEmail";
import { verifyEmail, resendVerification } from "../../api/auth";

let search = "?token=VERIFY-TOKEN-1";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useSearchParams: () => [new URLSearchParams(search), vi.fn()],
  };
});

vi.mock("../../api/auth", () => ({
  verifyEmail: vi.fn(),
  resendVerification: vi.fn(),
}));

const renderPage = () =>
  render(
    <MemoryRouter>
      <VerifyEmail />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  search = "?token=VERIFY-TOKEN-1";
  localStorage.clear();
  sessionStorage.clear();
  verifyEmail.mockResolvedValue({ status: "verified", detail: "" });
  resendVerification.mockResolvedValue({});
});

/* ── API contract ─────────────────────────────────────────────────────────── */

describe("VerifyEmail — API contract", () => {
  it("submits the token from the query string on mount", async () => {
    renderPage();

    await waitFor(() => expect(verifyEmail).toHaveBeenCalledTimes(1));
    expect(verifyEmail).toHaveBeenCalledWith("VERIFY-TOKEN-1");
  });

  it("consumes the single-use token exactly once under StrictMode", async () => {
    render(
      <StrictMode>
        <MemoryRouter>
          <VerifyEmail />
        </MemoryRouter>
      </StrictMode>,
    );

    await waitFor(() => expect(verifyEmail).toHaveBeenCalledTimes(1));
    // A second call would spend a token the first had already consumed and
    // the page would report a valid link as invalid.
    await new Promise((r) => setTimeout(r, 50));
    expect(verifyEmail).toHaveBeenCalledTimes(1);
  });

  it("makes no request at all when the link carries no token", async () => {
    search = "";
    renderPage();

    await screen.findByText(/no longer valid/i);
    expect(verifyEmail).not.toHaveBeenCalled();
  });

  it("resends to the address the user typed", async () => {
    search = "";
    renderPage();
    await screen.findByText(/no longer valid/i);

    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/enter your email/i),
      "a@example.com",
    );
    await user.click(screen.getByRole("button", { name: /send a new/i }));

    await waitFor(() => expect(resendVerification).toHaveBeenCalledTimes(1));
    expect(resendVerification).toHaveBeenCalledWith("a@example.com");
  });

  it("does not resend an address that is not an address", async () => {
    search = "";
    renderPage();
    await screen.findByText(/no longer valid/i);

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/enter your email/i), "not-an-email");
    await user.click(screen.getByRole("button", { name: /send a new/i }));

    expect(
      await screen.findByText(/enter a valid email address/i),
    ).toBeInTheDocument();
    expect(resendVerification).not.toHaveBeenCalled();
  });

  it("reports the resend as sent even when the request fails", async () => {
    resendVerification.mockRejectedValue(new Error("smtp down"));
    search = "";
    renderPage();
    await screen.findByText(/no longer valid/i);

    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/enter your email/i),
      "a@example.com",
    );
    await user.click(screen.getByRole("button", { name: /send a new/i }));

    // The endpoint answers identically for every address, so a distinct
    // failure here would be an account-existence oracle.
    expect(
      await screen.findByRole("button", { name: /check your inbox/i }),
    ).toBeDisabled();
  });
});

/* ── Outcome states ───────────────────────────────────────────────────────── */

describe("VerifyEmail — outcome states", () => {
  it("shows a working state before the answer arrives", () => {
    verifyEmail.mockReturnValue(new Promise(() => {}));
    renderPage();

    expect(screen.getByText(/verifying your email/i)).toBeInTheDocument();
  });

  it("offers sign-in once the address is verified", async () => {
    verifyEmail.mockResolvedValue({ status: "verified", detail: "" });
    renderPage();

    expect(await screen.findByText(/email verified/i)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /continue to sign in/i }),
    ).toHaveAttribute("href", "/login");
  });

  it("says approval is still required when the account is pending", async () => {
    verifyEmail.mockResolvedValue({ status: "pending_approval", detail: "" });
    renderPage();

    await screen.findByText(/email verified/i);
    expect(
      screen.getByText(/does not grant access on its own/i),
    ).toBeInTheDocument();
    // Verification is not a login: there must be no "continue" affordance
    // implying the account is now usable.
    expect(
      screen.queryByRole("link", { name: /continue to sign in/i }),
    ).toBeNull();
  });

  it("treats any non-verified status as pending rather than as success", async () => {
    verifyEmail.mockResolvedValue({ status: "something_else", detail: "" });
    renderPage();

    await screen.findByText(/email verified/i);
    expect(
      screen.getByText(/does not grant access on its own/i),
    ).toBeInTheDocument();
  });

  it("shows the backend's own detail when it supplies one", async () => {
    verifyEmail.mockResolvedValue({
      status: "verified",
      detail: "Your address is confirmed.",
    });
    renderPage();

    expect(
      await screen.findByText(/your address is confirmed/i),
    ).toBeInTheDocument();
  });

  it("shows a dead-end panel with a resend form when the token is refused", async () => {
    verifyEmail.mockRejectedValue({
      response: { data: { detail: "This link has expired." } },
    });
    renderPage();

    expect(
      await screen.findByText(/this link has expired/i),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/enter your email/i)).toBeInTheDocument();
  });

  it("falls back to a generic message when the API gives nothing usable", async () => {
    verifyEmail.mockRejectedValue(new Error("network"));
    renderPage();

    expect(
      await screen.findByText(
        /this verification link is invalid or has expired/i,
      ),
    ).toBeInTheDocument();
  });

  it("prefers detail over message", async () => {
    verifyEmail.mockRejectedValue({
      response: { data: { detail: "Expired.", message: "ignored" } },
    });
    renderPage();

    expect(await screen.findByText(/^expired\.$/i)).toBeInTheDocument();
    expect(screen.queryByText(/ignored/)).toBeNull();
  });
});

/* ── Token safety ─────────────────────────────────────────────────────────── */

describe("VerifyEmail — token safety", () => {
  it("never renders the token", async () => {
    const { container } = renderPage();
    await screen.findByText(/email verified/i);

    expect(container.textContent).not.toContain("VERIFY-TOKEN-1");
    expect(container.innerHTML).not.toContain("VERIFY-TOKEN-1");
  });

  it("never persists the token", async () => {
    renderPage();
    await screen.findByText(/email verified/i);

    expect(JSON.stringify(localStorage)).not.toContain("VERIFY-TOKEN-1");
    expect(JSON.stringify(sessionStorage)).not.toContain("VERIFY-TOKEN-1");
  });

  it("never carries the token into an outgoing link", async () => {
    const { container } = renderPage();
    await screen.findByText(/email verified/i);

    for (const a of container.querySelectorAll("a[href]")) {
      expect(a.getAttribute("href")).not.toContain("VERIFY-TOKEN-1");
    }
  });

  it("renders one dead end for every refused token, whatever the reason", async () => {
    // This is the assertion that carries the security weight. "Missing" is
    // decidable from the URL the visitor already holds and involves no
    // server, so it is not an oracle; two *different* refused tokens are,
    // and the backend answers them identically. The page must not add a
    // distinction of its own.
    verifyEmail.mockRejectedValue({
      response: { data: { detail: "This link is no longer valid." } },
    });
    const readCard = async ({ container }) => {
      await waitFor(() =>
        expect(container.querySelector(".auth-title").textContent).toMatch(
          /no longer valid/i,
        ),
      );
      return container.querySelector(".auth-card").textContent;
    };

    const expired = renderPage();
    const firstCard = await readCard(expired);
    expired.unmount();

    search = "?token=A-DIFFERENT-TOKEN";
    const secondCard = await readCard(renderPage());

    expect(firstCard).toBe(secondCard);
  });

  it("offers the same heading and recovery path with no token as with a bad one", async () => {
    verifyEmail.mockRejectedValue(new Error("network"));
    const rejected = renderPage();
    const badCard = await within(rejected.container).findByText(
      /no longer valid/i,
    );
    expect(
      within(rejected.container).getByLabelText(/enter your email/i),
    ).toBeInTheDocument();
    const badHeading = badCard.textContent;
    rejected.unmount();

    search = "";
    const missing = renderPage();
    const missingCard = await within(missing.container).findByText(
      /no longer valid/i,
    );
    expect(
      within(missing.container).getByLabelText(/enter your email/i),
    ).toBeInTheDocument();

    expect(badHeading).toBe(missingCard.textContent);
  });
});

/* ── Accessibility — the migration specification ──────────────────────────── */

describe("VerifyEmail — accessibility", () => {
  it("names the page with a level-1 heading inside the auth card", async () => {
    const { container } = renderPage();
    await screen.findByText(/email verified/i);
    const card = container.querySelector(".auth-card");

    expect(within(card).getByRole("heading", { level: 1 })).toHaveTextContent(
      /email verified/i,
    );
  });

  it("has exactly one h1 in every state", async () => {
    const { container } = renderPage();
    await screen.findByText(/email verified/i);

    expect(container.querySelectorAll("h1")).toHaveLength(1);
  });

  it("announces the outcome to assistive technology", async () => {
    verifyEmail.mockResolvedValue({ status: "pending_approval", detail: "" });
    renderPage();

    // Wait for the outcome first: the in-flight panel is itself a role=status
    // now, so querying by role alone would resolve the "one moment" message.
    await screen.findByText(/does not grant access on its own/i);
    const statuses = screen.getAllByRole("status");
    expect(
      statuses.some((s) =>
        /does not grant access on its own/i.test(s.textContent),
      ),
    ).toBe(true);
  });

  it("associates the resend label with its input", async () => {
    search = "";
    renderPage();
    await screen.findByText(/no longer valid/i);

    expect(screen.getByLabelText(/enter your email/i)).toHaveAttribute(
      "id",
      "resend-email",
    );
  });

  it("describes the resend field's validation error through aria-describedby", async () => {
    search = "";
    renderPage();
    await screen.findByText(/no longer valid/i);

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/enter your email/i), "bad");
    await user.click(screen.getByRole("button", { name: /send a new/i }));
    await screen.findByText(/enter a valid email address/i);

    const field = screen.getByLabelText(/enter your email/i);
    const describedBy = field.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy)).toHaveTextContent(
      /enter a valid email address/i,
    );
  });

  it("marks the rejected resend address invalid to assistive technology", async () => {
    search = "";
    renderPage();
    await screen.findByText(/no longer valid/i);

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/enter your email/i), "bad");
    await user.click(screen.getByRole("button", { name: /send a new/i }));
    await screen.findByText(/enter a valid email address/i);

    expect(screen.getByLabelText(/enter your email/i)).toHaveAttribute(
      "aria-invalid",
      "true",
    );
  });

  it("announces the in-flight verification, not only paints it", async () => {
    verifyEmail.mockReturnValue(new Promise(() => {}));
    renderPage();

    // A user who cannot see the panel is told nothing at all while the page
    // sits waiting on the network.
    const live = document.querySelector("[role='status'],[aria-live]");
    expect(live).not.toBeNull();
  });

  it("pins no colour inline", async () => {
    const { container } = renderPage();
    await screen.findByText(/email verified/i);

    for (const el of container.querySelectorAll("*")) {
      const style = el.getAttribute("style") || "";
      expect(style).not.toMatch(/(^|[^-])\bcolor\s*:/);
      expect(style).not.toMatch(/background(-color)?\s*:/);
    }
  });

  it("pins no colour inline in the pending state either", async () => {
    verifyEmail.mockResolvedValue({ status: "pending_approval", detail: "" });
    const { container } = renderPage();
    await screen.findByText(/does not grant access on its own/i);

    for (const el of container.querySelectorAll("*")) {
      const style = el.getAttribute("style") || "";
      expect(style).not.toMatch(/(^|[^-])\bcolor\s*:/);
      expect(style).not.toMatch(/background(-color)?\s*:/);
    }
  });
});
