/**
 * ForgotPassword — Checkpoint 3C batch 2 migration coverage.
 *
 * Written against the page BEFORE migration, so the assertions below record
 * the contract rather than describing the result. The security group is the
 * important one: `/auth/forgot-password` is deliberately an
 * account-enumeration-safe endpoint, and CLAUDE.md records that "User not
 * found." was once a fourth distinct failure message on this path. Nothing in
 * this page may reintroduce a way to tell a registered address from an
 * unregistered one.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import ForgotPassword from "../../pages/ForgotPassword";
import { forgotPassword } from "../../api/auth";

vi.mock("../../api/auth", () => ({
  forgotPassword: vi.fn(),
}));

const renderPage = () =>
  render(
    <MemoryRouter>
      <ForgotPassword />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  forgotPassword.mockResolvedValue({});
});

/* ── API contract — must hold identically after migration ────────────────── */

describe("ForgotPassword — API contract", () => {
  it("submits the trimmed identifier", async () => {
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "  a@b.com  ",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    // The page trims before calling; the api layer trims again. Both are part
    // of the existing contract.
    await waitFor(() => expect(forgotPassword).toHaveBeenCalledWith("a@b.com"));
  });

  it("calls the endpoint exactly once per submission", async () => {
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    await waitFor(() => expect(forgotPassword).toHaveBeenCalledTimes(1));
  });

  it("accepts a username, not only an email address", async () => {
    renderPage();
    const input = screen.getByLabelText(/email or username/i);
    // type="email" would make the browser reject this. The field is
    // deliberately type="text" because the endpoint takes either.
    expect(input).toHaveAttribute("type", "text");
    await userEvent.type(input, "pankaj");
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    await waitFor(() => expect(forgotPassword).toHaveBeenCalledWith("pankaj"));
  });

  it("makes no request on mount", () => {
    renderPage();
    expect(forgotPassword).not.toHaveBeenCalled();
  });
});

/* ── Security contract — the reason this page is handled carefully ───────── */

describe("ForgotPassword — account-enumeration safety", () => {
  const submit = async (value = "someone@example.com") => {
    await userEvent.type(screen.getByLabelText(/email or username/i), value);
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
  };

  it("shows the generic message when the backend returns no detail", async () => {
    forgotPassword.mockResolvedValue({});
    renderPage();
    await submit();
    expect(
      await screen.findByText(/If this account is registered/i),
    ).toBeInTheDocument();
  });

  it("renders an identical outcome for a registered and an unregistered address", async () => {
    // The endpoint answers 200 with the same body either way — that uniformity
    // is the protection, and the UI must not undo it by rendering two
    // different states.
    forgotPassword.mockResolvedValue({
      detail:
        "If this account is registered, you will receive a reset link shortly.",
    });

    // Scoped to the form panel, deliberately. AuthHeroPanel next to it runs a
    // decorative count-up (setInterval to 10,000 "Assets Audited"), so a
    // whole-container comparison differs between any two renders purely on
    // animation frame — it measured the clock, not the response. The form
    // panel is where an enumeration signal would actually surface.
    const formPanel = (c) => c.querySelector(".auth-form-panel").innerHTML;

    const first = renderPage();
    await submit("registered@example.com");
    await screen.findByText(/If this account is registered/i);
    const registeredHtml = formPanel(first.container);
    first.unmount();

    const second = renderPage();
    await submit("nobody@example.com");
    await screen.findByText(/If this account is registered/i);
    const unregisteredHtml = formPanel(second.container);

    expect(unregisteredHtml).toBe(registeredHtml);
  });

  it("never renders wording that discloses whether an account exists", async () => {
    forgotPassword.mockResolvedValue({});
    renderPage();
    await submit();
    await screen.findByText(/If this account is registered/i);
    const text = document.body.textContent.toLowerCase();
    // "User not found." was a real message on this path once.
    for (const leak of [
      "not found",
      "no account",
      "does not exist",
      "unregistered",
      "unknown user",
      "no such",
    ]) {
      expect(text).not.toContain(leak);
    }
  });

  it("does not reveal existence through the error path either", async () => {
    forgotPassword.mockRejectedValue({
      response: { data: { message: "An error occurred. Please try again." } },
    });
    renderPage();
    await submit();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent.toLowerCase()).not.toMatch(
      /not found|no account|does not exist/,
    );
  });

  it("makes the same single request regardless of the address submitted", async () => {
    renderPage();
    await submit("nobody@example.com");
    await waitFor(() => expect(forgotPassword).toHaveBeenCalledTimes(1));
    // No probe, no pre-check, no second request that could be timed.
    expect(forgotPassword).toHaveBeenCalledWith("nobody@example.com");
  });
});

/* ── Behaviour ───────────────────────────────────────────────────────────── */

describe("ForgotPassword — behaviour", () => {
  it("shows the backend's own detail when it supplies one", async () => {
    forgotPassword.mockResolvedValue({ detail: "Check your inbox." });
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    expect(await screen.findByText(/Check your inbox/i)).toBeInTheDocument();
  });

  it("replaces the form with the confirmation on success", async () => {
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    await screen.findByText(/If this account is registered/i);
    // Pre-existing behaviour: the form is unmounted, so the address cannot be
    // resubmitted from the confirmation screen.
    expect(screen.queryByLabelText(/email or username/i)).toBeNull();
  });

  it("surfaces a validation array from the API as joined messages", async () => {
    forgotPassword.mockRejectedValue({
      response: {
        data: { detail: [{ msg: "field required" }, { msg: "bad value" }] },
      },
    });
    renderPage();
    await userEvent.type(screen.getByLabelText(/email or username/i), "x");
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    expect(
      await screen.findByText(/field required, bad value/i),
    ).toBeInTheDocument();
  });

  it("falls back to a generic error when the API gives nothing usable", async () => {
    forgotPassword.mockRejectedValue(new Error("network"));
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    expect(
      await screen.findByText(/An error occurred\. Please try again\./i),
    ).toBeInTheDocument();
  });

  it("keeps the form mounted after an error so the user can retry", async () => {
    forgotPassword.mockRejectedValue(new Error("network"));
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    await screen.findByRole("alert");
    expect(screen.getByLabelText(/email or username/i)).toBeInTheDocument();
  });

  it("disables the submit control while the request is in flight", async () => {
    let resolve;
    forgotPassword.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );

    const button = screen.getByRole("button", {
      name: /sending recovery link/i,
    });
    expect(button).toBeDisabled();
    // A second click must not produce a second request.
    await userEvent.click(button);
    expect(forgotPassword).toHaveBeenCalledTimes(1);

    resolve({});
    await screen.findByText(/If this account is registered/i);
  });

  it("links back to sign in", () => {
    renderPage();
    expect(screen.getByRole("link", { name: /sign in/i })).toHaveAttribute(
      "href",
      "/login",
    );
  });
});

/* ── Accessibility — the gains this migration is for ─────────────────────── */

describe("ForgotPassword — accessibility", () => {
  it("associates the label with the input", () => {
    renderPage();
    // Already true before migration; asserted so it cannot regress.
    expect(screen.getByLabelText(/email or username/i)).toBeInstanceOf(
      HTMLInputElement,
    );
  });

  it("names the page with a level-1 heading inside the auth card", () => {
    const { container } = renderPage();
    const card = container.querySelector(".auth-card");
    const headings = card.querySelectorAll("h1");
    expect(headings).toHaveLength(1);
    expect(headings[0]).toHaveTextContent(/reset password/i);
  });

  it("has exactly one h1 on the page", () => {
    // This assertion previously pinned the *defect* — two level-1 headings,
    // because AuthHeroPanel rendered one beside the card's own — and said so,
    // because the panel is shared with the four pages batch 2 was not
    // permitted to touch. The auth-group batch migrates all four, so the
    // shared panel's headline is now an h2 and the expectation is inverted
    // rather than deleted: the same line now proves the fix instead of
    // recording the defect.
    const { container } = renderPage();
    expect(container.querySelectorAll("h1")).toHaveLength(1);
  });

  it("marks the field as required to assistive technology", () => {
    renderPage();
    const input = screen.getByLabelText(/email or username/i);
    expect(input).toBeRequired();
    // The visible label must say so too — a red asterisk alone is not a name.
    expect(screen.getByLabelText(/required/i)).toBe(input);
  });

  it("describes the field with its hint", () => {
    renderPage();
    // Before migration the placeholder was the only guidance, and a
    // placeholder disappears the moment the user types.
    expect(
      screen.getByLabelText(/email or username/i),
    ).toHaveAccessibleDescription(/email address or username/i);
  });

  it("announces the submission failure as an alert", async () => {
    forgotPassword.mockRejectedValue(new Error("network"));
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /An error occurred/i,
    );
  });

  it("announces the confirmation politely, not as an interruption", async () => {
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/If this account is registered/i);
  });

  it("keeps the button's accessible name while loading", async () => {
    let resolve;
    forgotPassword.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderPage();
    await userEvent.type(
      screen.getByLabelText(/email or username/i),
      "a@b.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /send recovery link/i }),
    );
    const button = screen.getByRole("button", {
      name: /sending recovery link/i,
    });
    expect(button).toHaveAttribute("aria-busy", "true");
    resolve({});
  });

  it("pins no colour inline", () => {
    const { container } = renderPage();
    // The auth surface is a fixed dark panel; the migrated controls must take
    // their colours from tokens scoped to it, not from literals.
    for (const el of container.querySelectorAll("*")) {
      expect(el.getAttribute("style") ?? "").not.toMatch(
        /(^|;)\s*(color|background)/,
      );
    }
  });
});
