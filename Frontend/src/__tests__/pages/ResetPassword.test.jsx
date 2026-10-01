/**
 * ResetPassword — Checkpoint 3C auth-group migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * The reset token arrives as a query parameter because that is what an email
 * client can click. It must reach the API in a POST body and nowhere else: not
 * in rendered text, not in storage, not in an outgoing link. CLAUDE.md records
 * that completing a reset retires *every* outstanding token for the account
 * and that all three failure branches answer identically — this page must not
 * reintroduce a distinction between "expired", "already used" and "no such
 * token", because that would be an oracle over which links exist.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import ResetPassword from "../../pages/ResetPassword";
import { resetPassword } from "@shell/api/auth";

const navigate = vi.fn();
let search = "?token=RESET-TOKEN-1";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useSearchParams: () => [new URLSearchParams(search), vi.fn()],
  };
});

vi.mock("@shell/api/auth", () => ({ resetPassword: vi.fn() }));

const renderPage = () =>
  render(
    <MemoryRouter>
      <ResetPassword />
    </MemoryRouter>,
  );

const STRONG = "Str0ng!Passphrase";

/** Fill both password fields and submit. */
const submit = async (password = STRONG, confirm = password) => {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(/^new password\b/i), password);
  await user.type(screen.getByLabelText(/^confirm password\b/i), confirm);
  await user.click(screen.getByRole("button", { name: /save password/i }));
  return user;
};

beforeEach(() => {
  // The success path schedules `navigate("/login")` 2500 ms later and nothing
  // cancels it on unmount, so under real timers a stale timeout from an
  // earlier test fires during a later one and calls the shared `navigate`
  // mock. Fake timers are discarded with the test, which keeps each case
  // isolated without changing the page's behaviour.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  vi.clearAllMocks();
  search = "?token=RESET-TOKEN-1";
  localStorage.clear();
  sessionStorage.clear();
  resetPassword.mockResolvedValue({});
});

afterEach(() => {
  vi.useRealTimers();
});

/* ── API contract ─────────────────────────────────────────────────────────── */

describe("ResetPassword — API contract", () => {
  it("posts the token from the query string with the new password", async () => {
    renderPage();
    await submit();

    await waitFor(() => expect(resetPassword).toHaveBeenCalledTimes(1));
    expect(resetPassword).toHaveBeenCalledWith("RESET-TOKEN-1", STRONG);
  });

  it("never trims the password", async () => {
    renderPage();
    await submit("  Str0ng!Pass  ", "  Str0ng!Pass  ");

    await waitFor(() => expect(resetPassword).toHaveBeenCalledTimes(1));
    expect(resetPassword.mock.calls[0][1]).toBe("  Str0ng!Pass  ");
  });

  it("submits exactly once per attempt", async () => {
    renderPage();
    await submit();

    await waitFor(() => expect(resetPassword).toHaveBeenCalledTimes(1));
  });

  it("makes no request on mount", () => {
    renderPage();

    expect(resetPassword).not.toHaveBeenCalled();
  });

  it("redirects to sign in after a successful reset", async () => {
    renderPage();
    await submit();

    await screen.findByText(/successfully reset/i);
    await vi.advanceTimersByTimeAsync(2500);
    expect(navigate).toHaveBeenCalledWith("/login");
  });

  it("does not navigate while the confirmation is still showing", async () => {
    renderPage();
    await submit();

    await screen.findByText(/successfully reset/i);
    expect(navigate).not.toHaveBeenCalled();
  });
});

/* ── Token handling ───────────────────────────────────────────────────────── */

describe("ResetPassword — token handling", () => {
  it("refuses to render the form with no token and offers a new link", async () => {
    search = "";
    renderPage();

    expect(
      await screen.findByText(/token is missing or invalid/i),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/^new password\b/i)).toBeNull();
    expect(
      screen.getByRole("link", { name: /request new reset link/i }),
    ).toHaveAttribute("href", "/forgot-password");
  });

  it("makes no request when there is no token", async () => {
    search = "";
    renderPage();

    await screen.findByText(/token is missing or invalid/i);
    expect(resetPassword).not.toHaveBeenCalled();
  });

  it("never renders the token anywhere on the page", async () => {
    const { container } = renderPage();
    await submit();
    await screen.findByText(/successfully reset/i);

    expect(container.textContent).not.toContain("RESET-TOKEN-1");
    expect(container.innerHTML).not.toContain("RESET-TOKEN-1");
  });

  it("never persists the token to storage", async () => {
    renderPage();
    await submit();
    await waitFor(() => expect(resetPassword).toHaveBeenCalled());

    expect(JSON.stringify(localStorage)).not.toContain("RESET-TOKEN-1");
    expect(JSON.stringify(sessionStorage)).not.toContain("RESET-TOKEN-1");
  });

  it("never puts the token in an outgoing link", async () => {
    const { container } = renderPage();

    for (const a of container.querySelectorAll("a[href]")) {
      expect(a.getAttribute("href")).not.toContain("RESET-TOKEN-1");
    }
  });
});

/* ── Failure-branch uniformity ────────────────────────────────────────────── */

describe("ResetPassword — failure branches stay indistinguishable", () => {
  it("uses one generic message when the API gives nothing usable", async () => {
    resetPassword.mockRejectedValue(new Error("network"));
    renderPage();
    await submit();

    expect(
      await screen.findByText(
        /failed to reset password\. the link might be expired or invalid\./i,
      ),
    ).toBeInTheDocument();
  });

  it("does not distinguish an expired link from an unknown one", async () => {
    // The backend answers all three failure branches identically. The page
    // renders whatever it is given, so what must hold is that the page adds
    // no wording of its own that separates them.
    const render1 = renderPage();
    resetPassword.mockRejectedValue({
      response: { data: { detail: "Invalid or expired reset token." } },
    });
    await submit();
    const first = (await screen.findByRole("alert")).textContent;
    render1.unmount();

    renderPage();
    await submit();
    const second = (await screen.findByRole("alert")).textContent;

    expect(first).toBe(second);
  });

  it("never says the account does not exist", async () => {
    resetPassword.mockRejectedValue({
      response: { data: { detail: "Invalid or expired reset token." } },
    });
    const { container } = renderPage();
    await submit();
    await screen.findByRole("alert");

    const text = container.textContent.toLowerCase();
    expect(text).not.toMatch(/user not found/);
    expect(text).not.toMatch(/no such account/);
    expect(text).not.toMatch(/account does not exist/);
  });

  it("keeps the form mounted after a failure so the user can retry", async () => {
    resetPassword.mockRejectedValue({ response: { data: { detail: "nope" } } });
    renderPage();
    await submit();

    await screen.findByText(/nope/i);
    expect(screen.getByLabelText(/^new password\b/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /save password/i }),
    ).toBeEnabled();
  });

  it("prefers message over detail", async () => {
    resetPassword.mockRejectedValue({
      response: { data: { message: "Link already used.", detail: "ignored" } },
    });
    renderPage();
    await submit();

    expect(await screen.findByText(/link already used/i)).toBeInTheDocument();
    expect(screen.queryByText(/ignored/)).toBeNull();
  });

  it("joins a validation array into one message", async () => {
    resetPassword.mockRejectedValue({
      response: {
        data: { detail: [{ msg: "too weak" }, { msg: "too short" }] },
      },
    });
    renderPage();
    await submit();

    expect(await screen.findByText(/too weak, too short/i)).toBeInTheDocument();
  });
});

/* ── Client-side validation ───────────────────────────────────────────────── */

describe("ResetPassword — validation", () => {
  const cases = [
    ["under 12 characters", "Sh0rt!", /at least 12 characters/i],
    ["no uppercase", "str0ng!passphrase", /uppercase letter/i],
    ["no digit", "Strong!Passphrase", /one digit/i],
    ["no special character", "Str0ngPassphrase1", /special character/i],
  ];

  for (const [name, password, expected] of cases) {
    it(`refuses a password with ${name} without calling the API`, async () => {
      renderPage();
      await submit(password, password);

      expect(await screen.findByText(expected)).toBeInTheDocument();
      expect(resetPassword).not.toHaveBeenCalled();
    });
  }

  it("refuses a mismatched confirmation without calling the API", async () => {
    renderPage();
    await submit(STRONG, "Different!Pass1");

    expect(
      await screen.findByText(/passwords do not match/i),
    ).toBeInTheDocument();
    expect(resetPassword).not.toHaveBeenCalled();
  });

  it("grades password strength", async () => {
    renderPage();
    const user = userEvent.setup();
    const field = screen.getByLabelText(/^new password\b/i);

    await user.type(field, "abcdefghijkl");
    expect(await screen.findByText("Weak")).toBeInTheDocument();

    await user.clear(field);
    await user.type(field, "Abcdefghijk1!");
    expect(await screen.findByText("Strong")).toBeInTheDocument();
  });

  it("flags a mismatch live and confirms a match", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^new password\b/i), STRONG);
    await user.type(
      screen.getByLabelText(/^confirm password\b/i),
      "Wrong1!aaaaa",
    );
    expect(await screen.findByText(/don't match/i)).toBeInTheDocument();

    await user.clear(screen.getByLabelText(/^confirm password\b/i));
    await user.type(screen.getByLabelText(/^confirm password\b/i), STRONG);
    expect(await screen.findByText(/passwords match/i)).toBeInTheDocument();
  });
});

/* ── Password fields ──────────────────────────────────────────────────────── */

describe("ResetPassword — password fields", () => {
  it("masks both fields by default", () => {
    renderPage();

    expect(screen.getByLabelText(/^new password\b/i)).toHaveAttribute(
      "type",
      "password",
    );
    expect(screen.getByLabelText(/^confirm password\b/i)).toHaveAttribute(
      "type",
      "password",
    );
  });

  it("toggles each field independently", async () => {
    renderPage();
    const user = userEvent.setup();
    // Each toggle is named for the field it belongs to. Two controls sharing
    // one accessible name is a defect in its own right on a form with two
    // password fields, so the name is asserted here rather than matched
    // loosely.
    await user.click(
      screen.getByRole("button", { name: /^toggle new password visibility$/i }),
    );

    expect(screen.getByLabelText(/^new password\b/i)).toHaveAttribute(
      "type",
      "text",
    );
    expect(screen.getByLabelText(/^confirm password\b/i)).toHaveAttribute(
      "type",
      "password",
    );
  });

  it("declares new-password autocomplete on both fields", () => {
    renderPage();

    expect(screen.getByLabelText(/^new password\b/i)).toHaveAttribute(
      "autocomplete",
      "new-password",
    );
    expect(screen.getByLabelText(/^confirm password\b/i)).toHaveAttribute(
      "autocomplete",
      "new-password",
    );
  });

  it("never echoes the chosen password outside its own fields", async () => {
    resetPassword.mockRejectedValue({ response: { data: { detail: "nope" } } });
    const { container } = renderPage();
    await submit("Uniq3!Secret", "Uniq3!Secret");
    await screen.findByText(/nope/i);

    expect(container.textContent).not.toContain("Uniq3!Secret");
    expect(JSON.stringify(localStorage)).not.toContain("Uniq3!Secret");
    expect(JSON.stringify(sessionStorage)).not.toContain("Uniq3!Secret");
  });
});

/* ── Accessibility — the migration specification ──────────────────────────── */

describe("ResetPassword — accessibility", () => {
  it("names the page with a level-1 heading inside the auth card", () => {
    const { container } = renderPage();
    const card = container.querySelector(".auth-card");

    expect(within(card).getByRole("heading", { level: 1 })).toHaveTextContent(
      /set new password/i,
    );
  });

  it("has exactly one h1 on the page", () => {
    const { container } = renderPage();

    expect(container.querySelectorAll("h1")).toHaveLength(1);
  });

  it("announces the failure as an alert", async () => {
    resetPassword.mockRejectedValue({ response: { data: { detail: "nope" } } });
    renderPage();
    await submit();

    expect(await screen.findByRole("alert")).toHaveTextContent(/nope/i);
  });

  it("announces the confirmation politely, not as an interruption", async () => {
    renderPage();
    await submit();

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/successfully reset/i);
  });

  it("describes the mismatch through aria-describedby", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^new password\b/i), STRONG);
    await user.type(
      screen.getByLabelText(/^confirm password\b/i),
      "Wrong1!aaaaa",
    );
    await screen.findByText(/don't match/i);

    const confirm = screen.getByLabelText(/^confirm password\b/i);
    const describedBy = confirm.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy)).toHaveTextContent(
      /don't match/i,
    );
  });

  it("marks a mismatched confirmation invalid to assistive technology", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^new password\b/i), STRONG);
    await user.type(
      screen.getByLabelText(/^confirm password\b/i),
      "Wrong1!aaaaa",
    );
    await screen.findByText(/don't match/i);

    expect(screen.getByLabelText(/^confirm password\b/i)).toHaveAttribute(
      "aria-invalid",
      "true",
    );
  });

  it("announces the caps-lock warning to assistive technology", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.keyboard("{CapsLock}");
    screen.getByLabelText(/^new password\b/i).focus();
    await user.keyboard("a");

    const warning = screen.getByText(/caps lock is on/i);
    expect(warning.closest("[role='status'],[aria-live]")).not.toBeNull();
  });

  it("exposes the strength meter as a labelled progress indicator", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^new password\b/i), "Abcdefghijk1!");
    await screen.findByText("Strong");

    // Four bare <span>s conveyed the grade visually and to nobody else. The
    // assertion is stronger than "has a role": the meter must carry a name,
    // a range and a spoken value, because "3" without "of 4" or "Good" is not
    // an announcement anyone can act on.
    const meter = screen.getByRole("meter", { name: /password strength/i });
    expect(meter).toHaveAttribute("aria-valuenow", "4");
    expect(meter).toHaveAttribute("aria-valuemax", "4");
    expect(meter).toHaveAttribute("aria-valuetext", "Strong password");
  });

  it("names each unmet rule in text, not only in colour", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^new password\b/i), "abcdefghijkl");
    await screen.findByText("Weak");

    // WCAG 1.4.1: the met/unmet state was previously carried by #34d399 vs
    // #64748b and nothing else, and the unmet colour measured 3.85:1.
    // "abcdefghijkl" meets length only, so one rule is met and three are not.
    expect(screen.getAllByText("Met:")).toHaveLength(1);
    expect(screen.getAllByText("Not met:")).toHaveLength(3);
  });

  it("marks both fields as required", () => {
    renderPage();

    expect(screen.getByLabelText(/^new password\b/i)).toBeRequired();
    expect(screen.getByLabelText(/^confirm password\b/i)).toBeRequired();
  });

  it("pins no colour inline", () => {
    const { container } = renderPage();

    for (const el of container.querySelectorAll("*")) {
      const style = el.getAttribute("style") || "";
      expect(style).not.toMatch(/(^|[^-])\bcolor\s*:/);
      expect(style).not.toMatch(/background(-color)?\s*:/);
    }
  });
});
