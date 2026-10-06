/**
 * Login — Checkpoint 3C auth-group migration coverage.
 *
 * Written against the page BEFORE migration. The functional and security
 * groups record the contract and must pass identically before and after; the
 * accessibility group is the migration's specification and contains
 * assertions that fail against the current implementation.
 *
 * The security surface here is larger than any other page in the batch:
 *
 *   * the identifier is trimmed and the password is not — trimming a password
 *     silently changes the credential the user chose;
 *   * "remember me" persists the identifier and never the password;
 *   * an MFA challenge must not navigate, and the mfa_token must never be
 *     rendered or persisted;
 *   * the post-login redirect comes from router state or a session key, and
 *     both are cleared on success so a stale destination cannot be replayed.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import Login from "@shell/auth/pages/Login";
import {
  verifyMfa,
  sendEmailOtp,
  isSelfRegistrationEnabled,
} from "@shell/api/auth";

const navigate = vi.fn();
let locationState = null;

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => ({
      pathname: "/login",
      search: "",
      hash: "",
      state: locationState,
    }),
  };
});

vi.mock("@shell/api/auth", () => ({
  verifyMfa: vi.fn(),
  sendEmailOtp: vi.fn(),
  isSelfRegistrationEnabled: vi.fn(),
}));

const login = vi.fn();
const refreshUser = vi.fn();
let authMessage = "";

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ login, refreshUser, authMessage }),
}));

const renderPage = () =>
  render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  );

/** Fill the credential form and submit it. */
const signIn = async (
  identifier = "user@example.com",
  password = "correct horse battery staple",
) => {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(/email or username/i), identifier);
  await user.type(screen.getByLabelText(/^password\b/i), password);
  await user.click(screen.getByRole("button", { name: /sign in/i }));
  return user;
};

beforeEach(() => {
  vi.clearAllMocks();
  locationState = null;
  authMessage = "";
  localStorage.clear();
  sessionStorage.clear();
  login.mockResolvedValue({ user: { id: 1 } });
  refreshUser.mockResolvedValue(undefined);
  verifyMfa.mockResolvedValue({});
  sendEmailOtp.mockResolvedValue({});
  isSelfRegistrationEnabled.mockResolvedValue(false);
});

afterEach(() => {
  vi.useRealTimers();
});

/* ── API contract ─────────────────────────────────────────────────────────── */

describe("Login — API contract", () => {
  it("posts the identifier under email_or_username", async () => {
    renderPage();
    await signIn("user@example.com", "hunter2hunter2");

    await waitFor(() => expect(login).toHaveBeenCalledTimes(1));
    expect(login).toHaveBeenCalledWith({
      email_or_username: "user@example.com",
      password: "hunter2hunter2",
    });
  });

  it("trims the identifier but never the password", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/email or username/i),
      "  spaced@example.com  ",
    );
    // A password with significant leading/trailing whitespace is legal and
    // trimming it would authenticate with a credential the user did not type.
    await user.type(screen.getByLabelText(/^password\b/i), "  pad  ");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(login).toHaveBeenCalledTimes(1));
    expect(login).toHaveBeenCalledWith({
      email_or_username: "spaced@example.com",
      password: "  pad  ",
    });
  });

  it("accepts a bare username, not only an email address", async () => {
    renderPage();
    await signIn("pankaj", "hunter2hunter2");

    await waitFor(() => expect(login).toHaveBeenCalledTimes(1));
    expect(login.mock.calls[0][0].email_or_username).toBe("pankaj");
  });

  it("submits exactly once per attempt", async () => {
    renderPage();
    await signIn();

    await waitFor(() => expect(login).toHaveBeenCalledTimes(1));
  });

  it("probes self-registration on mount and makes no other request", async () => {
    renderPage();

    await waitFor(() =>
      expect(isSelfRegistrationEnabled).toHaveBeenCalledTimes(1),
    );
    expect(login).not.toHaveBeenCalled();
    expect(verifyMfa).not.toHaveBeenCalled();
    expect(sendEmailOtp).not.toHaveBeenCalled();
  });
});

/* ── MFA challenge ────────────────────────────────────────────────────────── */

describe("Login — MFA challenge", () => {
  const challenge = async () => {
    login.mockResolvedValue({ status: "mfa_required", mfa_token: "MFA-TOK-1" });
    renderPage();
    await signIn();
    await screen.findByLabelText(/verification code/i);
  };

  it("shows the code form instead of navigating", async () => {
    await challenge();

    expect(navigate).not.toHaveBeenCalled();
    expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument();
    expect(
      screen.queryByLabelText(/email or username/i),
    ).not.toBeInTheDocument();
  });

  it("verifies with the challenge token and the trimmed code", async () => {
    await challenge();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/verification code/i), " 123456 ");
    await user.click(screen.getByRole("button", { name: /verify code/i }));

    await waitFor(() => expect(verifyMfa).toHaveBeenCalledTimes(1));
    expect(verifyMfa).toHaveBeenCalledWith("MFA-TOK-1", "123456");
  });

  it("refreshes the session before navigating", async () => {
    await challenge();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/verification code/i), "123456");
    await user.click(screen.getByRole("button", { name: /verify code/i }));

    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1));
    expect(refreshUser).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith("/", { replace: true });
  });

  it("never renders or persists the mfa_token", async () => {
    const { container } = render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );
    login.mockResolvedValue({ status: "mfa_required", mfa_token: "MFA-TOK-1" });
    await signIn();
    await screen.findByLabelText(/verification code/i);

    expect(container.textContent).not.toContain("MFA-TOK-1");
    expect(container.innerHTML).not.toContain("MFA-TOK-1");
    expect(JSON.stringify(localStorage)).not.toContain("MFA-TOK-1");
    expect(JSON.stringify(sessionStorage)).not.toContain("MFA-TOK-1");
  });

  it("requests an email OTP with the challenge token", async () => {
    await challenge();
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /send code to email/i }),
    );

    await waitFor(() => expect(sendEmailOtp).toHaveBeenCalledTimes(1));
    expect(sendEmailOtp).toHaveBeenCalledWith("MFA-TOK-1");
  });

  it("starts a resend cooldown that disables the control", async () => {
    await challenge();
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /send code to email/i }),
    );

    const resend = await screen.findByRole("button", {
      name: /resend code in/i,
    });
    expect(resend).toBeDisabled();
  });

  it("clears the cooldown when the send fails, so the user can retry", async () => {
    await challenge();
    sendEmailOtp.mockRejectedValue({
      response: { data: { detail: "Mail transport unavailable." } },
    });
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /send code to email/i }),
    );

    await screen.findByText(/mail transport unavailable/i);
    expect(
      screen.getByRole("button", { name: /send code to email/i }),
    ).toBeEnabled();
  });

  it("returns to the credential form and forgets the challenge", async () => {
    await challenge();
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /back to credentials/i }),
    );

    expect(
      await screen.findByLabelText(/email or username/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByLabelText(/verification code/i),
    ).not.toBeInTheDocument();
  });
});

/* ── Remember me ──────────────────────────────────────────────────────────── */

describe("Login — remember me", () => {
  it("persists the trimmed identifier and never the password", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("checkbox", { name: /remember me/i }));
    await user.type(
      screen.getByLabelText(/email or username/i),
      "  remembered@example.com  ",
    );
    await user.type(screen.getByLabelText(/^password\b/i), "TopSecret!123");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(login).toHaveBeenCalled());
    expect(localStorage.getItem("ccure_remember_me")).toBe("true");
    expect(localStorage.getItem("ccure_remembered_identity")).toBe(
      "remembered@example.com",
    );
    expect(JSON.stringify(localStorage)).not.toContain("TopSecret!123");
    expect(JSON.stringify(sessionStorage)).not.toContain("TopSecret!123");
  });

  it("clears both keys and the legacy email key when unchecked", async () => {
    localStorage.setItem("ccure_remember_me", "true");
    localStorage.setItem("ccure_remembered_identity", "old@example.com");
    localStorage.setItem("ccure_remembered_email", "legacy@example.com");
    renderPage();

    const user = userEvent.setup();
    await user.click(screen.getByRole("checkbox", { name: /remember me/i }));
    await user.type(screen.getByLabelText(/^password\b/i), "hunter2hunter2");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(login).toHaveBeenCalled());
    expect(localStorage.getItem("ccure_remember_me")).toBeNull();
    expect(localStorage.getItem("ccure_remembered_identity")).toBeNull();
    expect(localStorage.getItem("ccure_remembered_email")).toBeNull();
  });

  it("prefills from the stored identity", () => {
    localStorage.setItem("ccure_remember_me", "true");
    localStorage.setItem("ccure_remembered_identity", "stored@example.com");
    renderPage();

    expect(screen.getByLabelText(/email or username/i)).toHaveValue(
      "stored@example.com",
    );
    expect(
      screen.getByRole("checkbox", { name: /remember me/i }),
    ).toBeChecked();
  });

  it("falls back to the legacy email key", () => {
    localStorage.setItem("ccure_remembered_email", "legacy@example.com");
    renderPage();

    expect(screen.getByLabelText(/email or username/i)).toHaveValue(
      "legacy@example.com",
    );
  });
});

/* ── Redirect handling ────────────────────────────────────────────────────── */

describe("Login — post-login redirect", () => {
  it("defaults to CCure Home (Phase 12)", async () => {
    renderPage();
    await signIn();

    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1));
    expect(navigate).toHaveBeenCalledWith("/", { replace: true });
  });

  it("restores the attempted location including search and hash", async () => {
    locationState = {
      from: { pathname: "/scans/42", search: "?tab=findings", hash: "#top" },
    };
    renderPage();
    await signIn();

    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1));
    expect(navigate).toHaveBeenCalledWith("/scans/42?tab=findings#top", {
      replace: true,
    });
  });

  it("uses the saved redirect only when the session expired", async () => {
    sessionStorage.setItem("postLoginRedirect", "/reports/9");
    locationState = { reason: "expired" };
    renderPage();
    await signIn();

    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1));
    expect(navigate).toHaveBeenCalledWith("/reports/9", { replace: true });
  });

  it("ignores the saved redirect when the visit was not an expiry", async () => {
    sessionStorage.setItem("postLoginRedirect", "/reports/9");
    renderPage();
    await signIn();

    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1));
    expect(navigate).toHaveBeenCalledWith("/", { replace: true });
  });

  it("clears the saved redirect on success so it cannot be replayed", async () => {
    sessionStorage.setItem("postLoginRedirect", "/reports/9");
    locationState = { reason: "expired" };
    renderPage();
    await signIn();

    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(sessionStorage.getItem("postLoginRedirect")).toBeNull();
  });

  it("does not navigate when the credentials are refused", async () => {
    login.mockRejectedValue({ response: { data: { detail: "Bad creds" } } });
    renderPage();
    await signIn();

    await screen.findByText(/bad creds/i);
    expect(navigate).not.toHaveBeenCalled();
  });
});

/* ── Self-registration gate ───────────────────────────────────────────────── */

describe("Login — self-registration gate", () => {
  it("renders neither branch while the probe is in flight", () => {
    isSelfRegistrationEnabled.mockReturnValue(new Promise(() => {}));
    renderPage();

    expect(screen.queryByRole("link", { name: /register here/i })).toBeNull();
    expect(screen.queryByText(/created by your administrator/i)).toBeNull();
  });

  it("offers the register link only when the backend allows signup", async () => {
    isSelfRegistrationEnabled.mockResolvedValue(true);
    renderPage();

    expect(
      await screen.findByRole("link", { name: /register here/i }),
    ).toHaveAttribute("href", "/register");
  });

  it("explains provisioning instead when signup is off", async () => {
    isSelfRegistrationEnabled.mockResolvedValue(false);
    renderPage();

    expect(
      await screen.findByText(/accounts are created by your administrator/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /register here/i })).toBeNull();
  });
});

/* ── Error semantics ──────────────────────────────────────────────────────── */

describe("Login — error semantics", () => {
  it("prefers the API message over its detail", async () => {
    login.mockRejectedValue({
      response: { data: { message: "Account locked.", detail: "ignored" } },
    });
    renderPage();
    await signIn();

    expect(await screen.findByText(/account locked/i)).toBeInTheDocument();
    expect(screen.queryByText(/ignored/)).toBeNull();
  });

  it("joins a validation array into one message", async () => {
    login.mockRejectedValue({
      response: {
        data: { detail: [{ msg: "field required" }, { msg: "too short" }] },
      },
    });
    renderPage();
    await signIn();

    expect(
      await screen.findByText(/field required, too short/i),
    ).toBeInTheDocument();
  });

  it("falls back to a generic message when the API gives nothing usable", async () => {
    login.mockRejectedValue(new Error("network down"));
    renderPage();
    await signIn();

    expect(
      await screen.findByText(/login failed\. check your credentials\./i),
    ).toBeInTheDocument();
  });

  it("never echoes the submitted password outside its own field", async () => {
    login.mockRejectedValue({ response: { data: { detail: "Bad creds" } } });
    const { container } = renderPage();
    await signIn("user@example.com", "Sup3rSecret!Value");
    await screen.findByText(/bad creds/i);

    // React mirrors a controlled input's value into the DOM `value`
    // attribute — that is true of every controlled field in the app,
    // CcureInput included, and making the field uncontrolled to avoid it
    // would change authentication behaviour for no security gain. What must
    // hold is that the secret reaches nothing else: no rendered text, no
    // other element, no storage.
    expect(container.textContent).not.toContain("Sup3rSecret!Value");
    for (const el of container.querySelectorAll("*")) {
      if (el === screen.getByLabelText(/^password\b/i)) continue;
      expect(el.outerHTML.replace(el.innerHTML, "")).not.toContain(
        "Sup3rSecret!Value",
      );
    }
    expect(JSON.stringify(localStorage)).not.toContain("Sup3rSecret!Value");
    expect(JSON.stringify(sessionStorage)).not.toContain("Sup3rSecret!Value");
  });

  it("keeps the form mounted after a failure so the user can retry", async () => {
    login.mockRejectedValue({ response: { data: { detail: "Bad creds" } } });
    renderPage();
    await signIn();

    await screen.findByText(/bad creds/i);
    expect(screen.getByLabelText(/email or username/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeEnabled();
  });

  it("shows a routed notice when there is no error", async () => {
    locationState = { message: "Your session expired." };
    renderPage();

    expect(
      await screen.findByText(/your session expired/i),
    ).toBeInTheDocument();
  });

  it("suppresses the notice once an error is present", async () => {
    locationState = { message: "Your session expired." };
    login.mockRejectedValue({ response: { data: { detail: "Bad creds" } } });
    renderPage();
    await signIn();

    await screen.findByText(/bad creds/i);
    expect(screen.queryByText(/your session expired/i)).toBeNull();
  });
});

/* ── Password field behaviour ─────────────────────────────────────────────── */

describe("Login — password field", () => {
  it("masks the password by default", () => {
    renderPage();

    expect(screen.getByLabelText(/^password\b/i)).toHaveAttribute(
      "type",
      "password",
    );
  });

  it("reveals and re-masks on the toggle", async () => {
    renderPage();
    const user = userEvent.setup();
    const toggle = screen.getByRole("button", {
      name: /toggle password visibility/i,
    });

    await user.click(toggle);
    expect(screen.getByLabelText(/^password\b/i)).toHaveAttribute(
      "type",
      "text",
    );
    await user.click(toggle);
    expect(screen.getByLabelText(/^password\b/i)).toHaveAttribute(
      "type",
      "password",
    );
  });

  it("keeps the toggle out of the tab order", () => {
    renderPage();

    expect(
      screen.getByRole("button", { name: /toggle password visibility/i }),
    ).toHaveAttribute("tabindex", "-1");
  });

  it("does not submit the form from the toggle", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /toggle password visibility/i }),
    );

    expect(login).not.toHaveBeenCalled();
  });

  it("warns while caps lock is on and stops when it is released", async () => {
    renderPage();
    const user = userEvent.setup();
    const field = screen.getByLabelText(/^password\b/i);

    await user.keyboard("{CapsLock}");
    field.focus();
    await user.keyboard("a");
    expect(screen.getByText(/caps lock is on/i)).toBeInTheDocument();

    await user.keyboard("{CapsLock}");
    await user.keyboard("b");
    await waitFor(() =>
      expect(screen.queryByText(/caps lock is on/i)).toBeNull(),
    );
  });

  it("declares autocomplete hints the password manager needs", () => {
    renderPage();

    expect(screen.getByLabelText(/email or username/i)).toHaveAttribute(
      "autocomplete",
      "username",
    );
    expect(screen.getByLabelText(/^password\b/i)).toHaveAttribute(
      "autocomplete",
      "current-password",
    );
  });
});

/* ── Accessibility — the migration specification ──────────────────────────── */

describe("Login — accessibility", () => {
  it("names the page with a level-1 heading inside the auth card", () => {
    const { container } = renderPage();
    const card = container.querySelector(".auth-card");

    expect(within(card).getByRole("heading", { level: 1 })).toHaveTextContent(
      /sign in/i,
    );
  });

  it("has exactly one h1 on the page", () => {
    const { container } = renderPage();

    // Currently two: AuthHeroPanel renders `<h1 class="auth-hero-headline">`
    // beside the card's own. The hero is decorative marketing copy and the
    // card's title is the page's name, so the hero's becomes an h2.
    expect(container.querySelectorAll("h1")).toHaveLength(1);
  });

  it("announces the failure as an alert", async () => {
    login.mockRejectedValue({ response: { data: { detail: "Bad creds" } } });
    renderPage();
    await signIn();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/bad creds/i);
  });

  it("announces the caps-lock warning to assistive technology", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.keyboard("{CapsLock}");
    screen.getByLabelText(/^password\b/i).focus();
    await user.keyboard("a");

    // A silent visual warning does not reach anyone typing without sight of
    // the field, which is precisely the user most affected by it.
    const warning = screen.getByText(/caps lock is on/i);
    expect(warning.closest("[role='status'],[aria-live]")).not.toBeNull();
  });

  it("keeps the submit button's accessible name while in flight", async () => {
    let release;
    login.mockReturnValue(new Promise((r) => (release = r)));
    renderPage();
    await signIn();

    const button = screen.getByRole("button", { name: /signing in/i });
    expect(button).toBeDisabled();
    release({ user: { id: 1 } });
    await waitFor(() => expect(navigate).toHaveBeenCalled());
  });

  it("marks both credential fields as required", () => {
    renderPage();

    expect(screen.getByLabelText(/email or username/i)).toBeRequired();
    expect(screen.getByLabelText(/^password\b/i)).toBeRequired();
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
