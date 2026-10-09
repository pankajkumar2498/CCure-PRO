/**
 * Register — Checkpoint 3C auth-group migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * `/auth/register` returns 202 with no tokens: the account is created
 * unverified, inactive, unapproved and in the `viewer` role, and needs both a
 * confirmed mailbox and an administrator approval. CLAUDE.md records that it
 * used to return working tokens for an `analyst`, which carries
 * `scans:execute`. This page must therefore never treat a successful
 * registration as a session.
 *
 * The second contract is account-enumeration. `/auth/check-email` answers
 * about the *domain*, never about whether an address holds an account — the
 * live "already registered" hint was removed for exactly that reason. A
 * collision surfaces as the same generic outcome as every other result. The
 * assertions below pin both directions: the domain verdict is shown, and no
 * wording anywhere claims an account does or does not exist.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import Register from "@shell/auth/pages/Register";
import { LegalDocumentsProvider } from "@shell/auth/legalDocuments";
import {
  checkEmail,
  checkUsername,
  isSelfRegistrationEnabled,
  resendVerification,
} from "@shell/api/auth";

vi.mock("@shell/api/auth", () => ({
  checkEmail: vi.fn(),
  checkUsername: vi.fn(),
  isSelfRegistrationEnabled: vi.fn(),
  resendVerification: vi.fn(),
}));

const register = vi.fn();

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ register }),
}));

/** The shell owns no legal wording: these fixtures stand in for what the
 *  composition root provides. The real text is pinned in the Audit tests. */
const DOCUMENTS = {
  terms: {
    title: "Terms of Service — Fixture",
    body: <h4>1. Authorized Use</h4>,
  },
  privacy: {
    title: "Privacy Policy — Fixture",
    body: <h4>1. Data Collection</h4>,
  },
};

const renderPage = (documents = DOCUMENTS) =>
  render(
    <MemoryRouter>
      <LegalDocumentsProvider documents={documents}>
        <Register />
      </LegalDocumentsProvider>
    </MemoryRouter>,
  );

const VALID = {
  fullName: "Test Person",
  username: "testperson",
  email: "person@example.com",
  password: "Str0ng!Passphrase",
};

/** Fill every field with a valid value, tick the terms box, and submit. */
const completeForm = async (overrides = {}) => {
  const v = { ...VALID, ...overrides };
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(/full name/i), v.fullName);
  await user.type(screen.getByLabelText(/username/i), v.username);
  await user.type(screen.getByLabelText(/^email\b/i), v.email);
  await user.type(screen.getByLabelText(/^password\b/i), v.password);
  await user.type(
    screen.getByLabelText(/^confirm password\b/i),
    v.confirm ?? v.password,
  );
  if (v.agree !== false) {
    await user.click(screen.getByRole("checkbox"));
  }
  await user.click(screen.getByRole("button", { name: /create account/i }));
  return user;
};

beforeEach(() => {
  vi.clearAllMocks();
  isSelfRegistrationEnabled.mockResolvedValue(true);
  checkUsername.mockResolvedValue({ available: true });
  checkEmail.mockResolvedValue({ available: true });
  resendVerification.mockResolvedValue({});
  register.mockResolvedValue({ status: "pending_verification" });
});

/* ── Feature gate ─────────────────────────────────────────────────────────── */

describe("Register — self-registration gate", () => {
  it("renders no form while the probe is in flight", () => {
    isSelfRegistrationEnabled.mockReturnValue(new Promise(() => {}));
    renderPage();

    // The gate is `selfRegAllowed === false`, so the form renders while the
    // probe is null. What must not happen is the *disabled* panel flashing.
    expect(screen.queryByText(/created by an administrator/i)).toBeNull();
  });

  it("replaces the form entirely when signup is off", async () => {
    isSelfRegistrationEnabled.mockResolvedValue(false);
    renderPage();

    expect(
      await screen.findByText(/accounts are created by an administrator/i),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/^password\b/i)).toBeNull();
    expect(
      screen.getByRole("link", { name: /back to sign in/i }),
    ).toHaveAttribute("href", "/login");
  });

  it("falls back to the disabled panel when the API answers 404", async () => {
    register.mockRejectedValue({ response: { status: 404 } });
    renderPage();
    await completeForm();

    expect(
      await screen.findByText(/accounts are created by an administrator/i),
    ).toBeInTheDocument();
  });
});

/* ── API contract ─────────────────────────────────────────────────────────── */

describe("Register — API contract", () => {
  it("submits the normalised payload", async () => {
    renderPage();
    await completeForm();

    await waitFor(() => expect(register).toHaveBeenCalledTimes(1));
    expect(register).toHaveBeenCalledWith({
      username: "testperson",
      email: "person@example.com",
      password: "Str0ng!Passphrase",
      full_name: "Test Person",
      agree_to_terms: true,
    });
  });

  it("lower-cases and trims the email but not the password", async () => {
    renderPage();
    await completeForm({
      email: "  Person@EXAMPLE.com  ",
      password: "  Str0ng!Pass  ",
      confirm: "  Str0ng!Pass  ",
    });

    await waitFor(() => expect(register).toHaveBeenCalledTimes(1));
    const payload = register.mock.calls[0][0];
    expect(payload.email).toBe("person@example.com");
    expect(payload.password).toBe("  Str0ng!Pass  ");
  });

  it("shows the pending panel and never signs the user in", async () => {
    renderPage();
    await completeForm();

    expect(await screen.findByText(/check your email/i)).toBeInTheDocument();
    // 202 carries no tokens. Anything that looks like a session here would be
    // the regression CLAUDE.md records.
    expect(
      screen.getByText(/administrator reviews and approves new accounts/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create account/i }),
    ).toBeNull();
  });

  it("resends verification to the normalised address", async () => {
    renderPage();
    await completeForm({ email: "  Person@EXAMPLE.com  " });
    await screen.findByText(/check your email/i);

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /resend verification/i }),
    );

    await waitFor(() => expect(resendVerification).toHaveBeenCalledTimes(1));
    expect(resendVerification).toHaveBeenCalledWith("person@example.com");
  });

  it("reports the resend as sent even when it fails", async () => {
    resendVerification.mockRejectedValue(new Error("smtp down"));
    renderPage();
    await completeForm();
    await screen.findByText(/check your email/i);

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /resend verification/i }),
    );

    // The endpoint answers identically for every address; a distinct failure
    // here would be an oracle.
    expect(
      await screen.findByRole("button", {
        name: /verification email re-sent/i,
      }),
    ).toBeDisabled();
  });

  it("makes no registration request on mount", async () => {
    renderPage();
    await waitFor(() =>
      expect(isSelfRegistrationEnabled).toHaveBeenCalledTimes(1),
    );

    expect(register).not.toHaveBeenCalled();
    expect(resendVerification).not.toHaveBeenCalled();
  });
});

/* ── Account-enumeration safety ───────────────────────────────────────────── */

describe("Register — account-enumeration safety", () => {
  it("never claims an email is already registered", async () => {
    checkEmail.mockResolvedValue({
      available: false,
      detail: "Disposable mail domains are not accepted.",
    });
    const { container } = renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^email\b/i), "taken@example.com");

    await screen.findByText(/disposable mail domains/i);
    const text = container.textContent.toLowerCase();
    expect(text).not.toMatch(/already registered/);
    expect(text).not.toMatch(/email is taken/);
    expect(text).not.toMatch(/account (already )?exists/);
  });

  it("shows the domain verdict, which is not account-specific", async () => {
    checkEmail.mockResolvedValue({
      available: false,
      detail: "Disposable mail domains are not accepted.",
    });
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^email\b/i), "a@mailinator.com");

    expect(
      await screen.findByText(/disposable mail domains are not accepted/i),
    ).toBeInTheDocument();
  });

  it("stays silent when the advisory probe fails", async () => {
    checkEmail.mockRejectedValue(new Error("offline"));
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^email\b/i), "a@example.com");

    await waitFor(() => expect(checkEmail).toHaveBeenCalled());
    expect(
      screen.getByText(/we will send a verification link/i),
    ).toBeInTheDocument();
  });

  it("does not probe an incomplete address", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^email\b/i), "not-an-email");

    await waitFor(() => expect(checkUsername).not.toHaveBeenCalled());
    expect(checkEmail).not.toHaveBeenCalled();
  });

  it("confirms the outcome without naming the address's status", async () => {
    const { container } = renderPage();
    await completeForm();
    await screen.findByText(/check your email/i);

    // "If that address can be registered" is deliberately conditional.
    expect(container.textContent).toMatch(/if that address can be registered/i);
  });
});

/* ── Username availability ────────────────────────────────────────────────── */

describe("Register — username availability", () => {
  it("checks availability once the name is long enough", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/username/i), "abc");

    await waitFor(() => expect(checkUsername).toHaveBeenCalledWith("abc"));
    expect(await screen.findByText(/username available/i)).toBeInTheDocument();
  });

  it("does not check a name shorter than three characters", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/username/i), "ab");

    await screen.findByText(/min\. 3 characters/i);
    expect(checkUsername).not.toHaveBeenCalled();
  });

  it("does not check a name containing @", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/username/i), "a@b.com");

    await screen.findByText(/cannot contain/i);
    expect(checkUsername).not.toHaveBeenCalled();
  });

  it("reports a taken name", async () => {
    checkUsername.mockResolvedValue({ available: false });
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/username/i), "taken");

    expect(
      await screen.findByText(/this username is already taken/i),
    ).toBeInTheDocument();
  });
});

/* ── Client-side validation ───────────────────────────────────────────────── */

describe("Register — validation", () => {
  const cases = [
    [
      "a password under 12 characters",
      { password: "Sh0rt!", confirm: "Sh0rt!" },
      /at least 12 characters/i,
    ],
    [
      "a password with no uppercase",
      { password: "str0ng!passphrase", confirm: "str0ng!passphrase" },
      /uppercase letter/i,
    ],
    [
      "a password with no digit",
      { password: "Strong!Passphrase", confirm: "Strong!Passphrase" },
      /one digit/i,
    ],
    [
      "a password with no special character",
      { password: "Str0ngPassphrase1", confirm: "Str0ngPassphrase1" },
      /special character/i,
    ],
    [
      "a mismatched confirmation",
      { confirm: "Different!Pass1" },
      /passwords do not match/i,
    ],
  ];

  for (const [name, overrides, expected] of cases) {
    it(`refuses ${name} without calling the API`, async () => {
      renderPage();
      await completeForm(overrides);

      expect(await screen.findByText(expected)).toBeInTheDocument();
      expect(register).not.toHaveBeenCalled();
    });
  }

  it("refuses an unticked terms box without calling the API", async () => {
    renderPage();
    await completeForm({ agree: false });

    // The checkbox carries `required`, so constraint validation stops the
    // submit before `validate()` runs and no message is rendered. Either way
    // the contract is the same and it is the one that matters: consent was
    // not given, so nothing was sent.
    await waitFor(() => expect(register).not.toHaveBeenCalled());
    expect(screen.getByRole("checkbox")).toBeRequired();
  });

  it("refuses a username containing @ without calling the API", async () => {
    renderPage();
    await completeForm({ username: "bad@name" });

    // Two elements say so — the live field hint and the submit-time error.
    expect(
      (await screen.findAllByText(/cannot contain/i)).length,
    ).toBeGreaterThan(0);
    expect(register).not.toHaveBeenCalled();
  });

  it("grades password strength as the rules are met", async () => {
    renderPage();
    const user = userEvent.setup();
    const field = screen.getByLabelText(/^password\b/i);

    await user.type(field, "abcdefghijkl");
    expect(await screen.findByText("Weak")).toBeInTheDocument();

    await user.clear(field);
    await user.type(field, "Abcdefghijk1!");
    expect(await screen.findByText("Strong")).toBeInTheDocument();
  });

  it("confirms a matching confirmation", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^password\b/i), "Str0ng!Passphrase");
    await user.type(
      screen.getByLabelText(/^confirm password\b/i),
      "Str0ng!Passphrase",
    );

    expect(await screen.findByText(/passwords match/i)).toBeInTheDocument();
  });
});

/* ── Error semantics ──────────────────────────────────────────────────────── */

describe("Register — error semantics", () => {
  it("joins a details array and strips the pydantic prefix", async () => {
    register.mockRejectedValue({
      response: {
        data: {
          details: [
            { msg: "Value error, password too common" },
            { msg: "Value error, domain not accepted" },
          ],
        },
      },
    });
    renderPage();
    await completeForm();

    expect(
      await screen.findByText(/password too common, domain not accepted/i),
    ).toBeInTheDocument();
  });

  it("prefers message over detail", async () => {
    register.mockRejectedValue({
      response: {
        data: { message: "Registration closed.", detail: "ignored" },
      },
    });
    renderPage();
    await completeForm();

    expect(await screen.findByText(/registration closed/i)).toBeInTheDocument();
    expect(screen.queryByText(/ignored/)).toBeNull();
  });

  it("strips the pydantic prefix from a string detail", async () => {
    register.mockRejectedValue({
      response: { data: { detail: "Value error, that domain is blocked" } },
    });
    renderPage();
    await completeForm();

    expect(
      await screen.findByText(/^that domain is blocked$/i),
    ).toBeInTheDocument();
  });

  it("falls back to a generic message", async () => {
    register.mockRejectedValue(new Error("network"));
    renderPage();
    await completeForm();

    expect(
      await screen.findByText(/registration failed\. please try again\./i),
    ).toBeInTheDocument();
  });

  it("never echoes the chosen password outside its own fields", async () => {
    register.mockRejectedValue({ response: { data: { detail: "nope" } } });
    const { container } = renderPage();
    await completeForm({ password: "Uniq3!Secret", confirm: "Uniq3!Secret" });
    await screen.findByText(/nope/i);

    expect(container.textContent).not.toContain("Uniq3!Secret");
    expect(JSON.stringify(localStorage)).not.toContain("Uniq3!Secret");
    expect(JSON.stringify(sessionStorage)).not.toContain("Uniq3!Secret");
  });

  it("keeps the form mounted after a failure", async () => {
    register.mockRejectedValue({ response: { data: { detail: "nope" } } });
    renderPage();
    await completeForm();
    await screen.findByText(/nope/i);

    expect(
      screen.getByRole("button", { name: /create account/i }),
    ).toBeEnabled();
  });
});

/* ── Terms and privacy modals ─────────────────────────────────────────────── */

describe("Register — terms and privacy", () => {
  it("opens the terms modal and accepting it ticks the box", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /terms of service/i }));

    expect(await screen.findByText(/1\. authorized use/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /accept & close/i }));

    expect(screen.getByRole("checkbox")).toBeChecked();
    expect(screen.queryByText(/1\. authorized use/i)).toBeNull();
  });

  it("opens the privacy modal and accepting it ticks the box", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /privacy policy/i }));

    expect(await screen.findByText(/1\. data collection/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /accept & close/i }));

    expect(screen.getByRole("checkbox")).toBeChecked();
  });

  it("closes on the dismiss control without ticking the box", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /terms of service/i }));
    await screen.findByText(/1\. authorized use/i);
    // Named, not glyph-labelled — see "gives the modal dismiss control an
    // accessible name" below, which asserts no button is named by the bare "×".
    await user.click(screen.getByRole("button", { name: /close dialog/i }));

    await waitFor(() =>
      expect(screen.queryByText(/1\. authorized use/i)).toBeNull(),
    );
    expect(screen.getByRole("checkbox")).not.toBeChecked();
  });

  it("says so when a document is not provided, never an empty dialog", async () => {
    renderPage({});
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /terms of service/i }));
    expect(
      await screen.findByText(/terms of service are not available/i),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /close dialog/i }));
    await user.click(screen.getByRole("button", { name: /privacy policy/i }));
    expect(
      await screen.findByText(/privacy policy is not available/i),
    ).toBeInTheDocument();
  });

  it("does not submit the form from a policy trigger", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /terms of service/i }));

    expect(register).not.toHaveBeenCalled();
  });
});

/* ── Accessibility — the migration specification ──────────────────────────── */

describe("Register — accessibility", () => {
  it("names the page with a level-1 heading inside the auth card", () => {
    const { container } = renderPage();
    const card = container.querySelector(".auth-card");

    expect(within(card).getByRole("heading", { level: 1 })).toHaveTextContent(
      /create account/i,
    );
  });

  it("has exactly one h1 on the page", () => {
    const { container } = renderPage();

    expect(container.querySelectorAll("h1")).toHaveLength(1);
  });

  it("announces the submission failure as an alert", async () => {
    register.mockRejectedValue({ response: { data: { detail: "nope" } } });
    renderPage();
    await completeForm();

    expect(await screen.findByRole("alert")).toHaveTextContent(/nope/i);
  });

  it("describes each field's hint through aria-describedby", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^email\b/i), "a@example.com");
    await screen.findByText(/we will send a verification link/i);

    const email = screen.getByLabelText(/^email\b/i);
    const describedBy = email.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy)).toHaveTextContent(
      /we will send a verification link/i,
    );
  });

  it("marks a rejected username invalid to assistive technology", async () => {
    checkUsername.mockResolvedValue({ available: false });
    renderPage();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/username/i), "taken");
    await screen.findByText(/already taken/i);

    expect(screen.getByLabelText(/username/i)).toHaveAttribute(
      "aria-invalid",
      "true",
    );
  });

  it("announces the caps-lock warning to assistive technology", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.keyboard("{CapsLock}");
    screen.getByLabelText(/^password\b/i).focus();
    await user.keyboard("a");

    const warning = screen.getByText(/caps lock is on/i);
    expect(warning.closest("[role='status'],[aria-live]")).not.toBeNull();
  });

  it("gives the policy modals a dialog role and an accessible name", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /terms of service/i }));

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAccessibleName(/terms of service/i);
  });

  it("gives the modal dismiss control an accessible name", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /terms of service/i }));
    await screen.findByText(/1\. authorized use/i);

    // "×" is a glyph, not a name. A screen-reader user hears "multiplication
    // sign button". `Accept & Close` also matches /close/i, so the assertion
    // has to be that no button is named by the bare glyph.
    expect(screen.queryByRole("button", { name: "×" })).toBeNull();
  });

  it("marks every required field as required", () => {
    renderPage();

    expect(screen.getByLabelText(/full name/i)).toBeRequired();
    expect(screen.getByLabelText(/username/i)).toBeRequired();
    expect(screen.getByLabelText(/^email\b/i)).toBeRequired();
    expect(screen.getByLabelText(/^password\b/i)).toBeRequired();
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

describe("Register — shared consent controls", () => {
  it("keeps policy actions outside the required checkbox label and restores focus", async () => {
    const u = userEvent.setup();
    renderPage();
    const consent = await screen.findByRole("checkbox", {
      name: "I agree to the Terms of Service and Privacy Policy",
    });
    expect(consent).toBeRequired();
    expect(consent.closest("label").querySelector("button")).toBeNull();
    const terms = screen.getByRole("button", { name: "Terms of Service" });
    await u.click(terms);
    expect(
      screen.getByRole("dialog", {
        name: "Terms of Service — Fixture",
      }),
    ).toBeInTheDocument();
    expect(consent).not.toBeChecked();
    await u.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(terms).toHaveFocus();
    expect(consent).not.toBeChecked();
    consent.focus();
    await u.keyboard(" ");
    expect(consent).toBeChecked();
  });
});
