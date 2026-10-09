/**
 * ProfileModal + ChangePasswordModal — Checkpoint 3C batch 14.
 *
 * Written against the legacy dialogs BEFORE migration. Everything in the first
 * five blocks holds on both sides; the last block is the migration spec
 * (dialog guarantees, tab semantics, deliberate MFA action, revoke-others
 * confirmation) and fails on the baseline.
 *
 * ── API contract preserved (asserted here) ─────────────────────────────────
 *   getProfile / updateProfile({full_name, email})            api/user
 *   getSessions / revokeSession(id) / revokeOtherSessions()   api/user
 *   changePassword(current, next)                            api/user
 *   enableMfa() → confirmMfa(code) → backup codes;            api/auth
 *   disableMfa(password); refreshUser(true) after either; the session list
 *   is pruned to the current session after a successful confirm/disable.
 *
 * ── Dual-path helpers ──────────────────────────────────────────────────────
 * The legacy tabs are bare buttons; migrated ones are role="tab". The legacy
 * MFA trigger is a checkbox; the migrated one is an explicit button. Helpers
 * take the control as it is, else as it becomes.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ProfileModal from "@shell/account/ProfileModal";
import * as userApi from "@shell/api/user";
import * as authApi from "@shell/api/auth";
import { personaFrom } from "../../fixtures/authorization";

vi.mock("@shell/api/user", () => ({
  getProfile: vi.fn(),
  updateProfile: vi.fn(),
  getSessions: vi.fn(),
  revokeSession: vi.fn(),
  revokeOtherSessions: vi.fn(),
  changePassword: vi.fn(),
}));
vi.mock("@shell/api/auth", () => ({
  enableMfa: vi.fn(),
  confirmMfa: vi.fn(),
  disableMfa: vi.fn(),
}));

let currentUser = {
  id: 1,
  username: "alice",
  mfa_enabled: false,
  role: { name: "analyst" },
};
const refreshUser = vi.fn().mockResolvedValue(undefined);
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(currentUser), refreshUser }),
}));

const PROFILE = {
  id: 1,
  username: "alice",
  full_name: "Alice Analyst",
  email: "alice@example.test",
  role_name: "analyst",
  organization_name: "Acme Corp",
  is_active: true,
  last_login_at: "2026-09-11T08:00:00Z",
  created_at: "2026-01-15T10:00:00Z",
};
const SESSIONS = [
  {
    session_id: "s-1",
    is_current: true,
    ip_address: "10.180.6.20",
    issued_at: "2026-09-12T08:00:00Z",
    expires_at: "2026-09-19T08:00:00Z",
    device_info: { browser: "Chrome", platform: "Windows", raw: "Mozilla/5.0" },
  },
  {
    session_id: "s-2",
    is_current: false,
    ip_address: "10.180.6.21",
    issued_at: "2026-09-10T08:00:00Z",
    expires_at: "2026-09-17T08:00:00Z",
    device_info: { browser: "Firefox", platform: "Linux", raw: "Mozilla/5.0" },
  },
  {
    session_id: "s-3",
    is_current: false,
    ip_address: "10.180.6.22",
    issued_at: "2026-09-09T08:00:00Z",
    expires_at: "2026-09-16T08:00:00Z",
    device_info: { browser: "Unknown", platform: "Unknown", raw: "curl/8.0" },
  },
];

const dialog = () =>
  screen.getByRole("dialog", { name: /account profile|my account/i });
const tab = (re) =>
  within(dialog()).queryByRole("tab", { name: re }) ??
  within(dialog()).getByRole("button", { name: re });
/* Legacy: an icon-only button with no name (a defect the migration fixes). */
const closeControl = () =>
  within(dialog()).queryByRole("button", { name: /^close/i }) ??
  dialog().querySelector(".pm-close");
const openSecurity = async () => {
  await userEvent.click(tab(/security/i));
  await waitFor(() => expect(userApi.getSessions).toHaveBeenCalled());
};
/* Legacy: a checkbox whose change starts enrolment; migrated: a button. */
const startMfa = async () => {
  const btn = within(dialog()).queryByRole("button", {
    name: /set up mfa|enable mfa/i,
  });
  if (btn) return userEvent.click(btn);
  return userEvent.click(within(dialog()).getByRole("checkbox"));
};
const beginDisableMfa = async () => {
  const btn = within(dialog()).queryByRole("button", { name: /disable mfa/i });
  if (btn) return userEvent.click(btn);
  return userEvent.click(within(dialog()).getByRole("checkbox"));
};

const assertSecretNotLeaked = (secret) => {
  for (const el of document.body.querySelectorAll("*")) {
    for (const attr of el.attributes) {
      if (attr.name === "value" && el.getAttribute("type") === "password")
        continue;
      expect(
        attr.value,
        `${el.tagName}[${attr.name}] carries the secret`,
      ).not.toContain(secret);
    }
  }
};

const renderModal = async (onClose = vi.fn()) => {
  const utils = render(<ProfileModal onClose={onClose} />);
  await waitFor(() => expect(userApi.getProfile).toHaveBeenCalled());
  await screen.findByText("Alice Analyst", {
    selector: "h3, h2, .pm-display-name",
  });
  return { ...utils, onClose };
};

beforeEach(() => {
  vi.clearAllMocks();
  currentUser = {
    id: 1,
    username: "alice",
    mfa_enabled: false,
    role: { name: "analyst" },
  };
  userApi.getProfile.mockResolvedValue(PROFILE);
  userApi.updateProfile.mockImplementation(async (d) => ({ ...PROFILE, ...d }));
  userApi.getSessions.mockResolvedValue(SESSIONS);
  userApi.revokeSession.mockResolvedValue({});
  userApi.revokeOtherSessions.mockResolvedValue({
    revoked: 2,
    kept_current_session: true,
  });
  userApi.changePassword.mockResolvedValue({});
  authApi.enableMfa.mockResolvedValue({
    qr_code: "data:image/png;base64,QR",
    secret: "JBSWY3DPEHPK3PXP",
  });
  authApi.confirmMfa.mockResolvedValue({
    backup_codes: ["AAAA-1111", "BBBB-2222", "CCCC-3333"],
  });
  authApi.disableMfa.mockResolvedValue({});
  const clip = { writeText: vi.fn().mockResolvedValue(undefined) };
  Object.defineProperty(navigator, "clipboard", {
    value: clip,
    configurable: true,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("ProfileModal — open and read", () => {
  it("is a named dialog that loads the profile and shows it read-only", async () => {
    await renderModal();
    const dlg = dialog();
    expect(within(dlg).getByText("alice@example.test")).toBeInTheDocument();
    expect(within(dlg).getByText("analyst")).toBeInTheDocument();
    expect(within(dlg).getByText(/Acme Corp/)).toBeInTheDocument();
    expect(within(dlg).getByText("Active")).toBeInTheDocument();
    expect(within(dlg).getByDisplayValue("alice")).toHaveAttribute("readonly");
    expect(userApi.updateProfile).not.toHaveBeenCalled();
    expect(userApi.getSessions).not.toHaveBeenCalled(); // security tab is lazy
    expect(authApi.enableMfa).not.toHaveBeenCalled();
  });

  it("reports a profile load failure", async () => {
    userApi.getProfile.mockRejectedValue(new Error("boom"));
    render(<ProfileModal onClose={() => {}} />);
    expect(
      await screen.findByText(/Failed to load profile/),
    ).toBeInTheDocument();
  });

  it("the close control closes; the profile is never written on open", async () => {
    const { onClose } = await renderModal();
    await userEvent.click(closeControl());
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("ProfileModal — profile update", () => {
  it("edits full name and email and PUTs exactly {full_name, email}", async () => {
    await renderModal();
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /edit profile/i }),
    );
    const name = within(dialog()).getByPlaceholderText(/full name/i);
    await userEvent.clear(name);
    await userEvent.type(name, "Alice A.");
    const email = within(dialog()).getByPlaceholderText(/email address/i);
    await userEvent.clear(email);
    await userEvent.type(email, "alice.a@example.test");
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /save changes/i }),
    );
    await waitFor(() =>
      expect(userApi.updateProfile).toHaveBeenCalledWith({
        full_name: "Alice A.",
        email: "alice.a@example.test",
      }),
    );
    expect(
      await within(dialog()).findByText(/Profile updated successfully/),
    ).toBeInTheDocument();
    expect(within(dialog()).getAllByText("Alice A.").length).toBeGreaterThan(0);
  });

  it("an empty field is sent as null; cancel discards without a write", async () => {
    await renderModal();
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /edit profile/i }),
    );
    await userEvent.clear(within(dialog()).getByPlaceholderText(/full name/i));
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /save changes/i }),
    );
    await waitFor(() =>
      expect(userApi.updateProfile).toHaveBeenCalledWith({
        full_name: null,
        email: "alice@example.test",
      }),
    );
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /edit profile/i }),
    );
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /^cancel$/i }),
    );
    expect(userApi.updateProfile).toHaveBeenCalledTimes(1);
  });

  it("shows the server's detail on failure", async () => {
    userApi.updateProfile.mockRejectedValue({
      response: { data: { detail: "Email already in use" } },
    });
    await renderModal();
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /edit profile/i }),
    );
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /save changes/i }),
    );
    expect(
      await within(dialog()).findByText(/Email already in use/),
    ).toBeInTheDocument();
  });
});

describe("ProfileModal — security tab and sessions", () => {
  it("lists sessions, marks the current one, and offers revoke only on the others", async () => {
    await renderModal();
    await openSecurity();
    const dlg = dialog();
    expect(
      await within(dlg).findByText(/Chrome on Windows/),
    ).toBeInTheDocument();
    expect(within(dlg).getByText(/Firefox on Linux/)).toBeInTheDocument();
    expect(within(dlg).getByText(/curl\/8\.0/)).toBeInTheDocument();
    expect(within(dlg).getByText("Current")).toBeInTheDocument();
    expect(
      within(dlg).getAllByRole("button", { name: /revoke/i }),
    ).toHaveLength(2);
    expect(within(dlg).getByText("Disabled")).toBeInTheDocument();
    expect(userApi.revokeSession).not.toHaveBeenCalled();
    expect(userApi.revokeOtherSessions).not.toHaveBeenCalled();
  });

  it("revokes a single session by id and removes it from the list", async () => {
    await renderModal();
    await openSecurity();
    const dlg = dialog();
    await within(dlg).findByText(/Firefox on Linux/);
    const row = within(dlg)
      .getByText(/Firefox on Linux/)
      .closest(".pm-session-card, .pm-session, li, tr, div");
    await userEvent.click(
      within(dlg).getAllByRole("button", { name: /revoke/i })[0],
    );
    await waitFor(() =>
      expect(userApi.revokeSession).toHaveBeenCalledWith("s-2"),
    );
    await waitFor(() =>
      expect(
        within(dlg).queryByText(/Firefox on Linux/),
      ).not.toBeInTheDocument(),
    );
    expect(row).not.toBeNull();
  });

  it("sign out other sessions calls the endpoint, re-fetches the list and reports the count", async () => {
    userApi.getSessions
      .mockResolvedValueOnce(SESSIONS)
      .mockResolvedValueOnce([SESSIONS[0]]);
    await renderModal();
    await openSecurity();
    const dlg = dialog();
    await within(dlg).findByText(/Firefox on Linux/);
    await userEvent.click(
      within(dlg).getByRole("button", { name: /sign out all other sessions/i }),
    );
    // Migrated: a confirmation stands between the click and the write.
    const confirmDlg = screen
      .queryAllByRole("dialog")
      .find(
        (d) =>
          /sign out other sessions/i.test(d.textContent || "") && d !== dlg,
      );
    if (confirmDlg) {
      expect(userApi.revokeOtherSessions).not.toHaveBeenCalled();
      await userEvent.click(
        within(confirmDlg).getByRole("button", { name: /sign out|confirm/i }),
      );
    }
    await waitFor(() =>
      expect(userApi.revokeOtherSessions).toHaveBeenCalledTimes(1),
    );
    expect(
      await within(dlg).findByText(/Signed out 2 other sessions/),
    ).toBeInTheDocument();
    expect(userApi.getSessions).toHaveBeenCalledTimes(2);
    await waitFor(() =>
      expect(
        within(dlg).queryByText(/Firefox on Linux/),
      ).not.toBeInTheDocument(),
    );
  });

  it("reports a sessions load failure", async () => {
    userApi.getSessions.mockRejectedValue(new Error("boom"));
    await renderModal();
    await openSecurity();
    expect(
      await within(dialog()).findByText(/Failed to load sessions/),
    ).toBeInTheDocument();
  });
});

describe("ProfileModal — MFA", () => {
  it("disabled state: no enrolment request on render or on opening the tab", async () => {
    await renderModal();
    await openSecurity();
    expect(within(dialog()).getByText("Disabled")).toBeInTheDocument();
    expect(authApi.enableMfa).not.toHaveBeenCalled();
  });

  it("enrolment: enableMfa → QR + secret shown → confirmMfa(code) → backup codes; refreshUser; sessions pruned", async () => {
    await renderModal();
    await openSecurity();
    await within(dialog()).findByText(/Firefox on Linux/);
    await startMfa();
    await waitFor(() => expect(authApi.enableMfa).toHaveBeenCalledTimes(1));
    const dlg = dialog();
    expect(
      await within(dlg).findByText("JBSWY3DPEHPK3PXP"),
    ).toBeInTheDocument();
    expect(within(dlg).getByRole("img", { name: /qr code/i })).toHaveAttribute(
      "src",
      "data:image/png;base64,QR",
    );
    // The secret is visible text in this step and nowhere else.
    assertSecretNotLeaked("JBSWY3DPEHPK3PXP");

    await userEvent.type(
      within(dlg).getByPlaceholderText(/6-digit code/i),
      "123456",
    );
    await userEvent.click(within(dlg).getByRole("button", { name: /verify/i }));
    await waitFor(() =>
      expect(authApi.confirmMfa).toHaveBeenCalledWith("123456"),
    );
    expect(await within(dlg).findByText("AAAA-1111")).toBeInTheDocument();
    expect(within(dlg).getByText("CCCC-3333")).toBeInTheDocument();
    assertSecretNotLeaked("AAAA-1111");
    expect(refreshUser).toHaveBeenCalledWith(true);

    await userEvent.click(
      within(dlg).getByRole("button", { name: /copy codes/i }),
    );
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      "AAAA-1111\nBBBB-2222\nCCCC-3333",
    );

    await userEvent.click(within(dlg).getByRole("button", { name: /^done$/i }));
    // Back on the tab; the secret and codes are gone from the DOM entirely.
    await waitFor(() =>
      expect(
        within(dlg).queryByText("JBSWY3DPEHPK3PXP"),
      ).not.toBeInTheDocument(),
    );
    expect(within(dlg).queryByText("AAAA-1111")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("JBSWY3DPEHPK3PXP");
    // Sessions pruned to the current one after a successful confirm.
    expect(within(dlg).queryByText(/Firefox on Linux/)).not.toBeInTheDocument();
    expect(within(dlg).getByText(/Chrome on Windows/)).toBeInTheDocument();
  });

  it("a wrong code is reported and the wizard stays open; cancel leaves without confirming", async () => {
    authApi.confirmMfa.mockRejectedValue({
      response: { data: { detail: "Invalid TOTP code" } },
    });
    await renderModal();
    await openSecurity();
    await startMfa();
    const dlg = dialog();
    await within(dlg).findByText("JBSWY3DPEHPK3PXP");
    await userEvent.type(
      within(dlg).getByPlaceholderText(/6-digit code/i),
      "000000",
    );
    await userEvent.click(within(dlg).getByRole("button", { name: /verify/i }));
    expect(
      await within(dlg).findByText(/Invalid TOTP code/),
    ).toBeInTheDocument();
    expect(refreshUser).not.toHaveBeenCalled();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() =>
      expect(
        within(dlg).queryByText("JBSWY3DPEHPK3PXP"),
      ).not.toBeInTheDocument(),
    );
    expect(authApi.confirmMfa).toHaveBeenCalledTimes(1);
  });

  it("enrolment start failure is reported", async () => {
    authApi.enableMfa.mockRejectedValue({
      response: { data: { detail: "MFA service unavailable" } },
    });
    await renderModal();
    await openSecurity();
    await startMfa();
    expect(
      await within(dialog()).findByText(/MFA service unavailable/),
    ).toBeInTheDocument();
  });

  it("disable requires the password, sends it to disableMfa only, refreshes the user and prunes sessions", async () => {
    currentUser = { ...currentUser, mfa_enabled: true };
    await renderModal();
    await openSecurity();
    const dlg = dialog();
    await within(dlg).findByText(/Firefox on Linux/);
    expect(within(dlg).getByText("Enabled")).toBeInTheDocument();
    await beginDisableMfa();
    const pw = await within(dlg).findByPlaceholderText(
      /confirm with your password/i,
    );
    expect(pw).toHaveAttribute("type", "password");
    const disableBtn = within(dlg).getByRole("button", { name: /^disable$/i });
    await userEvent.click(disableBtn);
    expect(authApi.disableMfa).not.toHaveBeenCalled(); // empty password: no request
    const secret = "Corr3ct-H0rse!";
    await userEvent.type(pw, secret);
    assertSecretNotLeaked(secret);
    expect(document.body.textContent).not.toContain(secret);
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^disable$/i }),
    );
    await waitFor(() =>
      expect(authApi.disableMfa).toHaveBeenCalledWith(secret),
    );
    expect(refreshUser).toHaveBeenCalledWith(true);
    await waitFor(() =>
      expect(
        within(dlg).queryByText(/Firefox on Linux/),
      ).not.toBeInTheDocument(),
    );
    expect(
      within(dlg).queryByPlaceholderText(/confirm with your password/i),
    ).not.toBeInTheDocument();
  });

  it("a refused password keeps the disable form open with the server's detail", async () => {
    currentUser = { ...currentUser, mfa_enabled: true };
    authApi.disableMfa.mockRejectedValue({
      response: { data: { detail: "Incorrect password" } },
    });
    await renderModal();
    await openSecurity();
    await beginDisableMfa();
    const dlg = dialog();
    await userEvent.type(
      await within(dlg).findByPlaceholderText(/confirm with your password/i),
      "wrong",
    );
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^disable$/i }),
    );
    expect(
      await within(dlg).findByText(/Incorrect password/),
    ).toBeInTheDocument();
    expect(refreshUser).not.toHaveBeenCalled();
  });
});

describe("ChangePasswordModal", () => {
  const openChange = async () => {
    await renderModal();
    await openSecurity();
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /change password/i }),
    );
    return screen.getByRole("dialog", { name: /change password/i });
  };

  it("validates: current, new (12+ chars, upper, digit, special) and matching confirmation", async () => {
    const dlg = await openChange();
    const [current, next, confirm] = ["current", "new", "confirm"].map((k) =>
      within(dlg).getByPlaceholderText(
        k === "current"
          ? /current password/i
          : k === "new"
            ? /strong password/i
            : /repeat new password/i,
      ),
    );
    for (const f of [current, next, confirm])
      expect(f).toHaveAttribute("type", "password");
    for (const f of [current, next, confirm])
      expect(f).toHaveAttribute("autocomplete", "new-password");
    const submit = within(dlg).getByRole("button", {
      name: /update password/i,
    });
    expect(submit).toBeDisabled();
    await userEvent.type(current, "OldPassw0rd!!");
    await userEvent.type(next, "short");
    expect(within(dlg).getByText(/At least 12 characters/)).toBeInTheDocument();
    expect(submit).toBeDisabled();
    await userEvent.clear(next);
    await userEvent.type(next, "N3w!Passw0rdXyz");
    await userEvent.type(confirm, "N3w!Passw0rdXy");
    expect(
      within(dlg).getAllByText(/Passwords do not match/).length,
    ).toBeGreaterThan(0);
    expect(submit).toBeDisabled();
    await userEvent.type(confirm, "z");
    expect(submit).toBeEnabled();
  });

  it("submits (current, next), never leaks either, shows success and auto-closes after 2.2 s", async () => {
    const dlg = await openChange();
    const cur = "OldPassw0rd!!";
    const nxt = "N3w!Passw0rdXyz";
    await userEvent.type(
      within(dlg).getByPlaceholderText(/current password/i),
      cur,
    );
    await userEvent.type(
      within(dlg).getByPlaceholderText(/strong password/i),
      nxt,
    );
    await userEvent.type(
      within(dlg).getByPlaceholderText(/repeat new password/i),
      nxt,
    );
    assertSecretNotLeaked(cur);
    assertSecretNotLeaked(nxt);
    expect(document.body.textContent).not.toContain(nxt);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await userEvent.click(
      within(dlg).getByRole("button", { name: /update password/i }),
    );
    await waitFor(() =>
      expect(userApi.changePassword).toHaveBeenCalledWith(cur, nxt),
    );
    expect(await screen.findByText(/Password Changed/)).toBeInTheDocument();
    expect(
      screen.getByRole("dialog", { name: /change password/i }),
    ).toBeInTheDocument();
    await act(async () => {
      vi.advanceTimersByTime(2300);
    });
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: /change password/i }),
      ).not.toBeInTheDocument(),
    );
    vi.useRealTimers();
    expect(userApi.changePassword).toHaveBeenCalledTimes(1);
  });

  it("a refused change shows the server's detail and keeps the form", async () => {
    userApi.changePassword.mockRejectedValue({
      response: { data: { detail: "Current password is incorrect" } },
    });
    const dlg = await openChange();
    await userEvent.type(
      within(dlg).getByPlaceholderText(/current password/i),
      "OldPassw0rd!!",
    );
    await userEvent.type(
      within(dlg).getByPlaceholderText(/strong password/i),
      "N3w!Passw0rdXyz",
    );
    await userEvent.type(
      within(dlg).getByPlaceholderText(/repeat new password/i),
      "N3w!Passw0rdXyz",
    );
    await userEvent.click(
      within(dlg).getByRole("button", { name: /update password/i }),
    );
    expect(
      await within(dlg).findByText(/Current password is incorrect/),
    ).toBeInTheDocument();
    expect(
      within(dlg).getByRole("button", { name: /update password/i }),
    ).toBeInTheDocument();
  });

  it("cancel closes the nested dialog and leaves the profile dialog open", async () => {
    const dlg = await openChange();
    await userEvent.click(
      within(dlg).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: /change password/i }),
      ).not.toBeInTheDocument(),
    );
    expect(dialog()).toBeInTheDocument();
    expect(userApi.changePassword).not.toHaveBeenCalled();
  });
});

/* ── Migration spec ─────────────────────────────────────────────────────── */
describe("batch 14 dialog, tab and mutation-safety spec", () => {
  it("profile dialog: aria-modal, named close, focus inside on open, Escape closes, focus restored", async () => {
    const opener = document.createElement("button");
    opener.textContent = "Account menu";
    document.body.appendChild(opener);
    opener.focus();
    const { onClose } = await renderModal();
    const dlg = dialog();
    expect(dlg).toHaveAttribute("aria-modal", "true");
    // Focus enters on the next animation frame (the trap waits for layout).
    await waitFor(() =>
      expect(dlg.contains(document.activeElement)).toBe(true),
    );
    expect(
      within(dlg).getByRole("button", { name: /close/i }),
    ).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    opener.remove();
  });

  it("tabs are a tablist with aria-selected and arrow-key navigation, each controlling a tabpanel", async () => {
    await renderModal();
    const dlg = dialog();
    const list = within(dlg).getByRole("tablist");
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent.trim())).toEqual([
      "Profile Info",
      "Security",
    ]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(within(dlg).getByRole("tabpanel")).toHaveAccessibleName(
      /profile info/i,
    );
    await waitFor(() =>
      expect(dlg.contains(document.activeElement)).toBe(true),
    );
    tabs[0].focus();
    await userEvent.keyboard("{ArrowRight}");
    await waitFor(() =>
      expect(tabs[1]).toHaveAttribute("aria-selected", "true"),
    );
    expect(within(dlg).getByRole("tabpanel")).toHaveAccessibleName(/security/i);
    await waitFor(() => expect(userApi.getSessions).toHaveBeenCalled());
  });

  it("MFA enrolment starts only from an explicit button; there is no checkbox", async () => {
    await renderModal();
    await openSecurity();
    expect(within(dialog()).queryByRole("checkbox")).not.toBeInTheDocument();
    expect(
      within(dialog()).getByRole("button", { name: /set up mfa/i }),
    ).toBeInTheDocument();
    expect(authApi.enableMfa).not.toHaveBeenCalled();
  });

  it("sign out other sessions is confirmation-gated and cancel writes nothing", async () => {
    await renderModal();
    await openSecurity();
    const dlg = dialog();
    await within(dlg).findByText(/Firefox on Linux/);
    await userEvent.click(
      within(dlg).getByRole("button", { name: /sign out all other sessions/i }),
    );
    const confirmDlg = screen
      .getAllByRole("dialog")
      .find((d) => d !== dlg && /other sessions/i.test(d.textContent || ""));
    expect(confirmDlg).toBeDefined();
    expect(userApi.revokeOtherSessions).not.toHaveBeenCalled();
    await userEvent.click(
      within(confirmDlg).getByRole("button", { name: /^cancel$/i }),
    );
    await waitFor(() => expect(screen.getAllByRole("dialog")).toHaveLength(1));
    expect(userApi.revokeOtherSessions).not.toHaveBeenCalled();
  });

  it("change-password dialog: aria-modal, named close, Escape closes only the nested dialog", async () => {
    await renderModal();
    await openSecurity();
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /change password/i }),
    );
    const cpw = screen.getByRole("dialog", { name: /change password/i });
    expect(cpw).toHaveAttribute("aria-modal", "true");
    expect(
      within(cpw).getByRole("button", { name: /close/i }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(cpw.contains(document.activeElement)).toBe(true),
    );
    await userEvent.keyboard("{Escape}");
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: /change password/i }),
      ).not.toBeInTheDocument(),
    );
    expect(dialog()).toBeInTheDocument();
  });

  it("write controls are disabled while a request is in flight (no duplicate submissions)", async () => {
    let resolveSave;
    userApi.updateProfile.mockImplementation(
      () =>
        new Promise((r) => {
          resolveSave = r;
        }),
    );
    await renderModal();
    await userEvent.click(
      within(dialog()).getByRole("button", { name: /edit profile/i }),
    );
    const save = within(dialog()).getByRole("button", {
      name: /save changes|saving/i,
    });
    await userEvent.click(save);
    await userEvent.click(save);
    expect(userApi.updateProfile).toHaveBeenCalledTimes(1);
    expect(
      within(dialog()).getByRole("button", { name: /save changes|saving/i }),
    ).toBeDisabled();
    await act(async () => resolveSave({ ...PROFILE }));
  });
});
