/**
 * OrganizationForm + AuditLogDetailsModal — Checkpoint 3C batch 13.
 *
 * Both are legacy children under pages migrated in batch 5 and batch 10,
 * which stubbed them out of scope. Written against the components BEFORE
 * migration; every assertion holds on both sides except the accessibility
 * block at the end, which is the migration spec.
 *
 * ── OrganizationForm ────────────────────────────────────────────────────────
 *   * the create payload: name, slug, plan, max_assets and max_users as
 *     NUMBERS, and the optional admin_* provisioning block — including a
 *     password that reaches the payload and nothing else;
 *   * edit mode: prefilled, `is_active` only when `showStatus`;
 *   * submit disabled until valid; availability checks debounced.
 *
 * ── AuditLogDetailsModal ────────────────────────────────────────────────────
 *   * a dialog named "Audit log details" carrying the event's facts;
 *   * `password_hash` and `password` values are masked;
 *   * old → new changes are rendered as a pair;
 *   * Close and Escape both call onClose.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import OrganizationForm from "@audit/components/admin/OrganizationForm";
import AuditLogDetailsModal from "@audit/components/admin/AuditLogDetailsModal";
import { checkUsername, checkEmail } from "@shell/api/auth";

vi.mock("@shell/api/auth", () => ({
  checkUsername: vi.fn(),
  checkEmail: vi.fn(),
}));

const assertSecretNotLeaked = (secret) => {
  expect(document.body.textContent).not.toContain(secret);
  for (const el of document.body.querySelectorAll("*")) {
    for (const attr of el.attributes) {
      if (attr.name === "value" && el.getAttribute("type") === "password")
        continue;
      expect(
        attr.value,
        `${el.tagName}[${attr.name}] carries the password`,
      ).not.toContain(secret);
    }
  }
};

/* The parent page always passes a stable object; the default `{}` parameter
   is a new object per render and would reset the form on every keystroke. */
const EMPTY = {};

beforeEach(() => {
  vi.clearAllMocks();
  checkUsername.mockResolvedValue({ available: true });
  checkEmail.mockResolvedValue({ available: true });
});

describe("OrganizationForm — create", () => {
  it("submit is disabled until name (3+) and slug (2+) are set; numbers are coerced", async () => {
    const onSubmit = vi.fn();
    render(
      <OrganizationForm
        mode="create"
        organization={EMPTY}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    );
    const submit = screen.getByRole("button", { name: /create organization/i });
    expect(submit).toBeDisabled();
    await userEvent.type(
      screen.getByLabelText(/organization name/i),
      "Acme Security",
    );
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/^url/i), "acme");
    expect(submit).toBeEnabled();
    await userEvent.selectOptions(
      screen.getByLabelText(/subscription plan/i),
      "business",
    );
    await userEvent.clear(screen.getByLabelText(/max assets/i));
    await userEvent.type(screen.getByLabelText(/max assets/i), "900");
    await userEvent.clear(screen.getByLabelText(/max users/i));
    await userEvent.type(screen.getByLabelText(/max users/i), "40");
    await userEvent.click(submit);
    expect(onSubmit).toHaveBeenCalledWith({
      name: "Acme Security",
      slug: "acme",
      plan: "business",
      max_assets: 900,
      max_users: 40,
    });
  });

  it("no status field unless showStatus; is_active is included only then", async () => {
    const onSubmit = vi.fn();
    const { unmount } = render(
      <OrganizationForm
        mode="create"
        organization={EMPTY}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    );
    expect(screen.queryByLabelText(/^status/i)).not.toBeInTheDocument();
    unmount();
    render(
      <OrganizationForm
        mode="edit"
        showStatus
        organization={{
          id: 7,
          name: "Acme Corp",
          slug: "acme",
          plan: "enterprise",
          max_assets: 5000,
          max_users: 100,
          is_active: true,
        }}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    );
    await userEvent.selectOptions(
      screen.getByLabelText(/^status/i),
      "inactive",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /save changes/i }),
    );
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({ id: 7, is_active: false, max_assets: 5000 }),
    );
  });

  it("admin provisioning: the block is optional, validated as a unit, and the password reaches the payload only", async () => {
    const onSubmit = vi.fn();
    render(
      <OrganizationForm
        mode="create"
        organization={EMPTY}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    );
    await userEvent.type(
      screen.getByLabelText(/organization name/i),
      "Acme Security",
    );
    await userEvent.type(screen.getByLabelText(/^url/i), "acme");
    const submit = screen.getByRole("button", { name: /create organization/i });

    await userEvent.type(screen.getByLabelText(/admin username/i), "ad");
    expect(submit).toBeDisabled(); // a partial admin block is invalid
    await userEvent.type(screen.getByLabelText(/admin username/i), "min");
    await userEvent.type(
      screen.getByLabelText(/admin email/i),
      "admin@acme.test",
    );
    await userEvent.type(screen.getByLabelText(/full name/i), "Ada Admin");
    const pw = screen.getByLabelText(/^password/i);
    expect(pw).toHaveAttribute("type", "password");
    const secret = "S3cret!Admin#Pw";
    await userEvent.type(pw, secret);
    assertSecretNotLeaked(secret);
    expect(submit).toBeEnabled();
    await userEvent.click(submit);
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        admin_username: "admin",
        admin_email: "admin@acme.test",
        admin_full_name: "Ada Admin",
        admin_password: secret,
      }),
    );
  });

  it("availability checks are debounced and a taken username blocks submit", async () => {
    checkUsername.mockResolvedValue({ available: false });
    const onSubmit = vi.fn();
    render(
      <OrganizationForm
        mode="create"
        organization={EMPTY}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    );
    await userEvent.type(
      screen.getByLabelText(/organization name/i),
      "Acme Security",
    );
    await userEvent.type(screen.getByLabelText(/^url/i), "acme");
    await userEvent.type(screen.getByLabelText(/admin username/i), "root");
    await userEvent.type(
      screen.getByLabelText(/admin email/i),
      "root@acme.test",
    );
    await userEvent.type(
      screen.getByLabelText(/^password/i),
      "S3cret!Admin#Pw",
    );
    await waitFor(() => expect(checkUsername).toHaveBeenCalledWith("root"), {
      timeout: 2000,
    });
    expect(
      await screen.findByText(/username is already taken/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /create organization/i }),
    ).toBeDisabled();
  });

  it("edit mode has no admin provisioning block and cancel does not submit", async () => {
    const onSubmit = vi.fn();
    const onCancel = vi.fn();
    render(
      <OrganizationForm
        mode="edit"
        organization={{
          id: 7,
          name: "Acme Corp",
          slug: "acme",
          plan: "enterprise",
          max_assets: 5000,
          max_users: 100,
        }}
        onSubmit={onSubmit}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByLabelText(/organization name/i)).toHaveValue(
      "Acme Corp",
    );
    expect(screen.queryByLabelText(/admin username/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^password/i)).not.toBeInTheDocument();
    expect(
      screen.getByText(/Changing the URL will affect/),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
    expect(onCancel).toHaveBeenCalled();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

const LOG = {
  id: "evt-1",
  action: "user.update",
  user: "alice",
  user_email: "alice@example.test",
  timestamp: "2026-09-11T08:00:00Z",
  target: "user:10",
  severity: "high",
  status: "success",
  request_id: "req-abc",
  session_id: 12,
  ip_address: "10.180.6.20",
  timezone: "Asia/Kolkata",
  user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537.36 Edg/120",
  details: {
    is_active: { old: true, new: false },
    password_hash: { old: "$argon2id$abc", new: "$argon2id$def" },
    full_name: "Alice A.",
  },
};

describe("AuditLogDetailsModal", () => {
  it("renders nothing when closed or without a log", () => {
    const { container, rerender } = render(
      <AuditLogDetailsModal isOpen={false} log={LOG} onClose={() => {}} />,
    );
    expect(container).toBeEmptyDOMElement();
    rerender(<AuditLogDetailsModal isOpen log={null} onClose={() => {}} />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("is a named dialog carrying the event's facts, with the password hash masked", () => {
    render(<AuditLogDetailsModal isOpen log={LOG} onClose={() => {}} />);
    const dlg = screen.getByRole("dialog");
    expect(dlg).toHaveAccessibleName(/audit log details/i);
    expect(within(dlg).getByText("evt-1")).toBeInTheDocument();
    expect(within(dlg).getByText("user.update")).toBeInTheDocument();
    expect(within(dlg).getByText("req-abc")).toBeInTheDocument();
    expect(within(dlg).getByText("10.180.6.20")).toBeInTheDocument();
    expect(within(dlg).getByText("Edge")).toBeInTheDocument();
    expect(within(dlg).getByText("Windows 10/11")).toBeInTheDocument();
    expect(within(dlg).getByText(/^high$/i)).toBeInTheDocument();
    expect(within(dlg).getByText("SUCCESS")).toBeInTheDocument();
    expect(within(dlg).getByText("Account Status")).toBeInTheDocument();
    expect(within(dlg).getByText("Enabled ➔ Disabled")).toBeInTheDocument();
    expect(within(dlg).getByText("Password")).toBeInTheDocument();
    expect(within(dlg).getByText("•••••••• ➔ ••••••••")).toBeInTheDocument();
    expect(dlg.textContent).not.toContain("argon2");
    expect(within(dlg).getByText("Alice A.")).toBeInTheDocument();
  });

  it("says so when no changes were recorded, and flags a still-loading detail", () => {
    render(
      <AuditLogDetailsModal
        isOpen
        loading
        log={{ ...LOG, details: {} }}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText(/No changes recorded/)).toBeInTheDocument();
    expect(screen.getByText(/Loading full event details/)).toBeInTheDocument();
  });

  it("Close and Escape both call onClose", async () => {
    const onClose = vi.fn();
    render(<AuditLogDetailsModal isOpen log={LOG} onClose={onClose} />);
    // The dialog's own close control and the footer Close both exist; the
    // footer one is the last in DOM order on both sides of the migration.
    await userEvent.click(
      screen.getAllByRole("button", { name: /^close$/i }).at(-1),
    );
    expect(onClose).toHaveBeenCalledTimes(1);
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});

/* ── Migration spec ────────────────────────────────────────────────────────── */
describe("batch 13 accessibility spec", () => {
  it("OrganizationForm: the availability error is announced, and every control is labelled", async () => {
    checkUsername.mockResolvedValue({ available: false });
    render(
      <OrganizationForm
        mode="create"
        organization={EMPTY}
        onSubmit={() => {}}
        onCancel={() => {}}
      />,
    );
    await userEvent.type(screen.getByLabelText(/admin username/i), "root");
    const err = await screen.findByText(/username is already taken/i);
    expect(err).toHaveAttribute("role", "alert");
    for (const el of document.querySelectorAll("input, select")) {
      expect(el, `${el.id || el.name} is unlabelled`).toHaveAccessibleName();
    }
  });

  it("AuditLogDetailsModal: the changes table is captioned and its headers scoped", () => {
    render(<AuditLogDetailsModal isOpen log={LOG} onClose={() => {}} />);
    const table = screen.getByRole("table");
    expect(table.querySelector("caption")).not.toBeNull();
    for (const th of table.querySelectorAll("thead th"))
      expect(th).toHaveAttribute("scope", "col");
    expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
  });
});
