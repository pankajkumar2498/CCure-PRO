import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import RegistrationSettingsDialog from "@shell/admin/components/RegistrationSettingsDialog";
import AuthContext from "@shell/auth/AuthContext";
import * as api from "@shell/api/registrationSettings";
import { payload } from "../../../fixtures/authorization";

vi.mock("@shell/api/registrationSettings", () => ({
  getRegistrationSettings: vi.fn(),
  updateRegistrationSettings: vi.fn(),
}));

const base = {
  self_registration_enabled: false,
  deployment_default: false,
  administrator_approval_required: true,
  source: "deployment",
  revision: 0,
};
const saved = {
  ...base,
  self_registration_enabled: true,
  source: "administrator",
  revision: 1,
};
const keys = ["platform.registration.read", "platform.registration.manage"];
const mount = (grants = keys) =>
  render(
    <MemoryRouter>
      <AuthContext.Provider
        value={{
          user: {
            authorization: payload({ keys: grants }),
            username: "Superadmin",
          },
        }}
      >
        <RegistrationSettingsDialog onClose={() => {}} />
      </AuthContext.Provider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.resetAllMocks();
  api.getRegistrationSettings.mockResolvedValue(base);
  api.updateRegistrationSettings.mockResolvedValue(saved);
});

describe("Registration Settings", () => {
  it("does not display a policy or toggle before the configuration arrives", () => {
    api.getRegistrationSettings.mockReturnValue(new Promise(() => {}));
    mount();
    expect(
      screen.getByText("Loading registration settings…"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Disabled", { selector: "strong" }),
    ).not.toBeInTheDocument();
  });

  it("saves the requested value and revision, then shows the confirmed backend policy", async () => {
    const user = userEvent.setup();
    mount();
    const toggle = await screen.findByRole("checkbox", {
      name: "Allow self-registration",
    });
    await user.click(toggle);
    expect(
      screen.getByText("Disabled", { selector: "strong" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText("Self-registration enabled.");
    expect(api.updateRegistrationSettings).toHaveBeenCalledWith(
      { self_registration_enabled: true, revision: 0 },
      { reauthCode: undefined },
    );
    expect(
      screen.getByText("Enabled", { selector: "strong" }),
    ).toBeInTheDocument();
  });

  it("can disable a saved enabled policy", async () => {
    api.getRegistrationSettings.mockResolvedValue(saved);
    api.updateRegistrationSettings.mockResolvedValue({
      ...saved,
      self_registration_enabled: false,
      revision: 2,
    });
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText("Self-registration disabled.");
    expect(api.updateRegistrationSettings).toHaveBeenCalledWith(
      { self_registration_enabled: false, revision: 1 },
      { reauthCode: undefined },
    );
  });

  it("resets to the deployment default with an explicit null override", async () => {
    api.getRegistrationSettings.mockResolvedValue(saved);
    api.updateRegistrationSettings.mockResolvedValue({ ...base, revision: 2 });
    const user = userEvent.setup();
    mount();
    await user.click(
      await screen.findByRole("button", { name: "Use deployment default" }),
    );
    await screen.findByText("Now using the deployment default.");
    expect(api.updateRegistrationSettings).toHaveBeenCalledWith(
      { self_registration_enabled: null, revision: 1 },
      { reauthCode: undefined },
    );
    expect(
      screen.queryByRole("button", { name: "Use deployment default" }),
    ).not.toBeInTheDocument();
  });

  it("makes users without the manage permission read-only regardless of their name", async () => {
    mount(["platform.registration.read"]);
    expect(await screen.findByRole("checkbox")).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Save changes" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("You have read-only access to this policy."),
    ).toBeInTheDocument();
  });

  it.each([null, { ...base, self_registration_enabled: "false" }])(
    "treats malformed configuration as unavailable and allows retry",
    async (value) => {
      api.getRegistrationSettings.mockResolvedValueOnce(value);
      const user = userEvent.setup();
      mount();
      await screen.findByText(/Registration settings are unavailable/);
      expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Reload settings" }));
      expect(await screen.findByRole("checkbox")).not.toBeChecked();
    },
  );

  it("keeps the confirmed policy when saving fails and reports a stale revision", async () => {
    api.updateRegistrationSettings.mockRejectedValue({
      response: {
        status: 409,
        data: {
          detail:
            "Registration settings changed. Reload them before saving again.",
        },
      },
    });
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText(/Registration settings changed/);
    expect(
      screen.getByText("Disabled", { selector: "strong" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Self-registration enabled."),
    ).not.toBeInTheDocument();
  });

  it("waits for the authenticator and repeats exactly the pending request", async () => {
    api.updateRegistrationSettings.mockRejectedValueOnce({
      response: { status: 403, data: { detail: { code: "reauth_required" } } },
    });
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByRole("dialog", {
      name: "Confirm with your authenticator",
    });
    expect(screen.getByRole("checkbox", { hidden: true })).toBeDisabled();
    await user.type(screen.getByLabelText("Authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await screen.findByText("Self-registration enabled.");
    expect(api.updateRegistrationSettings).toHaveBeenLastCalledWith(
      { self_registration_enabled: true, revision: 0 },
      { reauthCode: "123456" },
    );
  });

  it("cancelling reauthentication leaves the saved policy unchanged", async () => {
    api.updateRegistrationSettings.mockRejectedValueOnce({
      response: { status: 403, data: { detail: { code: "reauth_required" } } },
    });
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByRole("dialog", {
      name: "Confirm with your authenticator",
    });
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", {
          name: "Confirm with your authenticator",
        }),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("dialog", { name: "Registration settings" }),
    ).toBeInTheDocument();
    expect(api.updateRegistrationSettings).toHaveBeenCalledTimes(1);
    expect(
      screen.getByText("Disabled", { selector: "strong" }),
    ).toBeInTheDocument();
  });
});
