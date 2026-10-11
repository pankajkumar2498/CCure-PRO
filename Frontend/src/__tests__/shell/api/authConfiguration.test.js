import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AxiosError } from "axios";
import axiosInstance, {
  authSession,
  publicAuthClient,
} from "@shell/api/axiosInstance";
import { isSelfRegistrationEnabled } from "@shell/api/auth";

const originalAdapter = publicAuthClient.defaults.adapter;
let adapter;
let logout;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  adapter = vi.fn();
  publicAuthClient.defaults.adapter = adapter;
  logout = vi.fn();
  window.addEventListener("auth:logout", logout);
});

afterEach(() => {
  publicAuthClient.defaults.adapter = originalAdapter;
  authSession.clear();
  window.removeEventListener("auth:logout", logout);
  vi.restoreAllMocks();
});

const reply = (data) =>
  adapter.mockResolvedValue({ status: 200, data, headers: {} });

describe("public registration configuration", () => {
  it.each([true, false])(
    "uses only the explicit boolean %s",
    async (enabled) => {
      reply({ self_registration_enabled: enabled });
      expect(await isSelfRegistrationEnabled()).toBe(enabled);
      expect(adapter.mock.calls[0][0].url).toBe("/auth/config");
    },
  );

  it.each([
    undefined,
    null,
    {},
    "<html>SPA fallback</html>",
    { self_registration_enabled: "true" },
    { self_registration_enabled: 1 },
    { available: true },
  ])("keeps malformed configuration unknown: %j", async (data) => {
    reply(data);
    expect(await isSelfRegistrationEnabled()).toBeNull();
  });

  it.each([401, 404, 429, 500, 503])(
    "keeps HTTP %s unknown without refreshing or logging out",
    async (status) => {
      authSession.setTokens({ access_token: "synthetic-expired-access" });
      localStorage.setItem("activeOrgId", "synthetic-stale-tenant");
      const sessionRequest = vi.spyOn(axiosInstance, "post");
      adapter.mockImplementation((config) =>
        Promise.reject(
          new AxiosError(
            "Synthetic HTTP error",
            "ERR_BAD_RESPONSE",
            config,
            null,
            { status, data: {}, headers: {}, config },
          ),
        ),
      );

      expect(await isSelfRegistrationEnabled()).toBeNull();
      const config = adapter.mock.calls[0][0];
      expect(config.headers.Authorization).toBeUndefined();
      expect(config.params).toBeUndefined();
      expect(config.withCredentials).toBe(false);
      expect(config.timeout).toBe(10000);
      expect(sessionRequest).not.toHaveBeenCalled();
      expect(logout).not.toHaveBeenCalled();
      expect(authSession.getAccessToken()).toBe("synthetic-expired-access");
      expect(localStorage.getItem("activeOrgId")).toBe(
        "synthetic-stale-tenant",
      );
    },
  );

  it.each(["ERR_NETWORK", "ECONNABORTED"])("keeps %s unknown", async (code) => {
    adapter.mockRejectedValue(
      new AxiosError("Synthetic transport failure", code),
    );
    expect(await isSelfRegistrationEnabled()).toBeNull();
  });

  it("does not persist a previous decision across requests", async () => {
    reply({ self_registration_enabled: true });
    expect(await isSelfRegistrationEnabled()).toBe(true);
    reply({ self_registration_enabled: false });
    expect(await isSelfRegistrationEnabled()).toBe(false);
    adapter.mockRejectedValue(new AxiosError("Synthetic network failure"));
    expect(await isSelfRegistrationEnabled()).toBeNull();
    expect(adapter).toHaveBeenCalledTimes(3);
  });
});
