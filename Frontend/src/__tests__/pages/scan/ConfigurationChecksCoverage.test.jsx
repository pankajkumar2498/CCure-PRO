/**
 * ConfigurationChecks — Phase 6 API → UI coverage.
 *
 * The migration-era suite beside this one holds the read-only contract and the
 * presentation properties. This file holds what Phase 6 added, and its
 * fixtures are the live API's own responses.
 *
 * The measurement that drove the phase: the page named `windows` and `linux`
 * in a constant while `/capabilities` serves six queryable platforms. Against
 * the live catalogue that reached 106 of 155 checks — the 49 `database` checks
 * that are the whole of the Phase 7 database assessment were unreachable, and
 * every platform added afterwards would have been too.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import caps from "../../fixtures/configAuditCapabilities.real.json";
import checks from "../../fixtures/configAuditChecks.real.json";
import ConfigurationChecks from "../../../pages/scan/ConfigurationChecks";
import axiosInstance from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

const checkCalls = () =>
  axiosInstance.get.mock.calls.filter((c) => c[0] === "/config-audit/checks");

const mount = async () => {
  const r = render(
    <MemoryRouter>
      <ConfigurationChecks />
    </MemoryRouter>,
  );
  await waitFor(() => expect(checkCalls().length).toBeGreaterThan(0));
  return r;
};

beforeEach(() => {
  vi.clearAllMocks();
  axiosInstance.get.mockImplementation((url) => {
    if (url === "/config-audit/capabilities")
      return Promise.resolve({ data: caps });
    if (url === "/config-audit/checks")
      return Promise.resolve({ data: checks });
    if (url.startsWith("/config-audit/checks/"))
      return Promise.resolve({ data: checks[0] });
    return Promise.resolve({ data: {} });
  });
});

describe("every platform the API can be queried for is reachable", () => {
  it("offers all six, not the two that used to be hardcoded", async () => {
    await mount();
    await screen.findByText(checks[0].title);

    // Six keys on the live build: windows, linux, network_device, database,
    // container, cloud.
    expect(Object.keys(caps.supported)).toHaveLength(6);
    for (const name of Object.keys(caps.supported)) {
      expect(
        screen.getByRole("button", { name: new RegExp(`^${name}$`, "i") }),
      ).toBeInTheDocument();
    }
  });

  it("reaches the database checks the old selector could not", async () => {
    await mount();
    await screen.findByText(checks[0].title);

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /^database$/i }));

    await waitFor(() =>
      expect(
        checkCalls().some((c) => c[1]?.params?.platform === "database"),
      ).toBe(true),
    );
  });

  it("does not offer `any`, which returns nothing", async () => {
    await mount();
    await screen.findByText(checks[0].title);
    // It is a targeting value on a check — "applies to every platform" — not
    // a platform to ask about, and the API answers it with zero rows.
    expect(caps.platforms).toContain("any");
    expect(screen.queryByRole("button", { name: /^any$/i })).toBeNull();
  });
});

describe("the server-side filters", () => {
  it("sends check_type", async () => {
    await mount();
    await screen.findByText(checks[0].title);

    await userEvent
      .setup()
      .selectOptions(screen.getByLabelText("Check type"), "registry");

    await waitFor(() =>
      expect(
        checkCalls().some((c) => c[1]?.params?.check_type === "registry"),
      ).toBe(true),
    );
  });

  it("sends domain, with options taken from the catalogue rather than invented", async () => {
    await mount();
    await screen.findByText(checks[0].title);

    const select = screen.getByLabelText("Domain");
    const options = [...select.querySelectorAll("option")]
      .map((o) => o.value)
      .filter(Boolean);
    // The API serves no domain vocabulary, so these come from the unfiltered
    // catalogue the page has already loaded.
    expect(options.sort()).toEqual(
      [...new Set(checks.map((c) => c.domain))].sort(),
    );

    await userEvent.setup().selectOptions(select, options[0]);
    await waitFor(() =>
      expect(
        checkCalls().some((c) => c[1]?.params?.domain === options[0]),
      ).toBe(true),
    );
  });

  it("keeps the domain options stable once a filter narrows the results", async () => {
    /* Reading them back from a filtered response would leave the select
       offering only the value already selected. */
    await mount();
    await screen.findByText(checks[0].title);
    const before = [
      ...screen.getByLabelText("Domain").querySelectorAll("option"),
    ].length;

    axiosInstance.get.mockImplementation((url) =>
      url === "/config-audit/capabilities"
        ? Promise.resolve({ data: caps })
        : Promise.resolve({ data: [checks[0]] }),
    );
    await userEvent
      .setup()
      .selectOptions(screen.getByLabelText("Check type"), "registry");

    await waitFor(() =>
      expect(
        [...screen.getByLabelText("Domain").querySelectorAll("option")].length,
      ).toBe(before),
    );
  });

  it("filters the loaded rows by search without asking the API", async () => {
    await mount();
    await screen.findByText(checks[0].title);
    const before = checkCalls().length;

    await userEvent
      .setup()
      .type(screen.getByLabelText("Search"), "zzzznomatch");

    expect(
      await screen.findByText(/No check matches this search/i),
    ).toBeInTheDocument();
    // The endpoint has no search parameter, and the hint says so.
    expect(checkCalls().length).toBe(before);
    expect(
      screen.getByText(/the API has no search parameter/i),
    ).toBeInTheDocument();
  });
});

describe("fields the row used to drop", () => {
  it("shows the domain and the tags", async () => {
    const user = userEvent.setup();
    await mount();
    const title = await screen.findByText(checks[0].title);
    await user.click(title.closest("button"));

    // "Domain" is also the filter's label, so this is scoped to the detail
    // list's own term.
    expect(
      [...document.querySelectorAll(".cfg-dl dt")].map((el) => el.textContent),
    ).toContain("Domain");
    expect(screen.getAllByText(checks[0].domain).length).toBeGreaterThan(0);
    for (const tag of checks[0].tags) {
      expect(screen.getAllByText(tag).length).toBeGreaterThan(0);
    }
  });

  it("states whether a check disturbs the host", async () => {
    const user = userEvent.setup();
    await mount();
    const title = await screen.findByText(checks[0].title);
    await user.click(title.closest("button"));

    /* Every shipped check is non-intrusive today, so a badge alone would never
       appear and the field would be invisible. On an OT segment this is the
       difference between an audit and an outage, so it is stated either way. */
    expect(screen.getByText("Disturbs the host")).toBeInTheDocument();
    expect(screen.getByText("No")).toBeInTheDocument();
    expect(checks[0].intrusive).toBe(false);
  });

  it("badges an intrusive check in the row, not only in the detail", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/config-audit/capabilities"
        ? Promise.resolve({ data: caps })
        : Promise.resolve({ data: [{ ...checks[0], intrusive: true }] }),
    );
    await mount();
    await screen.findByText(checks[0].title);
    expect(screen.getByText("Intrusive")).toBeInTheDocument();
  });
});

describe("an empty catalogue says which kind of empty it is", () => {
  it("names a platform this build has no collector for", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/config-audit/capabilities"
        ? Promise.resolve({ data: caps })
        : Promise.resolve({ data: [] }),
    );
    await mount();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /^cloud$/i }));

    // `cloud` is declared in the vocabulary with an empty collector list, so
    // this is a statement about the product rather than about the content.
    expect(caps.supported.cloud).toEqual([]);
    expect(
      await screen.findByText(/no collector for cloud/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/reports an error rather than a verdict/i),
    ).toBeInTheDocument();
  });
});

describe("the capability report", () => {
  it("shows the whole matrix when no platform is selected", async () => {
    await mount();
    await screen.findByText(checks[0].title);
    const banner = document.querySelector(".cfg-capability");
    for (const name of Object.keys(caps.supported)) {
      expect(within(banner).getAllByText(name).length).toBeGreaterThan(0);
    }
    // A platform with no collector is named as such rather than left blank.
    expect(
      within(banner).getAllByText(/no collector in this build/i).length,
    ).toBeGreaterThan(0);
  });

  it("still names the check types this build cannot execute", async () => {
    await mount();
    await screen.findByText(checks[0].title);
    expect(screen.getByText(/Not yet implemented/i)).toBeInTheDocument();
    for (const t of caps.declared_without_collector) {
      expect(screen.getAllByText(new RegExp(t)).length).toBeGreaterThan(0);
    }
  });
});

describe("looking a check up by id", () => {
  it("fetches it from the API rather than searching the loaded page", async () => {
    await mount();
    await screen.findByText(checks[0].title);

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Check id"), "ccure.win.uac.enabled");
    await user.click(screen.getByRole("button", { name: /look up/i }));

    await waitFor(() =>
      expect(
        axiosInstance.get.mock.calls.some(
          ([u]) => u === "/config-audit/checks/ccure.win.uac.enabled",
        ),
      ).toBe(true),
    );
  });

  it("says plainly when there is no such check", async () => {
    axiosInstance.get.mockImplementation((url) => {
      if (url === "/config-audit/capabilities")
        return Promise.resolve({ data: caps });
      if (url === "/config-audit/checks")
        return Promise.resolve({ data: checks });
      return Promise.reject({
        response: { status: 404, data: { message: "Check not found" } },
      });
    });
    await mount();
    await screen.findByText(checks[0].title);

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Check id"), "no.such.check");
    await user.click(screen.getByRole("button", { name: /look up/i }));

    expect(await screen.findByText("Check not found")).toBeInTheDocument();
  });
});

describe("the read-only contract still holds", () => {
  it("issues no mutation, with every new control operated", async () => {
    const user = userEvent.setup();
    const { container } = await mount();
    await screen.findByText(checks[0].title);

    await user.type(screen.getByLabelText("Check id"), "ccure.win.uac.enabled");
    await user.type(screen.getByLabelText("Search"), "uac");
    for (const btn of [...container.querySelectorAll("button")]) {
      await user.click(btn);
    }

    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });
});
