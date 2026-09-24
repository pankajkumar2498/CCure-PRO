/**
 * The rule validator.
 *
 * Every fixture here is a response captured from the running API. Three of
 * them exist because the obvious implementation gets them backwards:
 *
 *   * `valid: false` arrives as HTTP 200. It is the answer to the question
 *     that was asked, not a failed request, and must not be rendered through
 *     the error path.
 *   * a rule whose check type has no collector is still `valid: true`, with a
 *     warning. Authoring content ahead of its collector is legitimate, so
 *     treating the warning as a refusal would block it.
 *   * `check_definition` is returned only when the rule validates.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import caps from "../../fixtures/configAuditCapabilities.real.json";
import ok from "../../fixtures/configAuditValidateOk.real.json";
import warned from "../../fixtures/configAuditValidateWarning.real.json";
import bad from "../../fixtures/configAuditValidateInvalid.real.json";
import ConfigurationRuleValidator from "../../../pages/scan/ConfigurationRuleValidator";
import axiosInstance from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn() },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

const mount = async () => {
  const r = render(
    <MemoryRouter>
      <ConfigurationRuleValidator />
    </MemoryRouter>,
  );
  await screen.findByLabelText("Check type");
  return r;
};

const validate = () => screen.getByRole("button", { name: /^validate$/i });

beforeEach(() => {
  vi.clearAllMocks();
  axiosInstance.get.mockResolvedValue({ data: caps });
});

describe("the vocabulary is fetched, never hardcoded", () => {
  it("offers every check type, operator, platform and absence policy the API declares", async () => {
    await mount();

    const optionsOf = (label) =>
      [...screen.getByLabelText(label).querySelectorAll("option")].map(
        (o) => o.value,
      );

    expect(optionsOf("Check type")).toEqual(caps.check_types);
    expect(optionsOf("Operator")).toEqual(caps.operators);
    expect(optionsOf("If the item is absent")).toEqual(caps.absence_policies);
    // The queryable platforms, which is `supported`'s keys — not `platforms`,
    // which also carries the targeting value `any`.
    expect(optionsOf("Platform")).toEqual(Object.keys(caps.supported));
  });

  it("says so when the vocabulary could not be read", async () => {
    axiosInstance.get.mockRejectedValue({
      response: { data: { message: "Forbidden" } },
    });
    render(
      <MemoryRouter>
        <ConfigurationRuleValidator />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText(/Forbidden/)).toBeInTheDocument(),
    );
  });
});

describe("what the validator answers", () => {
  it("reports a well-formed rule and shows the definition it would store", async () => {
    axiosInstance.post.mockResolvedValue({ data: ok });
    await mount();
    await userEvent.setup().click(validate());

    await screen.findByText(/well-formed and the engine can build it/i);
    expect(
      screen.getByText(/The definition this rule would store/),
    ).toBeInTheDocument();
    // The stored JSONB, verbatim from the API.
    expect(screen.getByText(/"config_check": true/)).toBeInTheDocument();
  });

  it("treats valid:false as an answer, not as a failed request", async () => {
    axiosInstance.post.mockResolvedValue({ data: bad });
    await mount();
    await userEvent.setup().click(validate());

    await screen.findByText(/not executable as written/i);
    // The backend's own sentence, not a generic failure.
    expect(
      screen.getByText(/not a valid regular expression/i),
    ).toBeInTheDocument();
    // Nothing is offered as the stored definition, because none was returned.
    expect(
      screen.queryByText(/The definition this rule would store/),
    ).toBeNull();
  });

  it("keeps a warning from reading as a refusal", async () => {
    // The real case: no collector for this check type in this build, and the
    // rule is still valid.
    expect(warned.valid).toBe(true);
    expect(warned.warnings.length).toBeGreaterThan(0);

    axiosInstance.post.mockResolvedValue({ data: warned });
    await mount();
    await userEvent.setup().click(validate());

    await screen.findByText(/well-formed and the engine can build it/i);
    expect(screen.getByText("Warnings")).toBeInTheDocument();
    expect(
      screen.getByText(/would report an error rather than a verdict/i),
    ).toBeInTheDocument();
    expect(screen.queryByText("Errors")).toBeNull();
  });
});

describe("the request", () => {
  it("sends the platform as a list and the collect block as parsed JSON", async () => {
    axiosInstance.post.mockResolvedValue({ data: ok });
    await mount();
    await userEvent.setup().click(validate());

    await waitFor(() => expect(axiosInstance.post).toHaveBeenCalled());
    const [url, body] = axiosInstance.post.mock.calls[0];
    expect(url).toBe("/config-audit/validate");
    expect(body.platforms).toEqual(["windows"]);
    expect(body.collect).toMatchObject({ hive: "HKLM", value: "EnableLUA" });
  });

  it("reads a numeric expected as a number", async () => {
    /* `equals 1` and `equals "1"` are different comparisons and the API types
       `expected` as Any, so the distinction has to survive the form. */
    axiosInstance.post.mockResolvedValue({ data: ok });
    await mount();
    await userEvent.setup().click(validate());
    expect(axiosInstance.post.mock.calls[0][1].expected).toBe(1);
  });

  it("keeps a non-JSON expected as text", async () => {
    axiosInstance.post.mockResolvedValue({ data: ok });
    await mount();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Expected"));
    await user.type(screen.getByLabelText("Expected"), "^PermitRootLogin no");
    await user.click(validate());
    expect(axiosInstance.post.mock.calls[0][1].expected).toBe(
      "^PermitRootLogin no",
    );
  });

  it("refuses to send unparseable JSON, and says it is a parse error", async () => {
    await mount();
    const user = userEvent.setup();
    const area = screen.getByLabelText(/What to collect/i);
    await user.clear(area);
    await user.type(area, "{{not json");
    await user.click(validate());

    expect(await screen.findByText(/not valid JSON/i)).toBeInTheDocument();
    // A parse failure here is not a verdict about the rule.
    expect(screen.queryByText(/not executable as written/i)).toBeNull();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });

  it("refuses a collect block that is not an object", async () => {
    await mount();
    const user = userEvent.setup();
    const area = screen.getByLabelText(/What to collect/i);
    await user.clear(area);
    // A bare number parses as JSON and is not an object, which is the branch
    // under test. (`[` is a key descriptor to user-event, so an array literal
    // cannot simply be typed.)
    await user.type(area, "123");
    await user.click(validate());

    expect(
      await screen.findByText(/collect must be a JSON object/i),
    ).toBeInTheDocument();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });
});

describe("the capability gap is named before the request, not only after", () => {
  it("warns when the chosen platform has no collector for the chosen type", async () => {
    await mount();
    const user = userEvent.setup();
    // `database` supports only `database_query` on the live build.
    await user.selectOptions(screen.getByLabelText("Platform"), "database");
    await user.selectOptions(screen.getByLabelText("Check type"), "registry");

    expect(
      await screen.findByText(/has no collector for/i),
    ).toBeInTheDocument();
  });

  it("stays quiet when the combination is supported", async () => {
    await mount();
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText("Platform"), "windows");
    await user.selectOptions(screen.getByLabelText("Check type"), "registry");
    expect(screen.queryByText(/has no collector for/i)).toBeNull();
  });
});

describe("failure", () => {
  it("separates a transport failure from a rule that did not validate", async () => {
    axiosInstance.post.mockRejectedValue({
      response: { status: 429, data: { message: "Rate limit exceeded." } },
    });
    await mount();
    await userEvent.setup().click(validate());

    await screen.findByText("Rate limit exceeded.");
    expect(screen.queryByText(/not executable as written/i)).toBeNull();
  });
});
