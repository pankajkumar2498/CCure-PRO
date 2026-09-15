/**
 * ComplianceWorkspace (`/compliance`) — the ordinary writes: Marketplace
 * install and uninstall, and the Create Policy Baseline, Configure Rule
 * Parameters and Request Exception Waiver dialogs. Checkpoint 3C batch 27
 * baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 27 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Marketplace: an organisation admin or superadmin installs with one POST and
 * uninstalls with one POST after confirming; anyone else sees both disabled
 * with the reason. The three dialogs each send one request built from their
 * fields, close and re-read on success, and stay open with the API's detail on
 * failure. Nothing is sent by opening or closing a dialog.
 *
 * Only the axios instance, the shell and the signed-in user are replaced.
 * No Approvals, credential, remediation, attestation or evidence path is
 * exercised.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ComplianceWorkspace from "../../pages/ComplianceWorkspace";
import api from "../../api/axiosInstance";

vi.mock("../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let user;
vi.mock("../../context/AuthContext", () => ({
  useAuth: () => ({ user }),
}));

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const person = (roleName, id = 1) => ({
  id,
  username: `user-${id}`,
  role: { name: roleName, permissions: ["compliance:read"] },
});
const ANALYST = person("analyst");
const ORG_ADMIN = person("Org Admin", 2);
const SUPERADMIN = person("superadmin", 3);
const PERMISSION_HINT = "Requires Org Admin or Superadmin permission";

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const ISO = "cfw_iso27001_2022";
const NIST = "cfw_nist_csf_v2";
const MARKETPLACE = [
  {
    framework_id: ISO,
    name: "ISO/IEC 27001:2022",
    code: "ISO27001",
    version: "2022",
    controls_count: 93,
    is_installed: true,
  },
  {
    framework_id: "cfw_soc2_type2",
    name: "SOC 2 Type II",
    code: "SOC2",
    version: "2017",
    controls_count: 61,
    is_installed: false,
  },
];
const POLICIES = [
  {
    id: "pol-1",
    name: "ISO 27001 Linux baseline",
    target_platform: "linux",
    version_number: 3,
    rules_count: 2,
    status: "active",
  },
];
const RULES = [
  {
    id: "rule-1",
    control_number: "A.8.8",
    control_title: "Management of technical vulnerabilities",
    rule_name: "ccure.linux.sshd.permit_root_login",
    severity: "HIGH",
    evidence_source: "credentialed_config",
    check_definition: {
      key: "sshd.permit_root_login",
      operator: "equals",
      expected: "no",
    },
  },
  {
    id: "rule-2",
    control_number: "A.8.5",
    control_title: "Secure authentication",
    rule_name: "ccure.linux.auth.max_tries",
    severity: "MEDIUM",
    evidence_source: "credentialed_config",
    check_definition: {
      key: "sshd.max_auth_tries",
      operator: "lte",
      expected: 5,
    },
  },
];
const FINDINGS = [
  {
    id: "f-1",
    control_id: "A.8.8",
    control_title: "Management of technical vulnerabilities",
    severity: "HIGH",
    asset_id: "asset-1",
    asset_hostname: "web-01",
    asset_ip: "10.70.0.11",
    source: "credentialed",
    status: "fail",
  },
  {
    id: "f-3",
    control_id: "A.8.2",
    control_title: "Privileged access rights",
    rule_id: "rule-3",
    rule_name: "ccure.win.local_admins",
    asset_id: "asset-2",
    asset_ip: "10.70.0.12",
    source: "network",
    status: "pass",
    evidence: { observed: "2 local admins" },
  },
];
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const refusal = (detail) => ({
  response: { status: 403, data: { detail } },
  message: "Request failed with status code 403",
});

/* ── Harness ────────────────────────────────────────────────────────────── */
let writeReply;
let consoleError;
let confirmSpy;

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const mount = async () => {
  const view = render(<ComplianceWorkspace />);
  await flush();
  return view;
};
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);
const gets = () => api.get.mock.calls.map(([u]) => u);

const tabBar = () =>
  [...document.querySelectorAll("div")].find(
    (d) =>
      d.children.length === 8 &&
      /Approvals Queue/.test(d.textContent || "") &&
      /Marketplace/.test(d.textContent || ""),
  );
const openTab = async (label) => {
  const tab = [...tabBar().children].find(
    (c) => (c.textContent || "").trim() === label,
  );
  fireEvent.click(tab);
  await flush();
};
const frameworkSelect = () =>
  [...document.querySelectorAll("select")].find((s) =>
    [...s.options].some(
      (o) => o.value === "all" && o.textContent === "All Frameworks",
    ),
  );
const change = async (el, value) => {
  fireEvent.change(el, { target: { value } });
  await flush();
};
const click = async (el) => {
  fireEvent.click(el);
  await flush();
};
const dialog = (name) => screen.getByRole("dialog", { name });
const noDialog = () => expect(screen.queryByRole("dialog")).toBeNull();
const selectWith = (root, values) =>
  [...root.querySelectorAll("select")].find(
    (s) => [...s.options].map((o) => o.value).join(",") === values,
  );

// A framework's card: the element holding its name and its action button.
const cardOf = (name) => {
  let el = [...document.querySelectorAll("h1, h2, h3, h4")].find(
    (h) => (h.textContent || "").trim() === name,
  );
  while (el && !el.querySelector("button")) el = el.parentElement;
  return el;
};
const policyRow = () =>
  [...document.querySelectorAll("tbody tr")].find((r) =>
    (r.textContent || "").includes("ISO 27001 Linux baseline"),
  );
const openCreatePolicy = async () => {
  await openTab("Policies");
  await click(screen.getByRole("button", { name: /Create Baseline Policy/ }));
  return dialog("Create Policy Baseline");
};
const openConfigure = async (ruleIndex = 0) => {
  await openTab("Policies");
  const row = policyRow();
  await click(row.querySelector("[aria-expanded]") || row);
  await click(screen.getAllByRole("button", { name: "Configure" })[ruleIndex]);
  return dialog("Configure Rule Parameters");
};
const findingRow = (controlId) =>
  [...document.querySelectorAll("tbody tr")].find(
    (r) => (r.cells[0]?.textContent || "").trim() === controlId,
  );
const openFromFinding = async (controlId, button, title) => {
  await openTab("Findings");
  await click(
    within(findingRow(controlId)).getByRole("button", { name: button }),
  );
  return dialog(title);
};
const submitIn = async (root, name) => {
  await click(within(root).getByRole("button", { name }));
};

beforeEach(() => {
  user = ANALYST;
  writeReply = () => Promise.resolve({ data: {} });
  Element.prototype.scrollIntoView = vi.fn();
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url) => {
    if (url === "/compliance/marketplace")
      return Promise.resolve({ data: { data: MARKETPLACE } });
    if (url.startsWith("/compliance/summary"))
      return Promise.resolve({
        data: { score_pct: 70, weighted_score_pct: 60, kpis: {} },
      });
    if (/^\/compliance\/policies\/[^/?]+\/rules$/.test(url))
      return Promise.resolve({ data: { data: RULES } });
    if (url.startsWith("/compliance/policies"))
      return Promise.resolve({ data: { data: POLICIES } });
    if (url.startsWith("/compliance/findings"))
      return Promise.resolve({ data: { data: FINDINGS } });
    return Promise.resolve({ data: { data: [] } });
  });
  api.post.mockImplementation((...args) => writeReply(...args));
  api.put.mockImplementation((...args) => writeReply(...args));
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
  consoleError = vi.spyOn(console, "error");
});

afterEach(() => {
  cleanup();
  // Only the four ordinary writes are ever sent, and nothing is deleted or
  // patched. No credential, remediation, attestation or evidence path is read.
  expect(api.delete).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls)
    expect(url).toMatch(
      /^\/compliance\/(marketplace\/[a-z0-9_]+\/(install|uninstall)|policies|findings\/[a-z0-9-]+\/exception)$/,
    );
  for (const [url] of api.put.mock.calls)
    expect(url).toMatch(/^\/compliance\/rules\/[a-z0-9-]+$/);
  for (const url of gets())
    expect(url).not.toMatch(/credentials|evidence|remediations|reports/);
  confirmSpy.mockRestore();
  consoleError.mockRestore();
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace ordinary writes — contract", () => {
  describe("Marketplace", () => {
    it("opens by reading the marketplace and lists each framework with its action", async () => {
      await mount();
      const before = gets().length;
      await openTab("Marketplace");
      expect(gets().slice(before)).toEqual(["/compliance/marketplace"]);
      const iso = cardOf("ISO/IEC 27001:2022");
      expect(squash(iso)).toContain("Code: ISO27001 | Version: 2022");
      expect(squash(iso)).toContain("Total Requirements: 93");
      expect(squash(iso)).toMatch(/Installed/);
      expect(
        within(iso)
          .getAllByRole("button")
          .map((b) => squash(b)),
      ).toEqual(["Uninstall"]);
      const soc = cardOf("SOC 2 Type II");
      expect(squash(soc)).toContain("Code: SOC2 | Version: 2017");
      expect(squash(soc)).not.toMatch(/Installed/);
      expect(
        within(soc)
          .getAllByRole("button")
          .map((b) => squash(b)),
      ).toEqual(["Install"]);
    });

    it("anyone but an organisation admin or superadmin sees both actions disabled, with the reason, and sends nothing", async () => {
      await mount();
      await openTab("Marketplace");
      for (const [name, action] of [
        ["ISO/IEC 27001:2022", "Uninstall"],
        ["SOC 2 Type II", "Install"],
      ]) {
        const button = within(cardOf(name)).getByRole("button", {
          name: action,
        });
        expect(button).toBeDisabled();
        expect(button).toHaveAttribute("title", PERMISSION_HINT);
        await click(button);
      }
      expect(confirmSpy).not.toHaveBeenCalled();
      expect(api.post).not.toHaveBeenCalled();
    });

    it.each([
      ["an organisation admin", ORG_ADMIN],
      ["a superadmin", SUPERADMIN],
    ])(
      "%s installs with one POST, is told so, and the marketplace is read again quietly",
      async (_, who) => {
        user = who;
        await mount();
        await openTab("Marketplace");
        const install = within(cardOf("SOC 2 Type II")).getByRole("button", {
          name: "Install",
        });
        expect(install).toBeEnabled();
        expect(install.getAttribute("title") || "").toBe("");
        const before = gets().length;
        await click(install);
        expect(api.post.mock.calls).toEqual([
          ["/compliance/marketplace/cfw_soc2_type2/install"],
        ]);
        expect(bodyText()).toContain("Framework installed successfully.");
        expect(gets().slice(before)).toEqual(["/compliance/marketplace"]);
        expect(document.querySelector(".loading-bar")).toBeNull();
      },
    );

    it("a refused install reports the API's detail, or the error's message", async () => {
      user = ORG_ADMIN;
      writeReply = () => Promise.reject(refusal("Framework is parked"));
      await mount();
      await openTab("Marketplace");
      await click(
        within(cardOf("SOC 2 Type II")).getByRole("button", {
          name: "Install",
        }),
      );
      expect(bodyText()).toContain(
        "Failed to install framework: Framework is parked",
      );
      writeReply = () => Promise.reject(new Error("Network Error"));
      await click(
        within(cardOf("SOC 2 Type II")).getByRole("button", {
          name: "Install",
        }),
      );
      expect(bodyText()).toContain(
        "Failed to install framework: Network Error",
      );
    });

    it("uninstalling asks first, and declining sends nothing", async () => {
      user = ORG_ADMIN;
      confirmSpy.mockReturnValue(false);
      await mount();
      await openTab("Marketplace");
      await click(
        within(cardOf("ISO/IEC 27001:2022")).getByRole("button", {
          name: "Uninstall",
        }),
      );
      expect(confirmSpy).toHaveBeenCalledWith(
        "Are you sure you want to uninstall this compliance framework? This will hide its policies, findings, approvals, and dashboard averages.",
      );
      expect(api.post).not.toHaveBeenCalled();
    });

    it("confirming uninstall posts once and re-reads; a refusal reports its detail", async () => {
      user = ORG_ADMIN;
      await mount();
      await openTab("Marketplace");
      const before = gets().length;
      await click(
        within(cardOf("ISO/IEC 27001:2022")).getByRole("button", {
          name: "Uninstall",
        }),
      );
      expect(api.post.mock.calls).toEqual([
        [`/compliance/marketplace/${ISO}/uninstall`],
      ]);
      expect(bodyText()).toContain("Framework uninstalled successfully.");
      expect(gets().slice(before)).toEqual(["/compliance/marketplace"]);
      writeReply = () =>
        Promise.reject({ response: { data: { message: "Still in use" } } });
      await click(
        within(cardOf("ISO/IEC 27001:2022")).getByRole("button", {
          name: "Uninstall",
        }),
      );
      expect(bodyText()).toContain(
        "Failed to uninstall framework: Still in use",
      );
    });

    it("an install in flight leaves the button enabled", async () => {
      user = ORG_ADMIN;
      const pending = deferred();
      writeReply = () => pending.promise;
      await mount();
      await openTab("Marketplace");
      const install = within(cardOf("SOC 2 Type II")).getByRole("button", {
        name: "Install",
      });
      await click(install);
      expect(install).toBeEnabled();
      await act(async () => pending.resolve({ data: {} }));
      await flush();
    });
  });

  describe("Create Policy Baseline", () => {
    it("opens from the Policies header with its three fields, and opening or closing sends nothing", async () => {
      await mount();
      const box = await openCreatePolicy();
      const texts = box.querySelectorAll('input[type="text"]');
      expect(texts).toHaveLength(2);
      expect(texts[0]).toBeRequired();
      expect(texts[1]).toBeRequired();
      expect(texts[1]).toHaveAttribute(
        "placeholder",
        "crl_net_tls_001_v1, crl_auth_mfa_001_v1",
      );
      const platform = selectWith(box, "any,windows,linux");
      expect(platform.value).toBe("any");
      expect(
        within(box).getByRole("button", { name: "Publish Baseline" }),
      ).toHaveAttribute("type", "submit");
      await click(screen.getByRole("button", { name: "Close" }));
      noDialog();
      await openCreatePolicy();
      fireEvent.keyDown(document, { key: "Escape" });
      await flush();
      noDialog();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("publishing sends the name, platform and trimmed rule IDs for ISO 27001, closes, says so and re-reads", async () => {
      await mount();
      const box = await openCreatePolicy();
      const [name, rules] = box.querySelectorAll('input[type="text"]');
      await change(name, "Linux hardening");
      await change(selectWith(box, "any,windows,linux"), "linux");
      await change(rules, " crl_a , ,crl_b ");
      const before = gets().length;
      await submitIn(box, "Publish Baseline");
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/policies",
          {
            framework_id: ISO,
            name: "Linux hardening",
            target_platform: "linux",
            rule_ids: ["crl_a", "crl_b"],
          },
        ],
      ]);
      noDialog();
      expect(bodyText()).toContain("Policy baseline created successfully.");
      expect(gets().slice(before)).toEqual(["/compliance/policies"]);
    });

    it("with a framework chosen, the baseline is created for it", async () => {
      await mount();
      await openTab("Policies");
      await change(frameworkSelect(), NIST);
      await click(
        screen.getByRole("button", { name: /Create Baseline Policy/ }),
      );
      const box = dialog("Create Policy Baseline");
      const [name, rules] = box.querySelectorAll('input[type="text"]');
      await change(name, "CSF baseline");
      await change(rules, "crl_x");
      await submitIn(box, "Publish Baseline");
      expect(api.post.mock.calls[0][1]).toEqual({
        framework_id: NIST,
        name: "CSF baseline",
        target_platform: "any",
        rule_ids: ["crl_x"],
      });
    });

    it("a refused baseline stays open with the API's detail, and the button stays enabled while it is sent", async () => {
      const pending = deferred();
      writeReply = () => pending.promise;
      await mount();
      const box = await openCreatePolicy();
      const [name, rules] = box.querySelectorAll('input[type="text"]');
      await change(name, "Denied");
      await change(rules, "crl_a");
      await submitIn(box, "Publish Baseline");
      expect(
        within(box).getByRole("button", { name: "Publish Baseline" }),
      ).toBeEnabled();
      await act(async () =>
        pending.reject(refusal("Missing permission compliance:manage_rules")),
      );
      await flush();
      expect(bodyText()).toContain(
        "Failed to create policy: Missing permission compliance:manage_rules",
      );
      expect(dialog("Create Policy Baseline")).toBeInTheDocument();
    });
  });

  describe("Configure Rule Parameters", () => {
    it("Configure opens the dialog prefilled from the rule", async () => {
      await mount();
      const box = await openConfigure();
      expect(squash(box)).toContain(
        "Editing Rule: ccure.linux.sshd.permit_root_login",
      );
      expect(squash(box)).toContain(
        "Control: Management of technical vulnerabilities",
      );
      const severity = selectWith(box, "CRITICAL,HIGH,MEDIUM,LOW,INFO");
      expect(severity.value).toBe("HIGH");
      const expected = box.querySelector('input[type="text"]');
      expect(expected.value).toBe("no");
      expect(expected).toBeRequired();
      expect(squash(box)).toContain("Current evidence value is: {}");
      expect(api.put).not.toHaveBeenCalled();
    });

    it.each([
      ["CRITICAL", 10],
      ["HIGH", 7],
      ["MEDIUM", 5],
      ["LOW", 2],
      ["INFO", 0],
    ])(
      "saving with severity %s sends the edited definition, the lower-case severity and weight %i, closes and re-reads",
      async (level, weight) => {
        await mount();
        const box = await openConfigure();
        await change(selectWith(box, "CRITICAL,HIGH,MEDIUM,LOW,INFO"), level);
        await change(box.querySelector('input[type="text"]'), "yes");
        const before = gets().length;
        await submitIn(box, "Save Rule Configuration");
        expect(api.put.mock.calls).toEqual([
          [
            "/compliance/rules/rule-1",
            {
              check_definition: {
                key: "sshd.permit_root_login",
                operator: "equals",
                expected: "yes",
              },
              severity: level.toLowerCase(),
              severity_weight: weight,
            },
          ],
        ]);
        noDialog();
        expect(bodyText()).toContain(
          "Rule updated successfully! Click 'Run Compliance Scan' to apply changes and re-evaluate findings.",
        );
        expect(gets().slice(before)).toEqual(["/compliance/policies"]);
      },
    );

    it("a numeric expected value is sent as a number when it parses, and as typed when it does not", async () => {
      await mount();
      let box = await openConfigure(1);
      expect(box.querySelector('input[type="text"]').value).toBe("5");
      await change(box.querySelector('input[type="text"]'), "8");
      await submitIn(box, "Save Rule Configuration");
      expect(api.put.mock.calls[0][1].check_definition.expected).toBe(8);
      await click(screen.getAllByRole("button", { name: "Configure" })[1]);
      box = dialog("Configure Rule Parameters");
      await change(box.querySelector('input[type="text"]'), "three");
      await submitIn(box, "Save Rule Configuration");
      expect(api.put.mock.calls[1][1].check_definition.expected).toBe("three");
    });

    it("from Findings, Edit Rule prefills Medium when the finding has no severity, shows its evidence and re-reads the findings", async () => {
      await mount();
      const box = await openFromFinding(
        "A.8.2",
        "Edit Rule",
        "Configure Rule Parameters",
      );
      expect(selectWith(box, "CRITICAL,HIGH,MEDIUM,LOW,INFO").value).toBe(
        "MEDIUM",
      );
      expect(box.querySelector('input[type="text"]').value).toBe("");
      expect(squash(box)).toContain(
        'Current evidence value is: {"observed":"2 local admins"}',
      );
      await change(box.querySelector('input[type="text"]'), "1");
      const before = gets().length;
      await submitIn(box, "Save Rule Configuration");
      expect(api.put.mock.calls).toEqual([
        [
          "/compliance/rules/rule-3",
          {
            check_definition: { expected: "1" },
            severity: "medium",
            severity_weight: 5,
          },
        ],
      ]);
      expect(gets().slice(before)).toEqual([
        "/compliance/findings?limit=10000",
      ]);
    });

    it("a refused rule update stays open with the API's detail", async () => {
      writeReply = () => Promise.reject(refusal("Rule is locked"));
      await mount();
      const box = await openConfigure();
      await submitIn(box, "Save Rule Configuration");
      expect(bodyText()).toContain(
        "Failed to update compliance rule: Rule is locked",
      );
      expect(dialog("Configure Rule Parameters")).toBeInTheDocument();
    });
  });

  describe("Request Exception Waiver", () => {
    it("Waiver opens the dialog with a required reason and expiry date, and sends nothing", async () => {
      await mount();
      const box = await openFromFinding(
        "A.8.8",
        "Waiver",
        "Request Exception Waiver",
      );
      expect(box.querySelector("textarea")).toBeRequired();
      const expiry = box.querySelector('input[type="date"]');
      expect(expiry).toBeRequired();
      expect(
        within(box).getByRole("button", { name: "Request Waiver" }),
      ).toHaveAttribute("type", "submit");
      await click(screen.getByRole("button", { name: "Close" }));
      noDialog();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("requesting sends the reason and the expiry as an ISO timestamp, closes, says so and re-reads the findings", async () => {
      await mount();
      const box = await openFromFinding(
        "A.8.8",
        "Waiver",
        "Request Exception Waiver",
      );
      await change(box.querySelector("textarea"), "Compensating control");
      await change(box.querySelector('input[type="date"]'), "2026-12-31");
      const before = gets().length;
      await submitIn(box, "Request Waiver");
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/findings/f-1/exception",
          {
            reason: "Compensating control",
            expires_at: new Date("2026-12-31").toISOString(),
          },
        ],
      ]);
      noDialog();
      expect(bodyText()).toContain("Exception waiver request submitted.");
      expect(gets().slice(before)).toEqual([
        "/compliance/findings?limit=10000",
      ]);
    });

    it("a refused waiver stays open with the API's detail", async () => {
      writeReply = () => Promise.reject(refusal("Finding already waived"));
      await mount();
      const box = await openFromFinding(
        "A.8.8",
        "Waiver",
        "Request Exception Waiver",
      );
      await change(box.querySelector("textarea"), "Again");
      await change(box.querySelector('input[type="date"]'), "2026-12-31");
      await submitIn(box, "Request Waiver");
      expect(bodyText()).toContain(
        "Failed to submit exception waiver request: Finding already waived",
      );
      expect(dialog("Request Exception Waiver")).toBeInTheDocument();
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 27 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const LEGACY =
  /^(db-|compliance-form$|marketplace-view$|grid-3$|framework-|fw-|mono$)/;
const expectClean = (root) => {
  expect(root).toBeTruthy();
  expect([...root.querySelectorAll("[style]")]).toEqual([]);
  const classes = [root, ...root.querySelectorAll("[class]")].flatMap((el) => [
    ...el.classList,
  ]);
  expect(classes.filter((c) => LEGACY.test(c))).toEqual([]);
};

describe("ComplianceWorkspace ordinary writes — batch 27", () => {
  it("the marketplace is a headed section of framework cards named by their headings, with an Installed badge", async () => {
    user = ORG_ADMIN;
    await mount();
    await openTab("Marketplace");
    const heading = screen.getByRole("heading", {
      level: 2,
      name: "Framework Marketplace",
    });
    const section = heading.closest("section");
    expect(section).toHaveAttribute("aria-labelledby", heading.id);
    for (const name of ["ISO/IEC 27001:2022", "SOC 2 Type II"]) {
      const card = screen.getByRole("region", { name });
      expect(
        within(card).getByRole("heading", { level: 3, name }),
      ).toBeInTheDocument();
    }
    const badge = screen
      .getByRole("region", { name: "ISO/IEC 27001:2022" })
      .querySelector(".cc-badge");
    expect(squash(badge)).toBe("Installed");
    expectClean(section);
  });

  it("a disabled action is described by the visible permission reason", async () => {
    await mount();
    await openTab("Marketplace");
    const button = within(
      screen.getByRole("region", { name: "SOC 2 Type II" }),
    ).getByRole("button", { name: "Install" });
    const hint = document.getElementById(
      button.getAttribute("aria-describedby"),
    );
    expect(squash(hint)).toBe(PERMISSION_HINT);
  });

  it("Create Policy Baseline labels its fields, marks them required and hints the rule ID format", async () => {
    await mount();
    const box = await openCreatePolicy();
    expect(within(box).getByLabelText(/^Policy Name/)).toBeRequired();
    expect(within(box).getByLabelText(/^Target Platform/).tagName).toBe(
      "SELECT",
    );
    const rules = within(box).getByLabelText(/^Rule IDs/);
    expect(rules).toBeRequired();
    expect(
      squash(document.getElementById(rules.getAttribute("aria-describedby"))),
    ).toMatch(/comma/i);
    expectClean(box.querySelector("form"));
  });

  it("Configure Rule Parameters labels its fields and shows the evidence as code under a heading", async () => {
    await mount();
    const box = await openConfigure();
    expect(
      within(box).getByRole("heading", {
        level: 3,
        name: /Editing Rule: ccure\.linux\.sshd\.permit_root_login/,
      }),
    ).toBeInTheDocument();
    expect(within(box).getByLabelText(/^Severity Level/).tagName).toBe(
      "SELECT",
    );
    expect(within(box).getByLabelText(/^Expected Rule Value/)).toBeRequired();
    expect(squash(box.querySelector("code"))).toBe("{}");
    expectClean(box.querySelector("form"));
  });

  it("Request Exception Waiver labels its reason and expiry", async () => {
    await mount();
    const box = await openFromFinding(
      "A.8.8",
      "Waiver",
      "Request Exception Waiver",
    );
    const reason = within(box).getByLabelText(/^Reason for Exception Waiver/);
    expect(reason.tagName).toBe("TEXTAREA");
    expect(reason).toBeRequired();
    const expiry = within(box).getByLabelText(/^Expiry Date/);
    expect(expiry).toHaveAttribute("type", "date");
    expectClean(box.querySelector("form"));
  });

  it("the migrated source uses design-system parts and its stylesheet is token-only", () => {
    const source = readFileSync(
      path.join(SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-writes\.css["']/,
    );
    const at = (needle, from = 0) => {
      const i = source.indexOf(needle, from);
      expect(i).toBeGreaterThan(-1);
      return i;
    };
    const marketplace = at('{activeTab === "marketplace" && (');
    const policies = at('{activeTab === "policies" && (', marketplace);
    const policyDialog = at('{modalType === "policy" && (');
    const attest = at('{modalType === "attest" && (');
    const exception = at('{modalType === "exception" && (');
    const gap = at('{modalType === "gap_analysis" && gapAnalysis && (');
    for (const block of [
      source.slice(marketplace, policies),
      source.slice(policyDialog, attest),
      source.slice(exception, gap),
    ]) {
      expect(block).not.toMatch(/style=\{/);
      expect(block.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
      expect(block).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
      expect(block).not.toMatch(
        /className=["{`][^"}`]*\b(db-|compliance-form)/,
      );
      expect(block).not.toMatch(/<(button|input|select)\b/);
      expect(block).toMatch(/<Ccure[A-Z]/);
    }

    const cssPath = path.join(SRC, "styles/compliance-writes.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)[a-z0-9-]+/g) || []).toEqual([]);
    expect(css).not.toMatch(/prefers-color-scheme|ux4g|!important/i);
    expect(css).toMatch(/@media \(max-width: 640px\)/);
    const selectors = css
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .split("{")
      .slice(0, -1)
      .map((s) => s.split("}").pop().trim())
      .filter((s) => s && !s.startsWith("@"));
    for (const s of selectors) expect(s).toMatch(/\.cww-/);
  });
});
