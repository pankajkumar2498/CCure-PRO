/**
 * ComplianceWorkspace (`/compliance`) — credential-bearing remote execution:
 * the Approvals Queue, the remediation and rollback dialog and the execution
 * log viewer. Checkpoint 3C batch 30 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 30 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The Approvals Queue reads GET /compliance/remediations/requests and re-reads
 * it quietly every 5 seconds while the tab is open. A request's creator may
 * cancel it (after confirming); an organisation admin or superadmin who did not
 * create it may approve or reject it; anyone else sees it pending. An executed
 * or failed request with a log offers the log; an executed remediation with no
 * active rollback offers a rollback. The remediation and rollback dialog sends
 * one request with either a stored credential's id or one-time credentials, and
 * an administrator may ask for an emergency bypass. Every refusal is reported
 * with the API's detail.
 *
 * ── Secrets ────────────────────────────────────────────────────────────────
 * The one-time password and key are synthetic, low-entropy placeholders. The
 * afterEach fails any test in which either reached a URL, the console or
 * browser storage.
 *
 * Only the axios instance, the shell and the signed-in user are replaced.
 * Nothing is executed anywhere: every write is a mock.
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

import ComplianceWorkspace from "@audit/pages/ComplianceWorkspace";
import api from "@shell/api/axiosInstance";
import { AUDIT_SRC } from "../../../testPaths";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let user;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user }),
}));

const ME = 7;
const person = (roleName) => ({
  id: ME,
  username: "operator",
  role: { name: roleName, permissions: ["compliance:read"] },
});
const ADMIN = person("Org Admin");
const ANALYST = person("analyst");

/* ── Fixtures ────────────────────────────────────────────────────────────── */
// Synthetic, low-entropy stand-ins. Neither is a credential for anything.
const PASS = "synthetic-pass";
const KEY = "synthetic key text";
const request = (id, extra) => ({
  id,
  finding_id: `f-${id}`,
  control_id: "A.8.8",
  control_title: "Management of technical vulnerabilities",
  remediation_id: "rem-1",
  fix_command: "sed -i s/PermitRootLogin.yes/PermitRootLogin.no/ sshd_config",
  asset_ip: "10.70.0.11",
  status: "pending_approval",
  emergency_bypass: false,
  created_at: "2026-09-01T10:00:00Z",
  requested_by: 9,
  approved_by: null,
  execution_log: null,
  ...extra,
});
const REQUESTS = [
  request("crrq_a1b2"),
  request("crrq_rollback_c3d4", {
    finding_id: "f-shared",
    control_id: "A.8.2",
    control_title: "Privileged access rights",
    asset_ip: "10.70.0.12",
    fix_command: "restore sshd_config",
    requested_by: ME,
  }),
  request("crrq_o5p6", { control_id: "A.8.5", requested_by: ME }),
  request("crrq_rollback_q7r8", {
    control_id: "A.8.7",
    asset_ip: "10.70.0.14",
  }),
  request("crrq_e5f6", {
    control_id: "A.8.9",
    control_title: "Configuration management",
    asset_ip: "10.70.0.13",
    status: "executed",
    execution_log:
      "Connected to 10.70.0.13\nsshd_config updated\nsshd restarted",
  }),
  request("crrq_g7h8", {
    status: "failed",
    execution_log: "Connection refused",
  }),
  request("crrq_rollback_i9j0", {
    status: "executed",
    execution_log: "Rollback applied",
  }),
  request("crrq_k1l2", {
    finding_id: "f-shared",
    status: "executed",
    execution_log: "Applied",
  }),
  request("crrq_m3n4", { status: "approved" }),
];
const FINDINGS = [
  {
    id: "f-1",
    control_id: "A.8.8",
    control_title: "Management of technical vulnerabilities",
    rule_id: "rule-1",
    rule_name: "ccure.linux.sshd.permit_root_login",
    severity: "HIGH",
    asset_id: "asset-1",
    asset_hostname: "web-01",
    asset_ip: "10.70.0.11",
    source: "credentialed",
    status: "fail",
    fix_command: "sed -i s/PermitRootLogin.yes/PermitRootLogin.no/ sshd_config",
    recommendation_text: "Disable direct root login over SSH.",
  },
  {
    id: "f-9",
    control_id: "A.8.9",
    control_title: "Configuration management",
    severity: "MEDIUM",
    asset_id: "asset-9",
    asset_hostname: "Unknown",
    asset_ip: "10.70.0.19",
    source: "credentialed",
    status: "fail",
  },
];
const STORED = [
  {
    id: "cred-1",
    name: "Linux fleet",
    username: "auditor",
    auth_method: "password",
    port: 22,
    created_at: "2026-08-01T10:00:00Z",
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
  response: { status: 400, data: { detail, message: detail } },
  message: "Request failed with status code 400",
});

/* ── Harness ────────────────────────────────────────────────────────────── */
let requests;
let postReply;
let confirmSpy;
let consoleSpies;
let clipboard;

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const frame = async () => {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 40));
  });
  await flush();
};
const mount = async () => {
  const view = render(<ComplianceWorkspace />);
  await flush();
  return view;
};
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);
const gets = () => api.get.mock.calls.map(([u]) => u);
const REQUESTS_URL = "/compliance/remediations/requests";
const requestReads = () => gets().filter((u) => u === REQUESTS_URL).length;
const credentialReads = () =>
  gets().filter((u) => u === "/compliance/credentials").length;

const tabBar = () =>
  [...document.querySelectorAll("div")].find(
    (d) =>
      /* Nine since P3-2 added the Schedules tab. The identity of the bar is
         the two labels below; the count is incidental and is kept exact so a
         wrapper cannot satisfy it. */
      d.children.length === 9 &&
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
const openApprovals = () => openTab("Approvals Queue");
const click = async (el, init) => {
  fireEvent.click(el, init);
  await flush();
};
const change = async (el, value) => {
  fireEvent.change(el, { target: { value } });
  await flush();
};
const queueTable = () =>
  [...document.querySelectorAll("table")].find((t) =>
    /Ticket ID/.test(t.tHead?.textContent || ""),
  );
const ticketRow = (id) =>
  [...queueTable().tBodies[0].rows].find(
    (r) => r.cells.length > 1 && squash(r.cells[0]) === id,
  );
const cellsOf = (id) => [...ticketRow(id).cells].map((c) => squash(c));
const actionTexts = (id) =>
  [...ticketRow(id).cells[5].querySelectorAll("button")].map((b) => squash(b));
const actionOf = (id, text) =>
  [...ticketRow(id).cells[5].querySelectorAll("button")].find(
    (b) => squash(b) === text,
  );
// Answers a queue decision the way a person does: the button, then the
// question — the browser's confirm on the legacy page, the dialog where there
// is one. Returns the question's text, or null when nothing asked.
const decide = async (id, text, accept) => {
  let asked = null;
  confirmSpy.mockImplementation((message) => {
    asked = message;
    return accept;
  });
  const button = actionOf(id, text);
  button.focus();
  await click(button);
  const dialog = screen.queryByRole("dialog");
  if (dialog) {
    asked = squash(dialog);
    const confirm = within(dialog)
      .getAllByRole("button")
      .find((b) => squash(b) === text);
    await click(
      accept
        ? confirm
        : within(dialog).getByRole("button", { name: "Go back" }),
    );
  }
  return asked;
};
const dialogNamed = (name) => screen.getByRole("dialog", { name });
const findingRow = (controlId) =>
  [...document.querySelectorAll("tbody tr")].find(
    (r) => r.cells.length > 1 && squash(r.cells[0]) === controlId,
  );
const openRemediate = async (controlId) => {
  await openTab("Findings");
  await click(
    within(findingRow(controlId)).getByRole("button", { name: "Remediate" }),
  );
  return dialogNamed("Remediate Finding");
};
const openRollback = async (id) => {
  await openApprovals();
  await click(actionOf(id, "Rollback"));
  return dialogNamed("Roll Back Remediation");
};
const openLogs = async (id) => {
  await openApprovals();
  await click(actionOf(id, "View Logs"));
  return dialogNamed("Execution Log");
};
const radios = (box) => [...box.querySelectorAll('input[type="radio"]')];
const methodSelect = (box) =>
  [...box.querySelectorAll("select")].find(
    (s) => [...s.options].map((o) => o.value).join(",") === "password,key",
  );
const storedSelect = (box) =>
  [...box.querySelectorAll("select")].find(
    (s) => s.options[0]?.value === "" && s.options.length === STORED.length + 1,
  );
const jitUser = (box) => box.querySelector('input[type="text"]');
const jitPort = (box) => box.querySelector('input[type="number"]');
const jitPassword = (box) => box.querySelector('input[type="password"]');
const jitKey = (box) => box.querySelector("textarea");
const bypass = (box) => box.querySelector('input[type="checkbox"]');
const dispatchButton = (box) =>
  within(box).getByRole("button", {
    name: /Dispatch (Fix|Rollback) Request/,
  });

beforeEach(() => {
  user = ADMIN;
  requests = REQUESTS.map((r) => ({ ...r }));
  postReply = (url) => {
    if (/\/remediate$/.test(url))
      return Promise.resolve({
        data: {
          message: "Remediation request submitted to the approvals queue.",
        },
      });
    if (/\/rollback$/.test(url))
      return Promise.resolve({ data: { message: "Rollback request queued." } });
    return Promise.resolve({ data: { message: "ok" } });
  };
  Element.prototype.scrollIntoView = vi.fn();
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url) => {
    if (url === REQUESTS_URL)
      return Promise.resolve({
        data: { data: requests.map((r) => ({ ...r })) },
      });
    if (url === "/compliance/credentials")
      return Promise.resolve({ data: STORED.map((c) => ({ ...c })) });
    if (url.startsWith("/compliance/findings"))
      return Promise.resolve({ data: { data: FINDINGS } });
    if (url === "/compliance/marketplace")
      return Promise.resolve({ data: { data: [] } });
    if (url.startsWith("/compliance/summary"))
      return Promise.resolve({
        data: { score_pct: 70, weighted_score_pct: 60, kpis: {} },
      });
    return Promise.resolve({ data: { data: [] } });
  });
  api.post.mockImplementation((...args) => postReply(...args));
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
  consoleSpies = ["error", "warn", "log", "info", "debug"].map((m) =>
    vi.spyOn(console, m).mockImplementation(() => {}),
  );
  clipboard = { writeText: vi.fn(() => Promise.resolve()) };
  Object.defineProperty(navigator, "clipboard", {
    value: clipboard,
    configurable: true,
  });
  window.localStorage.clear();
  window.sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  // Only the remediation, rollback, approval and cancellation endpoints are
  // ever written, and a cancellation carries nothing but its URL. Nothing is
  // put, patched or deleted.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const args of api.post.mock.calls) {
    expect(args[0]).toMatch(
      /^\/compliance\/(findings\/f-[0-9]+\/remediate|remediations\/requests\/crrq_[a-z0-9_]+\/(approve|cancel|rollback))$/,
    );
    if (args[0].endsWith("/cancel")) expect(args).toHaveLength(1);
    if (args[0].endsWith("/approve")) expect(args).toHaveLength(2);
  }
  const urls = [...gets(), ...api.post.mock.calls.map(([u]) => u)];
  for (const url of urls) {
    expect(url).not.toContain("synthetic");
    expect(url).not.toMatch(/credential_id|jit|password|key_content/);
  }
  const logged = JSON.stringify(
    consoleSpies.flatMap((s) =>
      s.mock.calls.map((args) =>
        args.map((a) =>
          a instanceof Error ? `${a.message} ${a.stack}` : String(a),
        ),
      ),
    ),
  );
  expect(logged).not.toContain(PASS);
  expect(logged).not.toContain(KEY);
  const stored = JSON.stringify({
    ...window.localStorage,
    ...window.sessionStorage,
  });
  expect(stored).not.toContain(PASS);
  expect(stored).not.toContain(KEY);
  confirmSpy.mockRestore();
  for (const s of consoleSpies) s.mockRestore();
  delete navigator.clipboard;
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace credential-bearing execution — contract", () => {
  describe("The Approvals Queue", () => {
    it("reads the requests once and lists each ticket's id, control, host, command, requester and status", async () => {
      await mount();
      await openApprovals();
      expect(requestReads()).toBe(1);
      expect(
        [...queueTable().tHead.rows[0].cells].map((c) => squash(c)),
      ).toEqual([
        "Ticket ID",
        "Control & Asset",
        "Fix Command",
        "Requested By",
        "Status",
        "Actions",
      ]);
      const pending = cellsOf("crrq_a1b2");
      expect(pending[1]).toContain(
        "A.8.8 - Management of technical vulnerabilities",
      );
      expect(pending[1]).toContain("Target Host: 10.70.0.11");
      expect(pending[1]).not.toMatch(/^Rollback/);
      expect(pending[2]).toBe(
        "sed -i s/PermitRootLogin.yes/PermitRootLogin.no/ sshd_config",
      );
      expect(pending[3]).toBe("9");
      expect(pending[4]).toBe("pending approval");
      const rollback = cellsOf("crrq_rollback_c3d4");
      expect(rollback[1]).toMatch(/^Rollback/);
      expect(rollback[1]).toContain("A.8.2 - Privileged access rights");
      expect(cellsOf("crrq_e5f6")[4]).toBe("executed");
      expect(cellsOf("crrq_g7h8")[4]).toBe("failed");
      expect(cellsOf("crrq_m3n4")[4]).toBe("approved");
      expect(api.post).not.toHaveBeenCalled();
    });

    it("an empty queue says so", async () => {
      requests = [];
      await mount();
      await openApprovals();
      expect(bodyText()).toContain("No approval tickets in this status.");
    });

    it("an administrator decides others' requests, cancels their own, and sees logs and rollbacks where they apply", async () => {
      await mount();
      await openApprovals();
      expect(actionTexts("crrq_a1b2")).toEqual(["Approve", "Reject"]);
      expect(actionTexts("crrq_rollback_q7r8")).toEqual(["Approve", "Reject"]);
      expect(actionTexts("crrq_o5p6")).toEqual(["Cancel Request"]);
      expect(actionTexts("crrq_rollback_c3d4")).toEqual(["Cancel Rollback"]);
      expect(actionTexts("crrq_e5f6")).toEqual(["View Logs", "Rollback"]);
      expect(actionTexts("crrq_g7h8")).toEqual(["View Logs"]);
      expect(actionTexts("crrq_rollback_i9j0")).toEqual(["View Logs"]);
      // An executed remediation whose finding already has a rollback pending
      // offers no second rollback.
      expect(actionTexts("crrq_k1l2")).toEqual(["View Logs"]);
      expect(actionTexts("crrq_m3n4")).toEqual([]);
    });

    it("anyone else sees others' requests pending and may still cancel their own", async () => {
      user = ANALYST;
      await mount();
      await openApprovals();
      expect(actionTexts("crrq_a1b2")).toEqual([]);
      expect(squash(ticketRow("crrq_a1b2").cells[5])).toBe("Pending approval");
      expect(actionTexts("crrq_o5p6")).toEqual(["Cancel Request"]);
      expect(actionTexts("crrq_e5f6")).toEqual(["View Logs", "Rollback"]);
    });

    it("re-reads the queue quietly every 5 seconds while the tab is open, and stops on leaving it", async () => {
      vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
      await mount();
      await openApprovals();
      const advance = async (ms) => {
        await act(async () => {
          vi.advanceTimersByTime(ms);
        });
        await flush();
      };
      expect(requestReads()).toBe(1);
      await advance(4999);
      expect(requestReads()).toBe(1);
      await advance(1);
      expect(requestReads()).toBe(2);
      expect(document.querySelector(".loading-bar, .cwh-loading")).toBeNull();
      await openTab("Dashboard");
      await advance(20000);
      expect(requestReads()).toBe(2);
    });
  });

  describe("Cancelling a request", () => {
    it("the creator is asked first, and declining sends nothing", async () => {
      await mount();
      await openApprovals();
      const asked = await decide("crrq_o5p6", "Cancel Request", false);
      expect(asked).toContain(
        "Are you sure you want to cancel this remediation request?",
      );
      expect(api.post).not.toHaveBeenCalled();
    });

    it("confirming posts to cancel with nothing but the URL, says which kind was cancelled and re-reads the queue", async () => {
      await mount();
      await openApprovals();
      const asked = await decide("crrq_rollback_c3d4", "Cancel Rollback", true);
      expect(asked).toContain(
        "Are you sure you want to cancel this rollback request?",
      );
      expect(api.post.mock.calls).toEqual([
        [`${REQUESTS_URL}/crrq_rollback_c3d4/cancel`],
      ]);
      expect(bodyText()).toContain("Rollback request cancelled successfully.");
      expect(requestReads()).toBe(2);
      await decide("crrq_o5p6", "Cancel Request", true);
      expect(bodyText()).toContain(
        "Remediation request cancelled successfully.",
      );
    });

    it("a refused cancellation reports the API's detail, then its message, then the error's message", async () => {
      await mount();
      await openApprovals();
      postReply = () =>
        Promise.reject(
          refusal("Forbidden: Only the creator of the request can cancel it."),
        );
      await decide("crrq_o5p6", "Cancel Request", true);
      expect(bodyText()).toContain(
        "Cancellation failed: Forbidden: Only the creator of the request can cancel it.",
      );
      postReply = () =>
        Promise.reject({
          response: { data: { message: "Locked" } },
          message: "x",
        });
      await decide("crrq_o5p6", "Cancel Request", true);
      expect(bodyText()).toContain("Cancellation failed: Locked");
      postReply = () => Promise.reject(new Error("Network Error"));
      await decide("crrq_o5p6", "Cancel Request", true);
      expect(bodyText()).toContain("Cancellation failed: Network Error");
    });
  });

  describe("Approving and rejecting", () => {
    it("approving posts the approval, says which kind was queued and re-reads the queue", async () => {
      await mount();
      await openApprovals();
      await decide("crrq_a1b2", "Approve", true);
      expect(api.post.mock.calls).toEqual([
        [`${REQUESTS_URL}/crrq_a1b2/approve`, { status: "approved" }],
      ]);
      expect(bodyText()).toContain("Remediation request approved and queued.");
      expect(requestReads()).toBe(2);
      await decide("crrq_rollback_q7r8", "Approve", true);
      expect(api.post.mock.calls[1]).toEqual([
        `${REQUESTS_URL}/crrq_rollback_q7r8/approve`,
        { status: "approved" },
      ]);
      expect(bodyText()).toContain("Rollback approved and queued.");
    });

    it("rejecting posts the rejection and says which kind was rejected", async () => {
      await mount();
      await openApprovals();
      await decide("crrq_a1b2", "Reject", true);
      expect(api.post.mock.calls).toEqual([
        [`${REQUESTS_URL}/crrq_a1b2/approve`, { status: "rejected" }],
      ]);
      expect(bodyText()).toContain("Remediation request rejected.");
      await decide("crrq_rollback_q7r8", "Reject", true);
      expect(bodyText()).toContain("Rollback rejected.");
    });

    it("a refused approval or rejection reports the API's detail", async () => {
      postReply = () =>
        Promise.reject(
          refusal(
            "Zero-trust security violation: Request creator cannot self-approve remediation requests.",
          ),
        );
      await mount();
      await openApprovals();
      await decide("crrq_a1b2", "Approve", true);
      expect(bodyText()).toContain(
        "Approval failed: Zero-trust security violation: Request creator cannot self-approve remediation requests.",
      );
      postReply = () => Promise.reject(new Error("Network Error"));
      await decide("crrq_a1b2", "Reject", true);
      expect(bodyText()).toContain("Rejection failed: Network Error");
    });
  });

  describe("The execution log", () => {
    it("View Logs opens the log for that request and sends nothing", async () => {
      await mount();
      const box = await openLogs("crrq_e5f6");
      expect(squash(box)).toContain("Execution Log: A.8.9");
      expect(squash(box)).toContain("Target IP: 10.70.0.13");
      expect(box.querySelector("pre").textContent).toBe(
        "Connected to 10.70.0.13\nsshd_config updated\nsshd restarted",
      );
      await click(within(box).getByRole("button", { name: "Close Logs" }));
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.post).not.toHaveBeenCalled();
    });
  });

  describe("The remediation dialog", () => {
    it("Remediate opens the guide for the finding: its control, host, recommendation and script, with one-time credentials by default", async () => {
      await mount();
      const before = credentialReads();
      const box = await openRemediate("A.8.8");
      expect(credentialReads() - before).toBe(1);
      expect(squash(box)).toContain("Remediation Guide: A.8.8");
      expect(squash(box)).toContain(
        "Control Name: Management of technical vulnerabilities",
      );
      expect(squash(box)).toContain("web-01 (10.70.0.11)");
      expect(squash(box)).toContain("Disable direct root login over SSH.");
      expect(box.querySelector("pre").textContent).toBe(
        FINDINGS[0].fix_command,
      );
      const [jit, stored] = radios(box);
      expect(jit).toBeChecked();
      expect(stored).not.toBeChecked();
      expect(jitUser(box)).toHaveValue("");
      expect(jitUser(box)).toHaveAttribute("placeholder", "e.g. root");
      expect(jitPort(box)).toHaveValue(22);
      expect(methodSelect(box).value).toBe("password");
      expect(jitPassword(box)).toHaveAttribute("type", "password");
      expect(jitKey(box)).toBeNull();
      expect(storedSelect(box)).toBeUndefined();
      expect(dispatchButton(box)).toBeEnabled();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("a finding with no script says so and cannot be dispatched", async () => {
      await mount();
      const box = await openRemediate("A.8.9");
      expect(squash(box)).toContain("No recommendation text registered.");
      expect(squash(box)).toContain("10.70.0.19");
      expect(squash(box)).not.toContain("Unknown (10.70.0.19)");
      expect(box.querySelector("pre")).toBeNull();
      expect(
        within(box).getByRole("button", { name: /No Automated Fix Available/ }),
      ).toBeDisabled();
    });

    it("Copy puts the script on the clipboard and says so", async () => {
      await mount();
      const box = await openRemediate("A.8.8");
      await click(within(box).getByRole("button", { name: /^Copy/ }));
      expect(clipboard.writeText).toHaveBeenCalledWith(FINDINGS[0].fix_command);
      expect(bodyText()).toContain("Command copied to clipboard!");
    });

    it("dispatching with a one-time password posts it once, closes, reports the API's message, clears the secret and re-reads", async () => {
      await mount();
      let box = await openRemediate("A.8.8");
      await change(jitUser(box), "deploy");
      await change(jitPort(box), "2200");
      await change(jitPassword(box), PASS);
      const findingsBefore = gets().filter((u) =>
        u.startsWith("/compliance/findings"),
      ).length;
      await click(dispatchButton(box));
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/findings/f-1/remediate",
          {
            action: "apply_script",
            emergency_bypass: false,
            jit_credentials: {
              username: "deploy",
              port: 2200,
              auth_method: "password",
              password: PASS,
              key_content: null,
            },
          },
        ],
      ]);
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(bodyText()).toContain(
        "Remediation request submitted to the approvals queue.",
      );
      expect(
        gets().filter((u) => u.startsWith("/compliance/findings")).length,
      ).toBeGreaterThan(findingsBefore);
      expect(document.body.innerHTML).not.toContain(PASS);
      box = await openRemediate("A.8.8");
      expect(jitUser(box)).toHaveValue("");
      expect(jitPassword(box)).toHaveValue("");
    });

    it("dispatching with a one-time key posts the key and a null password", async () => {
      postReply = () => Promise.resolve({ data: {} });
      await mount();
      const box = await openRemediate("A.8.8");
      await change(jitUser(box), "ops");
      await change(methodSelect(box), "key");
      await change(jitKey(box), KEY);
      await click(dispatchButton(box));
      expect(api.post.mock.calls[0][1]).toEqual({
        action: "apply_script",
        emergency_bypass: false,
        jit_credentials: {
          username: "ops",
          port: 22,
          auth_method: "key",
          password: null,
          key_content: KEY,
        },
      });
      expect(bodyText()).toContain("Remediation script processed.");
      expect(document.body.innerHTML).not.toContain(KEY);
    });

    it("dispatching with a stored credential posts its id only, chosen from its name and account", async () => {
      await mount();
      const box = await openRemediate("A.8.8");
      await click(radios(box)[1]);
      const select = storedSelect(box);
      expect([...select.options].map((o) => o.textContent.trim())).toEqual([
        "-- Choose Credential --",
        "Linux fleet (auditor)",
      ]);
      expect(jitUser(box)).toBeNull();
      expect(jitPassword(box)).toBeNull();
      await change(select, "cred-1");
      await click(dispatchButton(box));
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/findings/f-1/remediate",
          {
            action: "apply_script",
            emergency_bypass: false,
            credential_id: "cred-1",
          },
        ],
      ]);
    });

    it("a missing username or stored credential is refused before anything is sent", async () => {
      await mount();
      let box = await openRemediate("A.8.8");
      await click(dispatchButton(box));
      expect(bodyText()).toContain("JIT Username is required.");
      box = await openRemediate("A.8.8");
      await click(radios(box)[1]);
      await click(dispatchButton(box));
      expect(bodyText()).toContain("Please select a stored credential.");
      expect(api.post).not.toHaveBeenCalled();
    });

    it("only an administrator is offered the emergency bypass, which the request then carries", async () => {
      await mount();
      const box = await openRemediate("A.8.8");
      expect(squash(box)).toContain(
        "Note: Emergency bypass will log a critical priority incident alert to the IP audit logs.",
      );
      await click(bypass(box));
      await change(jitUser(box), "deploy");
      await change(jitPassword(box), PASS);
      await click(dispatchButton(box));
      expect(api.post.mock.calls[0][1].emergency_bypass).toBe(true);
      cleanup();

      user = ANALYST;
      await mount();
      const analystBox = await openRemediate("A.8.8");
      expect(bypass(analystBox)).toBeNull();
      expect(squash(analystBox)).not.toContain("Emergency bypass will log");
    });

    it("a refused remediation reports the API's detail, and the typed username is kept", async () => {
      postReply = () =>
        Promise.reject(
          refusal("No automated fix script registered for this rule"),
        );
      await mount();
      let box = await openRemediate("A.8.8");
      await change(jitUser(box), "deploy");
      await change(jitPassword(box), PASS);
      await click(dispatchButton(box));
      expect(bodyText()).toContain(
        "Remediation error: No automated fix script registered for this rule",
      );
      expect(document.body.innerHTML).not.toContain(PASS);
      box = await openRemediate("A.8.8");
      expect(jitUser(box)).toHaveValue("deploy");
    });

    it("Close Guide closes the dialog and sends nothing", async () => {
      await mount();
      const box = await openRemediate("A.8.8");
      await click(within(box).getByRole("button", { name: "Close Guide" }));
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.post).not.toHaveBeenCalled();
    });
  });

  describe("The rollback dialog", () => {
    it("Rollback opens the warning for that request with its host and script, and reads the stored credentials", async () => {
      await mount();
      const before = credentialReads();
      const box = await openRollback("crrq_e5f6");
      expect(credentialReads() - before).toBe(1);
      expect(squash(box)).toContain("Rollback Security Rule: A.8.9");
      expect(squash(box)).toContain("Control Name: Configuration management");
      expect(squash(box)).toContain("10.70.0.13");
      expect(squash(box)).toContain(
        "This action will execute a script to reverse the security control and reopen the port on the target machine.",
      );
      expect(box.querySelector("pre").textContent).toBe(
        REQUESTS[4].fix_command,
      );
      expect(api.post).not.toHaveBeenCalled();
    });

    it("dispatching posts the rollback with the credentials and no action, closes and reports the result", async () => {
      await mount();
      const box = await openRollback("crrq_e5f6");
      await change(jitUser(box), "deploy");
      await change(jitPassword(box), PASS);
      await click(dispatchButton(box));
      expect(api.post.mock.calls).toEqual([
        [
          `${REQUESTS_URL}/crrq_e5f6/rollback`,
          {
            emergency_bypass: false,
            jit_credentials: {
              username: "deploy",
              port: 22,
              auth_method: "password",
              password: PASS,
              key_content: null,
            },
          },
        ],
      ]);
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(bodyText()).toContain("Rollback request queued.");
    });

    it("a refused rollback reports the API's detail", async () => {
      postReply = () =>
        Promise.reject(
          refusal("Only successfully executed requests can be rolled back."),
        );
      await mount();
      const box = await openRollback("crrq_e5f6");
      await click(radios(box)[1]);
      await change(storedSelect(box), "cred-1");
      await click(dispatchButton(box));
      expect(api.post.mock.calls[0][1]).toEqual({
        emergency_bypass: false,
        credential_id: "cred-1",
      });
      expect(bodyText()).toContain(
        "Rollback error: Only successfully executed requests can be rolled back.",
      );
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 30 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const LEGACY = /^(db-|compliance-form$|mono$)/;
const describedText = (el) =>
  (el.getAttribute("aria-describedby") || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => squash(document.getElementById(id)))
    .join(" ");
const expectClean = (root) => {
  expect(root).toBeTruthy();
  expect([...root.querySelectorAll("[style]")]).toEqual([]);
  const classes = [root, ...root.querySelectorAll("[class]")].flatMap((el) => [
    ...el.classList,
  ]);
  expect(classes.filter((c) => LEGACY.test(c))).toEqual([]);
};

describe("ComplianceWorkspace credential-bearing execution — batch 30", () => {
  it("the queue is a captioned table under a heading; tickets are row headers, status and rollback are badges, and actions are named for their ticket", async () => {
    await mount();
    await openApprovals();
    expect(
      screen.getByRole("heading", {
        level: 2,
        name: "Remediation Approvals Queue",
      }),
    ).toBeInTheDocument();
    const table = screen.getByRole("table", {
      name: "Remediation approval requests",
    });
    expect(
      within(table).getByRole("rowheader", { name: "crrq_a1b2" }),
    ).toBeInTheDocument();
    expect(
      squash(ticketRow("crrq_a1b2").cells[4].querySelector(".cc-badge")),
    ).toBe("pending approval");
    expect(
      squash(
        ticketRow("crrq_rollback_c3d4").cells[1].querySelector(".cc-badge"),
      ),
    ).toBe("Rollback");
    expect(actionOf("crrq_a1b2", "Approve")).toHaveAccessibleName(
      "Approve crrq_a1b2",
    );
    expect(actionOf("crrq_e5f6", "View Logs")).toHaveAccessibleName(
      "View Logs for crrq_e5f6",
    );
    expectClean(table);
  });

  it("cancelling, approving and rejecting each ask in a dialog with Go back focused; Go back and Escape send nothing; the browser's confirm is never used", async () => {
    await mount();
    await openApprovals();
    const cancel = actionOf("crrq_o5p6", "Cancel Request");
    cancel.focus();
    await click(cancel);
    await frame();
    let dialog = dialogNamed("Cancel remediation request");
    expect(squash(dialog)).toContain(
      "Are you sure you want to cancel this remediation request?",
    );
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: "Go back" }),
    );
    await click(within(dialog).getByRole("button", { name: "Go back" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(
      actionOf("crrq_o5p6", "Cancel Request"),
    );

    await click(actionOf("crrq_a1b2", "Approve"));
    dialog = dialogNamed("Approve remediation request");
    expect(squash(dialog)).toContain("10.70.0.11");
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();

    await click(actionOf("crrq_rollback_q7r8", "Reject"));
    expect(dialogNamed("Reject rollback request")).toBeInTheDocument();
    await click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Go back",
      }),
    );
    expect(api.post).not.toHaveBeenCalled();
    expect(confirmSpy).not.toHaveBeenCalled();
  });

  it("a decision in flight is busy, cannot be dismissed or sent twice, and the dialog closes when it settles", async () => {
    const pending = deferred();
    postReply = () => pending.promise;
    await mount();
    await openApprovals();
    await click(actionOf("crrq_a1b2", "Approve"));
    const dialog = dialogNamed("Approve remediation request");
    const confirm = within(dialog)
      .getAllByRole("button")
      .find((b) => squash(b) === "Approve");
    await click(confirm);
    await click(confirm);
    expect(api.post).toHaveBeenCalledTimes(1);
    expect(confirm).toBeDisabled();
    expect(confirm).toHaveAttribute("aria-busy", "true");
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await act(async () => pending.resolve({ data: {} }));
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(bodyText()).toContain("Remediation request approved and queued.");
  });

  it("the dialog's fields are labelled, the credential source is a radio group, the one-time password is masked, never autofilled and described, and the bypass is described", async () => {
    await mount();
    const box = await openRemediate("A.8.8");
    const group = within(box).getByRole("group", {
      name: "Execution Credentials",
    });
    const sources = within(group).getAllByRole("radio");
    expect(sources).toHaveLength(2);
    expect(sources[0]).toHaveAccessibleName("One-time JIT Credentials");
    expect(sources[1]).toHaveAccessibleName("Use Stored Credential");
    expect(sources[0].name).toBeTruthy();
    expect(sources[0].name).toBe(sources[1].name);
    expect(within(box).getByLabelText(/^SSH Username/).tagName).toBe("INPUT");
    expect(within(box).getByLabelText(/^SSH Port/)).toHaveAttribute(
      "type",
      "number",
    );
    expect(within(box).getByLabelText(/^Auth Method/).tagName).toBe("SELECT");
    const password = within(box).getByLabelText(/^Password/);
    expect(password).toHaveAttribute("type", "password");
    expect(password).toHaveAttribute("autocomplete", "new-password");
    expect(describedText(password)).toMatch(/not added to saved credentials/i);
    await change(within(box).getByLabelText(/^Auth Method/), "key");
    const key = within(box).getByLabelText(/^Private Key Content/);
    expect(key.tagName).toBe("TEXTAREA");
    expect(describedText(key)).toMatch(/not added to saved credentials/i);
    await click(sources[1]);
    expect(within(box).getByLabelText(/^Select Saved Credential/).tagName).toBe(
      "SELECT",
    );

    const bypassBox = within(box).getByRole("checkbox", {
      name: /Emergency Bypass/,
    });
    expect(describedText(bypassBox)).toMatch(/critical priority incident/);
    const dispatch = within(box).getByRole("button", {
      name: "Dispatch Fix Request",
    });
    expect(dispatch).not.toHaveClass("cc-btn--danger");
    await click(bypassBox);
    expect(
      within(box).getByRole("button", { name: "Dispatch Fix Request" }),
    ).toHaveClass("cc-btn--danger");
    expectClean(
      box.querySelector(".cc-modal__body > *, .modal-panel-body > *"),
    );
  });

  it("the repair script and the console output are named, keyboard-reachable regions, Copy says what it copies, and the rollback warning is an alert", async () => {
    await mount();
    let box = await openRemediate("A.8.8");
    const script = within(box).getByRole("region", {
      name: "Automated Repair Script",
    });
    expect(script).toHaveAttribute("tabindex", "0");
    expect(
      within(box).getByRole("button", { name: "Copy repair script" }),
    ).toBeInTheDocument();
    await click(within(box).getByRole("button", { name: "Close Guide" }));

    box = await openLogs("crrq_e5f6");
    const output = within(box).getByRole("region", { name: "Console Output" });
    expect(output).toHaveAttribute("tabindex", "0");
    expectClean(
      box.querySelector(".cc-modal__body > *, .modal-panel-body > *"),
    );
    await click(within(box).getByRole("button", { name: "Close Logs" }));

    box = await openRollback("crrq_e5f6");
    expect(box.querySelector(".cc-alert--warning")).toBeTruthy();
    expect(squash(box.querySelector(".cc-alert--warning"))).toContain(
      "reverse the security control",
    );
    expect(
      within(box).getByRole("button", { name: "Dispatch Rollback Request" }),
    ).toHaveClass("cc-btn--danger");
  });

  it("the migrated source uses design-system parts, asks in dialogs, and its stylesheet is token-only", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-execution\.css["']/,
    );
    const at = (needle, from = 0) => {
      const i = source.indexOf(needle, from);
      expect(i).toBeGreaterThan(-1);
      return i;
    };
    const approvals = source.slice(
      at('{activeTab === "approvals" && ('),
      at("{/* Dynamic Popups Modals */}"),
    );
    const dialog = source.slice(
      at('{(modalType === "remediate" || modalType === "rollback") &&'),
      at("</CcureModal>"),
    );
    for (const block of [approvals, dialog]) {
      expect(block).not.toMatch(/style=\{/);
      expect(block.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
      expect(block).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
      expect(block).not.toMatch(
        /className=["{`][^"}`]*(\bdb-|\bcompliance-form\b|(?<![\w-])mono(?![\w-]))/,
      );
      expect(block).not.toMatch(/<(button|select|table)\b/);
      expect(block).not.toMatch(/window\.confirm/);
      expect(block).toMatch(/<Ccure[A-Z]/);
    }
    expect(approvals).not.toMatch(/<PaginationBar\b/);
    expect(approvals).toMatch(/<CcureConfirmDialog\b/);
    expect(approvals).toMatch(/<CcureTable\b/);
    expect(dialog).toMatch(/<CcurePasswordField\b/);
    expect(dialog).toMatch(/autoComplete="new-password"/);
    // The native controls left have no primitive: the credential-source radios,
    // the bypass checkbox and the key field.
    expect(
      (dialog.match(/<input\b[^>]*>/gs) || []).every((tag) =>
        /type="(radio|checkbox)"/.test(tag),
      ),
    ).toBe(true);
    expect(dialog.match(/<textarea\b/g) || []).toHaveLength(1);

    const cssPath = path.join(AUDIT_SRC, "styles/compliance-execution.css");
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
    for (const s of selectors) expect(s).toMatch(/\.cwe-/);
  });
});
