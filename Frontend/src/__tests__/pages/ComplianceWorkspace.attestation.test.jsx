/**
 * ComplianceWorkspace (`/compliance`) — the Control Manual Attestation dialog
 * and its evidence: upload, list and removal. Checkpoint 3C batch 28 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 28 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Attest (Controls) and Verify (Findings) open the dialog for one control and
 * read only that control's evidence. Choosing a file posts it as multipart form
 * data under `file` — after refusing an empty file or one above 25 MB locally —
 * and re-reads the list. Removing a file sends one DELETE for it and re-reads
 * the list. Saving posts the attestation with the listed files' ids. Every
 * failure is reported with the API's detail. The client gates none of it: the
 * server's permission refusal is what a user without `compliance:attest` sees.
 *
 * The dialog offers no download. The API serves one; the page never did, and
 * this batch does not add it — every test fails if a download is requested.
 *
 * Only the axios instance, the shell and the signed-in user are replaced.
 * No credential, remediation, approval, report or download path is exercised.
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
import api from "@shell/api/axiosInstance";

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

vi.mock("../../components/layout/AppLayout", () => ({
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

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const person = (roleName, permissions, id = 1) => ({
  id,
  username: `user-${id}`,
  role: { name: roleName, permissions },
});
const ANALYST = person("analyst", ["compliance:read", "compliance:attest"]);
const VIEWER = person("viewer", ["compliance:read"], 2);

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const CONTROLS = {
  data: [
    {
      control_id: "cct_iso_5_1",
      control_number: "A.5.1",
      title: "Policies for information security",
      description: "Information security policy defined and approved.",
      evidence_checklist: [
        "Approved information security policy",
        "Management sign-off record",
      ],
      theme: "ORG",
      scannability: "manual",
      status: "pass",
      evidence_file_count: 3,
      reviewed_at: null,
    },
    {
      control_id: "cct_iso_6_7",
      control_number: "A.6.7",
      title: "Remote working",
      theme: "PPL",
      scannability: "manual",
      status: "not_applicable",
      justification: "No remote working is permitted.",
      evidence_file_count: 0,
      reviewed_at: null,
    },
  ],
  summary: { passed: 1, not_applicable: 1 },
  total: 2,
};
const FINDINGS = [
  {
    id: "f-2",
    control_id: "A.5.24",
    control_title: "Incident management planning",
    control_description: "Plan and prepare for information security incidents.",
    control_evidence_checklist: ["Incident response plan"],
    severity: "MEDIUM",
    source: "manual",
    status: "manual_review",
  },
];
const file = (id, filename, size) => ({
  id,
  filename,
  content_type: "application/pdf",
  size_bytes: size,
  sha256: "0".repeat(64),
  uploaded_by: 7,
  uploaded_at: "2026-09-01T10:00:00+00:00",
});
const START_EVIDENCE = () => ({
  cct_iso_5_1: [
    file("cef_policy", "access-policy.pdf", 2048),
    file("cef_signoff", "sign-off.png", 1536),
    file("cef_notes", "notes.txt", 400),
  ],
  cct_iso_6_7: [],
  "A.5.24": [],
});
const ACCEPT = ".pdf,.png,.jpg,.jpeg,.gif,.txt,.csv,.doc,.docx,.xls,.xlsx";
const MB = 1024 * 1024;
const upload = (name, size, type = "application/pdf") => {
  const f = new File(["x"], name, { type });
  Object.defineProperty(f, "size", { value: size });
  return f;
};
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
let evidence;
let evidenceRead;
let postReply;
let deleteReply;
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
const evidenceUrl = (id) => `/compliance/controls/${id}/evidence`;

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
const click = async (el, init) => {
  fireEvent.click(el, init);
  await flush();
};
const change = async (el, value) => {
  fireEvent.change(el, { target: { value } });
  await flush();
};
const pick = async (input, f) => {
  fireEvent.change(input, { target: { files: [f] } });
  await flush();
};
const rowOf = (first) =>
  [...document.querySelectorAll("tbody tr")].find(
    (r) => r.cells.length > 1 && squash(r.cells[0]) === first,
  );
const DIALOG = "Control Manual Attestation";
const dialog = () => screen.getByRole("dialog", { name: DIALOG });
const noDialog = () => expect(screen.queryByRole("dialog")).toBeNull();
const openAttest = async (controlNumber) => {
  await openTab("Controls");
  await click(
    within(rowOf(controlNumber)).getByRole("button", { name: "Attest" }),
  );
  return dialog();
};
const openVerify = async (controlId) => {
  await openTab("Findings");
  await click(within(rowOf(controlId)).getByRole("button", { name: "Verify" }));
  return dialog();
};
const statusSelect = (box) =>
  [...box.querySelectorAll("select")].find(
    (s) =>
      [...s.options].map((o) => o.value).join(",") ===
      "pass,fail,not_applicable",
  );
const textareas = (box) => [...box.querySelectorAll("textarea")];
const picker = (box) => box.querySelector('input[type="file"]');
// A listed file: the list item carrying its name.
const itemOf = (box, name) =>
  [...box.querySelectorAll("li")].find((li) =>
    (li.textContent || "").includes(name),
  );
const listedFiles = (box) =>
  ["access-policy.pdf", "sign-off.png", "notes.txt", "audit-log.csv"].filter(
    (n) => itemOf(box, n),
  );
const removeOf = (box, name) =>
  within(itemOf(box, name)).getByRole("button", { name: /^Remove\b/ });
// Removes a file the way a person does: Remove, then — where the dialog asks
// first — the confirmation.
const removeFile = async (box, name) => {
  await click(removeOf(box, name));
  const confirm = within(box).queryByRole("button", { name: "Delete file" });
  if (confirm) await click(confirm);
};
const saveButton = (box) =>
  within(box).getByRole("button", { name: "Save Attestation" });

beforeEach(() => {
  user = ANALYST;
  evidence = START_EVIDENCE();
  evidenceRead = (id) =>
    Promise.resolve({ data: { data: [...(evidence[id] || [])] } });
  postReply = (url, body) => {
    const m = url.match(/^\/compliance\/controls\/([^/]+)\/evidence$/);
    if (m) {
      const f = body.get("file");
      evidence[m[1]] = [
        file("cef_new", f.name, f.size),
        ...(evidence[m[1]] || []),
      ];
      return Promise.resolve({ data: { id: "cef_new", filename: f.name } });
    }
    return Promise.resolve({ data: {} });
  };
  deleteReply = (url) => {
    const id = url.split("/").pop();
    for (const k of Object.keys(evidence))
      evidence[k] = evidence[k].filter((f) => f.id !== id);
    return Promise.resolve({ data: { message: "Evidence file removed" } });
  };
  Element.prototype.scrollIntoView = vi.fn();
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url) => {
    const m = url.match(/^\/compliance\/controls\/([^/]+)\/evidence$/);
    if (m) return evidenceRead(m[1]);
    if (url === "/compliance/marketplace")
      return Promise.resolve({ data: { data: [] } });
    if (url.startsWith("/compliance/summary"))
      return Promise.resolve({
        data: { score_pct: 70, weighted_score_pct: 60, kpis: {} },
      });
    if (url.startsWith("/compliance/frameworks/"))
      return Promise.resolve({ data: CONTROLS });
    if (url.startsWith("/compliance/findings"))
      return Promise.resolve({ data: { data: FINDINGS } });
    return Promise.resolve({ data: { data: [] } });
  });
  api.post.mockImplementation((...args) => postReply(...args));
  api.delete.mockImplementation((...args) => deleteReply(...args));
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
  consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  // Only the attestation, an evidence upload and an evidence removal are ever
  // sent. A removal carries nothing but its URL. Nothing is put or patched,
  // nothing is downloaded, the browser's confirm is never used, and no
  // credential, remediation or report is read.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls)
    expect(url).toMatch(
      /^\/compliance\/controls\/(cct_iso_[0-9_]+|A\.5\.24)\/(evidence|attest)$/,
    );
  for (const args of api.delete.mock.calls) {
    expect(args).toHaveLength(1);
    expect(args[0]).toMatch(/^\/compliance\/evidence\/cef_[a-z]+$/);
  }
  for (const url of gets())
    expect(url).not.toMatch(/download|credentials|remediations|reports/);
  expect(confirmSpy).not.toHaveBeenCalled();
  confirmSpy.mockRestore();
  consoleError.mockRestore();
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace attestation and evidence — contract", () => {
  describe("Opening the dialog", () => {
    it("Attest opens the dialog for its control, reads only that control's evidence and sends nothing", async () => {
      await mount();
      await openTab("Controls");
      const before = gets().length;
      await click(
        within(rowOf("A.5.1")).getByRole("button", { name: "Attest" }),
      );
      const box = dialog();
      expect(gets().slice(before)).toEqual([evidenceUrl("cct_iso_5_1")]);
      expect(squash(box)).toContain(
        "A.5.1 — Policies for information security",
      );
      expect(squash(box)).toContain(
        "Information security policy defined and approved.",
      );

      const status = statusSelect(box);
      expect(status.value).toBe("pass");
      expect([...status.options].map((o) => o.textContent.trim())).toEqual([
        "Applicable — implemented",
        "Applicable — not implemented",
        "Not applicable — excluded from scope",
      ]);
      const [justification, note] = textareas(box);
      expect(justification).not.toBeRequired();
      expect(justification).toHaveValue("");
      expect(justification).toHaveAttribute(
        "placeholder",
        "Why this control is applicable — defaults to the control objective if left blank.",
      );
      expect(squash(box)).toContain("Justification for inclusion");
      expect(squash(box)).not.toContain("6.1.3(d)");
      expect(note).toBeRequired();
      expect(note).toHaveValue("");
      const review = box.querySelector('input[type="date"]');
      expect(review).toHaveValue("");
      expect(review).not.toBeRequired();
      for (const item of [
        "Audit evidence expected for this control",
        "Approved information security policy",
        "Management sign-off record",
        "Attached evidence",
      ])
        expect(squash(box)).toContain(item);
      expect(saveButton(box)).toHaveAttribute("type", "submit");
      expect(api.post).not.toHaveBeenCalled();
      expect(api.delete).not.toHaveBeenCalled();
    });

    it("a control already excluded opens as not applicable, its justification required and the clause explained", async () => {
      await mount();
      const box = await openAttest("A.6.7");
      expect(statusSelect(box).value).toBe("not_applicable");
      const [justification] = textareas(box);
      expect(justification).toBeRequired();
      expect(justification).toHaveValue("No remote working is permitted.");
      expect(justification).toHaveAttribute(
        "placeholder",
        "Why this control does not apply to the organization's ISMS scope.",
      );
      expect(squash(box)).toContain("Justification for exclusion");
      expect(squash(box)).toContain(
        "ISO/IEC 27001:2022 clause 6.1.3(d) requires every exclusion to carry a documented justification.",
      );
      expect(squash(box)).not.toContain(
        "Audit evidence expected for this control",
      );

      await change(statusSelect(box), "pass");
      expect(textareas(box)[0]).not.toBeRequired();
      expect(squash(box)).toContain("Justification for inclusion");
      expect(squash(box)).not.toContain("6.1.3(d)");
    });

    it("Verify on a finding awaiting review opens the same dialog for the finding's control", async () => {
      await mount();
      await openTab("Findings");
      const before = gets().length;
      await click(
        within(rowOf("A.5.24")).getByRole("button", { name: "Verify" }),
      );
      const box = dialog();
      expect(gets().slice(before)).toEqual([evidenceUrl("A.5.24")]);
      // As found: a finding carries no control number, and the control's
      // context is shown only when there is one — so the dialog opened from
      // a finding does not say which control it attests. Its checklist shows.
      expect(squash(box)).not.toContain("Incident management planning");
      expect(squash(box)).not.toContain(
        "Plan and prepare for information security incidents.",
      );
      expect(squash(box)).toContain("Incident response plan");
      expect(statusSelect(box).value).toBe("pass");
    });

    it("closing by the Close button or Escape sends nothing", async () => {
      await mount();
      await openAttest("A.5.1");
      await click(screen.getByRole("button", { name: "Close" }));
      noDialog();
      await click(
        within(rowOf("A.5.1")).getByRole("button", { name: "Attest" }),
      );
      fireEvent.keyDown(document, { key: "Escape" });
      await flush();
      noDialog();
      expect(api.post).not.toHaveBeenCalled();
      expect(api.delete).not.toHaveBeenCalled();
    });
  });

  describe("The evidence list", () => {
    it("each file shows its name and size with a Remove action — nothing else about it, and no download", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      expect(listedFiles(box)).toEqual([
        "access-policy.pdf",
        "sign-off.png",
        "notes.txt",
      ]);
      expect(squash(itemOf(box, "access-policy.pdf"))).toMatch(
        /^📎 access-policy\.pdf \(2 KB\)\s*Remove$/,
      );
      expect(squash(itemOf(box, "sign-off.png"))).toContain(
        "sign-off.png (2 KB)",
      );
      expect(squash(itemOf(box, "notes.txt"))).toContain("notes.txt (0 KB)");
      for (const name of listedFiles(box))
        expect(removeOf(box, name)).toBeEnabled();
      expect(box.querySelectorAll("a")).toHaveLength(0);
      for (const hidden of ["0000000000", "application/pdf", "2026-09-01"])
        expect(squash(box)).not.toContain(hidden);
    });

    it("a control with no evidence, or evidence that cannot be read, lists nothing", async () => {
      await mount();
      let box = await openAttest("A.6.7");
      expect(box.querySelectorAll("li")).toHaveLength(0);
      await click(screen.getByRole("button", { name: "Close" }));

      evidenceRead = () => Promise.reject(new Error("Network Error"));
      box = await openAttest("A.5.1");
      expect(listedFiles(box)).toEqual([]);
      expect(consoleError).toHaveBeenCalledWith(
        "Failed to load control evidence",
        expect.any(Error),
      );
    });
  });

  describe("Upload", () => {
    it("the picker offers the accepted evidence types", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      expect(picker(box)).toHaveAttribute("accept", ACCEPT);
      expect(picker(box)).toBeEnabled();
      expect(picker(box)).not.toHaveAttribute("multiple");
    });

    it("choosing a file posts it as multipart form data under `file`, says so, re-reads the list and clears the picker", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      const before = gets().length;
      const chosen = upload("audit-log.csv", 4096, "text/csv");
      await pick(picker(box), chosen);
      expect(api.post).toHaveBeenCalledTimes(1);
      const [url, form, config] = api.post.mock.calls[0];
      expect(url).toBe(evidenceUrl("cct_iso_5_1"));
      expect(form).toBeInstanceOf(FormData);
      expect([...form.keys()]).toEqual(["file"]);
      expect(form.get("file").name).toBe("audit-log.csv");
      expect(config).toEqual({
        headers: { "Content-Type": "multipart/form-data" },
      });
      expect(bodyText()).toContain("Attached audit-log.csv.");
      expect(gets().slice(before)).toEqual([evidenceUrl("cct_iso_5_1")]);
      expect(itemOf(box, "audit-log.csv")).toBeTruthy();
      expect(picker(box)).toHaveValue("");
    });

    it("an empty file, or one above 25 MB, is refused before anything is sent; 25 MB exactly is sent", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      await pick(picker(box), upload("empty.txt", 0, "text/plain"));
      expect(bodyText()).toContain("empty.txt is empty.");
      await pick(picker(box), upload("big.pdf", 25 * MB + 1));
      expect(bodyText()).toContain(
        "big.pdf is 25.0 MB, above the 25 MB evidence limit.",
      );
      expect(api.post).not.toHaveBeenCalled();
      await pick(picker(box), upload("limit.pdf", 25 * MB));
      expect(api.post).toHaveBeenCalledTimes(1);
    });

    it("while a file uploads the picker is disabled and the dialog says Uploading…", async () => {
      const pending = deferred();
      postReply = () => pending.promise;
      await mount();
      const box = await openAttest("A.5.1");
      await pick(picker(box), upload("audit-log.csv", 4096, "text/csv"));
      expect(picker(box)).toBeDisabled();
      expect(squash(box)).toContain("Uploading…");
      await act(async () => pending.resolve({ data: {} }));
      await flush();
      expect(picker(box)).toBeEnabled();
      expect(squash(box)).not.toContain("Uploading…");
    });

    it("a refused upload reports the API's detail, or the error's message, and re-reads nothing", async () => {
      postReply = () => Promise.reject(refusal("Upload a PDF, image, text."));
      await mount();
      const box = await openAttest("A.5.1");
      const before = gets().length;
      await pick(picker(box), upload("malware.pdf", 4096));
      expect(bodyText()).toContain(
        "Could not attach evidence: Upload a PDF, image, text.",
      );
      postReply = () => Promise.reject(new Error("Network Error"));
      await pick(picker(box), upload("again.pdf", 4096));
      expect(bodyText()).toContain("Could not attach evidence: Network Error");
      expect(gets().slice(before)).toEqual([]);
      expect(picker(box)).toBeEnabled();
    });

    it("from Verify, the file is attached to the finding's control", async () => {
      await mount();
      const box = await openVerify("A.5.24");
      await pick(picker(box), upload("ir-plan.pdf", 4096));
      expect(api.post.mock.calls[0][0]).toBe(evidenceUrl("A.5.24"));
    });
  });

  describe("Removal", () => {
    it("removing a file sends one DELETE for it, re-reads the list and says so", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      const before = gets().length;
      await removeFile(box, "sign-off.png");
      expect(api.delete.mock.calls).toEqual([
        ["/compliance/evidence/cef_signoff"],
      ]);
      expect(gets().slice(before)).toEqual([evidenceUrl("cct_iso_5_1")]);
      expect(bodyText()).toContain("Evidence removed.");
      expect(listedFiles(box)).toEqual(["access-policy.pdf", "notes.txt"]);
      expect(dialog()).toBeInTheDocument();
    });

    it("a refused removal reports the API's detail, or the error's message, and keeps the file", async () => {
      deleteReply = () => Promise.reject(refusal("Evidence file not found"));
      await mount();
      const box = await openAttest("A.5.1");
      const before = gets().length;
      await removeFile(box, "notes.txt");
      expect(bodyText()).toContain(
        "Could not remove evidence: Evidence file not found",
      );
      deleteReply = () => Promise.reject(new Error("Network Error"));
      await removeFile(box, "notes.txt");
      expect(bodyText()).toContain("Could not remove evidence: Network Error");
      expect(listedFiles(box)).toContain("notes.txt");
      expect(gets().slice(before)).toEqual([]);
    });
  });

  describe("Saving the attestation", () => {
    it("saving sends the status, note, justification, review date and the listed files' ids, closes, says so and re-reads", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      await change(statusSelect(box), "fail");
      const [justification, note] = textareas(box);
      await change(justification, "Policy drafted, not yet signed");
      await change(box.querySelector('input[type="date"]'), "2026-12-01");
      await change(note, "Reviewed with the CISO");
      const before = gets().length;
      await click(saveButton(box));
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/controls/cct_iso_5_1/attest",
          {
            status: "fail",
            note: "Reviewed with the CISO",
            justification: "Policy drafted, not yet signed",
            next_review_at: new Date("2026-12-01").toISOString(),
            evidence_file_ids: ["cef_policy", "cef_signoff", "cef_notes"],
          },
        ],
      ]);
      noDialog();
      expect(bodyText()).toContain("Attestation recorded.");
      expect(
        gets()
          .slice(before)
          .some((u) => u.startsWith("/compliance/frameworks/")),
      ).toBe(true);
    });

    it("a blank justification and review date are sent as null, with no files", async () => {
      await mount();
      const box = await openVerify("A.5.24");
      await change(textareas(box)[1], "Plan reviewed");
      await click(saveButton(box));
      expect(api.post.mock.calls).toEqual([
        [
          "/compliance/controls/A.5.24/attest",
          {
            status: "pass",
            note: "Plan reviewed",
            justification: null,
            next_review_at: null,
            evidence_file_ids: [],
          },
        ],
      ]);
    });

    it("excluding a control with a blank justification is refused before anything is sent", async () => {
      await mount();
      const box = await openAttest("A.5.1");
      await change(statusSelect(box), "not_applicable");
      const [justification, note] = textareas(box);
      await change(justification, "   ");
      await change(note, "Out of scope");
      await click(saveButton(box));
      expect(bodyText()).toContain(
        "Excluding a control requires a justification — it is a mandatory part of the Statement of Applicability.",
      );
      expect(api.post).not.toHaveBeenCalled();
      expect(dialog()).toBeInTheDocument();
    });

    it("a refused attestation stays open with the API's detail, and Save stays enabled while it is sent", async () => {
      const pending = deferred();
      postReply = () => pending.promise;
      await mount();
      const box = await openAttest("A.5.1");
      await change(textareas(box)[1], "Reviewed");
      await click(saveButton(box));
      expect(saveButton(box)).toBeEnabled();
      await act(async () =>
        pending.reject(refusal("Missing permission compliance:attest")),
      );
      await flush();
      expect(bodyText()).toContain(
        "Failed to submit attestation: Missing permission compliance:attest",
      );
      expect(dialog()).toBeInTheDocument();
    });
  });

  describe("Permissions", () => {
    it("nothing is hidden or disabled for a user without attest permission; the server's refusal is what they see", async () => {
      user = VIEWER;
      postReply = () =>
        Promise.reject(refusal("Missing permission compliance:attest"));
      deleteReply = () =>
        Promise.reject(refusal("Missing permission compliance:attest"));
      await mount();
      const box = await openAttest("A.5.1");
      expect(picker(box)).toBeEnabled();
      expect(removeOf(box, "notes.txt")).toBeEnabled();
      expect(saveButton(box)).toBeEnabled();
      await pick(picker(box), upload("audit-log.csv", 4096, "text/csv"));
      expect(bodyText()).toContain(
        "Could not attach evidence: Missing permission compliance:attest",
      );
      await removeFile(box, "notes.txt");
      expect(bodyText()).toContain(
        "Could not remove evidence: Missing permission compliance:attest",
      );
      expect(listedFiles(box)).toContain("notes.txt");
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 28 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const LEGACY = /^(db-|compliance-form$|mono$)/;
const expectClean = (root) => {
  expect(root).toBeTruthy();
  expect([...root.querySelectorAll("[style]")]).toEqual([]);
  const classes = [root, ...root.querySelectorAll("[class]")].flatMap((el) => [
    ...el.classList,
  ]);
  expect(classes.filter((c) => LEGACY.test(c))).toEqual([]);
};
const describedText = (el) =>
  (el.getAttribute("aria-describedby") || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => squash(document.getElementById(id)))
    .join(" ");

describe("ComplianceWorkspace attestation and evidence — batch 28", () => {
  it("the attestation fields are labelled, and an exclusion's justification is required and described by the clause", async () => {
    await mount();
    const box = await openAttest("A.5.1");
    expect(within(box).getByLabelText(/^Applicability & Status/).tagName).toBe(
      "SELECT",
    );
    const inclusion = within(box).getByLabelText(
      /^Justification for inclusion/,
    );
    expect(inclusion.tagName).toBe("TEXTAREA");
    expect(inclusion).not.toBeRequired();
    expect(within(box).getByLabelText(/^Next review date/)).toHaveAttribute(
      "type",
      "date",
    );
    const note = within(box).getByLabelText(/^Reviewer note/);
    expect(note.tagName).toBe("TEXTAREA");
    expect(note).toBeRequired();

    await change(statusSelect(box), "not_applicable");
    const exclusion = within(box).getByLabelText(
      /^Justification for exclusion/,
    );
    expect(exclusion).toBeRequired();
    expect(describedText(exclusion)).toMatch(/clause 6\.1\.3\(d\)/);
    expect(
      within(box).getByRole("button", { name: "Save Attestation" }),
    ).toHaveClass("cc-btn");
  });

  it("the checklist and the attached evidence are lists named by their headings", async () => {
    await mount();
    const box = await openAttest("A.5.1");
    const checklist = within(box).getByRole("heading", {
      level: 3,
      name: "Audit evidence expected for this control",
    });
    expect(
      within(box).getByRole("list", { name: checklist.textContent }),
    ).toBeInTheDocument();
    const attached = within(box).getByRole("heading", {
      level: 3,
      name: "Attached evidence",
    });
    const files = within(box).getByRole("list", { name: "Attached evidence" });
    expect(files.getAttribute("aria-labelledby")).toBe(attached.id);
    expect(within(files).getAllByRole("listitem")).toHaveLength(3);
    expectClean(box.querySelector("form"));
  });

  it("the file picker is labelled, described by the accepted types and the limit, and an upload is announced", async () => {
    const pending = deferred();
    postReply = () => pending.promise;
    await mount();
    const box = await openAttest("A.5.1");
    const input = within(box).getByLabelText(/^Add evidence file/);
    expect(input).toHaveAttribute("type", "file");
    expect(describedText(input)).toMatch(/PDF.*XLSX.*25 MB/);
    await pick(input, upload("audit-log.csv", 4096, "text/csv"));
    expect(squash(within(box).getByRole("status"))).toBe("Uploading…");
    await act(async () => pending.resolve({ data: {} }));
    await flush();
    expect(within(box).queryByRole("status")).toBeNull();
  });

  it("each Remove action is named for its file", async () => {
    await mount();
    const box = await openAttest("A.5.1");
    for (const name of ["access-policy.pdf", "sign-off.png", "notes.txt"])
      expect(
        within(itemOf(box, name)).getByRole("button", {
          name: `Remove ${name}`,
        }),
      ).toBeInTheDocument();
  });

  it("Remove asks first: nothing is sent until Delete file, and Keep file or Escape backs out with focus returned", async () => {
    await mount();
    const box = await openAttest("A.5.1");
    await click(removeOf(box, "access-policy.pdf"));
    expect(api.delete).not.toHaveBeenCalled();
    const ask = within(box).getByRole("group", {
      name: /^Delete access-policy\.pdf\?/,
    });
    const keep = within(ask).getByRole("button", { name: "Keep file" });
    expect(document.activeElement).toBe(keep);
    expect(
      within(ask).getByRole("button", { name: "Delete file" }),
    ).toHaveClass("cc-btn--danger");

    await click(keep);
    expect(within(box).queryByRole("group")).toBeNull();
    expect(document.activeElement).toBe(removeOf(box, "access-policy.pdf"));

    await click(removeOf(box, "access-policy.pdf"));
    fireEvent.keyDown(document.activeElement, { key: "Escape" });
    await flush();
    expect(dialog()).toBeInTheDocument();
    expect(within(box).queryByRole("group")).toBeNull();
    expect(document.activeElement).toBe(removeOf(box, "access-policy.pdf"));
    expect(api.delete).not.toHaveBeenCalled();

    await click(removeOf(box, "access-policy.pdf"));
    await click(within(box).getByRole("button", { name: "Delete file" }));
    expect(api.delete.mock.calls).toEqual([
      ["/compliance/evidence/cef_policy"],
    ]);
  });

  it("a double-click cannot delete, a removal in flight cannot be sent twice, and focus lands on the list's heading", async () => {
    const pending = deferred();
    deleteReply = () => pending.promise;
    await mount();
    const box = await openAttest("A.5.1");
    await click(removeOf(box, "sign-off.png"), { detail: 1 });
    await click(within(box).getByRole("button", { name: "Delete file" }), {
      detail: 2,
    });
    expect(api.delete).not.toHaveBeenCalled();

    const del = within(box).getByRole("button", { name: "Delete file" });
    await click(del, { detail: 1 });
    await click(del, { detail: 1 });
    expect(api.delete).toHaveBeenCalledTimes(1);
    expect(del).toBeDisabled();
    expect(del).toHaveAttribute("aria-busy", "true");
    expect(
      within(box).getByRole("button", { name: "Keep file" }),
    ).toBeDisabled();

    evidence.cct_iso_5_1 = evidence.cct_iso_5_1.filter(
      (f) => f.id !== "cef_signoff",
    );
    await act(async () => pending.resolve({ data: {} }));
    await flush();
    expect(listedFiles(box)).toEqual(["access-policy.pdf", "notes.txt"]);
    expect(document.activeElement).toBe(
      within(box).getByRole("heading", { level: 3, name: "Attached evidence" }),
    );
  });

  it("a refused removal closes the question and returns focus to that file's Remove", async () => {
    deleteReply = () => Promise.reject(refusal("Evidence file not found"));
    await mount();
    const box = await openAttest("A.5.1");
    await click(removeOf(box, "notes.txt"));
    await click(within(box).getByRole("button", { name: "Delete file" }));
    expect(api.delete).toHaveBeenCalledTimes(1);
    expect(within(box).queryByRole("group")).toBeNull();
    expect(document.activeElement).toBe(removeOf(box, "notes.txt"));
  });

  it("the migrated source uses design-system parts and its stylesheet is token-only", () => {
    const source = readFileSync(
      path.join(SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-attestation\.css["']/,
    );
    const at = (needle, from = 0) => {
      const i = source.indexOf(needle, from);
      expect(i).toBeGreaterThan(-1);
      return i;
    };
    const component = at("function AttestationEvidence(");
    const dialogBody = source.slice(
      at('{modalType === "attest" && ('),
      at('{modalType === "exception" && ('),
    );
    for (const block of [
      source.slice(component, source.indexOf("\n}\n", component)),
      dialogBody,
    ]) {
      expect(block).not.toMatch(/style=\{/);
      expect(block.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
      expect(block).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
      expect(block).not.toMatch(
        /className=["{`][^"}`]*\b(db-|compliance-form|mono\b)/,
      );
      expect(block).not.toMatch(/<(button|select|label)\b/);
      expect(block).toMatch(/<Ccure[A-Z]/);
    }
    // The one native input left is the file picker, which has no primitive.
    expect(dialogBody.match(/<input\b/g) || []).toHaveLength(1);
    expect(dialogBody).toMatch(/<input\s+id="cwa-evidence-file"\s+type="file"/);

    const cssPath = path.join(SRC, "styles/compliance-attestation.css");
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
    for (const s of selectors) expect(s).toMatch(/\.cwa-/);
  });
});
