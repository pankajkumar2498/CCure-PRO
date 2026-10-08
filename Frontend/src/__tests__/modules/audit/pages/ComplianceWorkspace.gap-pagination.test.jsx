/**
 * ComplianceWorkspace (`/compliance`) — the gap-analysis dialog and the
 * Credentials Manager's pager. Checkpoint 3C batch 31 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 31 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The header's Gap Analysis reads GET /compliance/gap-analysis for the gap
 * source against the header's framework — or the gap target, with All
 * Frameworks chosen — and opens the result: the pair, the estimated score, four
 * counts and every target control with its mapped source controls and
 * estimated status. In the dialog, Source Baseline and Target Mandate choose a
 * pair that is read only when Recalculate Gap is pressed; a refusal is reported
 * and the previous result kept. The Credentials Manager's list pages on the
 * client, 25 to a page by default, offering 10, 25, 50 or 100, and paging reads
 * nothing.
 *
 * Only the axios instance, the shell and the signed-in user are replaced.
 * Nothing on this surface writes: every request is a GET.
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
import { personaFrom } from "../../../fixtures/authorization";

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
  useAuth: () => ({ user: personaFrom(user) }),
}));

const ADMIN = {
  id: 7,
  username: "operator",
  role: { name: "Org Admin" },
  permissionKeys: ["audit.compliance.read"],
};

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const ACTIVE = ["cfw_iso27001_2022", "cfw_nist_csf_v2", "cfw_nis2"];
const LONG_NAMES = [
  "ISO 27001:2022 (Information Security)",
  "NIST CSF 2.0 (Cybersecurity Framework)",
  "EU NIS 2 Directive (Directive 2022/2555)",
];
const ISO = {
  id: "cfw_iso27001_2022",
  name: "ISO/IEC 27001:2022",
  code: "ISO27001",
};
const NIS2 = { id: "cfw_nis2", name: "EU NIS 2 Directive", code: "NIS2" };
const NIST = {
  id: "cfw_nist_csf_v2",
  name: "NIST CSF v2.0",
  code: "NIST_CSF_2",
};
// A target control as GET /compliance/gap-analysis lists it.
const control = (number, title, crosswalk, status) => ({
  control_id: `cct_${number.replace(/\W/g, "_")}`,
  control_number: number,
  theme: "GOVERNANCE",
  title,
  crosswalk,
  estimated_status: status,
});
const GAP = {
  source_framework: ISO,
  target_framework: NIS2,
  summary: {
    total_target_controls: 4,
    mapped_controls: 3,
    estimated_pass: 1,
    estimated_fail: 1,
    pending_manual: 2,
    estimated_score_pct: 25,
  },
  controls: [
    control(
      "21.2.a",
      "Risk analysis and information system security policies",
      ["ISO27001:A.5.1", "ISO27001:A.8.8"],
      "fail",
    ),
    control("21.2.b", "Incident handling", ["A.5.24"], "pass"),
    control(
      "21.2.c",
      "Business continuity and crisis management",
      ["A.5.29"],
      "pending_manual",
    ),
    control("23.1", "Reporting obligations", [], "pending_manual"),
  ],
};
const GAP_NIST = {
  source_framework: ISO,
  target_framework: NIST,
  summary: {
    total_target_controls: 2,
    mapped_controls: 2,
    estimated_pass: 2,
    estimated_fail: 0,
    pending_manual: 0,
    estimated_score_pct: 100,
  },
  controls: [
    control("GV.OC-01", "Organizational mission", ["A.5.1"], "pass"),
    control("PR.AA-01", "Identities and credentials", ["A.5.16"], "pass"),
  ],
};
// Saved credentials as the API lists them: references, no secret.
const fleet = (n) =>
  Array.from({ length: n }, (_, i) => ({
    id: `cred-${i + 1}`,
    name: `Fleet ${String(i + 1).padStart(2, "0")}`,
    username: "auditor",
    auth_method: "password",
    port: 22,
    created_at: "2026-08-01T10:00:00Z",
  }));
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
  response: { status: 400, data: { detail } },
  message: "Request failed with status code 400",
});

/* ── Harness ────────────────────────────────────────────────────────────── */
let credentials;
let gapReply;
let scrolled;

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
const click = async (el) => {
  fireEvent.click(el);
  await flush();
};
const change = async (el, value) => {
  fireEvent.change(el, { target: { value } });
  await flush();
};
const gets = () => api.get.mock.calls.map(([u]) => u);
const gapReads = () =>
  gets().filter((u) => u.startsWith("/compliance/gap-analysis"));
const credentialReads = () =>
  gets().filter((u) => u === "/compliance/credentials").length;
const GAP_URL = (source, target) =>
  `/compliance/gap-analysis?source_framework_id=${source}&target_framework_id=${target}`;

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
const frameworkSelect = () =>
  [...document.querySelectorAll("select")].find((s) =>
    [...s.options].some(
      (o) => o.value === "all" && o.textContent === "All Frameworks",
    ),
  );
// The header's trigger, which reads "Calculating..." while a read is out.
const gapButton = () =>
  [...document.querySelectorAll("button")].find((b) =>
    /Gap Analysis/.test(squash(b)),
  );
const dialog = () => screen.queryByRole("dialog");
const openGap = async () => {
  await mount();
  await click(gapButton());
  return dialog();
};
const recalcButton = (box) =>
  [...box.querySelectorAll("button")].find((b) =>
    /Recalculate Gap|Calculating/.test(squash(b)),
  );
const resultTable = (box) => box.querySelector("table");
const headerCells = (box) =>
  [...resultTable(box).tHead.rows[0].cells].map((c) => squash(c));
const controlRows = (box) =>
  [...resultTable(box).tBodies[0].rows].filter((r) => r.cells.length > 1);
const leafTexts = (cell) =>
  [...cell.querySelectorAll("span")]
    .filter((s) => s.children.length === 0)
    .map((s) => squash(s))
    .filter(Boolean);
const rowOf = (r) => [
  squash(r.cells[0]),
  squash(r.cells[1]),
  leafTexts(r.cells[2]),
  squash(r.cells[3]),
];

// Pager, by what either pager calls its parts.
const pageStatus = () => bodyText().match(/Page (\d+) of (\d+)/)?.[0];
const sizeSelect = () =>
  [...document.querySelectorAll("select")].find(
    (s) => [...s.options].map((o) => o.value).join(",") === "10,25,50,100",
  );
const buttonNamed = (...patterns) => {
  for (const name of patterns) {
    const found = screen.queryAllByRole("button", { name });
    if (found.length === 1) return found[0];
  }
  throw new Error(`no single button named ${patterns.join(" or ")}`);
};
const nextButton = () => buttonNamed(/^Next$/);
const previousButton = () => buttonNamed(/^Prev$/, /^Previous$/);
const firstButton = () => buttonNamed(/^«$/, /^First page$/);
const lastButton = () => buttonNamed(/^»$/, /^Last page$/);
const credentialRows = () =>
  [...document.querySelectorAll("tbody tr")].filter((r) =>
    /Fleet \d\d/.test(r.textContent || ""),
  );

beforeEach(() => {
  user = ADMIN;
  credentials = fleet(2);
  gapReply = () => Promise.resolve({ data: GAP });
  scrolled = [];
  Element.prototype.scrollIntoView = vi.fn(function (options) {
    scrolled.push({ element: this, options });
  });
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url) => {
    if (url === "/compliance/marketplace")
      return Promise.resolve({
        data: { data: [], active_framework_ids: ACTIVE },
      });
    if (url.startsWith("/compliance/gap-analysis")) return gapReply(url);
    if (url === "/compliance/credentials")
      return Promise.resolve({ data: credentials.map((c) => ({ ...c })) });
    if (url.startsWith("/compliance/summary"))
      return Promise.resolve({
        data: { score_pct: 70, weighted_score_pct: 60, kpis: {} },
      });
    return Promise.resolve({ data: { data: [] } });
  });
});

afterEach(() => {
  cleanup();
  // Nothing on this surface writes.
  expect(api.post).not.toHaveBeenCalled();
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  // A gap analysis names two frameworks and nothing else.
  for (const url of gapReads()) {
    expect(url).toMatch(
      /^\/compliance\/gap-analysis\?source_framework_id=cfw_[a-z0-9_]+&target_framework_id=cfw_[a-z0-9_]+$/,
    );
  }
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace gap analysis and pagination — contract", () => {
  describe("Gap analysis", () => {
    it("Gap Analysis reads the gap source against the gap target once and opens the result: the pair, its names, the score and four counts", async () => {
      const box = await openGap();
      expect(gapReads()).toEqual([GAP_URL("cfw_iso27001_2022", "cfw_nis2")]);
      expect(box).toBeTruthy();
      const text = squash(box);
      expect(text).toMatch(/ISO27001 .*to NIS2/);
      expect(text).toContain(
        "Estimated baseline compliance posture for EU NIS 2 Directive based on existing ISO/IEC 27001:2022 scan findings.",
      );
      expect(text).toContain("25%");
      expect(text).toMatch(/Target Controls:?\s*4/);
      expect(text).toMatch(/Crosswalk Mapped:?\s*3/);
      expect(text).toMatch(/Estimated Pass:?\s*1/);
      expect(text).toMatch(/Estimated Fail:?\s*1/);
    });

    it("with a framework chosen in the header, Gap Analysis compares the gap source against that framework", async () => {
      gapReply = () => Promise.resolve({ data: GAP_NIST });
      await mount();
      await change(frameworkSelect(), "cfw_nist_csf_v2");
      await click(gapButton());
      expect(gapReads()).toEqual([
        GAP_URL("cfw_iso27001_2022", "cfw_nist_csf_v2"),
      ]);
      expect(squash(dialog())).toContain("100%");
    });

    it("Gap Analysis is disabled and says Calculating... while the read is out, and nothing opens until it settles", async () => {
      const pending = deferred();
      gapReply = () => pending.promise;
      await mount();
      const button = gapButton();
      await click(button);
      expect(button).toBeDisabled();
      expect(squash(button)).toContain("Calculating...");
      expect(dialog()).toBeNull();
      await act(async () => pending.resolve({ data: GAP }));
      await flush();
      expect(dialog()).toBeTruthy();
      expect(gapButton()).toBeEnabled();
    });

    it("lists every target control with its number, title, mapped source controls and estimated status", async () => {
      const box = await openGap();
      expect(headerCells(box)).toEqual([
        "NIS2 Control",
        "Title",
        "Mapped ISO27001 Controls",
        "Estimated Status",
      ]);
      expect(controlRows(box).map(rowOf)).toEqual([
        [
          "21.2.a",
          "Risk analysis and information system security policies",
          ["ISO27001:A.5.1", "ISO27001:A.8.8"],
          "fail",
        ],
        ["21.2.b", "Incident handling", ["A.5.24"], "pass"],
        [
          "21.2.c",
          "Business continuity and crisis management",
          ["A.5.29"],
          "pending_manual",
        ],
        ["23.1", "Reporting obligations", [], "pending_manual"],
      ]);
    });

    it("a result without framework codes names its columns Target and Source", async () => {
      gapReply = () =>
        Promise.resolve({
          data: { ...GAP, source_framework: {}, target_framework: {} },
        });
      const box = await openGap();
      expect(headerCells(box)).toEqual([
        "Target Control",
        "Title",
        "Mapped Source Controls",
        "Estimated Status",
      ]);
    });

    it("a comparison with no target controls lists none and counts zero", async () => {
      gapReply = () =>
        Promise.resolve({
          data: {
            ...GAP,
            summary: {
              total_target_controls: 0,
              mapped_controls: 0,
              estimated_pass: 0,
              estimated_fail: 0,
              pending_manual: 0,
              estimated_score_pct: 0,
            },
            controls: [],
          },
        });
      const box = await openGap();
      expect(controlRows(box)).toEqual([]);
      expect(squash(box)).toContain("0%");
      expect(squash(box)).toMatch(/Target Controls:?\s*0/);
    });

    it("Source Baseline and Target Mandate offer the active frameworks by long name and show the pair; choosing one reads nothing", async () => {
      const box = await openGap();
      expect(squash(box)).toMatch(/Source Baseline/);
      expect(squash(box)).toMatch(/Target Mandate/);
      const [source, target] = [...box.querySelectorAll("select")];
      for (const select of [source, target]) {
        expect([...select.options].map((o) => o.textContent)).toEqual(
          LONG_NAMES,
        );
      }
      expect(source.value).toBe("cfw_iso27001_2022");
      expect(target.value).toBe("cfw_nis2");
      await change(target, "cfw_nist_csf_v2");
      await change(source, "cfw_nis2");
      expect(target.value).toBe("cfw_nist_csf_v2");
      expect(source.value).toBe("cfw_nis2");
      expect(gapReads()).toHaveLength(1);
    });

    it("Recalculate Gap reads the chosen pair, says Calculating... and is disabled until the read settles, then shows the new result", async () => {
      const box = await openGap();
      const [, target] = [...box.querySelectorAll("select")];
      await change(target, "cfw_nist_csf_v2");
      const pending = deferred();
      gapReply = () => pending.promise;
      await click(recalcButton(box));
      expect(gapReads()).toEqual([
        GAP_URL("cfw_iso27001_2022", "cfw_nis2"),
        GAP_URL("cfw_iso27001_2022", "cfw_nist_csf_v2"),
      ]);
      expect(recalcButton(dialog())).toBeDisabled();
      expect(squash(recalcButton(dialog()))).toContain("Calculating...");
      // The previous result stays on screen while the new one is read.
      expect(squash(dialog())).toContain("25%");
      await act(async () => pending.resolve({ data: GAP_NIST }));
      await flush();
      expect(squash(dialog())).toMatch(/ISO27001 .*to NIST_CSF_2/);
      expect(squash(dialog())).toContain("100%");
      expect(controlRows(dialog())).toHaveLength(2);
      expect(recalcButton(dialog())).toBeEnabled();
      expect(squash(recalcButton(dialog()))).toContain("Recalculate Gap");
    });

    it("a refused recalculation reports the API's detail, then the error's message, and keeps the previous result", async () => {
      const box = await openGap();
      gapReply = () =>
        Promise.reject(refusal("Target framework is not active"));
      await click(recalcButton(box));
      expect(bodyText()).toContain(
        "Failed to run gap analysis: Target framework is not active",
      );
      expect(squash(dialog())).toContain("25%");
      expect(controlRows(dialog())).toHaveLength(4);
      gapReply = () => Promise.reject(new Error("Network Error"));
      await click(recalcButton(dialog()));
      expect(bodyText()).toContain("Failed to run gap analysis: Network Error");
      expect(controlRows(dialog())).toHaveLength(4);
    });

    it("a failed first read opens nothing and reports it", async () => {
      gapReply = () => Promise.reject(new Error("Network Error"));
      await mount();
      await click(gapButton());
      expect(dialog()).toBeNull();
      expect(bodyText()).toContain("Failed to run gap analysis: Network Error");
    });
  });

  describe("The Credentials Manager's pager", () => {
    it("pages thirty credentials 25 at a time with Next, Previous, Last and First, reading the list once", async () => {
      credentials = fleet(30);
      await mount();
      await openTab("Credentials Manager");
      expect(bodyText()).toContain("Showing 1–25 of 30 credentials");
      expect(pageStatus()).toBe("Page 1 of 2");
      expect(credentialRows()).toHaveLength(25);
      expect(previousButton()).toBeDisabled();

      await click(nextButton());
      expect(bodyText()).toContain("Showing 26–30 of 30 credentials");
      expect(pageStatus()).toBe("Page 2 of 2");
      expect(credentialRows()).toHaveLength(5);
      expect(credentialRows()[0].textContent).toContain("Fleet 26");
      expect(nextButton()).toBeDisabled();
      expect(lastButton()).toBeDisabled();

      await click(previousButton());
      expect(pageStatus()).toBe("Page 1 of 2");
      await click(lastButton());
      expect(pageStatus()).toBe("Page 2 of 2");
      await click(firstButton());
      expect(pageStatus()).toBe("Page 1 of 2");
      expect(credentialRows()[0].textContent).toContain("Fleet 01");
      expect(credentialReads()).toBe(1);
    });

    it("offers 10, 25, 50 or 100 per page, starting at 25, and a change returns to page 1", async () => {
      credentials = fleet(30);
      await mount();
      await openTab("Credentials Manager");
      expect(sizeSelect().value).toBe("25");
      await click(nextButton());
      await change(sizeSelect(), "10");
      expect(pageStatus()).toBe("Page 1 of 3");
      expect(credentialRows()).toHaveLength(10);
      expect(credentialRows()[0].textContent).toContain("Fleet 01");
      await change(sizeSelect(), "100");
      expect(pageStatus()).toBe("Page 1 of 1");
      expect(credentialRows()).toHaveLength(30);
      expect(credentialReads()).toBe(1);
    });

    it("a page change scrolls the list back into view", async () => {
      credentials = fleet(30);
      await mount();
      await openTab("Credentials Manager");
      expect(scrolled).toHaveLength(0);
      await click(nextButton());
      expect(scrolled).toHaveLength(1);
      expect(scrolled[0].options).toEqual({
        behavior: "smooth",
        block: "start",
      });
    });

    it("an empty list has one page and nowhere to move", async () => {
      credentials = [];
      await mount();
      await openTab("Credentials Manager");
      expect(pageStatus()).toBe("Page 1 of 1");
      expect(nextButton()).toBeDisabled();
      expect(previousButton()).toBeDisabled();
      expect(credentialRows()).toEqual([]);
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 31 — the specification. Each fails on the legacy page.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace gap analysis and pagination — batch 31", () => {
  it("the dialog's framework choices are labelled selects, no arrow is read aloud, and Recalculate Gap is busy while it calculates", async () => {
    const box = await openGap();
    const source = within(box).getByLabelText("Source Baseline");
    const target = within(box).getByLabelText("Target Mandate");
    expect(source.tagName).toBe("SELECT");
    expect(source.value).toBe("cfw_iso27001_2022");
    expect(target.tagName).toBe("SELECT");
    expect(target.value).toBe("cfw_nis2");
    const spokenArrows = [...box.querySelectorAll("*")].filter(
      (e) =>
        [...e.childNodes].some(
          (n) => n.nodeType === 3 && n.textContent.includes("➔"),
        ) && !e.closest('[aria-hidden="true"]'),
    );
    expect(spokenArrows).toEqual([]);

    const pending = deferred();
    gapReply = () => pending.promise;
    await click(within(box).getByRole("button", { name: /Recalculate Gap/ }));
    const busy = within(dialog()).getByRole("button", { name: /Calculating/ });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toBeDisabled();
    await act(async () => pending.resolve({ data: GAP }));
    await flush();
    expect(
      within(dialog()).getByRole("button", { name: /Recalculate Gap/ }),
    ).not.toHaveAttribute("aria-busy");
  });

  it("the result is a heading naming the pair, the score is labelled, and the counts are a description list", async () => {
    const box = await openGap();
    const heading = within(box).getByRole("heading", {
      name: "ISO27001 to NIS2",
    });
    expect(heading.tagName).toBe("H3");
    expect(within(box).getByText("Estimated score")).toBeTruthy();
    const list = box.querySelector("dl");
    expect(list).toBeTruthy();
    expect([...list.querySelectorAll("dt")].map((e) => squash(e))).toEqual([
      "Target Controls",
      "Crosswalk Mapped",
      "Estimated Pass",
      "Estimated Fail",
      /* P3-2: pass and fail alone imply the remainder is one or the other.
         On the live installation 100 of 106 controls are neither. */
      "Pending manual assessment",
    ]);
    expect([...list.querySelectorAll("dd")].map((e) => squash(e))).toEqual([
      "4",
      "3",
      "1",
      "1",
      // The fixture's own `pending_manual`, alongside pass and fail.
      "2",
    ]);
  });

  it("the breakdown is a captioned table in a named, keyboard-reachable scroll region; control numbers are row headers, and mapped controls and statuses are badges", async () => {
    const box = await openGap();
    const region = within(box).getByRole("region", {
      name: "Estimated status by control",
    });
    expect(region).toHaveAttribute("tabindex", "0");
    const table = within(region).getByRole("table", {
      name: "NIS2 controls estimated from ISO27001 findings",
    });
    expect(
      within(table)
        .getAllByRole("rowheader")
        .map((e) => squash(e)),
    ).toEqual(["21.2.a", "21.2.b", "21.2.c", "23.1"]);
    const rows = controlRows(box);
    expect(
      [...rows[0].cells[2].querySelectorAll(".cc-badge")].map((e) => squash(e)),
    ).toEqual(["ISO27001:A.5.1", "ISO27001:A.8.8"]);
    const statuses = rows.map((r) => r.cells[3].querySelector(".cc-badge"));
    expect(statuses.map((e) => squash(e))).toEqual([
      "fail",
      "pass",
      "pending_manual",
      "pending_manual",
    ]);
    expect(statuses[0]).toHaveClass("cc-badge--danger");
    expect(statuses[1]).toHaveClass("cc-badge--success");
    expect(statuses[2]).toHaveClass("cc-badge--info");
  });

  it("a comparison with no target controls says there is nothing to compare", async () => {
    gapReply = () => Promise.resolve({ data: { ...GAP, controls: [] } });
    const box = await openGap();
    expect(squash(box)).toContain("No target controls to compare.");
  });

  it("the Credentials Manager's pager is the design-system pager: a named navigation, a labelled page size, and First page and Last page", async () => {
    credentials = fleet(30);
    await mount();
    await openTab("Credentials Manager");
    const nav = screen.getByRole("navigation", {
      name: "Credentials pagination",
    });
    expect(within(nav).getByLabelText("Rows per page").value).toBe("25");
    expect(screen.getByRole("group", { name: "Jump to page" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "First page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Last page" })).toBeEnabled();
    expect(screen.queryAllByRole("button", { name: /^[«»]$/ })).toEqual([]);
  });

  it("the migrated source keeps the gap block's anchor, uses design-system parts, retires PaginationBar, and its stylesheets are token-only", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-gap\.css["']/,
    );
    const at = (needle) => {
      const i = source.indexOf(needle);
      expect(i).toBeGreaterThan(-1);
      return i;
    };
    const gap = source.slice(
      at('{modalType === "gap_analysis" && gapAnalysis && ('),
      at('{(modalType === "remediate" || modalType === "rollback") &&'),
    );
    expect(gap).not.toMatch(/style=\{/);
    expect(gap.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(gap).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
    expect(gap).not.toMatch(
      /className=["{`][^"}`]*(\bdb-|\bcrosswalk-tag\b|(?<![\w-])mono(?![\w-]))/,
    );
    expect(gap).not.toMatch(/<(button|input|select|label|table)\b/);
    for (const part of [
      "CcureSelect",
      "CcureButton",
      "CcureTable",
      "CcureBadge",
    ])
      expect(gap).toMatch(new RegExp(`<${part}\\b`));

    const credentialsTab = source.slice(
      at('{activeTab === "credentials" && ('),
      at('{activeTab === "approvals" && ('),
    );
    expect(credentialsTab).toMatch(/<PagingControls\b/);
    expect(source).not.toMatch(/\bPaginationBar\b/);

    // The retired pager's rules are gone. `.cw-pagination-select` outlived
    // them on the header's selects until Batch 32 migrated those too, so no
    // rule of the family is left.
    const complianceCss = readFileSync(
      path.join(AUDIT_SRC, "styles/compliance.css"),
      "utf8",
    );
    expect(complianceCss).not.toMatch(/\.cw-pagination/);

    const cssPath = path.join(AUDIT_SRC, "styles/compliance-gap.css");
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
    for (const s of selectors) expect(s).toMatch(/\.cwg-/);
  });
});
