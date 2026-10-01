/**
 * Reports & Export panel.
 *
 * The capabilities under test were backend-only: the CSV and XLSX arms of
 * `/reports/download`, and the whole of `/reports/export`. What the tests
 * defend is not that the buttons render but that the requests are the ones the
 * API actually serves — every combination here was measured against the live
 * endpoint before it was written down.
 *
 * Four properties matter more than the rest:
 *
 * * **`csv` + everything is refused by the API** ("A CSV holds one table"), so
 *   the UI must never send it.
 * * **Array filters must serialise as repeated keys.** Measured: with
 *   `severity=critical` the API returns 154 rows; with `severity[]=critical`
 *   it returns 1,862 — the filter is silently ignored and the export looks
 *   successful. That is the worst failure shape available here, so it is
 *   pinned.
 * * **A second click must not become a second request.** Both endpoints are
 *   rate limited (20/min and 10/min) and a workbook takes seconds.
 * * **A control must never be left spinning.** On failure the UI has to come
 *   back, or a failed export is indistinguishable from a slow one.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ReportExportPanel from "@audit/components/scan/ReportExportPanel";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), delete: vi.fn() },
}));

const toast = {
  success: vi.fn(),
  danger: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
};
vi.mock("../../../../../design-system", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, useCcureToast: () => toast };
});

let currentUser = {
  id: "u1",
  role: { name: "analyst" },
  permissions: [{ resource: "reports", action: "read" }],
};
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

vi.mock("@shell/auth/permissions", () => ({
  can: (user, resource, action) =>
    (user?.permissions || []).some(
      (p) => p.resource === resource && p.action === action,
    ),
  denyMessage: "You do not have permission to do that.",
}));

/** A response shaped as the real endpoints answer. */
function fileResponse(filename, type = "application/pdf") {
  return {
    data: new Blob(["x"], { type }),
    headers: {
      "content-type": type,
      "content-disposition": `attachment; filename="${filename}"`,
    },
  };
}

function httpError(status, body) {
  return { response: { status, data: body } };
}

beforeEach(() => {
  vi.clearAllMocks();
  currentUser = {
    id: "u1",
    role: { name: "analyst" },
    permissions: [{ resource: "reports", action: "read" }],
  };
  // jsdom implements neither; the component only needs them not to throw.
  global.URL.createObjectURL = vi.fn(() => "blob:mock");
  global.URL.revokeObjectURL = vi.fn();
});

const renderPanel = () =>
  render(<ReportExportPanel scanId="scn_1" scanNo={84} />);

describe("ReportExportPanel — the four whole-scan reports", () => {
  it.each([
    ["Executive report", "JSON"],
    ["Technical report", "XML"],
    ["Host inventory", "CSV"],
    ["Full workbook", "XLSX"],
  ])("requests %s as fmt=%s", async (label, fmt) => {
    api.get.mockResolvedValue(fileResponse(`scan_84.${fmt}`));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: label }));

    await waitFor(() => expect(api.get).toHaveBeenCalled());
    const [url, config] = api.get.mock.calls[0];
    expect(url).toBe("/reports/download/scn_1");
    expect(config.params).toEqual({ fmt });
    // A file, not a parsed body.
    expect(config.responseType).toBe("blob");
  });

  it("shows CSV and XLSX, which the UI could not reach at all before", () => {
    renderPanel();
    expect(screen.getByRole("button", { name: "Host inventory" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Full workbook" })).toBeTruthy();
  });
});

describe("ReportExportPanel — dataset export", () => {
  it("defaults to the whole workbook", async () => {
    api.get.mockResolvedValue(fileResponse("scan_84_all.xlsx"));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));

    await waitFor(() => expect(api.get).toHaveBeenCalled());
    const [url, config] = api.get.mock.calls[0];
    expect(url).toBe("/reports/export/scn_1");
    expect(config.params.fmt).toBe("xlsx");
    expect(config.params.dataset).toBe("all");
  });

  it("sends every dataset the API accepts", async () => {
    api.get.mockResolvedValue(fileResponse("x.xlsx"));
    const user = userEvent.setup();
    renderPanel();

    for (const [label, value] of [
      ["Compliance verdicts", "compliance"],
      ["Findings", "findings"],
      ["Change since the previous scan", "comparison"],
    ]) {
      api.get.mockClear();
      await user.selectOptions(screen.getByLabelText("Content"), value);
      await user.click(screen.getByRole("button", { name: "Export" }));
      await waitFor(() => expect(api.get).toHaveBeenCalled());
      expect(api.get.mock.calls[0][1].params.dataset).toBe(value);
      expect(label).toBeTruthy();
    }
  });

  it("carries the scope through, and omits it when it is the default", async () => {
    api.get.mockResolvedValue(fileResponse("x.xlsx"));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    // `scan` is the API's own default; sending it would be noise.
    expect(api.get.mock.calls[0][1].params.scope).toBeUndefined();

    api.get.mockClear();
    await user.selectOptions(screen.getByLabelText("Findings from"), "asset");
    await user.click(screen.getByRole("button", { name: "Export" }));
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(api.get.mock.calls[0][1].params.scope).toBe("asset");
  });
});

describe("ReportExportPanel — the combination the API refuses", () => {
  it("disables Export for csv + everything rather than sending it", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.selectOptions(screen.getByLabelText("Format"), "csv");
    // "all" is still selected and is invalid for CSV.
    expect(screen.getByRole("button", { name: "Export" })).toBeDisabled();
    expect(screen.getByText(/A CSV holds one table/)).toBeInTheDocument();
    expect(api.get).not.toHaveBeenCalled();
  });

  it("re-enables Export once a single dataset is chosen", async () => {
    api.get.mockResolvedValue(fileResponse("x.csv", "text/csv"));
    const user = userEvent.setup();
    renderPanel();

    await user.selectOptions(screen.getByLabelText("Format"), "csv");
    await user.selectOptions(screen.getByLabelText("Content"), "findings");

    const button = screen.getByRole("button", { name: "Export" });
    expect(button).not.toBeDisabled();
    await user.click(button);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(api.get.mock.calls[0][1].params).toMatchObject({
      fmt: "csv",
      dataset: "findings",
    });
  });
});

describe("ReportExportPanel — filters", () => {
  it("sends repeated keys, not bracketed ones", async () => {
    /*
     * Measured against the live API: `severity=critical` returns 154 rows and
     * `severity[]=critical` returns 1,862 — the filter is ignored and the
     * export still looks successful. The serializer is what decides which of
     * those the browser sends.
     */
    api.get.mockResolvedValue(fileResponse("x.xlsx"));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByText("Filters"));
    await user.click(screen.getByRole("checkbox", { name: "critical" }));
    await user.click(screen.getByRole("checkbox", { name: "high" }));
    await user.click(screen.getByRole("button", { name: "Export" }));

    await waitFor(() => expect(api.get).toHaveBeenCalled());
    const config = api.get.mock.calls[0][1];
    expect(config.params.severity).toEqual(["critical", "high"]);
    // `indexes: null` is what makes axios emit `a=1&a=2` rather than `a[]=1`.
    expect(config.paramsSerializer).toEqual({ indexes: null });
  });

  it("omits empty filters instead of sending blanks", async () => {
    api.get.mockResolvedValue(fileResponse("x.xlsx"));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));
    await waitFor(() => expect(api.get).toHaveBeenCalled());

    const { params } = api.get.mock.calls[0][1];
    // An empty `severity=` matches a severity literally named "" and returns
    // nothing, which reads as a clean scan.
    for (const key of ["severity", "verdict", "status", "overdue_only"]) {
      expect(params[key]).toBeUndefined();
    }
  });

  it("sends overdue_only only when it is on", async () => {
    api.get.mockResolvedValue(fileResponse("x.xlsx"));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByText("Filters"));
    await user.click(
      screen.getByRole("checkbox", { name: /overdue findings only/i }),
    );
    await user.click(screen.getByRole("button", { name: "Export" }));

    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(api.get.mock.calls[0][1].params.overdue_only).toBe(true);
  });
});

describe("ReportExportPanel — states and duplicate clicks", () => {
  it("shows a generating state and restores it on success", async () => {
    let release;
    api.get.mockReturnValue(
      new Promise((resolve) => {
        release = () => resolve(fileResponse("x.xlsx"));
      }),
    );
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));
    expect(
      screen.getByRole("button", { name: /Generating export/ }),
    ).toBeTruthy();

    release();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Export" })).toBeTruthy(),
    );
  });

  it("does not issue a second request while one is in flight", async () => {
    let release;
    api.get.mockReturnValue(
      new Promise((resolve) => {
        release = () => resolve(fileResponse("x.xlsx"));
      }),
    );
    const user = userEvent.setup();
    renderPanel();

    const button = screen.getByRole("button", { name: "Export" });
    await user.click(button);
    await user.click(button);
    await user.click(button);

    expect(api.get).toHaveBeenCalledTimes(1);
    release();
  });

  it("disables the report buttons while an export runs", async () => {
    let release;
    api.get.mockReturnValue(
      new Promise((resolve) => {
        release = () => resolve(fileResponse("x.xlsx"));
      }),
    );
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));
    expect(
      screen.getByRole("button", { name: "Executive report" }),
    ).toBeDisabled();
    release();
  });

  it("restores the control after a failure", async () => {
    api.get.mockRejectedValue(httpError(500, { message: "boom" }));
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Export" })).not.toBeDisabled(),
    );
  });
});

describe("ReportExportPanel — API failures", () => {
  it.each([
    [401, {}, /session has expired/i],
    [403, { message: "Insufficient privileges." }, /Insufficient privileges/],
    [404, { message: "Scan not found." }, /Scan not found/],
    [
      503,
      { message: "openpyxl is not installed" },
      /openpyxl is not installed/,
    ],
    [400, { message: "A CSV holds one table." }, /A CSV holds one table/],
  ])(
    "surfaces a %s with the backend's own wording",
    async (status, body, match) => {
      api.get.mockRejectedValue(httpError(status, body));
      const user = userEvent.setup();
      renderPanel();

      await user.click(screen.getByRole("button", { name: "Export" }));
      await waitFor(() => expect(screen.getByText(match)).toBeInTheDocument());
      expect(toast.danger).toHaveBeenCalled();
    },
  );

  it("names the wait on a 429 rather than failing generically", async () => {
    api.get.mockRejectedValue(
      httpError(429, {
        error_code: "RATE_LIMIT_EXCEEDED",
        message: "Rate limit exceeded (10 per 1 minute).",
        retry_after_seconds: 60,
      }),
    );
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: "Export" }));
    await waitFor(() =>
      expect(screen.getByText(/try again in 60 seconds/i)).toBeInTheDocument(),
    );
  });
});

describe("ReportExportPanel — permissions", () => {
  it("refuses entirely without reports:read, and says why", () => {
    currentUser = { id: "u1", role: { name: "viewer" }, permissions: [] };
    renderPanel();

    expect(screen.getByText(/reports:read/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Export" })).toBeNull();
  });

  it("does not treat scans:read as permission to export", () => {
    // The backend checks reports:read; viewing a scan is a different grant.
    currentUser = {
      id: "u1",
      role: { name: "viewer" },
      permissions: [{ resource: "scans", action: "read" }],
    };
    renderPanel();
    expect(screen.queryByRole("button", { name: "Export" })).toBeNull();
  });
});
