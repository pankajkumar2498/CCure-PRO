import { expect, test } from "@playwright/test";
import { AUDIT_STATES } from "../scripts/ux4g-harness/b5-b6.mjs";
import { assertPage, openState } from "./helpers.mjs";

const base = AUDIT_STATES.find((state) => state.id === "p3-report");
const outcomes = [
  {
    plugin: "tls_scanner",
    status: "failed",
    coverage_complete: false,
    detail: "Synthetic TLS failure " + "x".repeat(180),
  },
  {
    plugin: "dns_probe",
    status: "timed_out",
    coverage_complete: false,
    detail: "Synthetic DNS timeout",
  },
];
const host = {
  ip_address: "192.0.2.1",
  hostname: "fixture",
  is_active: true,
  open_ports: [{ port: 443, protocol: "tcp", service: "https" }],
  cves: [],
  plugin_outcomes: outcomes,
};
const coverage = {
  recorded: true,
  complete: false,
  counts: { failed: 1, timed_out: 1 },
  incomplete: outcomes.map((outcome) => ({
    host: host.ip_address,
    ...outcome,
  })),
};
const state = {
  ...base,
  id: "plugin-coverage-incomplete",
  route: "/scan/plugin-fixture/phase3",
  session: undefined,
  ready: "document.body.innerText.includes('Plugin coverage incomplete')",
  stubs: {
    ...base.stubs,
    "/scans/plugin-fixture": {
      id: "plugin-fixture",
      scan_no: 1410,
      status: "complete",
      pipeline_mode: "vulnerability_audit",
      target: host.ip_address,
      results: {
        phase1: { data: [host], summary: { total_hosts: 1, active_hosts: 1 } },
        phase2: { data: [host], summary: { total_hosts: 1, active_hosts: 1 } },
        phase3: {
          data: [host],
          summary: {
            total_hosts: 1,
            active_hosts: 1,
            network_plugin_coverage: coverage,
          },
        },
      },
    },
  },
};

for (const width of [320, 1440]) {
  for (const theme of ["light", "dark"]) {
    test(`incomplete plugin coverage at ${width}px in ${theme} mode`, async ({
      page,
    }) => {
      const log = await openState(page, state, { width, theme });
      await expect(page.getByText("Plugin coverage incomplete")).toBeVisible();
      await expect(
        page.getByText(
          /Absence of findings does not establish a clean assessment/,
        ),
      ).toBeVisible();
      const summary = page.getByText("View plugin outcomes (2)");
      await summary.focus();
      await summary.press("Enter");
      await expect(
        page.getByRole("table", { name: "Plugin execution outcomes" }),
      ).toBeVisible();
      await expect(
        page.getByRole("cell", { name: "Timed out", exact: true }),
      ).toBeVisible();
      await assertPage(page, log);
      expect(
        log.requests.filter(
          (request) =>
            request.method !== "GET" && !request.path.endsWith("/auth/refresh"),
        ),
      ).toEqual([]);
    });
  }
}
