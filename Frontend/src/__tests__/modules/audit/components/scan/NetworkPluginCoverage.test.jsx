import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import NetworkPluginCoverage from "@audit/components/scan/NetworkPluginCoverage";

describe("Plugin execution coverage", () => {
  it.each(["failed", "timed_out", "unsupported", "skipped"])(
    "makes %s visible with no findings",
    (status) => {
      render(
        <NetworkPluginCoverage
          hosts={[
            {
              ip_address: "192.0.2.1",
              cves: [],
              plugin_outcomes: [
                {
                  plugin: "fixture",
                  status,
                  coverage_complete: false,
                  detail: "Fixture did not complete",
                },
              ],
            },
          ]}
        />,
      );
      expect(
        screen.getByText("Plugin coverage incomplete"),
      ).toBeInTheDocument();
      expect(
        screen.getByText(
          /Absence of findings does not establish a clean assessment/,
        ),
      ).toBeInTheDocument();
      expect(screen.getByText("Fixture did not complete")).toBeInTheDocument();
      expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
    },
  );
  it("marks an older scan without outcomes unverified", () => {
    render(<NetworkPluginCoverage hosts={[{ cves: [] }]} />);
    expect(screen.getByText("Plugin coverage unverified")).toBeInTheDocument();
  });
  it("distinguishes a recorded completed negative from incomplete coverage", () => {
    render(
      <NetworkPluginCoverage
        hosts={[
          {
            ip_address: "192.0.2.1",
            plugin_outcomes: [
              {
                plugin: "fixture",
                status: "completed_with_no_findings",
                coverage_complete: true,
              },
            ],
          },
        ]}
      />,
    );
    expect(
      screen.getByText("Selected plugin checks completed"),
    ).toBeInTheDocument();
    expect(screen.getByText("Completed with no findings")).toBeInTheDocument();
  });
});
