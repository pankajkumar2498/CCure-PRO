/**
 * CVELink — Checkpoint 3C batch 15.
 *
 * Written against the legacy component BEFORE migration. Everything up to the
 * last block holds on both sides; the last block is the migration spec and
 * fails on the baseline.
 *
 * ── Two call shapes, both pinned ───────────────────────────────────────────
 * Nine call sites across six pages. The migrated pages (AssetDetail,
 * VulnerabilityBrowser) pass their own class — `ad-cve-link`, `ad-inherit`,
 * `vb-inherit` — and expect it to decide the colour. The unmigrated
 * CredentialedResults passes an inline colour and expects that to win. The
 * rest pass nothing and rely on the legacy `cve-id` class from scan.css.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import CVELink from "../../../components/common/CVELink";

const NVD = "https://nvd.nist.gov/vuln/detail/";

/* ══════════════════════════════════════════════════════════════════════════
   Which identifiers become links
   ══════════════════════════════════════════════════════════════════════════ */

describe("CVELink — which identifiers become links", () => {
  it("links a well-formed CVE to its NVD record", () => {
    render(<CVELink cveId="CVE-2021-44228" />);
    expect(
      screen.getByRole("link", { name: /CVE-2021-44228/ }),
    ).toHaveAttribute("href", `${NVD}CVE-2021-44228`);
  });

  it("upper-cases the URL but shows the identifier as written", () => {
    render(<CVELink cveId="cve-2024-3094" />);
    const link = screen.getByRole("link", { name: /cve-2024-3094/ });
    expect(link).toHaveAttribute("href", `${NVD}CVE-2024-3094`);
    expect(link).toHaveTextContent(/^cve-2024-3094/);
  });

  it("trims surrounding whitespace before validating", () => {
    render(<CVELink cveId={"  CVE-2023-4863\n"} />);
    expect(screen.getByRole("link", { name: /CVE-2023-4863/ })).toHaveAttribute(
      "href",
      `${NVD}CVE-2023-4863`,
    );
  });

  it("accepts sequence numbers longer than four digits", () => {
    render(<CVELink cveId="CVE-2024-123456" />);
    expect(screen.getByRole("link")).toHaveAttribute(
      "href",
      `${NVD}CVE-2024-123456`,
    );
  });

  it.each([
    ["N/A"],
    ["Unknown"],
    ["Unknown CVE"],
    ["CCURE-CFG-ccure.linux.passwd.permissions"],
    ["CCURE-CHK-NUCLEI-generic-env"],
    ["MISC-FTP-ANON"],
    ["GHSA-jfh8-c2jp-5v3q"],
    ["CVE-2021-123"],
    ["CVE-21-44228"],
  ])("renders %s as text, not as a link", (id) => {
    const { container } = render(<CVELink cveId={id} />);
    expect(screen.queryByRole("link")).toBeNull();
    expect(container).toHaveTextContent(id);
  });

  it.each([[undefined], [null], [""]])(
    "renders no link for a missing identifier (%s)",
    (id) => {
      render(<CVELink cveId={id} />);
      expect(screen.queryByRole("link")).toBeNull();
    },
  );
});

/* ══════════════════════════════════════════════════════════════════════════
   The external link is safe
   ══════════════════════════════════════════════════════════════════════════ */

describe("CVELink — the external link is safe", () => {
  it("opens in a new context with neither opener nor referrer", () => {
    render(<CVELink cveId="CVE-2021-44228" />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("target", "_blank");
    const rel = link.getAttribute("rel").split(/\s+/);
    expect(rel).toEqual(expect.arrayContaining(["noopener", "noreferrer"]));
  });

  it("only ever links to nvd.nist.gov", () => {
    render(<CVELink cveId="CVE-2022-22965" />);
    expect(new URL(screen.getByRole("link").href).origin).toBe(
      "https://nvd.nist.gov",
    );
  });

  it.each([
    ['CVE-2021-44228"><img src=x onerror=alert(1)>'],
    ["javascript:alert(1)"],
    ["see CVE-2021-44228"],
    ["CVE-2021-44228/../../../evil"],
    ["CVE-2021-44228?x=https://attacker.test"],
  ])("builds no URL from %s", (hostile) => {
    const { container } = render(<CVELink cveId={hostile} />);
    expect(screen.queryByRole("link")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    // Rendered as inert text, exactly as supplied.
    expect(container).toHaveTextContent(hostile.trim());
  });

  it("does not let its click reach a clickable row", () => {
    const onRow = vi.fn();
    render(
      <table>
        <tbody>
          <tr onClick={onRow}>
            <td>
              <CVELink cveId="CVE-2021-44228" />
            </td>
          </tr>
        </tbody>
      </table>,
    );
    const link = screen.getByRole("link");
    // jsdom cannot open a tab; stop the default without touching propagation.
    link.addEventListener("click", (e) => e.preventDefault());
    fireEvent.click(link);
    expect(onRow).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Consumer contract
   ══════════════════════════════════════════════════════════════════════════ */

describe("CVELink — consumer contract", () => {
  it("carries the legacy cve-id class when the consumer passes none", () => {
    render(<CVELink cveId="CVE-2021-44228" />);
    expect(screen.getByRole("link")).toHaveClass("cve-id");
  });

  it("carries it on the text form too", () => {
    const { container } = render(<CVELink cveId="N/A" />);
    expect(container.querySelector(".cve-id")).toHaveTextContent("N/A");
  });

  it("replaces the default class with the consumer's", () => {
    render(<CVELink cveId="CVE-2021-44228" className="ad-cve-link" />);
    const link = screen.getByRole("link");
    expect(link).toHaveClass("ad-cve-link");
    expect(link).not.toHaveClass("cve-id");
  });

  it("lets a consumer's inline style win", () => {
    render(
      <CVELink
        cveId="CVE-2021-44228"
        style={{ color: "rgb(249, 115, 22)", fontWeight: 600 }}
      />,
    );
    const link = screen.getByRole("link");
    expect(link.style.color).toBe("rgb(249, 115, 22)");
    expect(link.style.fontWeight).toBe("600");
  });

  it("applies a consumer's inline style to the text form", () => {
    const { container } = render(
      <CVELink cveId="Unknown" style={{ color: "rgb(96, 165, 250)" }} />,
    );
    expect(container.querySelector(".cve-id").style.color).toBe(
      "rgb(96, 165, 250)",
    );
  });

  it("is named by the identifier alone", () => {
    render(<CVELink cveId="CVE-2021-44228" />);
    expect(screen.getByRole("link")).toHaveAccessibleName("CVE-2021-44228");
  });

  it("does not add anything to the name of a dialog its heading labels", () => {
    // AssetDetail's drawer is labelled by an h2 that contains only this link.
    render(
      <div role="dialog" aria-labelledby="drawer-title">
        <h2 id="drawer-title">
          <CVELink cveId="CVE-2026-1111" className="ad-inherit" />
        </h2>
      </div>,
    );
    expect(screen.getByRole("dialog")).toHaveAccessibleName("CVE-2026-1111");
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Migration spec — fails on the baseline
   ══════════════════════════════════════════════════════════════════════════ */

describe("CVELink — migration spec", () => {
  it("renders no inline style of its own", () => {
    // The legacy anchor's own `color: var(--accent, #3b82f6)` overrode every
    // page class, so `ad-cve-link` and `vb-inherit` never took effect.
    render(<CVELink cveId="CVE-2021-44228" className="ad-cve-link" />);
    expect(screen.getByRole("link")).not.toHaveAttribute("style");
  });

  it("carries the stylesheet hook alongside the consumer's class", () => {
    render(<CVELink cveId="CVE-2021-44228" className="vb-inherit" />);
    const link = screen.getByRole("link");
    expect(link).toHaveClass("cve-link");
    expect(link).toHaveClass("vb-inherit");
  });

  it("says the link leaves the application for NVD, in its description", () => {
    render(<CVELink cveId="CVE-2021-44228" />);
    expect(screen.getByRole("link")).toHaveAccessibleDescription(
      /opens.*NVD.*new tab/i,
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Colour inside legacy `.db-table` hosts
   ══════════════════════════════════════════════════════════════════════════
   The legacy anchor's inline colour used to outrank dashboard.css's
   `.db-table .cve-id { color: var(--db-accent) }`. Removing it exposed that
   rule on SecurityDashboard and VulnerabilityBrowser: #3b82f6, measured
   rendered at 3.98:1 on the dark table (it had been 5.28:1) and 3.68:1 on the
   light one. CVELink keeps its own link token there instead, without
   touching dashboard.css. The guard has since been retired: dashboard.css lost
   its last importer in the post-migration cleanup, so the rule it outranked can
   no longer reach any page. What is pinned now is that absence. */

const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

describe("CVELink — the retired .db-table guard", () => {
  it("has no consumer of dashboard.css left to guard against", () => {
    for (const page of [
      "SecurityDashboard.jsx",
      "VulnerabilityBrowser.jsx",
      "ComplianceWorkspace.jsx",
    ]) {
      const src = readFileSync(path.join(SRC, "pages", page), "utf8");
      expect(src, `${page} imports dashboard.css again`).not.toMatch(
        /styles\/dashboard\.css/,
      );
    }
  });

  it("carries no .db-table rule of its own", () => {
    const css = readFileSync(path.join(SRC, "styles", "cve-link.css"), "utf8");
    expect(css).not.toMatch(/\.db-table/);
  });
});
