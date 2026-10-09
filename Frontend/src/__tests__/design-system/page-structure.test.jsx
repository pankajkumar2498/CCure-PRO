/**
 * B.13 — one page structure and one icon set for every module.
 *
 * The component tests pin the shared pieces' contract. The source tests are the
 * ratchet: before B.13 the application had twenty page-header implementations,
 * five title sizes and 295 lines of emoji used as icons, and nothing stopped a
 * new page adding a twenty-first or a new button using an emoji. These do.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { render, screen } from "@testing-library/react";

import {
  CcurePage,
  CcurePageHeader,
} from "../../design-system/patterns/CcurePage";
import CcureIcon from "../../design-system/icons/CcureIcon";
import { ICONS, ICON_NAMES } from "../../design-system/icons/icons";
import { SRC, AUDIT_SRC, SHELL_SRC } from "../testPaths";

function files(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "__tests__") continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) files(full, out);
    else if (/\.jsx?$/.test(name)) out.push(full);
  }
  return out;
}

describe("CcurePageHeader", () => {
  it("renders the title as the page's only h1, with badges outside it", () => {
    render(
      <CcurePage>
        <CcurePageHeader
          title="Scan History"
          badges={<span>Live</span>}
          subtitle="14 scans"
          actions={<button type="button">Sync now</button>}
          breadcrumb={<a href="/">Back</a>}
        />
      </CcurePage>,
    );
    const headings = screen.getAllByRole("heading", { level: 1 });
    expect(headings).toHaveLength(1);
    expect(headings[0]).toHaveAccessibleName("Scan History");
    expect(screen.getByText("14 scans").tagName).toBe("P");
    expect(screen.getByRole("button", { name: "Sync now" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Back" })).toBeTruthy();
  });

  it("omits the optional regions when they are not given", () => {
    const { container } = render(<CcurePageHeader title="Remediation" />);
    expect(container.querySelector(".cc-page-header__subtitle")).toBeNull();
    expect(container.querySelector(".cc-page-header__actions")).toBeNull();
    expect(container.querySelector(".cc-page-header__breadcrumb")).toBeNull();
  });

  it("CcurePage forwards its ref and keeps the page's own class", () => {
    let node = null;
    render(
      <CcurePage className="nmap-page" ref={(el) => (node = el)}>
        x
      </CcurePage>,
    );
    expect(node.className).toBe("cc-page nmap-page");
  });
});

describe("CcureIcon", () => {
  it("is decorative unless titled", () => {
    const { container, rerender } = render(<CcureIcon name="download" />);
    const svg = container.querySelector("svg");
    expect(svg.getAttribute("aria-hidden")).toBe("true");
    expect(svg.getAttribute("focusable")).toBe("false");
    rerender(<CcureIcon name="download" title="Download" />);
    expect(screen.getByRole("img", { name: "Download" })).toBeTruthy();
  });

  it("renders nothing for a name it does not have", () => {
    const { container } = render(<CcureIcon name="no-such-icon" />);
    expect(container.innerHTML).toBe("");
  });

  it("every icon is drawn with SVG shapes only", () => {
    const allowed = new Set([
      "path",
      "line",
      "circle",
      "polyline",
      "polygon",
      "rect",
    ]);
    for (const name of ICON_NAMES) {
      expect(ICONS[name].length, name).toBeGreaterThan(0);
      for (const [shape] of ICONS[name])
        expect(allowed.has(shape), name).toBe(true);
    }
  });
});

describe("page structure ratchet", () => {
  const PAGE_DIRS = [
    path.join(AUDIT_SRC, "pages"),
    path.join(AUDIT_SRC, "web-scanning", "pages"),
    path.join(SHELL_SRC, "pages"),
    path.join(SHELL_SRC, "admin", "pages"),
  ];
  // Development-only, excluded from the production build.
  const EXEMPT = new Set(["DesignSystemShowcase.jsx"]);
  const pages = PAGE_DIRS.flatMap((dir) => files(dir)).filter(
    (f) =>
      !EXEMPT.has(path.basename(f)) &&
      /<(AppLayout|ProductFrame|PlatformLayout)\b/.test(
        readFileSync(f, "utf8"),
      ),
  );

  it("finds the routed pages", () => {
    expect(pages.length).toBeGreaterThan(40);
  });

  it("every page composes CcurePage and CcurePageHeader and draws no h1 itself", () => {
    const problems = [];
    for (const f of pages) {
      const src = readFileSync(f, "utf8");
      const rel = path.relative(SRC, f);
      if (!/<CcurePage\b/.test(src)) problems.push(`${rel}: no CcurePage`);
      if (!/<CcurePageHeader\b/.test(src))
        problems.push(`${rel}: no CcurePageHeader`);
      if (/<h1\b/.test(src)) problems.push(`${rel}: draws its own <h1>`);
    }
    expect(problems).toEqual([]);
  });

  it("no source uses the retired page classes", () => {
    const retired =
      /className=["`{][^"`}]*\b(page-inner|page-title-row|page-title|page-subtitle|pl-title|pl-lead)\b/;
    const offenders = files(SRC)
      .filter((f) => retired.test(readFileSync(f, "utf8")))
      .map((f) => path.relative(SRC, f));
    expect(offenders).toEqual([]);
  });
});

describe("icon ratchet", () => {
  // The one place an emoji is allowed: the table that translates the glyphs some
  // Audit endpoints return into icon names.
  const ALLOWED = new Set([
    path.join("modules", "audit", "utils", "backendIcons.js"),
  ]);
  const EMOJI =
    /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{231A}-\u{23FF}\u{2139}]/u;
  // Typographic marks, not pictographs.
  const TEXT_MARKS = new Set([..."✓✕✔✗→←↑↓↔▾▸▴▲▼►◄•·−"]);

  it("no UI source uses an emoji as an icon", () => {
    const offenders = [];
    for (const f of files(SRC)) {
      const rel = path.relative(SRC, f);
      if (ALLOWED.has(rel)) continue;
      readFileSync(f, "utf8")
        .split("\n")
        .forEach((line, i) => {
          const code = line.trim();
          if (/^(\/\/|\*|\/\*)/.test(code)) return;
          const hits = [...line].filter(
            (ch) => EMOJI.test(ch) && !TEXT_MARKS.has(ch),
          );
          if (hits.length) offenders.push(`${rel}:${i + 1}: ${hits.join("")}`);
        });
    }
    expect(offenders).toEqual([]);
  });

  it("every icon named in the source exists in the set", () => {
    const named = new Set();
    const patterns = [
      /<CcureIcon\s+name="([a-z0-9-]+)"/g,
      /\bnav\("([a-z0-9-]+)"\)/g,
      /\bicon: "([a-z0-9-]+)"/g,
    ];
    for (const f of files(SRC)) {
      const src = readFileSync(f, "utf8");
      for (const re of patterns)
        for (const m of src.matchAll(re)) named.add(m[1]);
    }
    const missing = [...named].filter((n) => !ICONS[n]);
    expect(missing).toEqual([]);
    expect(named.size).toBeGreaterThan(40);
  });
});
