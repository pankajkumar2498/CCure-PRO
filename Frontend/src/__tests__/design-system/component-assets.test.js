// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  componentCss,
  componentCssProblems,
} from "../../../scripts/ux4g-component-assets.mjs";
import { loadBaseline } from "../../../scripts/ux4g-baseline.mjs";
import { readFileSync } from "node:fs";
import { assetPaths } from "../../../scripts/ux4g-pipeline.mjs";

describe("official component subset", () => {
  it("ships scoped components with no global reset, font faces or unrelated journeys", () => {
    const css = readFileSync(assetPaths().components, "utf8");
    expect(componentCssProblems(css)).toEqual([]);
    expect(css).not.toContain("@font-face");
    expect(css).not.toContain(":where(*,:before,:after)");
    expect(css).not.toContain(".ux4g-application-submission");
    expect(css).not.toContain(".ux4g-journey-card");
    expect(css).not.toContain(".ux4g-aadhaar-option-card");
    expect(css).toContain("ux4g-spinner-rotate");
  });
  it("rejects a bare vendor selector and alternate external/font sources", () => {
    expect(componentCssProblems(".ux4g-btn{color:red}")).toContain(
      "component CSS escapes the CCure adapter scope",
    );
    expect(
      componentCssProblems(
        ':where(.cc-ux4g).ux4g-btn{background:url("https://example.invalid/a")}',
      ),
    ).toContain("component CSS contains an external/font URL");
    expect(
      componentCssProblems(
        '@font-face{font-family:Other;src:url("data:font/ttf;base64,AA")}',
      ),
    ).toContain("unapproved component CSS at-rule: font-face");
  });
  it("generates the same official subset from the same verified source", () => {
    const baseline = loadBaseline();
    const source = readFileSync(
      new URL(
        "../../../node_modules/ux4g-web-components/styles/ux4g.css",
        import.meta.url,
      ),
      "utf8",
    );
    expect(componentCss(source, baseline)).toBe(
      readFileSync(assetPaths().components, "utf8"),
    );
  });
});
