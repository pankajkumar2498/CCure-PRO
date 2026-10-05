import { describe, it, expect } from "vitest";
import {
  uiSourceProblems,
  cssProblems,
  checkUiArchitecture,
} from "../../../scripts/check-ux4g-architecture.mjs";

describe("permanent UX4G boundary", () => {
  it("accepts shared adapters and rejects native or vendor duplicates", () => {
    expect(
      uiSourceProblems(
        "src/pages/Example.jsx",
        'import { CcureButton } from "../../design-system"; const x = <CcureButton>Save</CcureButton>;',
      ),
    ).toEqual([]);
    for (const source of [
      "const x = <button>Save</button>",
      'const x = <input type="text"/>',
      "const x = <select/>",
      "const x = <textarea/>",
      "const x = <table/>",
      "const x = <dialog/>",
      'const x = <div className={"ux4g-button"}/>',
      'import Button from "../../design-system/components/CcureButton"',
    ])
      expect(
        uiSourceProblems("src/pages/Example.jsx", source).length,
      ).toBeGreaterThan(0);
  });
  it("keeps the single documented file input exception narrow", () => {
    const path = "src/modules/audit/pages/scan/NewScan.jsx";
    expect(uiSourceProblems(path, 'const x = <input type="file"/>')).toEqual(
      [],
    );
    expect(
      uiSourceProblems(path, 'const x = <input type="text"/>').length,
    ).toBe(1);
    expect(
      uiSourceProblems(
        path,
        'const x = <><input type="file"/><input type="file"/></>',
      ).length,
    ).toBe(1);
    expect(
      uiSourceProblems(
        "src/pages/Example.jsx",
        'const x = <input type="file"/>',
      ).length,
    ).toBe(1);
  });
  it("rejects native alert feedback", () => {
    for (const source of [
      'alert("Failed")',
      'window.alert("Failed")',
      'globalThis["alert"]("Failed")',
    ])
      expect(uiSourceProblems("src/pages/Example.jsx", source).length).toBe(1);
  });
  it("detects global overflow workarounds and additions to the important ratchet", () => {
    expect(
      cssProblems("example.css", "body { overflow-x: hidden; }").length,
    ).toBe(1);
    expect(
      cssProblems("example.css", ".cc-main { overflow: clip; }").length,
    ).toBe(1);
    expect(
      cssProblems("example.css", ".table-wrap { overflow-x: auto; }"),
    ).toEqual([]);
    expect(
      cssProblems("example.css", ".label { color: red !important; }").length,
    ).toBe(1);
    expect(
      cssProblems("example.css", ".label { color: red !important; }", [
        ".label|color|red",
      ]),
    ).toEqual([]);
    expect(
      cssProblems("example.css", ".label { color: red; }", [
        ".label|color|red",
      ]),
    ).toEqual([]);
  });
  it("the current source and architecture documentation satisfy the standard", () => {
    expect(checkUiArchitecture()).toEqual([]);
  });
});
