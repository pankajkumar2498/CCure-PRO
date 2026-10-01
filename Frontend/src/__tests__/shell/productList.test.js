/**
 * The product-list reader (Phase 12.2): what the frontend makes of
 * `GET /platform/modules`. The fixture is the live :443 response recorded at
 * the 12.1 activation (1 Oct 2026).
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import real from "../fixtures/platformModules.real.json";
import {
  AVAILABILITY,
  MalformedProductList,
  availabilityOf,
  describeLoadError,
  isEntryPath,
  parseProductList,
} from "../../shell/products/productList";

describe("parseProductList", () => {
  it("reads the real response in the registry's order", () => {
    const { tileStates, products } = parseProductList(real);
    expect(tileStates).toEqual(["available", "not_yet_available"]);
    expect(products.map((p) => p.key)).toEqual([
      "policy_pro",
      "audit",
      "rank",
      "ir",
    ]);
    expect(products[1]).toEqual({
      key: "audit",
      title: "CCure Audit",
      kind: "core_module",
      description: real.modules[1].description,
      entryPath: "/audit-dashboard",
      tileState: "available",
    });
  });

  it.each([
    ["no body", undefined],
    ["a string", "<html>"],
    ["no modules key", { tile_states: ["available"] }],
    ["modules not a list", { modules: {} }],
  ])("refuses %s rather than reading it as no products", (_, body) => {
    expect(() => parseProductList(body)).toThrow(MalformedProductList);
  });

  it("keeps a product whose entry address is malformed, without the address", () => {
    const { products } = parseProductList({
      tile_states: ["available"],
      modules: [{ key: "x", title: "X", entry_path: "javascript:alert(1)" }],
    });
    expect(products).toHaveLength(1);
    expect(products[0].entryPath).toBeNull();
  });
});

describe("isEntryPath", () => {
  it.each(["/audit-dashboard", "/ir-dashboard", "/x1"])("accepts %s", (p) =>
    expect(isEntryPath(p)).toBe(true),
  );
  it.each([
    "audit-dashboard",
    "/a/b",
    "//evil.example",
    "https://evil.example",
    "/",
    "",
    null,
  ])("refuses %s", (p) => expect(isEntryPath(p)).toBe(false));
});

describe("availabilityOf — an unknown state is never a known one", () => {
  const vocab = ["available", "not_yet_available"];
  it("available is available", () =>
    expect(availabilityOf({ tileState: "available" }, vocab)).toBe(
      AVAILABILITY.AVAILABLE,
    ));
  it("not_yet_available is not yet available", () =>
    expect(availabilityOf({ tileState: "not_yet_available" }, vocab)).toBe(
      AVAILABILITY.NOT_YET_AVAILABLE,
    ));
  it("a state outside the fetched vocabulary is unknown", () =>
    expect(availabilityOf({ tileState: "beta" }, vocab)).toBe(
      AVAILABILITY.UNKNOWN,
    ));
  it("a state in the vocabulary this build cannot render is unknown", () =>
    expect(
      availabilityOf({ tileState: "retired" }, [...vocab, "retired"]),
    ).toBe(AVAILABILITY.UNKNOWN));
  it("available is unknown when the server sent no vocabulary", () =>
    expect(availabilityOf({ tileState: "available" }, [])).toBe(
      AVAILABILITY.UNKNOWN,
    ));
  it("a missing state is unknown", () =>
    expect(availabilityOf({ tileState: null }, vocab)).toBe(
      AVAILABILITY.UNKNOWN,
    ));
});

describe("describeLoadError", () => {
  it("names the HTTP status", () =>
    expect(describeLoadError({ response: { status: 403 } })).toBe(
      "The server answered HTTP 403.",
    ));
  it("says when nothing answered", () =>
    expect(describeLoadError(new Error("Network Error"))).toBe(
      "The server could not be reached.",
    ));
});

describe("no second product catalogue", () => {
  // The registry is the only source of product metadata (§0). A title or a
  // description appearing in shell source would be a hardcoded copy of it.
  const root = join(process.cwd(), "src", "shell");
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(jsx?|css)$/.test(name)) files.push(p);
    }
  };
  walk(root);

  it("finds the shell source", () => expect(files.length).toBeGreaterThan(3));

  it.each(real.modules.map((m) => [m.title, m]))(
    "shell source names nothing of %s",
    (_, m) => {
      for (const f of files) {
        const text = readFileSync(f, "utf8");
        expect(text, f).not.toContain(m.title);
        expect(text, f).not.toContain(m.entry_path);
        expect(text, f).not.toContain(m.description.slice(0, 40));
      }
    },
  );
});
