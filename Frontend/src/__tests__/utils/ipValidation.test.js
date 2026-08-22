import { describe, it, expect } from "vitest";
import {
  isValidCIDR,
  isValidIPv4,
  isValidRange,
  parseExcludeIpsJS,
} from "../../utils/ipValidation";

describe("isValidCIDR", () => {
  it("accepts a well-formed v4 and v6 prefix", () => {
    expect(isValidCIDR("10.0.0.0/24")).toBe(true);
    expect(isValidCIDR("2001:db8::/32")).toBe(true);
  });

  // Regression: NewScan and Phase1Results carried separate copies of this
  // predicate and only NewScan's rejected a second slash, so the same token
  // was refused as a scan target but accepted as an exclusion on the results
  // screen. Both screens import this module now.
  it("rejects a token carrying more than one slash", () => {
    expect(isValidCIDR("10.0.0.0/24/8")).toBe(false);
  });

  it("rejects an empty or non-numeric mask", () => {
    expect(isValidCIDR("10.0.0.0/")).toBe(false);
    expect(isValidCIDR("10.0.0.0/abc")).toBe(false);
  });

  it("rejects a mask wider than the address family allows", () => {
    expect(isValidCIDR("10.0.0.0/33")).toBe(false);
  });
});

describe("isValidIPv4", () => {
  it("rejects octets with leading zeroes and out-of-range values", () => {
    expect(isValidIPv4("10.0.0.01")).toBe(false);
    expect(isValidIPv4("10.0.0.256")).toBe(false);
    expect(isValidIPv4("10.0.0.1")).toBe(true);
  });
});

describe("isValidRange", () => {
  it("accepts both full and short-form ends", () => {
    expect(isValidRange("10.0.0.1-10.0.0.9")).toBe(true);
    expect(isValidRange("10.0.0.1-9")).toBe(true);
  });

  it("rejects a descending range", () => {
    expect(isValidRange("10.0.0.9-10.0.0.1")).toBe(false);
  });
});

describe("parseExcludeIpsJS", () => {
  it("treats blank input as an empty exclusion list", () => {
    expect(parseExcludeIpsJS("   ")).toEqual({ ips: [], error: "" });
  });

  it("splits on commas and tolerates surrounding whitespace", () => {
    expect(parseExcludeIpsJS(" 10.0.0.1, 10.0.0.0/24 ")).toEqual({
      ips: ["10.0.0.1", "10.0.0.0/24"],
      error: "",
    });
  });

  it("names the first offending token and returns no addresses", () => {
    const { ips, error } = parseExcludeIpsJS("10.0.0.1,not an ip!");
    expect(ips).toEqual([]);
    expect(error).toContain("notanip!");
  });

  it("refuses a double-slashed prefix on every screen", () => {
    expect(parseExcludeIpsJS("10.0.0.0/24/8").error).toBeTruthy();
  });
});
