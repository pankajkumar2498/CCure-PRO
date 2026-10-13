/**
 * The "Affected:" line of a CVE finding.
 *
 * Pinned because the field arrives in several shapes and rendering it as it
 * arrives crashed the Risk Report (React error #31) on the first credentialed
 * vulnerability audit that produced a CPE record list.
 */

import { describe, it, expect } from "vitest";
import { describeAffected } from "@audit/utils/affectedSoftware";

const cpe = (extra) => ({
  vendor: "google",
  product: "chrome",
  cpe_uri: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
  version_start_including: null,
  version_start_excluding: null,
  version_end_including: null,
  version_end_excluding: null,
  ...extra,
});

describe("describeAffected", () => {
  it("names the installed package for a credentialed finding", () => {
    expect(
      describeAffected({
        package: "Google Chrome",
        installed_ver: "138.0.7204.184",
        affected_software: [cpe({ version_end_excluding: "140.0.7339.185" })],
      }),
    ).toBe("Google Chrome 138.0.7204.184");
  });

  it("does not repeat a version the package name already carries", () => {
    expect(
      describeAffected({ package: "Nmap 7.95", installed_version: "7.95" }),
    ).toBe("Nmap 7.95");
  });

  it("describes a list of CPE records as product and range", () => {
    expect(
      describeAffected({
        affected_software: [
          cpe({
            version_start_including: "8.6",
            version_end_including: "9.8",
            vendor: "openbsd",
            product: "openssh",
          }),
        ],
      }),
    ).toBe("openbsd openssh >= 8.6, <= 9.8");
  });

  it("reads the network path's `affected` key and groups ranges by product", () => {
    const ranges = ["14.23", "15.18", "16.14", "17.10", "18.4"].map((end, i) =>
      cpe({
        vendor: "postgresql",
        product: "postgresql",
        version_start_including: i ? `${end.split(".")[0]}.0` : null,
        version_end_excluding: end,
      }),
    );
    expect(describeAffected({ affected: ranges })).toBe(
      "postgresql postgresql < 14.23; >= 15.0, < 15.18; >= 16.0, < 16.14 (+2 more)",
    );
  });

  it("uses a version pinned in the URI when no bounds are published", () => {
    expect(
      describeAffected({
        affected: [
          cpe({
            vendor: "openbsd",
            product: "openssh",
            cpe_uri: "cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*",
          }),
        ],
      }),
    ).toBe("openbsd openssh 8.5");
  });

  it("takes vendor and product from the URI when the record omits them", () => {
    expect(
      describeAffected({
        affected_software: ["cpe:2.3:a:nmap:nmap:7.95:*:*:*:*:*:*:*"],
      }),
    ).toBe("nmap nmap 7.95");
  });

  it("passes a plain string through", () => {
    expect(describeAffected({ affected_software: "OpenSSH 8.9p1" })).toBe(
      "OpenSSH 8.9p1",
    );
  });

  it("says nothing rather than something empty", () => {
    expect(describeAffected({ affected_software: [] })).toBe("");
    expect(describeAffected({ affected_software: [{}] })).toBe("");
    expect(describeAffected({})).toBe("");
    expect(describeAffected(null)).toBe("");
  });

  it("always returns a string, never an object React would refuse", () => {
    for (const value of [
      [cpe({})],
      cpe({}),
      [{ vendor: { nested: true } }],
      [null, 3, "cpe:2.3:a:x:y:*"],
      42,
    ]) {
      expect(typeof describeAffected({ affected_software: value })).toBe(
        "string",
      );
    }
  });
});
