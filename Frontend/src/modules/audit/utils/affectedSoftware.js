/**
 * What a CVE finding says it affects, as one line of text.
 *
 * The backend does not send one shape for this, and rendering the field as it
 * arrives is what took the Risk Report down: a credentialed finding carries
 * `affected_software` as a list of CPE match records
 * (`{vendor, product, cpe_uri, version_start_including, …}`), and React refuses
 * an object as a child. The shapes that occur:
 *
 *   * a credentialed package finding — `package` plus `installed_ver` (or
 *     `installed_version`), which names what is actually on this host and is
 *     the more useful answer, so it wins;
 *   * `affected_software` or `affected` as a list of CPE match records — the
 *     credentialed matcher and the network CVE search respectively;
 *   * a bare string, from older records and the CVE database search;
 *   * a list of CPE URI strings.
 *
 * Returns "" when nothing can be said, so the caller leaves the line out
 * rather than printing "Affected:" over nothing.
 */

/** Ranges listed per product before the rest are summarised as "+N more". */
const MAX_RANGES = 3;

const text = (value) =>
  typeof value === "string" || typeof value === "number"
    ? String(value).trim()
    : "";

/** CPE 2.3 fields: cpe:2.3:part:vendor:product:version:… */
function cpeFields(uri) {
  const parts = text(uri).split(":");
  if (parts[0] !== "cpe") return null;
  const offset = parts[1] === "2.3" ? 2 : 1;
  return {
    vendor: parts[offset + 1] || "",
    product: parts[offset + 2] || "",
    version: parts[offset + 3] || "",
  };
}

const label = (value) => text(value).replace(/_/g, " ");

/** The version range one CPE match record publishes, e.g. ">= 18.0, < 18.4". */
function rangeOf(match, pinnedVersion) {
  const bounds = [
    [">=", match.version_start_including ?? match.versionStartIncluding],
    [">", match.version_start_excluding ?? match.versionStartExcluding],
    ["<=", match.version_end_including ?? match.versionEndIncluding],
    ["<", match.version_end_excluding ?? match.versionEndExcluding],
  ]
    .filter(([, bound]) => text(bound))
    .map(([op, bound]) => `${op} ${text(bound)}`);
  if (bounds.length) return bounds.join(", ");
  // No bounds: the record pins one release in the URI itself. "*" and "-"
  // mean "any" and "not applicable", neither of which is a version.
  return pinnedVersion && !["*", "-"].includes(pinnedVersion)
    ? pinnedVersion
    : "";
}

/** One CPE record (object or URI string) as {name, range}. */
function describeMatch(entry) {
  if (typeof entry === "string") {
    const fields = cpeFields(entry);
    if (!fields) return { name: text(entry), range: "" };
    return {
      name: [label(fields.vendor), label(fields.product)]
        .filter(Boolean)
        .join(" "),
      range: rangeOf({}, fields.version),
    };
  }
  if (!entry || typeof entry !== "object") return null;
  const uri = entry.cpe_uri ?? entry.cpe23Uri ?? entry.criteria;
  const fields = cpeFields(uri) || {};
  const vendor = text(entry.vendor) || fields.vendor || "";
  const product = text(entry.product) || fields.product || "";
  return {
    name: [label(vendor), label(product)].filter(Boolean).join(" "),
    range: rangeOf(entry, fields.version),
  };
}

/** A list of CPE records, grouped by product, ranges joined. */
function describeMatches(entries) {
  const byName = new Map();
  for (const entry of entries) {
    const described = describeMatch(entry);
    if (!described || !described.name) continue;
    const ranges = byName.get(described.name) || [];
    if (described.range && !ranges.includes(described.range)) {
      ranges.push(described.range);
    }
    byName.set(described.name, ranges);
  }
  return [...byName.entries()]
    .map(([name, ranges]) => {
      if (!ranges.length) return name;
      const shown = ranges.slice(0, MAX_RANGES).join("; ");
      const more =
        ranges.length > MAX_RANGES
          ? ` (+${ranges.length - MAX_RANGES} more)`
          : "";
      return `${name} ${shown}${more}`;
    })
    .join(" · ");
}

export function describeAffected(cve) {
  if (!cve || typeof cve !== "object") return "";

  const pkg = text(cve.package);
  if (pkg) {
    const installed = text(cve.installed_ver) || text(cve.installed_version);
    return installed && !pkg.includes(installed) ? `${pkg} ${installed}` : pkg;
  }

  for (const value of [cve.affected_software, cve.affected]) {
    if (typeof value === "string") {
      if (text(value)) return text(value);
      continue;
    }
    if (Array.isArray(value)) {
      const described = describeMatches(value);
      if (described) return described;
      continue;
    }
    if (value && typeof value === "object") {
      const described = describeMatches([value]);
      if (described) return described;
    }
  }
  return "";
}
