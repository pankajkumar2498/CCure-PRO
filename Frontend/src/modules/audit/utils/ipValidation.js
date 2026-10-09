/**
 * Target-syntax validation shared by the scan screens.
 *
 * These predicates were duplicated verbatim in `pages/scan/NewScan.jsx` and
 * `pages/scan/Phase1Results.jsx`, and the copies had drifted: NewScan's
 * `isValidCIDR` rejected a token with more than one slash, Phase1Results' did
 * not, so `10.0.0.0/24/8` was refused on one screen and accepted as an
 * exclusion on the other. The stricter form is kept here and both screens now
 * import it, so the two agree by construction.
 *
 * They are module scope on purpose. As component-local `const` arrows they were
 * rebuilt every render, which made `parseExcludeIpsJS` an unstable dependency
 * of the exclusion-validation effects in both files.
 */

export function isValidIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const num = Number(p);
    return (
      p !== "" && !isNaN(num) && num >= 0 && num <= 255 && String(num) === p
    );
  });
}

export function isValidIPv6(ip) {
  if (!ip.includes(":")) return false;
  return (
    /^[0-9a-fA-F:]+$/.test(ip) &&
    !ip.includes(":::") &&
    (ip.match(/:/g) || []).length <= 7
  );
}

export function isValidCIDR(cidr) {
  if (!cidr.includes("/")) return false;
  const parts = cidr.split("/");
  if (parts.length !== 2) return false;
  const [ip, maskStr] = parts;
  const mask = Number(maskStr);
  if (isNaN(mask) || maskStr === "") return false;
  if (isValidIPv4(ip)) return mask >= 0 && mask <= 32;
  if (isValidIPv6(ip)) return mask >= 0 && mask <= 128;
  return false;
}

export function ipToLong(ip) {
  return (
    ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0
  );
}

export function isValidRange(range) {
  if (!range.includes("-")) return false;
  const parts = range.split("-");
  if (parts.length !== 2) return false;
  const [start, end] = parts.map((p) => p.trim());
  if (!isValidIPv4(start)) return false;
  if (isValidIPv4(end)) {
    return ipToLong(start) <= ipToLong(end);
  } else if (/^\d+$/.test(end)) {
    const endOctet = Number(end);
    const startParts = start.split(".");
    const startOctet = Number(startParts[3]);
    return endOctet >= startOctet && endOctet <= 255;
  }
  return false;
}

export function isValidHostname(host) {
  if (host.length > 253) return false;
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(
    host,
  );
}

export function detectTargetType(val) {
  if (isValidCIDR(val)) return "CIDR";
  if (isValidRange(val)) return "Range";
  if (isValidIPv4(val) || isValidIPv6(val)) return "IP";
  if (isValidHostname(val)) return "Hostname";
  return null;
}

/** Split a comma-separated exclusion list, refusing the first bad token. */
export function parseExcludeIpsJS(ipsStr) {
  if (!ipsStr || !ipsStr.trim()) {
    return { ips: [], error: "" };
  }
  const clean = ipsStr.replace(/\s+/g, "");
  const tokens = clean.split(",");
  const ipsArray = [];
  for (const token of tokens) {
    if (!token) continue;
    const isValid =
      isValidIPv4(token) ||
      isValidIPv6(token) ||
      isValidCIDR(token) ||
      isValidRange(token) ||
      isValidHostname(token);
    if (!isValid) {
      return {
        ips: [],
        error: `Invalid IP, range, or CIDR format: "${token}"`,
      };
    }
    ipsArray.push(token);
  }
  return { ips: ipsArray, error: "" };
}
