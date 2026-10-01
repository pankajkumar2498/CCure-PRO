import axiosInstance from "@shell/api/axiosInstance";

// The generic configuration audit engine's read surface (Phase 3).
//
// There is deliberately no "run an audit" call here. Configuration checks run
// inside the credentialed scan, on the session the collectors already opened,
// and their results arrive in the scan's own findings. A separate dispatch
// would be a second way to start a scan against a named target.

export const listConfigChecks = async ({
  platform,
  checkType,
  domain,
} = {}) => {
  const params = {};
  if (platform) params.platform = platform;
  if (checkType) params.check_type = checkType;
  if (domain) params.domain = domain;
  const response = await axiosInstance.get("/config-audit/checks", { params });
  return response.data;
};

export const getConfigCheck = async (checkId) => {
  const response = await axiosInstance.get(
    `/config-audit/checks/${encodeURIComponent(checkId)}`,
  );
  return response.data;
};

// Which check types actually have a collector, per platform.
//
// Read from the server rather than hardcoded, for the same reason
// `listCredentialTypes` is: the vocabulary admits `api` and `database_query`
// ahead of the phases that implement them, and a UI that presented those as
// available would be describing a capability this build does not have.
export const getConfigCapabilities = async () => {
  const response = await axiosInstance.get("/config-audit/capabilities");
  return response.data;
};

export const validateConfigRule = async (rule) => {
  const response = await axiosInstance.post("/config-audit/validate", rule);
  return response.data;
};

/**
 * The platforms the catalogue can actually be queried for.
 *
 * `capabilities.supported` is keyed by every platform except `any`, which is
 * the set that returns rows — and `any` is a *targeting* value on a check
 * ("applies to every platform"), not a platform to ask about: the API answers
 * `platform=any` with zero checks, because a check declared for `windows` does
 * not apply to a thing called "any".
 *
 * Derived rather than hardcoded. The page used to name `windows` and `linux`
 * in a constant, which put the 49 `database` checks — the whole of the Phase 7
 * database assessment — beyond reach of the UI, and would have done the same
 * to every platform added afterwards.
 */
export const queryablePlatforms = (capabilities) =>
  Object.keys(capabilities?.supported || {});

/** The backend's own wording for a failure, rather than a generic sentence. */
export const configAuditErrorMessage = (error, fallback) => {
  const body = error?.response?.data;
  const rows = body?.errors;
  if (Array.isArray(rows) && rows.length) {
    return rows
      .map((row) => String(row?.msg || "").replace(/^Value error,\s*/, ""))
      .filter(Boolean)
      .join(" ");
  }
  return body?.message || body?.detail || fallback;
};
