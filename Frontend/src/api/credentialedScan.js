/**
 * src/api/credentialedScan.js
 * Wrapper for POST /scan/credentialed
 * Credentials are never stored — used once and discarded.
 */
import api from "./axiosInstance";

/**
 * Split a target field into individual expressions.
 * Accepts commas, whitespace or newlines between entries so an operator can
 * paste a list from a spreadsheet or an inventory export without reformatting.
 */
export const parseTargets = (value) =>
  String(value ?? "")
    .split(/[\s,;]+/)
    .map((t) => t.trim())
    .filter(Boolean);

export const runCredentialedScan = ({
  targets,
  username,
  password,
  keyPath,
  // No default. `undefined` tells the API to discover which authentication
  // service the host offers; defaulting to 22 here would pin every scan to
  // SSH and silently turn that off.
  port,
  authMethod = "password",
  sections = null,
  osType = "auto",
  credentialId = null,
}) =>
  api.post("/scan/credentialed", {
    targets,
    username,
    password: authMethod === "password" ? password : undefined,
    key_path: authMethod === "key" ? keyPath : undefined,
    port,
    auth_method: authMethod,
    sections,
    os_type: osType,
    credential_id: credentialId,
  });
