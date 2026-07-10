/**
 * src/api/credentialedScan.js
 * Wrapper for POST /scan/credentialed
 * Credentials are never stored — used once and discarded.
 */
import api from "./axiosInstance";

export const runCredentialedScan = ({
  ip,
  username,
  password,
  keyPath,
  port = 22,
  authMethod = "password",
  sections = null,
  osType = "auto",
  credentialId = null,
}) =>
  api.post("/scan/credentialed", {
    ip,
    username,
    password:    authMethod === "password" ? password  : undefined,
    key_path:    authMethod === "key"      ? keyPath   : undefined,
    port,
    auth_method: authMethod,
    sections,
    os_type:     osType,
    credential_id: credentialId,
  });
