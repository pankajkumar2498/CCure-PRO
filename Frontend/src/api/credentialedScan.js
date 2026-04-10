/**
 * src/api/credentialedScan.js
 * Wrapper for POST /scan/credentialed
 */
import api from "./axiosInstance";

/**
 * Run a credentialed SSH scan.
 *
 * @param {Object} params
 * @param {string} params.ip          - Target IP or hostname
 * @param {string} params.username    - SSH username
 * @param {string} [params.password]  - SSH password (not stored by backend)
 * @param {string} [params.keyPath]   - SSH key path (alternative to password)
 * @param {number} [params.port=22]   - SSH port
 * @param {string} [params.authMethod="password"] - "password" | "key"
 * @param {string[]} [params.sections] - Data categories to collect (null = all)
 * @returns {Promise<import("axios").AxiosResponse>}
 */
export const runCredentialedScan = ({
  ip,
  username,
  password,
  keyPath,
  port = 22,
  authMethod = "password",
  sections = null,
}) =>
  api.post("/scan/credentialed", {
    ip,
    username,
    password:    authMethod === "password" ? password : undefined,
    key_path:    authMethod === "key"      ? keyPath  : undefined,
    port,
    auth_method: authMethod,
    sections,
  });
