import axiosInstance from "@shell/api/axiosInstance";

// The platform credential store — SSH and native Windows (WinRM).
//
// A secret goes in and never comes back out. No function here returns
// credential material, and the server has no branch that can emit it: the list
// and detail responses carry `has_secret` (a boolean) instead. If you find
// yourself wanting the password on the client, the answer is validation —
// `validateCredential` authenticates server-side and tells you what happened.

export const listCredentials = async ({ credentialType } = {}) => {
  const params = {};
  if (credentialType) params.credential_type = credentialType;
  const response = await axiosInstance.get("/credentials", { params });
  return response.data;
};

// What this build can actually authenticate with. Read from the server rather
// than hardcoded here: a deployment without pywinrm reports Windows as
// unavailable, and offering it anyway would collect credentials that every
// scan then fails to use.
export const listCredentialTypes = async () => {
  const response = await axiosInstance.get("/credentials/types");
  return response.data.types || [];
};

export const getCredential = async (id) => {
  const response = await axiosInstance.get(`/credentials/${id}`);
  return response.data;
};

const toPayload = (form, { includeSecret = true } = {}) => {
  const payload = {
    name: form.name,
    username: form.username,
    domain: form.domain || null,
    credential_type: form.credentialType,
    auth_method: form.authMethod,
    port: form.port ? Number(form.port) : null,
    options: form.options || {},
  };
  // On edit the secret fields are omitted unless the user typed a new one, so
  // changing a port cannot silently blank the password and leave the
  // credential failing authentication for a reason nothing explains.
  if (includeSecret) {
    if (form.password) payload.password = form.password;
    if (form.privateKey) payload.private_key = form.privateKey;
  }
  return payload;
};

export const createCredential = async (form) => {
  const response = await axiosInstance.post("/credentials", toPayload(form));
  return response.data;
};

export const updateCredential = async (id, form) => {
  const payload = toPayload(form);
  delete payload.credential_type; // create-only: it decides the transport
  const response = await axiosInstance.patch(`/credentials/${id}`, payload);
  return response.data;
};

// Authenticates for real against `target`. There is no "looks plausible"
// answer — the point is to find out now rather than at 02:00 with nobody
// watching. `reason` is one of: authenticated, authentication_failed,
// insufficient_privileges, unreachable, configuration_error, failed.
export const validateCredential = async (id, target, port) => {
  const response = await axiosInstance.post(`/credentials/${id}/validate`, {
    target,
    ...(port ? { port: Number(port) } : {}),
  });
  return response.data;
};

export const deleteCredential = async (id) => {
  const response = await axiosInstance.delete(`/credentials/${id}`);
  return response.data;
};
