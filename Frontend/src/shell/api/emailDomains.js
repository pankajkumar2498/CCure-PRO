import axiosInstance from "./axiosInstance";

// Email domain ALLOW / DENY rules.
//
// Superadmin-only on the server, and that is a tenant-isolation rule rather
// than caution: these rules are platform-wide, so an org_admin denying a domain
// would be blocking a different tenant's customers.

export const listEmailDomainRules = async ({
  q,
  verdict,
  source,
  skip = 0,
  limit = 50,
} = {}) => {
  const params = { skip, limit };
  if (q) params.q = q;
  if (verdict) params.verdict = verdict;
  if (source) params.source = source;
  const response = await axiosInstance.get("/admin/email-domains", { params });
  return response.data;
};

export const getEmailDomainStats = async () => {
  const response = await axiosInstance.get("/admin/email-domains/stats");
  return response.data;
};

// Run an address or domain through the live guard. Answers "why can't this
// person register" in one request, naming the rule or list that matched.
export const lookupEmailDomain = async (q) => {
  const response = await axiosInstance.get("/admin/email-domains/lookup", {
    params: { q },
  });
  return response.data;
};

export const createEmailDomainRule = async ({ domain, verdict, reason }) => {
  const response = await axiosInstance.post("/admin/email-domains", {
    domain,
    verdict,
    reason: reason || null,
  });
  return response.data;
};

export const updateEmailDomainRule = async (id, { verdict, reason } = {}) => {
  const body = {};
  if (verdict !== undefined) body.verdict = verdict;
  if (reason !== undefined) body.reason = reason;
  const response = await axiosInstance.patch(
    `/admin/email-domains/${id}`,
    body,
  );
  return response.data;
};

// The response reports what the domain's verdict becomes *without* the rule.
// Worth surfacing: removing an ALLOW from a domain that also sits in the
// blocklist corpus does not return it to neutral, it starts blocking it.
export const deleteEmailDomainRule = async (id) => {
  const response = await axiosInstance.delete(`/admin/email-domains/${id}`);
  return response.data;
};
