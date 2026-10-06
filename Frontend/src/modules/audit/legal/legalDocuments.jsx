/**
 * src/modules/audit/legal/legalDocuments.jsx — the Terms of Service and Privacy
 * Policy shown at sign-up.
 * ─────────────────────────────────────────────────────────────────────────────
 * Moved here **verbatim** from the sign-in screen (6 Oct 2026) so the platform's
 * sign-in screens could join the shell, which may name no product. These documents
 * describe Audit (scans, vulnerability reports) and still say "CCure Audit PRO".
 * Whether they should be reworded for the platform is a legal decision for the
 * owner (D12-9); no word of them was changed, and nothing here is a legal opinion.
 */

export const AUDIT_LEGAL_DOCUMENTS = {
  terms: {
    title: "Terms of Service — CCure Audit PRO",
    body: (
      <>
        <p>
          Welcome to CCure Audit PRO. By creating an account and using our
          network security platform, you agree to comply with the following
          terms:
        </p>
        <h4>1. Authorized Use</h4>
        <p>
          You agree to only perform security assessments and vulnerability scans
          on networks, hosts, and domain infrastructure that you own or have
          explicit written authorization to audit.
        </p>
        <h4>2. Account Security</h4>
        <p>
          You are responsible for maintaining the confidentiality of your
          credentials and multi-factor authentication tokens. Any action
          initiated under your credentials is your responsibility.
        </p>
        <h4>3. Compliance &amp; Audit Logs</h4>
        <p>
          All activities performed on this platform are recorded in
          tamper-resistant immutable audit logs for enterprise compliance and
          SIEM auditing.
        </p>
      </>
    ),
  },
  privacy: {
    title: "Privacy Policy — CCure Audit PRO",
    body: (
      <>
        <p>
          Your privacy and data security are our top priorities. Here is how we
          handle your personal and enterprise telemetry data:
        </p>
        <h4>1. Data Collection</h4>
        <p>
          We collect your username, email address, optional full name, and
          authentication logs to provide secure tenant isolation and audit
          trails.
        </p>
        <h4>2. Scan Result Encryption</h4>
        <p>
          All network scan assets, vulnerability reports, and credential
          credentials are stored with strict multi-tenant isolation and database
          encryption.
        </p>
        <h4>3. No Data Sharing</h4>
        <p>
          We never sell or share your telemetry or scan findings with third
          parties.
        </p>
      </>
    ),
  },
};
