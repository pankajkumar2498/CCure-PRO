/**
 * The Terms of Service and Privacy Policy text moved from the sign-up screen to
 * Audit's module on 6 Oct 2026 so the platform's sign-in screens could join the
 * shell. It moved verbatim: this pins the wording so a change to legal copy is a
 * deliberate, reviewed one (the owner's decision, D12-9), never a side effect.
 */
import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AUDIT_LEGAL_DOCUMENTS } from "@audit/legal/legalDocuments";

const text = (node) =>
  renderToStaticMarkup(node)
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();

describe("Audit legal documents (verbatim)", () => {
  it("keeps the titles", () => {
    expect(AUDIT_LEGAL_DOCUMENTS.terms.title).toBe(
      "Terms of Service — CCure Audit PRO",
    );
    expect(AUDIT_LEGAL_DOCUMENTS.privacy.title).toBe(
      "Privacy Policy — CCure Audit PRO",
    );
  });

  it("keeps the Terms of Service wording", () => {
    expect(text(AUDIT_LEGAL_DOCUMENTS.terms.body)).toBe(
      "Welcome to CCure Audit PRO. By creating an account and using our network security platform, you agree to comply with the following terms: 1. Authorized Use You agree to only perform security assessments and vulnerability scans on networks, hosts, and domain infrastructure that you own or have explicit written authorization to audit. 2. Account Security You are responsible for maintaining the confidentiality of your credentials and multi-factor authentication tokens. Any action initiated under your credentials is your responsibility. 3. Compliance & Audit Logs All activities performed on this platform are recorded in tamper-resistant immutable audit logs for enterprise compliance and SIEM auditing.",
    );
  });

  it("keeps the Privacy Policy wording", () => {
    expect(text(AUDIT_LEGAL_DOCUMENTS.privacy.body)).toBe(
      "Your privacy and data security are our top priorities. Here is how we handle your personal and enterprise telemetry data: 1. Data Collection We collect your username, email address, optional full name, and authentication logs to provide secure tenant isolation and audit trails. 2. Scan Result Encryption All network scan assets, vulnerability reports, and credential credentials are stored with strict multi-tenant isolation and database encryption. 3. No Data Sharing We never sell or share your telemetry or scan findings with third parties.",
    );
  });
});
