/**
 * src/shell/auth/legalDocuments.jsx — the legal documents the sign-up screen shows.
 * ─────────────────────────────────────────────────────────────────────────────
 * Registration asks the person to accept a Terms of Service and a Privacy Policy.
 * Their *wording* is legal copy and describes a product (what is scanned, what is
 * logged), so it is not the shell's to write and the shell may name no product. The
 * composition root hands the documents over here, the same pattern as
 * `accessFallback.jsx` and `notifications/notificationPresentation.jsx`.
 *
 * With no provider (or a document missing) the sign-up screen says plainly that the
 * document is not available; it never shows an empty dialog, which would read as
 * "there is nothing to agree to".
 *
 * Shape: `{ terms: { title, body }, privacy: { title, body } }`, `body` a React node.
 */
import { createContext, useContext } from "react";

const LegalDocumentsContext = createContext({});

export function LegalDocumentsProvider({ documents, children }) {
  return (
    <LegalDocumentsContext.Provider value={documents || {}}>
      {children}
    </LegalDocumentsContext.Provider>
  );
}

export const useLegalDocuments = () => useContext(LegalDocumentsContext);
