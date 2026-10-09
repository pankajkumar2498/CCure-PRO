/**
 * src/shell/auth/accessFallback.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Where a signed-in user refused a route is sent instead (Phase 12.3).
 *
 * The rule belongs to the shell's route guard: the first candidate the user is
 * permitted to open, other than the page they were refused, else sign-in. The
 * *candidates* are a product's pages, so the shell does not name them — the
 * composition root supplies them through this provider. With no provider the
 * list is empty and a refusal goes to sign-in.
 *
 * A refusal is never turned into a trip to CCure Home (D12-8): `/` is not a
 * candidate unless a product deliberately lists it.
 */
import { createContext, useContext } from "react";

const AccessFallbackContext = createContext([]);

export function AccessFallbackProvider({ candidates, children }) {
  return (
    <AccessFallbackContext.Provider value={candidates || []}>
      {children}
    </AccessFallbackContext.Provider>
  );
}

export const useAccessFallbacks = () => useContext(AccessFallbackContext);
