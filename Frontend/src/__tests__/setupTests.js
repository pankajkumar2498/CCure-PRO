import "@testing-library/jest-dom";
import { configure } from "@testing-library/react";

// waitFor / findBy* default to a 1000 ms ceiling, which is tuned for a
// developer laptop. CI runs all 46 files in parallel worker threads on a
// 2-vCPU runner; measured at a 0.4-CPU quota, single dialog tests took up to
// 2.6 s end to end, so a 1 s wait is not generous headroom there. A longer
// ceiling costs nothing on a passing test — the wait returns as soon as the
// condition holds — and only delays the report of a genuine failure.
//
// It is not a substitute for a real fix: the CI failures that prompted it
// turned out to be a focus race in useFocusTrap, and raising this alone did
// not make them pass. vitest's own per-test ceiling is raised to match in
// vite.config.js; the two must stay consistent or the outer one fires first
// with a less useful message.
configure({ asyncUtilTimeout: 5000 });

// Test providers attach payloads from explicit native permissionKeys and platformReach.
// Existing authorization payloads are passed through unchanged.
// Production code never derives permissions from these fixture fields.
//
// It is installed in `beforeEach`, not at setup time: importing AuthContext here
// would load its real dependencies before a test file's own `vi.mock` calls apply.
import React from "react";
import { beforeEach } from "vitest";
import { personaFrom } from "./fixtures/authorization";

let patched = false;
beforeEach(async () => {
  if (patched) return;
  let Context;
  try {
    // a test that mocks the module without a default export has no Provider to wrap
    Context = (await import("@shell/auth/AuthContext")).default;
  } catch {
    return;
  }
  if (!Context || !Context.Provider) return;
  const Original = Context.Provider;
  Context.Provider = function PersonaProvider({ value, children }) {
    const next =
      value && value.user ? { ...value, user: personaFrom(value.user) } : value;
    return React.createElement(Original, { value: next }, children);
  };
  patched = true;
});
