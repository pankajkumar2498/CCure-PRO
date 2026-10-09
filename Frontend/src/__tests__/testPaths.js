/**
 * Anchors for tests that read source files (Phase 12.4).
 *
 * Never count `..` from a test's own location to reach src/: a test's depth
 * changes whenever it moves, and a wrong count surfaces as ENOENT on a file
 * that plainly exists. Import these instead.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Frontend/src */
export const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
/** Frontend/src/modules/audit — CCure Audit's code. */
export const AUDIT_SRC = path.join(SRC, "modules", "audit");
/** Frontend/src/shell — the platform shell. */
export const SHELL_SRC = path.join(SRC, "shell");
