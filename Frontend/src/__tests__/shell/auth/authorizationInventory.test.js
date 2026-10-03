import { describe, it, expect } from "vitest";
import fs from "node:fs";
import {
  build,
  render,
  INVENTORY,
} from "../../../../scripts/build-authorization-inventory.mjs";

const inv = JSON.parse(fs.readFileSync(INVENTORY, "utf8"));
const STATUSES = new Set([
  "migrated",
  "display-only",
  "intentionally-retained",
  "compatibility-history",
]);

describe("frontend authorization inventory", () => {
  it("is exactly what the generator produces from the source (deterministic)", () => {
    expect(fs.readFileSync(INVENTORY, "utf8")).toBe(render(build()));
    expect(render(build())).toBe(render(build()));
  });

  it("leaves no authorization decision unclassified or unexplained", () => {
    for (const s of inv.sites) {
      expect(STATUSES.has(s.status), JSON.stringify(s)).toBe(true);
      expect(s.reason.trim(), JSON.stringify(s)).not.toBe("");
    }
  });

  it("no role-name helper or wildcard survives in application code", () => {
    const src = fs.readFileSync("src/shell/auth/permissions.js", "utf8");
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "");
    expect(code).not.toMatch(/isSuperAdmin|isOrgAdmin|hasRole|:manage/);
    const sites = inv.sites.filter(
      (s) => s.kind === "role_name_read" && s.status !== "display-only",
    );
    // RBAC-7 removed the last one: no role name is read for anything but display
    expect(sites).toEqual([]);
  });

  it("no legacy role-permission read survives", () => {
    const reads = inv.sites.filter((s) => s.kind === "role_permissions_read");
    expect(reads).toEqual([]);
  });

  it("what was removed stays removed: none of the recorded text is in the source", () => {
    expect(inv.removed.length).toBeGreaterThan(0);
    const walk = (dir) =>
      fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
        const p = `${dir}/${e.name}`;
        if (e.isDirectory()) return e.name === "__tests__" ? [] : walk(p);
        return /\.(js|jsx)$/.test(e.name) ? [p] : [];
      });
    const text = walk("src")
      .map((p) => fs.readFileSync(p, "utf8"))
      .join("\n");
    for (const r of inv.removed) {
      expect(r.status).toBe("removed");
      for (const needle of r.forbidden) {
        expect(text.includes(needle), `${needle} (${r.what})`).toBe(false);
      }
    }
  });

  it("the organisation hint is never an authorization input", () => {
    const hints = inv.sites.filter((s) => s.kind === "active_org_hint");
    expect(
      hints.every((s) =>
        ["intentionally-retained", "display-only", "migrated"].includes(
          s.status,
        ),
      ),
    ).toBe(true);
  });
});
