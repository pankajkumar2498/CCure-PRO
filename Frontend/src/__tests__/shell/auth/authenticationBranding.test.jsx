import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { render, screen } from "@testing-library/react";
import { SHELL_SRC } from "../../testPaths";
import AuthLayout from "@shell/auth/components/AuthLayout";

const { parse } = createRequire(import.meta.url)("espree");

const filesIn = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(dir, entry.name);
    return entry.isDirectory()
      ? filesIn(file)
      : /\.jsx?$/.test(file)
        ? [file]
        : [];
  });

function copyIn(node, copy = []) {
  if (!node || typeof node !== "object") return copy;
  if (
    ["Literal", "JSXText"].includes(node.type) &&
    typeof node.value === "string"
  )
    copy.push(node.value);
  if (node.type === "TemplateElement") copy.push(node.value.cooked);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) value.forEach((child) => copyIn(child, copy));
    else if (value && typeof value === "object") copyIn(value, copy);
  }
  return copy;
}

describe("Authentication platform identity", () => {
  it("keeps all Authentication copy and helpers free of legacy product branding and unsupported claims", () => {
    // Legal documents are supplied by the composition root, preserved verbatim
    // in the product's legal module; the browser tests inspect both dialogs.
    // Permission keys such as audit.scan.read are contracts, not UI branding.
    for (const file of [
      ...filesIn(path.join(SHELL_SRC, "auth")),
      path.join(SHELL_SRC, "api/auth.js"),
    ]) {
      const ast = parse(readFileSync(file, "utf8"), {
        ecmaVersion: "latest",
        sourceType: "module",
        ecmaFeatures: { jsx: true },
      });
      for (const copy of copyIn(ast)) {
        expect(copy, file).not.toMatch(
          /ccure[\s_-]*audit|\baudit(?:[\s_-]|$)/i,
        );
        expect(copy, file).not.toMatch(
          /SOC\s?2|256-bit|TLS\s?1\.[23]|ISO\s?27001|FIPS|certified|\bcompliant\b|encrypted reset|\b99\.9%|10,000\+ assets/i,
        );
      }
    }
  });

  it("keeps platform identity visible outside the desktop panel and restores the document title on exit", () => {
    const previousTitle = document.title;
    const { container, unmount } = render(
      <AuthLayout title="Sign in">
        <h1>Sign in</h1>
      </AuthLayout>,
    );
    expect(container.querySelector("header")).toHaveTextContent("CCure");
    expect(container.querySelector("header")).toHaveTextContent(
      "Enterprise Security / Vulnerability Management Platform",
    );
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(document.title).toBe("Sign in | CCure");
    unmount();
    expect(document.title).toBe(previousTitle);
  });
});
