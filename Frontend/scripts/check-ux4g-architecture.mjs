/** Offline UI boundaries. Exceptions are narrow, documented and never auto-added. */
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import postcss from "postcss";
import { FRONTEND_ROOT } from "./ux4g-baseline.mjs";
const require = createRequire(import.meta.url);
const { parse } = require("espree");

const UPLOADS = new Set([
  "src/modules/audit/pages/admin/AMTIntegration.jsx",
  "src/modules/audit/pages/ComplianceWorkspace.jsx",
  "src/modules/audit/pages/scan/NewScan.jsx",
]);
const walk = (node, visit) => {
  if (!node || typeof node !== "object") return;
  if (node.type) visit(node);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) value.forEach((child) => walk(child, visit));
    else if (value && typeof value === "object") walk(value, visit);
  }
};
export function uiSourceProblems(filename, text) {
  const problems = [];
  const ds = filename.startsWith("src/design-system/");
  const ast = parse(text, {
    ecmaVersion: "latest",
    sourceType: "module",
    ecmaFeatures: { jsx: true },
  });
  let uploads = 0;
  walk(ast, (node) => {
    if (
      node.type === "ImportDeclaration" &&
      !ds &&
      /design-system\/(?:components|hooks|patterns|tokens)(?:\/|$)/.test(
        node.source.value,
      )
    )
      problems.push(`${filename}: import the shared design-system entrypoint`);
    if (
      node.type === "CallExpression" &&
      (node.callee.name === "alert" ||
        (node.callee.type === "MemberExpression" &&
          ["window", "globalThis"].includes(node.callee.object.name) &&
          (node.callee.property.name === "alert" ||
            node.callee.property.value === "alert")))
    )
      problems.push(
        `${filename}: use shared accessible feedback instead of alert()`,
      );
    if (
      node.type === "JSXOpeningElement" &&
      !ds &&
      ["button", "input", "select", "textarea", "table", "dialog"].includes(
        node.name.name,
      )
    ) {
      const type = node.attributes.find((a) => a.name?.name === "type")?.value
        ?.value;
      if (
        node.name.name === "input" &&
        type === "file" &&
        UPLOADS.has(filename)
      )
        uploads++;
      else
        problems.push(
          `${filename}: native ${node.name.name} bypasses the shared primitive`,
        );
    }
    if (
      !ds &&
      ((node.type === "Literal" &&
        typeof node.value === "string" &&
        /\bux4g-/.test(node.value)) ||
        (node.type === "TemplateElement" && /\bux4g-/.test(node.value.raw)))
    )
      problems.push(
        `${filename}: vendor classes belong inside shared adapters`,
      );
  });
  if (uploads > 1)
    problems.push(
      `${filename}: only the documented single file-input exception is approved`,
    );
  return problems;
}

export function cssProblems(filename, text, approvedImportant = []) {
  const problems = [];
  const ast = postcss.parse(text, { from: filename });
  const important = [];
  ast.walkDecls((decl) => {
    const selector = decl.parent.selector || "";
    if (
      /^(?:overflow-x|overflow)$/.test(decl.prop) &&
      /(?:hidden|clip)/.test(decl.value) &&
      selector
        .split(",")
        .some((s) =>
          /^(?:html|body|:root|\*|\.cc-shell|\.cc-main|\.page-inner)$/.test(
            s.trim(),
          ),
        )
    )
      problems.push(
        `${filename}: global horizontal overflow suppression is forbidden (${selector})`,
      );
    if (decl.important)
      important.push(
        `${selector.replace(/\s+/g, " ")}|${decl.prop}|${decl.value}`,
      );
  });
  const remaining = [...approvedImportant];
  for (const signature of important) {
    const index = remaining.indexOf(signature);
    if (index < 0)
      problems.push(
        `${filename}: new !important needs scoped cascade correction (${signature})`,
      );
    else remaining.splice(index, 1);
  }
  return problems;
}

function files(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === "__tests__") return [];
    const name = path.join(dir, entry.name);
    return entry.isDirectory() ? files(name) : [name];
  });
}
export function checkUiArchitecture(root = FRONTEND_ROOT) {
  const baseline = JSON.parse(
    readFileSync(path.join(root, "ux4g-ui-exceptions.json"), "utf8"),
  );
  const problems = [];
  for (const name of files(path.join(root, "src"))) {
    const relative = path.relative(root, name).split(path.sep).join("/");
    if (/\.jsx?$/.test(name))
      problems.push(...uiSourceProblems(relative, readFileSync(name, "utf8")));
    if (/\.css$/.test(name) && !/\.generated\.css$/.test(name))
      problems.push(
        ...cssProblems(
          relative,
          readFileSync(name, "utf8"),
          baseline.legacyImportant[relative],
        ),
      );
  }
  const documents = [
    "AGENTS.md",
    "README.md",
    "../AGENTS.md",
    "../README.md",
    "../CLAUDE.md",
    "../docs/FRONTEND_ARCHITECTURE.md",
  ];
  for (const document of documents) {
    const text = readFileSync(path.resolve(root, document), "utf8");
    if (!text.includes("UX4G_STANDARD.md"))
      problems.push(`${document}: link the permanent UX4G standard`);
  }
  const standard = readFileSync(
    path.resolve(root, "../docs/ux4g/UX4G_STANDARD.md"),
    "utf8",
  );
  const approved = JSON.parse(
    readFileSync(path.join(root, "ux4g-baseline.json"), "utf8"),
  );
  for (const term of [
    "ux4g-baseline.json",
    "ux4g:architecture",
    "test:browser",
    `${approved.npm.package}@${approved.npm.version}`,
    "compatibility",
    "CSP",
  ])
    if (!standard.includes(term))
      problems.push(`UX4G_STANDARD.md: missing ${term}`);
  return problems;
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const problems = checkUiArchitecture();
  if (problems.length) {
    console.error(problems.join("\n"));
    process.exitCode = 1;
  } else
    console.log(
      "[ux4g:architecture] PASS — shared UI boundaries, exception ratchet and documentation",
    );
}
