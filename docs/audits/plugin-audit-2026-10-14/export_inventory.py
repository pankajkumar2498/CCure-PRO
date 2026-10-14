"""Export source catalogues without connecting to targets or databases.

Run from Backend with SKIP_DOTENV_LOAD=1 and safe test infrastructure variables.
Imports establish availability only; they do not establish functionality.
"""

import ast
import dataclasses
import importlib
import json
import hashlib
from collections import Counter
from pathlib import Path

from core.checks.legacy_plugins import all_dispatchable_plugin_names, describe_plugin
from core.config_audit.builtin import BUILTIN_CHECKS
from core.config_audit.collectors import register_builtin_collectors
from core.config_audit.collectors.base import collector_registry
from engines.vulnerability import plugin_selector
from engines.vulnerability.network_checks import NETWORK_CHECKS


def plain(value):
    if dataclasses.is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [plain(v) for v in value]
    if hasattr(value, "value"):
        return value.value
    return value


root = Path.cwd()
tests = {str(p.relative_to(root)): p.read_text() for p in (root / "tests").rglob("test_*.py")}
register_builtin_collectors()
plugins = []
for name, dispatch in all_dispatchable_plugin_names().items():
    contract = describe_plugin(name, dispatch)
    path = root / "engines/vulnerability/plugins" / (name + ".py")
    tree = ast.parse(path.read_text())
    plugins.append({
        "name": name, "contract": plain(contract), "problems": contract.problems,
        "trigger_ports": [p for p, names in plugin_selector._PORT_MAP.items() if name in names],
        "always": name in plugin_selector._ALWAYS_RUN,
        "serial": name in plugin_selector._SERIAL_LAST,
        "path": str(path.relative_to(root)),
        "run_line": next(n.lineno for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run"),
        "test_references": [p for p, text in tests.items() if name in text],
    })

checks = []
pack_sources = {}
for path in (root / "core/config_audit/builtin").glob("*.py"):
    if path.stem == "__init__":
        continue
    module = importlib.import_module(f"core.config_audit.builtin.{path.stem}")
    for value in vars(module).values():
        if isinstance(value, list):
            for item in value:
                if hasattr(item, "check_id"):
                    pack_sources.setdefault(item.check_id, []).append(path)
for check in BUILTIN_CHECKS:
    row = plain(check)
    row["test_references"] = [p for p, text in tests.items() if check.check_id in text]
    sources = []
    for path in set(pack_sources.get(check.check_id, [])):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if check.check_id in line:
                sources.append(f"Backend/{path.relative_to(root)}:{n}")
        if not sources:
            tree = ast.parse(path.read_text())
            # Helper-built ids preserve the literal suffix/slug at the call.
            candidates = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and any(
                k.arg in ("suffix", "slug") and isinstance(k.value, ast.Constant)
                and check.check_id.endswith('.' + str(k.value.value)) for k in n.keywords)]
            line = candidates[0].lineno if candidates else 1
            sources.append(f"Backend/{path.relative_to(root)}:{line}")
    row["code_references"] = sources
    row["execution_status"] = "reachable; individual target execution unverified"
    checks.append(row)

network = [plain(c) for c in NETWORK_CHECKS]
modules = []
for folder in ("engines", "core/discovery", "core/config_audit", "core/scap", "core/web", "core/topology", "scans/cve_engine", "orchestrator"):
    for path in (root / folder).rglob("*.py"):
        tree = ast.parse(path.read_text())
        modules.append({"path": f"Backend/{path.relative_to(root)}", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "symbols": [
            {"name": n.name, "line": n.lineno, "kind": type(n).__name__}
            for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        ]})

payload = {
    "plugins": plugins, "builtin_checks": checks, "network_checks": network,
    "collector_pairs": sorted(str(k) for k in collector_registry._by_key),
    "collectors": [{"name": type(c).__name__, "module": type(c).__module__, "check_type": c.check_type, "platforms": list(c.platforms)} for c in collector_registry.all_collectors()],
    "source_modules": modules,
    "credentialed_commands": {
        platform: dict(importlib.import_module(f"engines.credentialed.{platform}_collector").COMMANDS)
        for platform in ("linux", "windows")
    },
    "builtin_by_pack": dict(Counter(c["code_references"][0].split(":")[0] for c in checks)),
    "counts": {
        "legacy_plugins": len(plugins), "legacy_loadable": sum(p["contract"]["imported"] for p in plugins),
        "legacy_contract_valid": sum(not p["problems"] for p in plugins),
        "builtin_checks": len(checks), "builtin_unique_ids": len({c["check_id"] for c in checks}),
        "builtin_by_platform": dict(Counter(p for c in checks for p in c["platforms"])),
        "builtin_by_domain": dict(Counter(c["domain"] for c in checks)),
        "builtin_direct_id_test_references": sum(bool(c["test_references"]) for c in checks),
        "network_check_areas": len(network), "collector_pairs": len(collector_registry._by_key),
        "collector_implementations": len(list(collector_registry.all_collectors())),
        "source_modules": len(modules),
    },
}
print(json.dumps(payload, indent=2, default=str))
