"""Summarise a Trivy JSON report as a Markdown table for the Actions job summary.

    python3 scripts/ci/trivy_summary.py <report.json> <title>

Counts every finding by package type, severity and whether a fixed version is
published. The gate in images.yml blocks only on fixable CRITICAL and HIGH;
this table is how the rest stays visible instead of disappearing.
"""

import collections
import json
import sys

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def main(path: str, title: str) -> None:
    report = json.load(open(path))
    counts = collections.Counter()
    for result in report.get("Results") or []:
        kind = result.get("Type", "?")
        for vuln in result.get("Vulnerabilities") or []:
            fixable = "fixed version published" if vuln.get("FixedVersion") else "no fix published"
            counts[(kind, vuln.get("Severity", "UNKNOWN"), fixable)] += 1

    print(f"### {title}")
    if not counts:
        print("\nNo vulnerabilities reported.")
        return
    print("\n| Package type | Severity | Fix | Count |\n|---|---|---|---|")
    for (kind, sev, fixable), n in sorted(
        counts.items(), key=lambda kv: (kv[0][0], ORDER.index(kv[0][1]), kv[0][2])
    ):
        print(f"| {kind} | {sev} | {fixable} | {n} |")
    print(f"\nTotal: {sum(counts.values())}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
