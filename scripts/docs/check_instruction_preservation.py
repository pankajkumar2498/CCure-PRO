#!/usr/bin/env python3
"""Prove that splitting CLAUDE.md lost no instruction.

The original file is rebuilt from the verbatim blocks of
docs/archive/engineering-record/ (and checked against the SHA-256 its README
names). Every statement in it that carries an obligation (must, never, do not,
only, always, refuse, ...) and every fenced code block must then be either

  * present in the live instructions: CLAUDE.md, AGENTS.md, Frontend/AGENTS.md,
    .claude/rules/*.md and .claude/skills/*/SKILL.md; or
  * inside a range the archive README lists as living only in the archive,
    which records the reason; or
  * inside a range its "Corrections since the split" table lists, which names
    the live file, the correction and the evidence for it.

Anything else is reported as MISSING and the exit status is 1. Matching
ignores Markdown emphasis, code ticks, escapes and line wrapping, because the
live files are reformatted by Prettier and end-of-file fixers.

    python3 scripts/docs/check_instruction_preservation.py [--list]
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "docs" / "archive" / "engineering-record"
LIVE = [
    ROOT / "CLAUDE.md",
    ROOT / "AGENTS.md",
    ROOT / "Frontend" / "AGENTS.md",
    *sorted((ROOT / ".claude" / "rules").glob("*.md")),
    *sorted((ROOT / ".claude" / "skills").glob("*/SKILL.md")),
]
BLOCK = re.compile(
    r"<!-- verbatim: CLAUDE\.md@[0-9a-f]+ lines (\d+)-(\d+) -->\n(.*?)\n<!-- /verbatim -->",
    re.S,
)
OBLIGATION = re.compile(
    r"\b(must|never|do not|don't|does not|cannot|can't|may not|must not|only|always|"
    r"required?|requires|refuse[sd]?|forbid\w*|mandatory|not optional|no \w+ may)\b",
    re.I,
)


def original():
    blocks = []
    for path in sorted(RECORD.glob("*.md")):
        if path.name != "README.md":
            blocks += [(int(a), int(b), body) for a, b, body in BLOCK.findall(path.read_text())]
    blocks.sort()
    text = "\n".join(body for _, _, body in blocks) + "\n"
    readme = (RECORD / "README.md").read_text()
    sha = re.search(r"SHA-256 `([0-9a-f]{64})`", readme)[1]
    if hashlib.sha256(text.encode()).hexdigest() != sha:
        sys.exit("the engineering record does not reassemble to its recorded SHA-256")
    reasons = readme.split("lives **only** here", 1)[1].split("## Index", 1)[0]
    archive_only = [
        (int(a), int(b), why)
        for a, b, why in re.findall(r"^\| (\d+)–(\d+) \| ([^|]+?) \|$", reasons, re.M)
    ]
    corrections = []
    if "## Corrections since the split" in readme:
        section = readme.split("## Corrections since the split", 1)[1].split("\n## ", 1)[0]
        corrections = [
            (int(a), int(b), why)
            for a, b, why in re.findall(r"^\| (\d+)–(\d+) \| (.+?) \|$", section, re.M)
        ]
    return text.split("\n")[:-1], archive_only, corrections


def norm(text):
    text = text.replace("\\", " ")  # escapes and shell line continuations
    text = re.sub(r"[*_`>|#]", " ", text)
    text = text.replace("’", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", text).strip().lower()


def units(lines):
    """Yield (first line, kind, text): prose sentences and fenced code blocks."""
    i = 0
    while i < len(lines):
        line = lines[i]
        fence = re.match(r"\s*(```|~~~)", line)
        if fence:
            start = i
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(fence[1]):
                i += 1
            yield start + 1, "code", "\n".join(lines[start + 1 : i])
            i += 1
            continue
        if not line.strip() or line.lstrip().startswith("<!--"):
            i += 1
            continue
        start = i
        para = [line]
        i += 1
        while (
            i < len(lines)
            and lines[i].strip()
            and not re.match(r"\s*([-*] |\d+\. |\||#|```)", lines[i])
        ):
            para.append(lines[i])
            i += 1
        joined = " ".join(p.strip() for p in para)
        for sentence in re.split(r"(?<=[.!?:;])\s+(?=[A-Z(\"`*_])", joined):
            yield start + 1, "prose", sentence


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--list", action="store_true", help="list every archived unit too")
    args = parser.parse_args()
    lines, archive_only, corrections = original()
    corpus = norm("\n".join(p.read_text(encoding="utf-8") for p in LIVE))
    counts = {"live": 0, "archived": 0, "corrected": 0, "missing": 0}
    code = {"live": 0, "archived": 0, "corrected": 0, "missing": 0}
    missing = []
    for line_no, kind, text in units(lines):
        if kind == "prose" and not OBLIGATION.search(text):
            continue
        if kind == "code" and not text.strip():
            continue
        bucket = code if kind == "code" else counts
        reason = next((why for a, b, why in archive_only if a <= line_no <= b), None)
        fixed = next((why for a, b, why in corrections if a <= line_no <= b), None)
        if norm(text) in corpus:
            bucket["live"] += 1
        elif fixed:
            bucket["corrected"] += 1
            if args.list:
                print(f"corrected line {line_no}: {text[:100]!r}  ({fixed[:60]})")
        elif reason:
            bucket["archived"] += 1
            if args.list:
                print(f"archived  line {line_no}: {text[:100]!r}  ({reason[:60]})")
        else:
            bucket["missing"] += 1
            missing.append((line_no, kind, text))
    # Every non-blank line, commands in indented blocks included, outside the
    # archive-only ranges must survive somewhere live.
    line_counts = {"live": 0, "archived": 0, "corrected": 0, "missing": 0}
    for line_no, line in enumerate(lines, 1):
        if not norm(line):
            continue
        reason = next((why for a, b, why in archive_only if a <= line_no <= b), None)
        fixed = any(a <= line_no <= b for a, b, _ in corrections)
        if norm(line) in corpus:
            line_counts["live"] += 1
        elif fixed:
            line_counts["corrected"] += 1
        elif reason:
            line_counts["archived"] += 1
        else:
            line_counts["missing"] += 1
            missing.append((line_no, "line", line))
    print(f"original: {len(lines)} lines, rebuilt from the engineering record (SHA-256 verified)")
    print(
        "non-blank lines: "
        f"{line_counts['live']} live, {line_counts['archived']} archive-only, "
        f"{line_counts['corrected']} corrected with recorded evidence, "
        f"{line_counts['missing']} missing"
    )
    print(f"live files checked: {len(LIVE)}")
    print(
        "obligation statements: "
        f"{counts['live']} live, {counts['archived']} archive-only with a recorded reason, "
        f"{counts['corrected']} corrected with recorded evidence, {counts['missing']} missing"
    )
    print(
        "code blocks: "
        f"{code['live']} live, {code['archived']} archive-only, {code['missing']} missing"
    )
    for line_no, kind, text in missing:
        print(f"MISSING {kind} at original line {line_no}: {text[:160]!r}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
