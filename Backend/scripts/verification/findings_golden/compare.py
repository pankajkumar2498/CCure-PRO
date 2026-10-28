"""
Compare two findings-golden captures byte for byte.

    python3 compare.py <capture-a> <capture-b>

Every file of each capture is compared, except the run logs (``*.log``) and the
``commit`` stamp, which name the run rather than its results. A differing text
file is shown as the first lines of a unified diff; a differing workbook is
opened as the ZIP it is and its differing members named. Exit status 0 when the
captures are identical, 1 when they differ.
"""

from __future__ import annotations

import difflib
import sys
import zipfile
from pathlib import Path

IGNORED_SUFFIXES = (".log",)
IGNORED_NAMES = ("commit",)
DIFF_LINES = 40


def files_of(root: Path) -> dict[str, Path]:
    return {
        str(p.relative_to(root)): p
        for p in sorted(root.rglob("*"))
        if p.is_file()
        and not p.name.endswith(IGNORED_SUFFIXES)
        and p.name not in IGNORED_NAMES
    }


def describe_zip(a: Path, b: Path) -> list[str]:
    with zipfile.ZipFile(a) as za, zipfile.ZipFile(b) as zb:
        names = sorted(set(za.namelist()) | set(zb.namelist()))
        lines = []
        for name in names:
            if name not in za.namelist() or name not in zb.namelist():
                lines.append(f"    member only on one side: {name}")
                continue
            ia, ib = za.getinfo(name), zb.getinfo(name)
            if za.read(name) != zb.read(name):
                lines.append(f"    member differs: {name}")
            elif ia.date_time != ib.date_time:
                lines.append(f"    member timestamp differs: {name}")
        return lines or ["    members identical; the archive bytes differ"]


def describe_text(a: Path, b: Path) -> list[str]:
    try:
        left = a.read_text(encoding="utf-8").splitlines()
        right = b.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return ["    binary content differs"]
    diff = list(difflib.unified_diff(left, right, "a", "b", lineterm="", n=1))
    shown = [f"    {line[:300]}" for line in diff[:DIFF_LINES]]
    if len(diff) > DIFF_LINES:
        shown.append(f"    … {len(diff) - DIFF_LINES} more diff lines")
    return shown


def main(a_root: str, b_root: str) -> int:
    a, b = Path(a_root), Path(b_root)
    fa, fb = files_of(a), files_of(b)
    only_a = sorted(set(fa) - set(fb))
    only_b = sorted(set(fb) - set(fa))
    differing = [
        n for n in sorted(set(fa) & set(fb)) if fa[n].read_bytes() != fb[n].read_bytes()
    ]
    print(f"{a} vs {b}: {len(set(fa) & set(fb))} files in both")
    for name in only_a:
        print(f"only in a: {name}")
    for name in only_b:
        print(f"only in b: {name}")
    for name in differing:
        print(f"differs: {name}")
        if name.endswith(".xlsx"):
            lines = describe_zip(fa[name], fb[name])
        else:
            lines = describe_text(fa[name], fb[name])
        print("\n".join(lines))
    identical = not (only_a or only_b or differing)
    print(
        "IDENTICAL"
        if identical
        else f"DIFFERENT: {len(differing)} differing, "
        f"{len(only_a)} only in a, {len(only_b)} only in b"
    )
    return 0 if identical else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
