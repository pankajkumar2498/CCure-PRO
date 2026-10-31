"""
The engineering record: CLAUDE.md as it was before the instruction split
(docs/archive/engineering-record/README.md).

The record is frozen and verbatim. Its files wrap each piece of the original in
`<!-- verbatim: CLAUDE.md@<rev> lines A-B -->` blocks; reassembled in line order
they must cover every line exactly once and reproduce the original byte for
byte. That is what lets the live instructions be shortened without losing a
decision, a measurement or a command.
"""

import hashlib
import re

from testpaths import REPO_ROOT

RECORD = REPO_ROOT / "docs" / "archive" / "engineering-record"
BLOCK = re.compile(
    r"<!-- verbatim: CLAUDE\.md@(?P<rev>[0-9a-f]+) lines (?P<a>\d+)-(?P<b>\d+) -->\n"
    r"(?P<body>.*?)\n<!-- /verbatim -->",
    re.S,
)
SOURCE = re.compile(
    r"`CLAUDE\.md` at `(?P<rev>[0-9a-f]+)`, (?P<n>\d+) lines, SHA-256 `(?P<sha>[0-9a-f]{64})`"
)


def _blocks():
    found = []
    for path in sorted(RECORD.glob("*.md")):
        if path.name == "README.md":
            continue
        for match in BLOCK.finditer(path.read_text(encoding="utf-8")):
            found.append(
                (
                    int(match["a"]),
                    int(match["b"]),
                    match["rev"],
                    match["body"],
                    path.name,
                )
            )
    return sorted(found)


def _source():
    match = SOURCE.search((RECORD / "README.md").read_text(encoding="utf-8"))
    assert match, "README.md must name the source revision, line count and SHA-256"
    return match["rev"], int(match["n"]), match["sha"]


def test_blocks_cover_every_original_line_exactly_once():
    rev, total, _ = _source()
    expect = 1
    for a, b, block_rev, body, name in _blocks():
        assert block_rev == rev, f"{name}: block from {block_rev}, record is {rev}"
        assert a == expect, f"{name}: lines {a}-{b} leave a gap or overlap at {expect}"
        assert (
            body.count("\n") + 1 == b - a + 1
        ), f"{name}: lines {a}-{b} hold the wrong count"
        expect = b + 1
    assert expect == total + 1, f"the blocks stop at line {expect - 1} of {total}"


def test_reassembly_is_byte_identical_to_the_original():
    _, _, sha = _source()
    text = "\n".join(body for _, _, _, body, _ in _blocks()) + "\n"
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == sha


def test_every_record_file_is_indexed():
    readme = (RECORD / "README.md").read_text(encoding="utf-8")
    for path in RECORD.glob("*.md"):
        if path.name != "README.md":
            assert f"]({path.name})" in readme, f"{path.name} is not in the index"


def test_every_correction_names_real_lines_and_a_live_file():
    # A correction lets the preservation audit accept a changed original line,
    # so each one must point inside the original and at a file that exists.
    _, total, _ = _source()
    readme = (RECORD / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Corrections since the split", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| (\d+)–(\d+) \| `([^`]+)` \|", section, re.M)
    assert rows, "the corrections table has no rows"
    for a, b, live in rows:
        assert 1 <= int(a) <= int(b) <= total, f"lines {a}-{b} are outside the original"
        assert (REPO_ROOT / live).is_file(), f"{live} does not exist"


def test_the_record_is_excluded_from_prettier():
    # Prettier re-pads tables and re-wraps code spans, which would break the
    # byte-for-byte guarantee on the first commit that touched the folder.
    config = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "archive/engineering-record" in config
