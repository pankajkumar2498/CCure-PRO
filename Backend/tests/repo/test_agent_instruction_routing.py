"""
Every agent reaches the same module instructions (AGENTS.md, "Module and task
instructions").

The module rules live once, in `.claude/rules/`, and the task procedures in
`.claude/skills/`. Claude Code loads a rule by its `paths` frontmatter; Codex
and every other agent find it through the routing table in AGENTS.md. Both
routes must name the same files and the same paths, or one kind of agent
silently works without rules the other one follows. A glob matching nothing is
the same failure: the rule never loads.
"""

import os
import re

import pytest

from testpaths import REPO_ROOT

RULES = REPO_ROOT / ".claude" / "rules"
SKILLS = REPO_ROOT / ".claude" / "skills"
AGENTS = REPO_ROOT / "AGENTS.md"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "__pycache__", "backups"}


def _frontmatter(path):
    text = path.read_text(encoding="utf-8")
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert match, f"{path.name}: no frontmatter"
    return match[1]


def _paths(rule):
    lines = _frontmatter(rule).splitlines()
    assert (
        lines and lines[0] == "paths:"
    ), f"{rule.name}: frontmatter must start with paths:"
    globs = [re.fullmatch(r'  - "([^"]+)"', line) for line in lines[1:]]
    assert globs and all(globs), f"{rule.name}: paths must be a quoted list"
    return [g[1] for g in globs]


def _glob_regex(pattern):
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def _repo_files():
    files = []
    for root, dirs, names in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel = os.path.relpath(root, REPO_ROOT)
        for name in names:
            files.append(name if rel == "." else f"{rel}/{name}".replace(os.sep, "/"))
    return files


RULE_FILES = sorted(RULES.glob("*.md"))
SKILL_FILES = sorted(SKILLS.glob("*/SKILL.md"))


def test_there_are_rules_and_skills_to_route():
    assert RULE_FILES and SKILL_FILES


@pytest.mark.parametrize("rule", RULE_FILES, ids=lambda p: p.name)
def test_every_rule_path_matches_a_file(rule):
    files = _repo_files()
    for pattern in _paths(rule):
        regex = _glob_regex(pattern)
        assert any(
            regex.match(f) for f in files
        ), f"{rule.name}: {pattern} matches nothing"


@pytest.mark.parametrize("rule", RULE_FILES, ids=lambda p: p.name)
def test_agents_md_routes_to_every_rule_with_its_paths(rule):
    link = f"(.claude/rules/{rule.name})"
    rows = [
        line for line in AGENTS.read_text(encoding="utf-8").splitlines() if link in line
    ]
    assert len(rows) == 1, f"AGENTS.md must have one routing row for {rule.name}"
    listed = re.findall(r"`([^`]+)`", rows[0].split("|")[3])
    assert listed == _paths(rule), f"AGENTS.md lists different paths for {rule.name}"


@pytest.mark.parametrize("skill", SKILL_FILES, ids=lambda p: p.parent.name)
def test_every_skill_is_well_formed_and_routed(skill):
    front = _frontmatter(skill)
    assert re.search(rf"^name: {re.escape(skill.parent.name)}$", front, re.M)
    assert re.search(
        r"^description: \S.{40,}$", front, re.M
    ), "a skill needs a description"
    assert f"(.claude/skills/{skill.parent.name}/SKILL.md)" in AGENTS.read_text(
        encoding="utf-8"
    )


def test_no_rule_is_loaded_unconditionally():
    # A rule without paths loads in every session, which is CLAUDE.md's job.
    for rule in RULE_FILES:
        assert _paths(rule)


def test_frontend_shares_one_copy_with_every_agent():
    claude_md = (REPO_ROOT / "Frontend" / "CLAUDE.md").read_text(encoding="utf-8")
    assert re.search(r"^@AGENTS\.md$", claude_md, re.M)
    assert "UX4G_STANDARD.md" in (REPO_ROOT / "Frontend" / "AGENTS.md").read_text(
        encoding="utf-8"
    )


def test_the_shared_instructions_are_not_ignored_by_git():
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".claude/" not in ignore
    assert {"!.claude/rules/", "!.claude/skills/"} <= set(ignore)
