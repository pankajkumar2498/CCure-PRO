"""
The commit-msg hook that keeps AI agents out of commit co-authors
(CLAUDE.md, "Commits made by AI agents").

It must reject every common AI identity and must never reject a person,
including people whose first name is also a product name. Both directions are
pinned here, because a check that refuses a human co-author would be switched
off, and a check that misses an agent enforces nothing.
"""

import importlib.util

import pytest
import yaml

from testpaths import REPO_ROOT

CHECKER = REPO_ROOT / "scripts" / "git" / "check_ai_coauthors.py"
PRECOMMIT_CONFIG = REPO_ROOT / ".pre-commit-config.yaml"


def _checker():
    spec = importlib.util.spec_from_file_location("check_ai_coauthors", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _checker()


@pytest.mark.parametrize(
    "identity",
    [
        "Claude Opus 5.5 <noreply@anthropic.com>",
        "Claude <noreply@anthropic.com>",
        "Claude Code <noreply@anthropic.com>",
        "Claude Sonnet 5.5 <someone@example.com>",
        "claude[bot] <209825114+claude[bot]@users.noreply.github.com>",
        "Anthropic <bot@example.com>",
        "Codex <codex@openai.com>",
        "OpenAI Codex <agent@example.com>",
        "ChatGPT <noreply@example.com>",
        "Copilot <175728472+Copilot@users.noreply.github.com>",
        "GitHub Copilot <copilot@github.com>",
        "Gemini Code Assist <agent@google.com>",
        "Cursor Agent <cursoragent@cursor.com>",
        "devin-ai-integration[bot] <158243242+devin-ai-integration[bot]@users.noreply.github.com>",
        "aider (gpt-4o) <noreply@aider.chat>",
        "Amazon Q Developer <q@amazon.com>",
        "Windsurf <noreply@windsurf.com>",
        "Someone <assistant@anthropic.com>",
    ],
)
def test_ai_identities_are_rejected(identity):
    assert checker.is_ai_identity(identity)


@pytest.mark.parametrize(
    "identity",
    [
        "pankajkumar2498 <pankaj2498.kumar@gmail.com>",
        "Jane Doe <jane@example.com>",
        "Claude Dupont <claude.dupont@cdac.in>",
        "Devin Patel <devin@cdac.in>",
        "Cody Smith <cody@example.org>",
        "Jules Verne <jules@example.fr>",
    ],
)
def test_people_are_never_rejected(identity):
    assert not checker.is_ai_identity(identity)


def test_only_real_trailers_in_the_message_count():
    message = (
        "docs: explain the attribution rule\n"
        "\n"
        "Agents such as Claude used to add a Co-authored-by trailer.\n"
        "\n"
        "Co-authored-by: Jane Doe <jane@example.com>\n"
        "# Co-authored-by: Claude <noreply@anthropic.com>\n"
        "# ------------------------ >8 ------------------------\n"
        "+Co-authored-by: Claude <noreply@anthropic.com>\n"
        "Co-authored-by: Claude <noreply@anthropic.com>\n"
    )
    assert checker.ai_coauthor_lines(message) == []


def test_a_trailer_is_found_in_any_letter_case():
    message = "fix: x\n\nco-AUTHORED-by: Claude Opus 5.5 <noreply@anthropic.com>\n"
    assert checker.ai_coauthor_lines(message) == [
        "co-AUTHORED-by: Claude Opus 5.5 <noreply@anthropic.com>"
    ]


def test_the_hook_rejects_and_explains(tmp_path, capsys):
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text(
        "feat: y\n\nCo-authored-by: Codex <codex@openai.com>\n", encoding="utf-8"
    )
    assert checker.main([str(message)]) == 1
    error = capsys.readouterr().err
    assert "Co-authored-by: Codex <codex@openai.com>" in error
    assert "must never add themselves as Git co-authors" in error

    message.write_text(
        "feat: y\n\nCo-authored-by: Jane Doe <jane@example.com>\n", encoding="utf-8"
    )
    assert checker.main([str(message)]) == 0


def test_the_hook_runs_on_the_commit_message_and_is_installed_by_default():
    config = yaml.safe_load(PRECOMMIT_CONFIG.read_text(encoding="utf-8"))
    assert "commit-msg" in config["default_install_hook_types"]
    # Every other hook stays at the pre-commit stage; without this they would
    # all run a second time on the message.
    assert config["default_stages"] == ["pre-commit"]
    hooks = [hook for repo in config["repos"] for hook in repo["hooks"]]
    (hook,) = [hook for hook in hooks if hook["id"] == "no-ai-coauthor"]
    assert hook["stages"] == ["commit-msg"]
    assert (REPO_ROOT / hook["entry"].split()[-1]).is_file()


def test_the_rule_is_in_the_primary_instructions():
    claude_md = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert "**AI Commit Attribution:**" in claude_md
    assert "no-ai-coauthor" in claude_md
