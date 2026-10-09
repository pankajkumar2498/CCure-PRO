"""
Reject a commit message that lists an AI coding agent as a co-author.

The rule is CLAUDE.md, "Commits made by AI agents": AI coding agents must never
add themselves as Git co-authors. This is its mechanical half, run by
pre-commit at the ``commit-msg`` stage (``.pre-commit-config.yaml``, hook
``no-ai-coauthor``), so it holds whichever agent wrote the message and whether
or not it read the instructions.

    python scripts/git/check_ai_coauthors.py .git/COMMIT_EDITMSG

A line is checked when it is a ``Co-authored-by:`` trailer, in any case. Git
comment lines and everything below the ``git commit -v`` scissors line are not
part of the message and are ignored. Prose that merely mentions an AI tool is
not a trailer and is allowed.

A co-author is an AI agent when its e-mail domain belongs to an AI vendor or
agent, or its name is an AI product or agent. "Claude" is treated with care
because it is also a human first name: ``Claude Opus 5.5``, ``Claude Code``,
``Claude`` alone and anything at ``anthropic.com`` are rejected, while a person
such as ``Claude Dupont <claude.dupont@example.org>`` is not. Human co-authors
are never rejected for their name alone, so ``Devin``, ``Cody`` and ``Jules``
are allowed unless the identity says it is an agent.

Standard library only: pre-commit runs this in its own small environment.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404 — fixed argv, reading git config only
import sys
from pathlib import Path

TRAILER = re.compile(r"^\s*co-authored-by\s*:\s*(?P<value>.*\S)\s*$", re.IGNORECASE)
SCISSORS = re.compile(r"^. -+ >8 -+$")
IDENTITY = re.compile(r"^(?P<name>.*?)\s*(?:<(?P<email>[^>]*)>)?$")

# Domains whose addresses are AI vendors or agents, never a person's employer
# in this context. Matched exactly or as a parent domain.
AI_EMAIL_DOMAINS = (
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "openai.com",
    "chatgpt.com",
    "cursor.com",
    "cursor.sh",
    "codeium.com",
    "windsurf.com",
    "tabnine.com",
    "aider.chat",
    "devin.ai",
    "cognition.ai",
    "sweep.dev",
)

# Names that are AI products or agents, never a person's name.
AI_NAME = re.compile(
    r"""
    \b(
        anthropic | openai | codex | copilot | chatgpt | gpt-?\d[\w.]*
      | gemini | bard | codewhisperer | amazon[\s-]+q\b | codeium | windsurf
      | tabnine | aider | cursor[\s-]?(?:agent|ai|bot) | cursoragent
      | devin[\s-]?ai | sourcegraph | cody[\s-]?ai | replit[\s-]?(?:agent|ai)
      | sweep[\s-]?ai | jules[\s-]?(?:agent|ai|bot) | google[\s-]?jules
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# "Claude" as Anthropic's model or agent: alone, as a bot, or followed by a
# product or model word. "Claude Dupont" is a person and does not match.
CLAUDE_AGENT = re.compile(
    r"""
    ^claude
    (?:
        \s*\[bot\]
      | \s+(?:code|ai|agent|assistant|opus|sonnet|haiku|fable|instant|\d[\w.]*)\b.*
    )?$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _comment_char() -> str:
    try:
        value = subprocess.run(  # nosec B603 B607 — fixed argv
            ["git", "config", "--get", "core.commentChar"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except OSError:
        return "#"
    return value if len(value) == 1 else "#"


def is_ai_identity(value: str) -> bool:
    """True when a ``Co-authored-by`` value names an AI agent."""
    match = IDENTITY.match(value.strip())
    name = (match.group("name") if match else value).strip().strip('"')
    email = (match.group("email") or "").strip().lower() if match else ""
    domain = email.rpartition("@")[2]
    if domain and any(
        domain == d or domain.endswith("." + d) for d in AI_EMAIL_DOMAINS
    ):
        return True
    if AI_NAME.search(name) or AI_NAME.search(email.rpartition("@")[0]):
        return True
    return bool(CLAUDE_AGENT.match(name))


def message_lines(text: str, comment_char: str = "#") -> list[str]:
    """The lines git keeps as the message: no comments, nothing past scissors."""
    kept = []
    for line in text.splitlines():
        if SCISSORS.match(line) and line.startswith(comment_char):
            break
        if line.startswith(comment_char):
            continue
        kept.append(line)
    return kept


def ai_coauthor_lines(text: str, comment_char: str = "#") -> list[str]:
    """Every ``Co-authored-by`` line in the message that names an AI agent."""
    found = []
    for line in message_lines(text, comment_char):
        trailer = TRAILER.match(line)
        if trailer and is_ai_identity(trailer.group("value")):
            found.append(line.strip())
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_ai_coauthors.py <commit-message-file>", file=sys.stderr)
        return 2
    text = Path(argv[0]).read_text(encoding="utf-8", errors="replace")
    offending = ai_coauthor_lines(text, _comment_char())
    if not offending:
        return 0
    print(
        "Commit rejected: an AI coding agent is listed as a co-author.\n\n    "
        + "\n    ".join(offending)
        + "\n\nAI coding agents must never add themselves as Git co-authors "
        '(CLAUDE.md, "Commits made by AI agents"). Remove the line(s) above '
        "and commit again. Human co-authors are allowed.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
