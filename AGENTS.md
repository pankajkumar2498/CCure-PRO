# Repository instructions for contributors and AI assistants

For any frontend change, read [Frontend/AGENTS.md](Frontend/AGENTS.md),
[frontend architecture](docs/FRONTEND_ARCHITECTURE.md) and the permanent
[UX4G standard](docs/ux4g/UX4G_STANDARD.md). The same standard applies to Common,
Auth, Audit, Policy, Rank, IR and future modules. Use the approved exact UX4G
release through the central asset pipeline and shared CCure adapters. Preserve
CSP, API/auth/RBAC/routing contracts. Run the documented frontend CI checks.

Read [CLAUDE.md](CLAUDE.md) for repository operational rules before backend,
database or deployment work. Frontend-only validation uses synthetic API fixtures;
do not run destructive backend tests against the live application database.

**Commits, for every change:** an AI coding agent creating a Git commit must not
add itself as a co-author. Do not add `Claude`, `Anthropic`, `Codex`, `OpenAI`,
`Copilot`, or any other AI identity as a `Co-authored-by` trailer. Preserve the
legitimate human author/committer information and any explicitly required human
co-authors. Defined in [CLAUDE.md](CLAUDE.md), "Commits made by AI agents".
