# Repository instructions for contributors and AI agents

**Read and follow [CLAUDE.md](CLAUDE.md) before any change, in any part of the
repository.** It is the primary instruction document and the source of truth for
repository-wide rules: commits, test-database safety, architecture guardrails,
deployment, and the rest. This file only routes; it adds no rules of its own.

Then read the specialist documents for the area you are changing:

| Area | Read |
| ---- | ---- |
| Frontend (anything under `Frontend/`) | [Frontend/AGENTS.md](Frontend/AGENTS.md), [docs/FRONTEND_ARCHITECTURE.md](docs/FRONTEND_ARCHITECTURE.md) |
| UX4G and the CCure Design System | [docs/ux4g/UX4G_STANDARD.md](docs/ux4g/UX4G_STANDARD.md), the standard; [Frontend/ux4g-baseline.json](Frontend/ux4g-baseline.json), the binding release pin and checksums |
| Backend tests | [Backend/tests/README.md](Backend/tests/README.md) |
| Which tests to run for a change (targeted first) | [CLAUDE.md](CLAUDE.md), "Test targeted-first"; [docs/ci/CI_SCOPE.md](docs/ci/CI_SCOPE.md) |
| CI, branch protection, security gates | [docs/ci/](docs/ci/) |

`.pre-commit-config.yaml`, the architecture guardrails in
`Backend/scripts/architecture/` and the repository tests enforce many of these
rules and are authoritative for the rules they enforce.
