# Repository Guidelines

## Project Structure & Module Organization

This Python 3.11+ repository provides read-only Linux and network-device discovery over SSH. Human and AI-assisted contributions follow the same requirements for scoped changes, independent review, verification, and human PR approval.

- `src/infra_discovery/`: CLI, validated inputs, domain models, discovery orchestration, SSH collectors, and output serialization.
- `tests/`: offline pytest coverage using sanitized fixtures and simulated SSH sessions.
- `examples/`: location for sanitized usage examples and sample configuration.
- `pyproject.toml`: package metadata and setuptools build configuration.
- `README.md`: setup and usage documentation.

## Build, Test, and Development Commands

Run commands from the repository root:

- `python -m venv .venv`: create a local virtual environment.
- `.\.venv\Scripts\Activate.ps1`: activate it in PowerShell.
- `python -m pip install -e ".[dev]"`: install the package and development tools in editable mode.
- `python -m build`: build a source distribution and wheel using the configured setuptools backend.
- `python -m pytest`: run the complete offline test suite. On Windows, use `--basetemp=.pytest-temp` if the default temporary directory is inaccessible.
- `git diff --check`: check changes for whitespace errors.

The installed CLI is `infra-discovery`; use `infra-discovery --help` for syntax. No static-check tooling is configured.

## Coding Style & Naming Conventions

Use four-space indentation and PEP 8 conventions: `snake_case` for modules, functions, and variables; `PascalCase` for classes; `UPPER_SNAKE_CASE` for constants and enum members. Use type annotations for public interfaces.

Preserve per-target failure isolation: one infrastructure target's failure must not terminate processing of unrelated targets.

## Testing Guidelines

Use pytest, files named `tests/test_*.py`, and functions named `test_*`. All behavioral changes require appropriate tests. Never contact real infrastructure from automated tests; use mocks or fixtures.

Do not weaken, remove, skip, or rewrite tests merely to pass validation unless the task explicitly changes the tested behavior.

## Task Scope & Workflow

Keep changes scoped to the requested task; avoid unrelated refactors and preserve unrelated local edits. Introduce dependencies only when they solve a current task requirement. Do not modify CI, security controls, `AGENTS.md`, or validation configuration during unrelated implementation tasks.

## Commit & Pull Request Guidelines

Follow the existing `chore: initialize project structure` prefix style, for example `feat: add target validation`.

Use task-specific branches; never commit directly to `main`. PRs should describe requirements addressed and verification results, link relevant issues, and receive human review.

## Security & Configuration

Never commit credentials, secrets, private keys, real inventories, or sensitive infrastructure information. Never hardcode credentials into source, tests, examples, logs, exceptions, or serialized output. Use sanitized fixtures and examples.

## Definition of Done

- Satisfy the stated requirements, including appropriate behavioral tests; running successfully alone is insufficient.
- Run the repository's defined tests and static checks; pass all required verification and remediate failures before declaring implementation complete.
- Inspect the final Git diff for unintended changes and report verification results and any blockers.
