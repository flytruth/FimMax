# Contributing to wazuh-fim-telegram

Thanks for considering a contribution! This document is short on purpose.

## Quick checklist before opening a PR

1. **Open an issue first** for anything beyond a typo / small bugfix, so we can
   discuss the approach before you spend time on code.
2. **Keep PRs small** and focused on one concern. A PR that mixes a refactor,
   a feature, and a config change is much harder to review.
3. **Add tests** for new behaviour. We don't require 100% coverage, but new
   code paths should be exercised.
4. **All checks green locally**:
   ```bash
   ruff check src tests scripts
   ruff format --check src tests
   mypy
   pytest
   ```
   (`make lint test typecheck` runs all of them.)
5. **No secrets** in code, commits, or PRs. Review your diff before pushing.
6. **Update docs** (`README.md`, `docs/`, `CHANGELOG.md`) if behaviour or
   config changes.

## Development setup

```bash
git clone https://github.com/your-org/wazuh-fim-telegram.git
cd wazuh-fim-telegram
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

`pre-commit` will run ruff (autofix), ruff-format, mypy and a few sanity
hooks (YAML/TOML validity, trailing whitespace, private-key detection) on
every commit.

## Code style

- **Formatter**: `ruff format` (Black-compatible).
- **Linter**: `ruff check` with `E, F, W, I, B, UP, SIM, RUF` rules.
- **Types**: `mypy --strict`. New modules should be fully typed; if a third-
  party library lacks stubs, add a `[[tool.mypy.overrides]]` block in
  `pyproject.toml`.
- **Async**: the bot and the Wazuh client are async. Don't introduce sync
  HTTP calls in the hot path.

## Commit messages

Conventional Commits are appreciated but not enforced:

```
feat(bot): add /silence command for temporary global mute
fix(wazuh_client): retry on 429
docs: clarify DIGEST_CRON format
```

## Tests

Tests live in `tests/` and use `pytest` + `pytest-asyncio` (auto mode) +
`respx` (httpx mocking) + `freezegun` (time mocking). No test should hit a
real external service; mark integration tests with `@pytest.mark.integration`
so they can be skipped in CI (`pytest -m "not integration"`).

Coverage is collected automatically by `pytest --cov`; aim to keep total
coverage above 85% and never regress it without a written reason in the PR
description.

## CI

`.github/workflows/ci.yml` runs on every push and PR:

- `ruff check` + `ruff format --check`
- `mypy`
- `pytest` on Python 3.10, 3.11, 3.12
- Docker build + smoke test
- `shellcheck` on `scripts/*.sh`

`.github/workflows/codeql.yml` runs a weekly CodeQL scan.

All of these must be green for a PR to be merged.

## Releasing

1. Update `CHANGELOG.md` under a new `## [Unreleased]` → `## [x.y.z]` heading.
2. Bump `version` in `pyproject.toml` and `src/wazuh_fim_telegram/__init__.py`.
3. Tag `git tag vx.y.z && git push --tags`.
4. The GitHub release page will pick up the tag and CHANGELOG entry.
