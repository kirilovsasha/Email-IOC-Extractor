# Contributing

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e ".[dev]"
```

## Checks before a PR

```bash
python build/sync_version_info.py   # keeps pyproject + version_info in sync with __init__
ruff check reliquary
pytest -q --cov=reliquary/core --cov-fail-under=68
python scripts/corpus_metrics.py
```

Bump `__version__` in `reliquary/__init__.py` for user-facing changes, then run
`python build/sync_version_info.py` and update `CHANGELOG.md`.

## Scope

- Prefer small PRs: detection/verdict, GUI, packaging, docs.
- Keep the tool offline — no telemetry, no network clients in `reliquary/`.
- Golden corpus: if you change scoring, update `samples/corpus/expected.json` via
  `scripts/regen_expected.py` only when intentional.

## Code style

- Python 3.10+, ruff (`E`, `F`, `I`, `W`), line length 100.
- Type hints on new core APIs; mypy runs on listed modules in CI.
