# Development

`llmbuster` is a Python 3.12 project managed with [`uv`](https://github.com/astral-sh/uv).
Lint is `ruff`, types are checked with `mypy` (strict), tests run on `pytest`.

## Setup

```bash
uv sync                       # install deps (including the dev group)
uv run llmbuster --help       # verify the entrypoint
uv run llmbuster selftest     # validate packs + detectors, no API calls
```

## Checks

Run all three before pushing. The CI workflow (`.github/workflows/ci.yml`)
runs the same commands.

```bash
uv run ruff check             # lint
uv run mypy llmbuster         # type check (strict)
uv run pytest                 # test suite (offline + deterministic)
```

ruff rules: `E, F, I, UP, B, SIM, ANN`. Line length 100. Target py312.

## Authoritative spec & conventions

- [`PLAN.md`](https://github.com/g-goessel/llmbuster/blob/main/PLAN.md) — binding
  specification. §3 (SQLite schema), §4 (payload pack schema), §5 (target
  profile schema), and §6 (domain models) are authoritative references; build
  against them exactly.
- [`AGENTS.md`](https://github.com/g-goessel/llmbuster/blob/main/AGENTS.md) —
  conventions and definition-of-done for contributors.

Conventions in brief:

- Type-hint everything.
- pydantic v2 models for all serializable data.
- Shared types live in `llmbuster/domain/` to avoid circular imports.
- Do not add comments to code unless explicitly requested.
- Follow existing file style; mimic neighboring code.

## Package layout

```
llmbuster/
  domain/        # models, protocols
  target/        # targets, profile engine, interpolation
  payload/       # loader, mutation
  detector/      # detectors
  orchestrator/  # scanning, repetition, chains, summary
  store/         # sqlite + writer task
  tui/           # Textual app + panels
    app.py       # LlmBusterApp (tabs, content switcher, drainer)
    screens/     # ConfigPanel, DashboardPanel, HistoryPanel, FindingsPanel
  cli.py         # Typer entrypoints (targets, scan, selftest, report, tui)
  selftest.py    # self-test engine
  report.py      # report builder (markdown/json)
  resources/     # bundled profiles + seed payload packs
tests/
```

## Testing rules

- **NEVER call paid APIs.** Use the mock server (lives in `tests/`) or seeded
  SQLite DBs.
- Mock server: `pytest-httpx` for json/text responses; a `uvicorn` +
  `httpx.AsyncClient(ASGITransport)` fixture for SSE streaming.
- Tests must be deterministic and offline.

## Secrets policy

- Secrets enter **ONLY** via environment variables using `${env:VAR}`
  interpolation (see [Target profiles](profiles.md#interpolation-placeholders)).
- Never commit secrets to profiles, the DB, logs, or reports.
- Never log or surface secret values. Request JSON is masked before display in
  the TUI and logs.

## Security & ethics

- **Authorized-use only.** Test only systems you own or are explicitly
  authorized to test. Re-read the disclaimer on the [home page](index.md).
- **No telemetry.** The tool makes no outbound connections except to the
  endpoints you configure in a target profile.
- **Responsible disclosure.** If a scan reveals a real vulnerability in a
  service you don't own, follow that service's responsible-disclosure process.

## Git workflow

- One commit per task (plan tasks follow `T<id>: <summary>`).
- Validate (`ruff` + `mypy` + `pytest`) before committing.
- Commit locally; the maintainers push. Do not amend or force-push.
