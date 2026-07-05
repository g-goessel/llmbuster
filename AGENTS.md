# AGENTS.md — llmbuster agent guidance

## Project overview
`llmbuster` is a terminal-based (TUI) security scanner that lets authorized users
assess their own LLM implementations against the OWASP Top 10 for LLMs, like a
pentester would. Interactions are logged proxy-style into a portable SQLite DB.

## Authoritative spec
`PLAN.md` (repo root) is the binding specification. Follow these sections exactly:
- **§3** — SQLite schema (column names, types, indexes, pragmas).
- **§4** — Payload pack YAML schema.
- **§5** — Target profile YAML schema (profile / plugin / command kinds).
- **§6** — Domain models (pydantic v2) and protocols. Names and fields are binding.

Tasks are listed in `PLAN.md` §8. Respect dependency order; each task is
self-contained against §3/§4/§5/§6 plus its listed deps.

## Tooling
- **Env / lock:** `uv` (version 0.11.26). Target **Python 3.12**.
- `uv sync` — create venv + install deps from lock.
- `uv run ruff check` — lint.
- `uv run mypy llmbuster` — type check.
- `uv run pytest` — tests.
- `uv run llmbuster --help` — verify entrypoint.
- `uv run llmbuster tui` — launch the interactive TUI.

## Package layout
```
llmbuster/
  domain/        # T0.2 models, protocols
  target/        # T1.x targets, profile engine, interpolation
  payload/       # T2.x loader, mutation
  detector/      # T2.x detectors
  orchestrator/  # T3.x scanning, repetition, chains, summary
  store/         # T4.x sqlite + writer task
  tui/           # T5.x Textual app + panels
    app.py       # LlmBusterApp (tabs, content switcher, drainer)
    screens/     # ConfigPanel, DashboardPanel, HistoryPanel, FindingsPanel
  cli.py         # Typer entrypoints (targets, scan, selftest, report, tui)
  selftest.py    # T6.1 self-test engine
  report.py      # T6.2 report builder (markdown/json)
  resources/     # bundled profiles + seed payload packs
tests/
```

## Definition of done (every task)
1. `uv run ruff check` — clean.
2. `uv run mypy llmbuster` — clean.
3. `uv run pytest` — green for the task.
All three must pass before committing.

## Testing rules
- NEVER call paid APIs. Use the mock server (T1.2, lives in `tests/`) or seeded
  SQLite DBs.
- Mock server: `pytest-httpx` for json/text responses; a `uvicorn` +
  `httpx.AsyncClient(ASGITransport)` fixture for SSE streaming.
- Tests must be deterministic and offline.

## Secrets
- Secrets enter ONLY via environment variables using `${env:VAR}` interpolation.
- Never commit secrets to profiles, DB, logs, or reports.
- Never log or surface secret values.

## Conventions
- Always be concise.
- Type-hint everything.
- pydantic v2 models for all serializable data.
- Shared types live in `llmbuster/domain/` to avoid circular imports.
- Do NOT add comments to code unless explicitly requested.
- Follow existing file style; mimic neighboring code.
- ruff rules: E, F, I, UP, B, SIM, ANN. Line length 100. Target py312.

## Git
- One commit per task.
- Validate (ruff + mypy + pytest) before committing.
- Commit locally only; the user pushes. Do not push.
- Do not amend or force-push.
- Commit message format: `T<id>: <summary>` for plan tasks; free-form for
  fixes and improvements outside the plan.

## Metric formulas (from §1)
- `duration_ms` = wall-clock from request send to last token.
- `ttft_ms` = request send to first token (requires streaming).
- `tps` = `completion_tokens / ((duration_ms - ttft_ms) / 1000)`.
  Guard division by zero: if `duration_ms <= ttft_ms`, set `tps = None`.

## Security & ethics
- Authorized-use-only. Display/ship the disclaimer.
- Network egress only to user-configured targets — no telemetry.
- Test only systems you own or are explicitly authorized to test.
