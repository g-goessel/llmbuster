# llmbuster

A terminal-based (TUI) security scanner that lets authorized users assess their
own LLM implementations against the OWASP Top 10 for LLMs, like a pentester
would. Interactions are logged proxy-style into a portable SQLite DB.

> **Responsible use — read first**
>
> `llmbuster` is a **pentesting tool for your OWN LLM implementations**. It sends
> adversarial prompts and records the responses. Use it **only against systems
> you own or are explicitly authorized to test**. Unauthorized scanning of
> third-party services may violate their terms of service and applicable law.
>
> - **Authorized-use only.** You are responsible for obtaining permission before
>   testing any target.
> - **No telemetry.** `llmbuster` never phones home. There is no analytics,
>   crash reporting, or usage tracking.
> - **Network egress only to user-configured targets.** The only outbound
>   connections are to the endpoints *you* declare in a target profile.
> - **Secrets via environment variables only.** Never hardcode API keys in
>   profiles; use `${env:VAR}` interpolation (see [Target profiles](profiles.md)).
>   **Warning:** The generated SQLite database will contain these credentials in plaintext. Do not share your `.db` file.
>
> By using this software you confirm that you are testing systems you are
> authorized to test. The authors accept no liability for misuse.

## Features

- **OWASP Top 10 for LLMs coverage** — 10 bundled payload packs (LLM01–LLM10),
  32 payloads spanning prompt injection, sensitive-info disclosure, excessive
  agency, model DoS, and more.
- **Proxy-grade logging** — every request/response is persisted to a portable
  SQLite DB (WAL mode, foreign keys on) for replay, audit, and reporting.
- **Concurrency-limited async scans** — `asyncio` + semaphore, with per-payload
  repeat counts, category filters, and escalation chains for vulnerable hits.
- **Streaming metrics** — TTFT (time to first token), TPS (tokens/sec), and
  total `duration_ms` captured from SSE token deltas.
- **Pluggable targets** — declarative HTTP profiles, Python plugins
  (`importlib`), subprocess commands, and a built-in OpenRouter adapter.
- **Mutation engine** — base64, leetspeak, unicode-homoglyph, and translation
  payload variants to probe input-filtering bypasses.
- **Detectors** — `CanaryDetector` (exact token) and `RegexDetector` (with
  flags), wired through a small registry.
- **LLM-as-judge verification** — optional second-stage judge model confirms or
  overrides canary hits to cut false positives.
- **Reproducibility scoring** — verdicts are rolled up across attempts with a
  reproducibility score, so you can tell a flaky hit from a reliable vuln.
- **Textual TUI** — tabbed interface with config, live dashboard, proxy history
  browser (split request/response detail view), and findings summary screens.
  Browse previous runs via a dropdown picker.
- **Reports** — export a run as Markdown or JSON, to a file or stdout.
- **Offline & deterministic** — no paid APIs required for `selftest`; tests use
  a mock server and seeded SQLite DBs.

## Quick links

- [Installation](install.md) — get `llmbuster` running with `uv`, `pipx`, or Docker.
- [Quick start](quickstart.md) — five-step walkthrough from `selftest` to report.
- [CLI reference](cli.md) — every command and option.
- [Target profiles](profiles.md) — the four target kinds and interpolation engine.
- [Payload packs](payloads.md) — YAML schema, detectors, mutations, escalation.
- [TUI guide](tui.md) — tabs, key bindings, history browser.
- [Metrics](metrics.md) — `duration_ms`, `ttft_ms`, `tps` formulas.
- [Architecture](architecture.md) — layer diagram and design.
- [Development](development.md) — contributing, lint, type-check, tests.
