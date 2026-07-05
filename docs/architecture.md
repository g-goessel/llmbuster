# Architecture

`llmbuster` is a layered Python 3.12 application. The CLI and TUI are thin
front-ends over an async orchestrator that drives pluggable targets, payloads,
and detectors, persisting everything through a single-writer SQLite store.

## Diagram

```
                       ┌─────────────────────────────────────┐
   CLI  (Typer)  ──────┤  llmbuster/cli.py                   │
                       │   targets · scan run · selftest     │
                       │   report                            │
                       └───────────────┬─────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                      ▼
 ┌──────────────────────┐                            ┌──────────────────────┐
 │  TUI  (Textual)      │                            │  Orchestrator        │
 │  tui/screens/        │                            │  orchestrator/       │
 │   config · dashboard │◄──── progress events ──────│  ScanOrchestrator    │
 │   history · findings │                            │  aggregation · summary│
 └──────────────────────┘                            └──────────┬───────────┘
                                                                │
                       ┌────────────────────────────────────────┤
                       ▼                  ▼                     ▼
              ┌────────────────┐  ┌──────────────┐    ┌──────────────────┐
              │  Targets       │  │  Payloads     │    │  Detectors       │
              │  target/       │  │  payload/     │    │  detector/       │
              │  ProfileTarget │  │  loader       │    │  Canary · Regex  │
              │  PluginTarget  │  │  mutation     │    │  registry         │
              │  CommandTarget │  │  10 OWASP pk  │    └──────────────────┘
              │  OpenRouter    │  └──────────────┘
              │  factory+interp│
              └────────┬───────┘
                       │ interactions
                       ▼
              ┌──────────────────────┐
              │  Store               │
              │  store/              │
              │  SQLiteStore (WAL)   │
              │  WriterTask (async)  │
              └──────────────────────┘
```

## Layers

### CLI — `llmbuster/cli.py`

A Typer app exposing `targets` (init/test/list), `scan run`, `selftest`,
`report`, `replay`, and `tui`. Thin entrypoints that wire targets, payloads,
the orchestrator, and the store together. See [CLI reference](cli.md).

### TUI — `llmbuster/tui/`

A Textual app (`LlmBusterApp`) with a tabbed interface containing four panels:
**config** (target/system-prompt/concurrency/repeat/categories/escalate with a
multi-select OWASP category list), **dashboard** (live progress bar +
per-category table + TTFT/TPS counters), **history** (proxy-grade interaction
table with run picker, category/verdict filters, and a split
request/response detail view that updates on arrow-key navigation), and
**findings** (per-category aggregates + per-payload reproducibility + run stats).
See [TUI guide](tui.md).

### Orchestrator — `llmbuster/orchestrator/`

`ScanOrchestrator` runs an asyncio event loop with a concurrency semaphore,
emits progress events on a queue, drives escalation chains on vulnerable
payloads, and persists results through a queue. `aggregation` computes
reproducibility scores and verdict rollups; `summary` builds per-category and
per-payload run summaries.

### Targets — `llmbuster/target/`

`ProfileTarget` (declarative HTTP: json/sse/text), `PluginTarget` (`importlib`
adapter), `CommandTarget` (subprocess JSON-line protocol), and a built-in
OpenRouter target. A factory loads profiles and an interpolation engine resolves
`${env:...}`, `${uuid}`, `${timestamp}`, `${messages_json}`, etc. See
[Target profiles](profiles.md).

### Payloads — `llmbuster/payload/`

YAML pack loader, a mutation engine (`base64`, `leetspeak`,
`unicode_homoglyph`, `translation`), and 10 bundled OWASP packs (32 payloads)
shipped under `llmbuster/resources/packs/`. See [Payload packs](payloads.md).

### Detectors — `llmbuster/detector/`

`CanaryDetector` (matches an exact token in the reply) and `RegexDetector`
(regex + flags), exposed through a small registry. All bundled packs use
`CanaryDetector` to avoid false positives from refusal phrases. An
`LlmJudgeDetector` wraps a first-stage detector and confirms/overrides via an
LLM-as-judge second stage (enabled with `--judge-model`).

### Store — `llmbuster/store/`

`SQLiteStore` (WAL mode, `foreign_keys=ON`, the proxy schema from `PLAN.md` §3)
and `WriterTask`, a single-consumer async task that drains the interaction
queue and persists serially. WAL mode lets the TUI read while a scan writes.
The SQLite connection is never shared across coroutines.

### Resources — `llmbuster/resources/`

Bundled `openrouter.yaml` template and the 10 pack YAMLs, accessed via
`importlib.resources` so they ship inside the wheel.

## Design notes

- **Async, single-writer.** The workload is I/O-bound; `asyncio` + a
  `Semaphore` cap in-flight requests. One dedicated writer task owns the SQLite
  connection and drains an `asyncio.Queue` so persistence is serial and
  thread-safe.
- **Detection is a protocol.** `Detector.evaluate` is synchronous in v1 but the
  pipeline already treats detection as a producible result, so a future async
  LLM-as-judge detector swaps in without reshaping the flow. The judge
  detector is already wired.
- **Data, not code, for payloads.** Packs are YAML; no `eval`. Custom Python
  logic goes through the `plugin` target kind with `importlib`.
- **Secrets never touch disk.** Secrets enter only via `${env:VAR}` and are
  masked in logs/TUI/reports. See [Secrets policy](development.md#secrets-policy).
