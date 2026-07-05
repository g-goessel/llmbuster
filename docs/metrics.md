# Metrics

`llmbuster` captures per-interaction metrics from the target response. These
are stored on the `interactions` table and surfaced in the TUI history/detail
view and in exported reports.

## Formulas

- **`duration_ms`** — wall-clock from request send to last token.
- **`ttft_ms`** — request send to first token. **Requires streaming.**
- **`tps`** — tokens per second:

  ```
  tps = completion_tokens / ((duration_ms - ttft_ms) / 1000)
  ```

## Division-by-zero guard

If `duration_ms <= ttft_ms`, `tps` is set to `None` rather than dividing by
zero. Downstream code (TUI, reports) treats `None` as "not available".

## Streaming requirement

TTFT and TPS depend on token deltas from a streaming response. Use a target
profile with `response.type: sse` (see [Target profiles](profiles.md#response-transports))
to capture them. With `response.type: json` or `text`, only `duration_ms` is
available and `ttft_ms`/`tps` will be `None`.

The bundled `openrouter` target streams over SSE by default
(`"stream": true`), so TTFT/TPS work out of the box for OpenRouter scans.

## Where metrics appear

- **CLI** — `llmbuster targets test <profile>` prints `ttft_ms`, `duration_ms`,
  `tps` for the single probe.
- **TUI** — the History table has `TTFT(ms)` and `TPS` columns; the detail view
  shows the full metrics block (including token counts). See
  [TUI guide](tui.md#history-panel).
- **Reports** — Markdown/JSON reports include latency stats and reproducibility
  scores. See [CLI reference](cli.md#report-options).

The authoritative definitions live in `PLAN.md` §1 ("Metric definitions").
