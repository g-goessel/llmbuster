# TUI guide

`llmbuster tui` launches a [Textual](https://textual.textualize.io/) terminal
app: a tabbed interface with a live scan dashboard, a proxy-grade history
browser, and a findings summary.

```bash
uv run llmbuster tui
uv run llmbuster tui --db /path/to/llmbuster.db
```

## Tabs

The app has four tabs. Switch with the number keys or by activating the tab:

| Key | Tab        | Purpose                                                       |
| --- | ---------- | ------------------------------------------------------------- |
| `1` | Config     | Target/system-prompt/concurrency/repeat/categories/escalate. |
| `2` | Dashboard  | Live progress bar, per-category table, TTFT/TPS counters.   |
| `3` | History    | Proxy-grade interaction table with run picker + detail view. |
| `4` | Findings   | Per-category aggregates + reproducibility + run stats.       |

## Key bindings

| Key       | Action                          |
| --------- | ------------------------------- |
| `1`–`4`   | Switch to the corresponding tab. |
| `?`       | Show help.                      |
| `q`       | Quit.                           |
| `ctrl+c`  | Quit.                           |

Arrow keys navigate within tables/lists (see History below).

## Config panel

The Config tab is a form. Fields:

- **Target profile path** — path to a target YAML (see
  [Target profiles](profiles.md)).
- **OpenRouter model id** (optional, only for `openrouter` targets).
- **System prompt** — multi-line text area; prepended to all requests.
- **Concurrency** — max in-flight requests (default 5).
- **Repeat count** — optional; blank = use each payload's `repeat` default.
- **Categories** — a multi-select of all OWASP categories (`LLM01`–`LLM10`).
  Leave all unchecked to run every category.
- **Escalate** — toggle to enable escalation chains for vulnerable payloads.

Buttons: **Test load** validates the target profile without starting a scan;
**Start Scan** loads the profile, creates a run in the SQLite DB, and switches
to the Dashboard tab. A status line reports load errors or the new run id.

## Dashboard panel

The Dashboard tab renders progress events emitted by the
`ScanOrchestrator`:

- a progress bar over completed attempts,
- a per-category status table,
- live counters including findings and TTFT/TPS.

Events flow through an asyncio queue drained by a background task in the app.

## History panel

The History tab is a Burp-style proxy history browser for **all** interactions
in a run.

- **Run picker** — a dropdown (`Select`) at the top lists every run in the DB
  (`#id — target (started_at)`). Pick one to reload the table.
- **Filters** — two text inputs filter live by category (e.g. `LLM01`) and
  verdict (e.g. `vulnerable`). Filtering is case-insensitive substring match.
- **Table** — columns: `id`, `Category`, `Payload`, `Attempt`, `Mutation`,
  `Verdict`, `TTFT(ms)`, `TPS`, `Detector`. Use ↑/↓ arrow keys to move the
  cursor.
- **Split detail view** — below the table, a horizontal split with a **Request**
  pane (sent history + masked raw request) and a **Response** pane (extracted
  reply, detector id/detail, metrics, raw response). The detail view updates
  live as you arrow-key through rows (`RowHighlighted`/`RowSelected`).

Long responses are truncated at 4000 chars in the detail view (the full text is
still in the DB and reports). Request JSON is masked so secret values are never
surfaced — see [Secrets policy](development.md#secrets-policy).

## Findings panel

The Findings tab shows the executive summary: per-category vulnerable rate and
reproducibility scores, plus run-level stats. Use it alongside the History tab
to triage — aggregated view here, raw exchanges there.

## `--db` option

The TUI opens a single `SQLiteStore` against the DB path (default
`./llmbuster.db`). Because the store runs in WAL mode, you can run a scan from
the CLI and watch interactions land in the TUI in (near) real time by
re-picking the run. Pass a different DB with `--db`:

```bash
uv run llmbuster tui --db ./runs/2026-07.db
```
