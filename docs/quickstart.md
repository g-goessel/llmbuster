# Quick start

This walkthrough takes you from a fresh checkout to an exported report and the
interactive TUI. All commands assume the `uv` install path (see
[Installation](install.md)).

## 1. Self-test (no API calls)

Bootstrap the venv and sanity-check the bundled payload packs and detectors:

```bash
uv sync
uv run llmbuster selftest
```

`selftest` validates every bundled pack, runs detector sanity checks against
canned responses, and exits non-zero if anything is broken. It makes no network
calls — safe to run offline.

## 2. Create a target profile

The easiest path is the built-in `openrouter` kind — just set the `model`:

```bash
cat > openrouter.yaml <<'YAML'
kind: openrouter
name: "OpenRouter (free model)"
model: "openai/gpt-oss-20b:free"
YAML
export OPENROUTER_API_KEY="sk-or-..."     # secrets ONLY via env vars
```

Or generate a fully-commented declarative profile you can edit:

```bash
uv run llmbuster targets init ./my-target.yaml
```

See [Target profiles](profiles.md) for the four kinds (`openrouter`, `profile`,
`plugin`, `command`) and the full interpolation/placeholder reference.

## 3. Smoke-test the target

Send a single message and print the request, response, extracted reply, and
metrics:

```bash
uv run llmbuster targets test openrouter.yaml
```

This is the fastest way to confirm auth, URL, and response parsing are correct
before running a full scan.

## 4. Run a scan and export the report

Run a scan with a system prompt, repeat count, concurrency cap, a category
filter, and escalation chains:

```bash
uv run llmbuster scan run openrouter.yaml \
  --system-prompt "You are a helpful assistant." \
  --repeat 3 --concurrency 5 --category LLM01 --escalate
```

The CLI prints the new run id and a live progress feed. When it finishes, export
the report:

```bash
uv run llmbuster report <run_id> --format markdown --out report.md
uv run llmbuster report <run_id> --format json     # to stdout
```

For an optional second-stage LLM-as-judge pass that confirms or overrides canary
hits (cuts false positives), add `--judge-model`:

```bash
uv run llmbuster scan run openrouter.yaml \
  --category LLM06 --judge-model openai/gpt-oss-20b:free
```

See [Payload packs](payloads.md) for the judge workflow and
[CLI reference](cli.md) for every `scan run` option.

## 5. Explore results in the TUI

Launch the interactive terminal UI:

```bash
uv run llmbuster tui
```

Tabs (number keys switch): **1=Config**, **2=Dashboard**, **3=History**,
**4=Findings**. Press `q` to quit.

In the **History** tab, pick a run from the dropdown, arrow-key through
interactions, and the split request/response detail view updates live. See the
[TUI guide](tui.md) for key bindings and panel details.
