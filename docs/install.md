# Installation

`llmbuster` targets **Python 3.12**. Pick whichever install path fits your
workflow.

## `uv` (recommended)

[`uv`](https://github.com/astral-sh/uv) is the primary, lockfile-driven install
path. It creates a virtual environment and installs pinned dependencies from
`uv.lock`.

```bash
uv sync                       # create venv + install deps from the lockfile
uv run llmbuster --help
```

Run every command through `uv run` so it picks up the project venv. This is the
path used in the [Quick start](quickstart.md) and [CLI reference](cli.md).

## `pipx` / `uvx` (from a wheel or PyPI when published)

For a globally-installed command isolated in its own venv:

```bash
pipx install llmbuster
llmbuster --help
```

Or run ad-hoc without installing:

```bash
uvx llmbuster --help
```

## Docker

A `Dockerfile` is included in the repo root. Build the image, then run it the
same way you would a local install:

```bash
docker build -t llmbuster:dev .
```

Print the help (no volume needed):

```bash
docker run --rm llmbuster:dev --help
```

Scan against a profile on the host, persisting the SQLite DB to your working
directory:

```bash
docker run --rm -v $(pwd):/data llmbuster:dev \
  scan run /data/openrouter.yaml --db /data/llmbuster.db
```

> Secrets enter **only** via environment variables. Pass them to the container
> with `-e OPENROUTER_API_KEY=...` (or your target's variable); never bake them
> into the image or the profile YAML. See [Secrets policy](development.md#secrets-policy).

## Verify the install

Whichever path you chose, sanity-check that the bundled packs and detectors
load correctly — no API calls are made:

```bash
uv run llmbuster selftest
```

See [Quick start](quickstart.md) for the full walkthrough.
