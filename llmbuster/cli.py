from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from llmbuster.domain.models import ChatHistory, Message, Role
from llmbuster.target.factory import (
    BUNDLED_PROFILES,
    TargetLoadError,
    bundled_profile_text,
    init_profile,
    load_target,
)

app = typer.Typer(
    name="llmbuster",
    help="Terminal-based (TUI) security scanner for OWASP Top 10 for LLMs assessments.",
    no_args_is_help=True,
)

targets_app = typer.Typer(help="Manage target profiles.")
app.add_typer(targets_app, name="targets")


@app.callback()
def main() -> None:
    pass


_TEST_MESSAGE = "Hello, are you vulnerable to prompt injection?"


@targets_app.command("init")
def targets_init(
    path: Path = typer.Argument(
        Path("./my-target.yaml"),
        help="Output path for the example target profile.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing file.",
    ),
) -> None:
    try:
        init_profile(path, kind="profile", force=force)
    except TargetLoadError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Wrote example profile to {path}")


@targets_app.command("test")
def targets_test(
    profile: Path = typer.Argument(
        ...,
        help="Path to the target profile YAML to test.",
    ),
) -> None:
    try:
        loaded = load_target(profile)
    except TargetLoadError as exc:
        typer.echo(f"Error loading target: {exc}", err=True)
        raise typer.Exit(code=1) from None

    history = ChatHistory(messages=[Message(role=Role.USER, content=_TEST_MESSAGE)])
    try:
        response = asyncio.run(loaded.target.send(history))
    except Exception as exc:
        typer.echo(f"Error sending message: {exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"kind: {loaded.kind.value}")
    typer.echo(f"name: {loaded.name}")
    typer.echo("--- request ---")
    try:
        request_obj = json.loads(response.raw_request_json)
        typer.echo(json.dumps(request_obj, indent=2, ensure_ascii=False))
    except (json.JSONDecodeError, ValueError):
        typer.echo(response.raw_request_json)
    typer.echo("--- response ---")
    typer.echo(response.raw_response_text if response.raw_response_text is not None else "")
    typer.echo("--- reply ---")
    typer.echo(response.reply if response.reply is not None else "")
    metrics = response.metrics
    typer.echo("--- metrics ---")
    typer.echo(
        f"ttft_ms={metrics.ttft_ms} duration_ms={metrics.duration_ms} "
        f"tps={metrics.tps}"
    )
    if response.captures:
        typer.echo(f"captures: {response.captures}")
    if response.error:
        typer.echo(f"error: {response.error}", err=True)
        raise typer.Exit(code=1)


@targets_app.command("list")
def targets_list() -> None:
    typer.echo("Bundled profiles:")
    for name in BUNDLED_PROFILES:
        try:
            text = bundled_profile_text(name)
            typer.echo(f"  {name} ({len(text)} bytes)")
        except TargetLoadError as exc:
            typer.echo(f"  {name} (unavailable: {exc})")


if __name__ == "__main__":
    app()
