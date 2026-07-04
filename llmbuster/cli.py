from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import typer

from llmbuster.domain.models import ChatHistory, Message, Role
from llmbuster.orchestrator import ScanConfig, ScanOrchestrator
from llmbuster.payload.bundled import load_bundled_packs, load_bundled_packs_as_packs
from llmbuster.store import SQLiteStore, WriterTask
from llmbuster.store.sqlite_store import RunRecord
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


scan_app = typer.Typer(help="Run security scans against LLM targets.")
app.add_typer(scan_app, name="scan")


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


@scan_app.command("run")
def scan_run(
    profile: Path = typer.Argument(
        ...,
        help="Path to the target profile YAML.",
    ),
    db: Path = typer.Option(
        Path("./llmbuster.db"),
        "--db",
        help="Path to the SQLite database file.",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Max concurrent requests.",
    ),
    repeat: int | None = typer.Option(
        None,
        "--repeat",
        "-r",
        help="Override repeat count for all payloads.",
    ),
    categories: list[str] | None = typer.Option(
        None,
        "--category",
        help="Filter by OWASP category (e.g. LLM01). Repeatable.",
    ),
    system_prompt: str | None = typer.Option(
        None,
        "--system-prompt",
        help="System prompt to prepend to all requests.",
    ),
    escalate: bool = typer.Option(
        False,
        "--escalate",
        help="Enable escalation chains for vulnerable payloads.",
    ),
) -> None:
    try:
        loaded = load_target(profile)
    except TargetLoadError as exc:
        typer.echo(f"Error loading target: {exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"Target: {loaded.name} ({loaded.kind.value})")

    packs = load_bundled_packs_as_packs()
    payloads = load_bundled_packs()
    owasp_categories: dict[str, object] = {}
    for pack in packs:
        for p in pack.payloads:
            owasp_categories[p.id] = pack.category
    typer.echo(f"Loaded {len(payloads)} payloads across {len(packs)} categories")

    store = SQLiteStore(db)
    run_id = store.create_run(
        RunRecord(
            started_at=datetime.now(UTC).isoformat(),
            target_kind=loaded.kind.value,
            target_name=loaded.name,
            system_prompt=system_prompt,
            config_json=json.dumps(
                {"concurrency": concurrency, "repeat": repeat, "categories": categories}
            ),
        )
    )
    typer.echo(f"Run {run_id} created in {db}")

    config = ScanConfig(
        run_id=run_id,
        concurrency=concurrency,
        repeat=repeat,
        system_prompt=system_prompt,
        categories=categories,
        escalate=escalate,
    )
    orchestrator = ScanOrchestrator(
        loaded.target, config, payloads, owasp_categories  # type: ignore[arg-type]
    )
    writer = WriterTask(store, orchestrator.interaction_queue)

    async def _run_scan() -> None:
        writer_task_obj = asyncio.create_task(writer.run())
        progress_task = asyncio.create_task(_print_progress(orchestrator))
        await orchestrator.run()
        await writer_task_obj
        progress_task.cancel()

    asyncio.run(_run_scan())

    interactions = store.interactions_for_run(run_id)
    findings = store.findings_for_run(run_id)
    total = len(interactions)
    vuln = len(findings)
    typer.echo("\n--- scan complete ---")
    typer.echo(f"Total interactions: {total}")
    typer.echo(f"Vulnerable findings: {vuln}")
    typer.echo(f"Run ID: {run_id} (use 'llmbuster scan report {run_id}' to view details)")
    store.close()


async def _print_progress(orchestrator: ScanOrchestrator) -> None:
    completed = 0
    vulnerable = 0
    errors = 0
    try:
        while True:
            event = await orchestrator.progress_queue.get()
            if event is None:
                break
            if event.phase == "completed":
                completed += 1
                if event.verdict.value == "vulnerable":
                    vulnerable += 1
                    typer.echo(
                        f"  [{event.owasp_category}] {event.payload_id} "
                        f"attempt={event.attempt_index} "
                        f"mutation={event.mutation or 'none'} "
                        f"-> {event.verdict.value}"
                    )
            elif event.phase == "error":
                errors += 1
                typer.echo(
                    f"  [{event.owasp_category}] {event.payload_id} "
                    f"-> ERROR: {event.detail}",
                    err=True,
                )
            elif event.phase == "escalation":
                typer.echo(f"  ESCALATION: {event.detail}")
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    app()
