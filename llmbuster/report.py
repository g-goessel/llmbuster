from __future__ import annotations

import json

from pydantic import BaseModel

from llmbuster.orchestrator.summary import (
    CategorySummary,
    PayloadSummary,
    RunStats,
    summarize_run,
)
from llmbuster.store.sqlite_store import InteractionRecord, RunRecord, SQLiteStore

_MAX_SYSTEM_PROMPT = 200
_MAX_RESPONSE_TEXT = 500


class ReportError(ValueError):
    pass


class ReportData(BaseModel):
    run: RunRecord
    stats: RunStats
    categories: list[CategorySummary]
    vulnerable_payloads: list[PayloadSummary]
    findings: list[InteractionRecord]
    all_interactions: list[InteractionRecord]


def build_report(store: SQLiteStore, run_id: int) -> ReportData:
    run = store.get_run(run_id)
    if run is None:
        raise ReportError(f"run {run_id} not found")
    interactions = store.interactions_for_run(run_id)
    findings = store.findings_for_run(run_id)
    categories, payloads, stats = summarize_run(interactions)
    return ReportData(
        run=run,
        stats=stats,
        categories=categories,
        vulnerable_payloads=payloads,
        findings=findings,
        all_interactions=interactions,
    )


def _fmt_rate(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value * 100:.1f}%"


def _fmt_latency(value: float | None) -> str:
    if value is None:
        return "-"
    return str(int(round(value)))


def _fmt_tps(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


def _truncate(text: str | None, limit: int) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\u2026"


def render_markdown(data: ReportData) -> str:
    run = data.run
    lines: list[str] = []
    run_id_str = str(run.id) if run.id is not None else "?"
    lines.append(f"# llmbuster Run Report \u2014 Run {run_id_str}")
    lines.append("")

    lines.append(f"- **Started at:** {run.started_at}")
    lines.append(f"- **Target kind:** {run.target_kind}")
    if run.target_name is not None:
        lines.append(f"- **Target name:** {run.target_name}")
    if run.model is not None:
        lines.append(f"- **Model:** {run.model}")
    if run.system_prompt is not None:
        lines.append(
            f"- **System prompt:** {_truncate(run.system_prompt, _MAX_SYSTEM_PROMPT)}"
        )
    lines.append("")

    stats = data.stats
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total interactions: {stats.total_interactions}")
    lines.append(f"- Total vulnerable: {stats.total_vulnerable}")
    lines.append(f"- Overall vulnerable rate: {_fmt_rate(stats.overall_vulnerable_rate)}")
    lines.append(f"- Avg TTFT (ms): {_fmt_latency(stats.avg_ttft_ms)}")
    lines.append(f"- Avg TPS: {_fmt_tps(stats.avg_tps)}")
    lines.append("")

    lines.append("## Per-Category Summary")
    lines.append("")
    lines.append(
        "| Category | Total | Vulnerable | Safe | Error | Vuln Rate | "
        "Avg TTFT (ms) | Avg TPS | Avg Duration (ms) |"
    )
    lines.append(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    )
    for cat in data.categories:
        lines.append(
            f"| {cat.category} | {cat.total} | {cat.vulnerable} | {cat.safe} | "
            f"{cat.error} | {_fmt_rate(cat.vulnerable_rate)} | "
            f"{_fmt_latency(cat.avg_ttft_ms)} | {_fmt_tps(cat.avg_tps)} | "
            f"{_fmt_latency(cat.avg_duration_ms)} |"
        )
    lines.append("")

    lines.append("## Reproducibly Vulnerable Payloads")
    lines.append("")
    lines.append(
        "| Payload ID | Category | Total | Vulnerable | Vulnerable Rate | Verdict |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for payload in data.vulnerable_payloads:
        lines.append(
            f"| {payload.payload_id} | {payload.category} | {payload.total} | "
            f"{payload.vulnerable} | {_fmt_rate(payload.vulnerable_rate)} | "
            f"{payload.rolled_up_verdict.value} |"
        )
    lines.append("")

    lines.append("## Findings Detail")
    lines.append("")
    for finding in data.findings:
        lines.append(f"### {finding.payload_id} \u2014 {finding.owasp_category}")
        lines.append("")
        lines.append(f"- Attempt index: {finding.attempt_index}")
        lines.append(f"- Mutation: {finding.mutation or 'none'}")
        lines.append(f"- Detector: {finding.detector_id or '-'}")
        if finding.detector_detail is not None:
            lines.append(f"- Detector detail: {finding.detector_detail}")
        lines.append(
            f"- Response: {_truncate(finding.response_text, _MAX_RESPONSE_TEXT)}"
        )
        lines.append(
            f"- TTFT (ms): {_fmt_latency(finding.ttft_ms)}"
        )
        lines.append(
            f"- Duration (ms): {_fmt_latency(finding.duration_ms)}"
        )
        lines.append(f"- TPS: {_fmt_tps(finding.tps)}")
        lines.append("")

    lines.append("---")
    lines.append("Generated by llmbuster")
    lines.append("")
    return "\n".join(lines)


def render_json(data: ReportData) -> str:
    return json.dumps(
        data.model_dump(mode="json"), indent=2, ensure_ascii=False
    )
