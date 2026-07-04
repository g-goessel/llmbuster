from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from llmbuster.cli import app
from llmbuster.payload.bundled import load_bundled_packs
from llmbuster.selftest import run_selftest

runner = CliRunner()

BROKEN_PACK_YAML = (
    "category: LLM01\n"
    "payloads:\n"
    '  - prompt: "missing required id field"\n'
)


def test_run_selftest_healthy_by_default() -> None:
    result = run_selftest()
    assert result.healthy is True
    assert result.pack_count == 10
    assert result.payload_count == len(load_bundled_packs())
    assert len(result.detector_checks) == 4
    assert all(c.passed for c in result.detector_checks)
    assert result.pack_errors == {}


def test_detector_checks_all_present() -> None:
    result = run_selftest()
    names = {c.name for c in result.detector_checks}
    assert names == {"canary-match", "canary-nomatch", "regex-match", "regex-nomatch"}


def test_selftest_detects_broken_pack(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text(BROKEN_PACK_YAML, encoding="utf-8")

    result = run_selftest(extra_pack_paths=[broken])
    assert result.healthy is False
    assert str(broken) in result.pack_errors
    assert result.pack_errors[str(broken)] != []


def test_selftest_cli_exits_zero_when_healthy() -> None:
    result = runner.invoke(app, ["selftest"])
    assert result.exit_code == 0, result.output
    assert "Self-test: OK" in result.output


def test_selftest_cli_exits_one_when_broken(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text(BROKEN_PACK_YAML, encoding="utf-8")

    result = runner.invoke(app, ["selftest", "--pack", str(broken)])
    assert result.exit_code == 1, result.output
    assert "Self-test: FAILED" in result.output


def test_selftest_cli_help_lists_pack_option() -> None:
    result = runner.invoke(app, ["selftest", "--help"])
    assert result.exit_code == 0
    assert "--pack" in result.output
