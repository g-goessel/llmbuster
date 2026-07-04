from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from llmbuster.cli import app
from llmbuster.target.factory import load_target

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
ECHO_ADAPTER = str(FIXTURES / "echo_adapter.py")


def test_help_mentions_targets() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "targets" in result.output


def test_targets_help_mentions_init_and_test() -> None:
    result = runner.invoke(app, ["targets", "--help"])
    assert result.exit_code == 0
    assert "init" in result.output
    assert "test" in result.output


def test_targets_init_writes_loadable_file(tmp_path: Path) -> None:
    out = tmp_path / "profile.yaml"
    result = runner.invoke(app, ["targets", "init", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    loaded = load_target(out)
    assert loaded.kind.value == "profile"


def test_targets_init_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "profile.yaml"
    first = runner.invoke(app, ["targets", "init", str(out)])
    assert first.exit_code == 0
    second = runner.invoke(app, ["targets", "init", str(out)])
    assert second.exit_code != 0


def test_targets_init_force_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "profile.yaml"
    runner.invoke(app, ["targets", "init", str(out)])
    result = runner.invoke(app, ["targets", "init", str(out), "--force"])
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_targets_test_command_profile(tmp_path: Path) -> None:
    profile = tmp_path / "cmd.yaml"
    profile.write_text(
        "kind: command\n"
        'name: "echo"\n'
        f'command: ["python3", "{ECHO_ADAPTER}"]\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["targets", "test", str(profile)])
    assert result.exit_code == 0, result.output
    assert "echo:" in result.output
    assert "kind: command" in result.output
    assert "name: echo" in result.output


def test_targets_test_bad_profile(tmp_path: Path) -> None:
    result = runner.invoke(app, ["targets", "test", str(tmp_path / "nope.yaml")])
    assert result.exit_code != 0


def test_targets_list() -> None:
    result = runner.invoke(app, ["targets", "list"])
    assert result.exit_code == 0, result.output
    assert "openrouter" in result.output
