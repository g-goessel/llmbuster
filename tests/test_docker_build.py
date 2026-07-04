from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
IMAGE = "llmbuster:dev-test"


def _container_runtime() -> str | None:
    for candidate in ("docker", "podman"):
        if shutil.which(candidate) is None:
            continue
        try:
            result = subprocess.run(
                [candidate, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if result.returncode == 0:
            return candidate
        if candidate == "podman":
            try:
                ok = subprocess.run(
                    [candidate, "version", "--format", "{{.Client.Version}}"],
                    capture_output=True,
                    timeout=10,
                )
            except (subprocess.TimeoutExpired, OSError):
                continue
            if ok.returncode == 0:
                return candidate
    return None


@pytest.mark.skipif(
    _container_runtime() is None,
    reason="requires docker or podman daemon; run manually with -m docker",
)
@pytest.mark.docker
def test_docker_image_runs_selftest() -> None:
    rt = _container_runtime()
    assert rt is not None
    build = subprocess.run(
        [rt, "build", "-t", IMAGE, "."],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    assert build.returncode == 0, build.stderr.decode(errors="replace")

    run = subprocess.run(
        [rt, "run", "--rm", IMAGE, "selftest"],
        capture_output=True,
    )
    out = run.stdout.decode(errors="replace")
    assert run.returncode == 0, run.stderr.decode(errors="replace")
    assert "Self-test: OK" in out


@pytest.mark.skipif(
    _container_runtime() is None,
    reason="requires docker or podman daemon; run manually with -m docker",
)
@pytest.mark.docker
def test_docker_image_help() -> None:
    rt = _container_runtime()
    assert rt is not None
    build = subprocess.run(
        [rt, "build", "-t", IMAGE, "."],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    assert build.returncode == 0, build.stderr.decode(errors="replace")
    run = subprocess.run(
        [rt, "run", "--rm", IMAGE, "--help"],
        capture_output=True,
    )
    out = run.stdout.decode(errors="replace")
    assert run.returncode == 0, run.stderr.decode(errors="replace")
    assert "llmbuster" in out.lower()
