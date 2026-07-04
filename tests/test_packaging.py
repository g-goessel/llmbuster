from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _find_wheel() -> Path | None:
    dist = REPO_ROOT / "dist"
    if not dist.is_dir():
        return None
    wheels = sorted(dist.glob("llmbuster-*.whl"))
    return wheels[0] if wheels else None


def _build_wheel() -> Path | None:
    if shutil.which("uv") is None:
        return None
    try:
        subprocess.run(
            ["uv", "build", "--wheel"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return None
    return _find_wheel()


def test_wheel_includes_resources() -> None:
    wheel = _find_wheel() or _build_wheel()
    if wheel is None:
        pytest.skip("no wheel in dist/ and uv build unavailable")
    assert wheel.suffix == ".whl"

    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    assert "llmbuster/resources/openrouter.yaml" in names, (
        "bundled openrouter.yaml missing from wheel"
    )
    pack_yamls = [n for n in names if n.startswith("llmbuster/resources/packs/llm")]
    assert len(pack_yamls) == 10, f"expected 10 pack YAMLs, got {len(pack_yamls)}"


def test_wheel_entrypoint_registered() -> None:
    wheel = _find_wheel() or _build_wheel()
    if wheel is None:
        pytest.skip("no wheel in dist/ and uv build unavailable")

    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        entry_point_files = [n for n in names if n.endswith("entry_points.txt")]
        assert entry_point_files, "entry_points.txt missing from wheel"
        entry_points = zf.read(entry_point_files[0]).decode()
    assert "llmbuster = " in entry_points, "console entrypoint missing in wheel"


def test_dockerfile_exists() -> None:
    dockerfile = REPO_ROOT / "Dockerfile"
    assert dockerfile.is_file(), "Dockerfile missing at repo root"
    text = dockerfile.read_text(encoding="utf-8")
    assert "python:3.12-slim" in text, "Dockerfile must use python:3.12-slim base"
    assert "ENTRYPOINT" in text, "Dockerfile must define ENTRYPOINT"
    assert "llmbuster" in text


def test_dockerfile_has_volume_and_workdir() -> None:
    dockerfile = REPO_ROOT / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")
    assert "VOLUME" in text and "/data" in text
    assert "WORKDIR /data" in text


def test_dockerignore_exists() -> None:
    di = REPO_ROOT / ".dockerignore"
    assert di.is_file(), ".dockerignore missing at repo root"
    text = di.read_text(encoding="utf-8")
    assert any(line.strip() == "dist/" for line in text.splitlines())
    assert any(line.strip() == ".venv/" for line in text.splitlines())
    assert any(line.strip() == "tests/" for line in text.splitlines())
    assert any(line.strip() == "__pycache__/" for line in text.splitlines())


def test_pyinstaller_spec_exists() -> None:
    spec = REPO_ROOT / "llmbuster.spec"
    assert spec.is_file(), "llmbuster.spec missing at repo root"
    text = spec.read_text(encoding="utf-8")
    assert "Analysis(" in text
    assert (
        "collect_data_files" in text and "llmbuster.resources" in text
    ), "spec must collect llmbuster.resources data files"
    assert "EXE(" in text
    assert 'name="llmbuster"' in text
    assert "console=True" in text


def test_pyinstaller_spec_has_datas_fallback() -> None:
    spec = REPO_ROOT / "llmbuster.spec"
    text = spec.read_text(encoding="utf-8")
    assert "datas" in text, "spec should declare datas (explicit or via collect_data_files)"


def test_pyproject_has_pyinstaller_optional_group() -> None:
    pp = REPO_ROOT / "pyproject.toml"
    text = pp.read_text(encoding="utf-8")
    assert "pyinstaller = [" in text, "optional pyinstaller dependency group missing"


def test_importlib_resources_accessible_from_wheel_layout() -> None:
    from importlib.resources import files

    res = files("llmbuster.resources")
    profile = res / "openrouter.yaml"
    assert profile.is_file(), "openrouter.yaml not visible via importlib.resources"
    assert "openrouter" in profile.read_text(encoding="utf-8").lower()

    packs = files("llmbuster.resources.packs")
    pack_files = [
        entry.name
        for entry in packs.iterdir()
        if entry.is_file() and entry.name.endswith((".yaml", ".yml"))
    ]
    assert len(pack_files) == 10, f"expected 10 bundled pack YAMLs, got {len(pack_files)}"
