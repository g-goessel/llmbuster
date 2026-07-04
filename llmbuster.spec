# PyInstaller spec for llmbuster single-file executable.
#
# Build with:
#   uv run --with pyinstaller pyinstaller llmbuster.spec --clean --noconfirm
# Produces: dist/llmbuster  (a single-file ELF executable)
#
# The bundled resources (llmbuster/resources/**) are collected via
# collect_data_files so the importlib.resources access in factory.py and
# bundled.py keeps working at runtime.

from __future__ import annotations

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("llmbuster.resources")
binaries: list[tuple[str, str]] = []

hiddenimports = [
    *collect_submodules("llmbuster"),
    "typer",
    "click",
    "textual",
    "pydantic",
    "pydantic.deprecated.decorator",
    "yaml",
    "jsonpath_ng",
    "httpx",
    "httpx._transports",
    "httpx._transports.default",
    "anyio._backends._asyncio",
]

a = Analysis(
    ["llmbuster/cli.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="llmbuster",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
