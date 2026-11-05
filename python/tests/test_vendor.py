"""Вендоринг: команда кладёт файлы с VERSION, правка руками ловится, guard лёгкий."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "vendor.py"
EXAMPLE = ROOT / "examples" / "test_vendored_unchanged.py"


def _vendor(dest: Path, parts: str) -> Path:
    subprocess.run(
        [sys.executable, str(TOOL), "--dest", str(dest), "--ref", "HEAD", "--parts", parts],
        check=True, capture_output=True,
    )
    return dest / "vendor" / "labops-pii"


def _load_example(vendor_dir: Path):  # noqa: ANN202
    spec = importlib.util.spec_from_file_location("vendored_example", EXAMPLE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.VENDOR_DIR = vendor_dir
    return module


def test_vendor_writes_version_and_example_test_passes(tmp_path: Path) -> None:
    vendor_dir = _vendor(tmp_path, "guard,service,media")
    version = (vendor_dir / "VERSION").read_text(encoding="utf-8")
    assert "commit: " in version and "labops_pii/pii_patterns.py" in version
    module = _load_example(vendor_dir)
    module.test_vendored_files_unchanged()


def test_manual_edit_is_detected(tmp_path: Path) -> None:
    vendor_dir = _vendor(tmp_path, "guard")
    target = vendor_dir / "labops_pii" / "pii_patterns.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# правка\n", encoding="utf-8")
    module = _load_example(vendor_dir)
    with pytest.raises(AssertionError):
        module.test_vendored_files_unchanged()


def test_guard_part_does_not_need_morphology(tmp_path: Path) -> None:
    """Вендоренный guard импортируется без natasha и pymorphy (образ шлюза лёгкий)."""
    vendor_dir = _vendor(tmp_path, "guard")
    code = (
        "import sys; import labops_pii.guard.litellm.app, labops_pii.guard.edge.app;"
        "bad=[m for m in ('natasha','pymorphy3','labops_pii.detector','labops_pii.morph')"
        " if m in sys.modules]; assert not bad, bad"
    )
    subprocess.run(
        [sys.executable, "-c", code], check=True, capture_output=True,
        env={"PYTHONPATH": str(vendor_dir), "PATH": "/usr/bin"},
        cwd=tmp_path,
    )


def test_ts_part_vendors_sources_only(tmp_path: Path) -> None:
    """Часть ts: исходники, манифест, lock и лицензия; тесты и node_modules не вендорятся."""
    vendor_dir = _vendor(tmp_path, "ts")
    names = {
        str(p.relative_to(vendor_dir)) for p in vendor_dir.rglob("*") if p.is_file()
    }
    assert {"ts/package.json", "ts/bun.lock", "ts/LICENSE", "ts/src/index.ts", "VERSION"} <= names
    assert not any(n.startswith("labops_pii/") for n in names)
    assert not any("tests/" in n or "node_modules" in n for n in names)
    version = (vendor_dir / "VERSION").read_text(encoding="utf-8")
    assert "parts: ts" in version and "ts/src/index.ts" in version
    _load_example(vendor_dir).test_vendored_files_unchanged()


def test_ts_part_combines_with_python_parts(tmp_path: Path) -> None:
    vendor_dir = _vendor(tmp_path, "service,ts")
    assert (vendor_dir / "labops_pii" / "service.py").is_file()
    assert (vendor_dir / "ts" / "src" / "masker.ts").is_file()
    _load_example(vendor_dir).test_vendored_files_unchanged()



# Аннотированный тег библиотеки: на нём rev-parse без ^{commit} даёт хеш объекта тега
ANNOTATED_TAG = "v0.8.0"


def test_vendor_records_commit_of_annotated_tag(tmp_path: Path) -> None:
    """У аннотированного тега в VERSION - хеш коммита, а не объекта тега."""
    found = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "-q", "--verify", f"{ANNOTATED_TAG}^{{commit}}"],
        capture_output=True, text=True,
    )
    if found.returncode != 0:
        pytest.skip(f"в клоне нет тега {ANNOTATED_TAG}")
    subprocess.run(
        [sys.executable, str(TOOL), "--dest", str(tmp_path), "--ref", ANNOTATED_TAG,
         "--parts", "guard"],
        check=True, capture_output=True,
    )
    version = (tmp_path / "vendor" / "labops-pii" / "VERSION").read_text(encoding="utf-8")
    assert f"commit: {found.stdout.strip()}\n" in version
