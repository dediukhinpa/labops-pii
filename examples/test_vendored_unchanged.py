"""Пример теста проекта: вендоренные файлы labops-pii не правились руками.

Положите в тесты проекта и поправьте VENDOR_DIR. Тест читает vendor/labops-pii/VERSION и
сверяет sha256 каждого файла; лишний или изменённый файл — падение. Чинить нужно в
репозитории labops-pii (PR, тег), затем обновить копию командой tools/vendor.sh.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "labops-pii"
IGNORED_DIRS = {"__pycache__"}


def _declared() -> dict[str, str]:
    """Хеши из VERSION: путь -> sha256."""
    result: dict[str, str] = {}
    in_files = False
    for line in (VENDOR_DIR / "VERSION").read_text(encoding="utf-8").splitlines():
        if line.startswith("files:"):
            in_files = True
        elif in_files and line.strip():
            digest, name = line.split(None, 1)
            result[name.strip()] = digest
    return result


def test_version_file_declares_files() -> None:
    assert _declared(), "в VERSION нет списка файлов"


def test_vendored_files_unchanged() -> None:
    declared = _declared()
    actual = {
        str(p.relative_to(VENDOR_DIR)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in VENDOR_DIR.rglob("*")
        if p.is_file() and p.name != "VERSION" and not IGNORED_DIRS & set(p.parts)
        and p.suffix != ".pyc"
    }
    assert actual == declared, (
        "вендоренные файлы изменены руками или не совпадают с VERSION: "
        "обновите командой labops-pii/tools/vendor.sh"
    )
