"""Сверка библиотеки с эталонными снимками исходных копий (побайтно, по профилям).

Эталоны в tests/fixtures/reference/*.json сняты tools/reference_snapshot.py на КОДЕ ИСХОДНЫХ
копий: labops-ai-assistant e271609, pragmatica-ai origin/prod 53c84abc, web-app-v2 1aebe40.
Библиотека снимается в отдельном процессе под своим профилем. Для pragmatika расхождений
быть не должно, кроме ИНН организации (0.7.0). Для всех профилей допустимы только расхождения из
fixtures/accepted_divergences.json (осознанные фиксы, см. CHANGELOG): любое новое
расхождение роняет тест, пока его не разобрали и не записали.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "reference_snapshot.py"
FIXTURES = Path(__file__).parent / "fixtures"
ACCEPTED = json.loads((FIXTURES / "accepted_divergences.json").read_text(encoding="utf-8"))

# имя эталона -> аргументы запуска библиотеки
CASES = {
    "labops_pseudonymizer": ["--kind", "pseudonymizer", "--profile", "labops",
                             "--with-case-labels"],
    "pragmatika_pseudonymizer": ["--kind", "pseudonymizer", "--profile", "pragmatika",
                                 "--with-signatory"],
    "pragmatika_guard": ["--kind", "guard-litellm", "--profile", "pragmatika"],
    "webapp_v2_guard": ["--kind", "guard-edge", "--profile", "webapp_v2"],
}


def divergent_items(ref: Any, lib: Any, path: str = "") -> dict[str, set[int]]:
    """Номера элементов корпуса, на которых ответы расходятся, по разделам снимка."""
    found: dict[str, set[int]] = {}

    def walk(a: Any, b: Any, section: str, index: int | None) -> None:
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a) | set(b)):
                walk(a.get(key), b.get(key), f"{section}/{key}" if index is None else section,
                     index)
        elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            for i, (x, y) in enumerate(zip(a, b)):
                walk(x, y, section, i if index is None else index)
        elif a != b:
            found.setdefault(section, set()).add(-1 if index is None else index)

    walk(ref, lib, path, None)
    return found


@pytest.mark.parametrize("name", sorted(CASES))
def test_library_matches_original_snapshot(name: str, tmp_path: Path) -> None:
    """Ответы библиотеки на общем корпусе совпадают с эталоном исходной копии."""
    out = tmp_path / "lib.json"
    subprocess.run(
        [sys.executable, str(TOOL), "--impl", "library", "--out", str(out), *CASES[name]],
        check=True, capture_output=True,
    )
    ref = json.loads((FIXTURES / "reference" / f"{name}.json").read_text(encoding="utf-8"))
    lib = json.loads(out.read_text(encoding="utf-8"))
    got = {k: sorted(v) for k, v in divergent_items(ref, lib).items()}
    assert got == ACCEPTED.get(name, {}).get("divergences", {}), (
        "расхождение с исходной копией: разберите и, если это фикс, запишите в "
        "accepted_divergences.json и CHANGELOG"
    )
