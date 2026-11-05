"""Сверка с эталоном бывших профилей: набор переменных даёт прежнее поведение побайтно.

Профили (labops, webapp_v2, pragmatika) удалены в 1.0.0. До удаления
`tools/reference_snapshot.py` снял поведение каждого из них (`fixtures/profiles/*.json`):
ответы сервиса и guard на общем корпусе и эффективные настройки. Здесь та же комбинация
задаётся переменными окружения (`tests/env_sets.py`) и снимок сравнивается с эталоном.
Любое расхождение - изменение поведения, а не тестовая погрешность.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.env_sets import ENV_SETS

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "reference_snapshot.py"
FIXTURES = Path(__file__).parent / "fixtures" / "profiles"

# вид снимка -> аргументы запуска (как при снятии эталона)
KINDS = {
    "config": ["--kind", "config"],
    "pseudonymizer": ["--kind", "pseudonymizer", "--with-case-labels", "--with-signatory"],
    "guard-litellm": ["--kind", "guard-litellm", "--all-modes"],
    "guard-edge": ["--kind", "guard-edge", "--all-modes"],
}


@pytest.mark.parametrize("kind", sorted(KINDS))
@pytest.mark.parametrize("env_set", sorted(ENV_SETS))
def test_env_set_matches_former_profile(env_set: str, kind: str, tmp_path: Path) -> None:
    """Набор переменных воспроизводит прежнее поведение профиля (побайтно)."""
    out = tmp_path / "snapshot.json"
    subprocess.run(
        [sys.executable, str(TOOL), "--impl", "library", "--env-set", env_set,
         "--out", str(out), *KINDS[kind]],
        check=True, capture_output=True,
    )
    expected = (FIXTURES / f"{env_set}__{kind}.json").read_bytes()
    assert out.read_bytes() == expected, (
        f"набор «{env_set}», снимок «{kind}»: поведение разошлось с бывшим профилем"
    )


def test_every_former_profile_has_all_fixtures() -> None:
    """Эталон есть для каждой комбинации набор x вид (удалённый файл не должен молча пройти)."""
    missing = [f"{s}__{k}.json" for s in ENV_SETS for k in KINDS
               if not (FIXTURES / f"{s}__{k}.json").is_file()]
    assert not missing
