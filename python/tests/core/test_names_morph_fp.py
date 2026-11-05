"""Замер ложных срабатываний поиска ФИО в guard: эвристика и морфология на корпусе.

Корпус «чисто» — тексты без ФИО из наборов трёх копий (названия, артефакты, адреса, прайсы,
имена файлов без людей). Тест фиксирует измеренные числа: рост ложных срабатываний при
правке эвристики или морфологии станет видно в CI. Числа попадают в отчёт (-s).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from labops_pii.guard import detector
from labops_pii.guard.names import NAME_TYPE

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
# Размеченный набор: тексты без ФИО (negative) и с ФИО (positive) из общего корпуса
LABELS = json.loads((FIXTURES / "names_labels.json").read_text(encoding="utf-8"))


def _rate(env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> tuple[int, int]:
    """(ложные срабатывания на «чисто», найдено на «с ФИО») при заданном окружении."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    false_positive = sum(NAME_TYPE in detector.find_pii_types(t) for t in LABELS["negative"])
    hits = sum(NAME_TYPE in detector.find_pii_types(t) for t in LABELS["positive"])
    return false_positive, hits


def test_heuristic_false_positive_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Эвристика (по умолчанию): число ложных срабатываний и полнота на размеченном наборе."""
    fp, hits = _rate({"PII_GUARD_NAMES_MODE": "enforce"}, monkeypatch)
    print(f"\n[замер] эвристика: ложных {fp} из {len(LABELS['negative'])}, "
          f"найдено ФИО {hits} из {len(LABELS['positive'])}")
    assert fp <= LABELS["max_heuristic_fp"]
    assert hits >= LABELS["min_heuristic_hits"]


def test_morph_false_positive_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Морфология (опция): ложных не больше, чем у эвристики плюс запас, полнота не ниже."""
    fp, hits = _rate(
        {"PII_GUARD_NAMES_MODE": "enforce", "PII_GUARD_NAMES_MORPH": "on"}, monkeypatch
    )
    print(f"\n[замер] эвристика+морфология: ложных {fp} из {len(LABELS['negative'])}, "
          f"найдено ФИО {hits} из {len(LABELS['positive'])}")
    assert fp <= LABELS["max_morph_fp"]
    assert hits >= LABELS["min_heuristic_hits"]


def test_morph_off_by_default_for_all_profiles() -> None:
    """Опция выключена по умолчанию во всех профилях: поведение как у исходных копий."""
    from labops_pii.profiles import PROFILES

    assert not any(p.guard_names_morph for p in PROFILES.values())
