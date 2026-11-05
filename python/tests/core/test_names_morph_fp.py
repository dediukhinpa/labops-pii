"""Замер ложных срабатываний поиска ФИО в guard на корпусе (морфология убрана в 0.7.0).

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


# Синтетические фрагменты страниц поставщиков (общая фикстура с TS-детектором): товары,
# бренды, города и улицы, совпадающие с фамилиями
WEB_FRAGMENTS = json.loads(
    (FIXTURES.parents[2] / "ts" / "tests" / "fixtures" / "web_page_fragments.json").read_text(
        encoding="utf-8"
    )
)
# Измерено 05.11.26 (v0.7.0, строгое правило): ложных нет
MAX_WEB_FP = 0


def test_false_positive_rate_on_web_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    """Текст страниц поставщиков: модели, сорта, города и улицы не дают ФИО."""
    monkeypatch.setenv("PII_GUARD_NAMES_MODE", "enforce")
    fp = [t for t in WEB_FRAGMENTS["negative"] if NAME_TYPE in detector.find_pii_types(t)]
    print(f"\n[замер] страницы: ложных {len(fp)} из "
          f"{len(WEB_FRAGMENTS['negative'])}")
    assert len(fp) <= MAX_WEB_FP
