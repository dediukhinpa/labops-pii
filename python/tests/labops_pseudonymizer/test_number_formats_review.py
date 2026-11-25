"""Цифровые ПДн в форматах, которые уходили открытыми (ревью и матрица 25.11.2026).

Номера вымышленные; ИНН, карты и счета подобраны с верной контрольной суммой.
"""

from __future__ import annotations

import time

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.guard.detector import find_pii_types
from labops_pii.service import Pseudonymizer

# Предел на враждебный ряд пробелов: прежний шаблон паспорта давал секунды
HOSTILE_SPACES = 64_000
HOSTILE_SECONDS = 2.0


def _types(detector: PiiDetector, text: str) -> list[tuple[str, str]]:
    return [(d.pii_type.value, text[d.start:d.end]) for d in detector.detect(text)]


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("Паспорт серия 4510, номер 123456", "4510, номер 123456"),
        ("Паспорт: серия 4510 номер: 123456", "4510 номер: 123456"),
        ("паспорт 4510-123456", "4510-123456"),
        ("Серия: 45 10, № 123456", "45 10, № 123456"),
    ],
)
def test_passport_with_punctuation_near_keyword(
    detector: PiiDetector, text: str, fragment: str
) -> None:
    assert ("PASSPORT", fragment) in _types(detector, text)


def test_passport_punctuation_without_keyword_is_not_passport(detector: PiiDetector) -> None:
    assert all(t != "PASSPORT" for t, _ in _types(detector, "Заказ 4510-123456 отгружен"))


def test_passport_pattern_is_linear_on_hostile_spaces(detector: PiiDetector) -> None:
    started = time.perf_counter()
    detector.detect("1234" + " " * HOSTILE_SPACES + "x")
    assert time.perf_counter() - started < HOSTILE_SECONDS


def test_inn_in_groups_after_keyword(detector: PiiDetector) -> None:
    assert _types(detector, "ИНН 5497 0940 0950") == [("INN", "5497 0940 0950")]
    # без слова «ИНН» группы цифр - не ИНН
    assert _types(detector, "Код 5497 0940 0950") == []


@pytest.mark.parametrize(
    "text",
    ["р/с 4070 2810 1380 0002 2345", "р/с 4081 7810 0999 1000 4313"],
)
def test_account_in_groups_of_four(detector: PiiDetector, text: str) -> None:
    found = _types(detector, text)
    assert [frag for _, frag in found] == [text[len("р/с "):]]
    assert "account" in find_pii_types(text)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("+7 916 12 345 67", "+7 916 12 345 67"),
        ("тел. 8 916 1234 567", "8 916 1234 567"),
        ("Телефон: 8 916 12-34-567", "8 916 12-34-567"),
    ],
)
def test_phone_in_unusual_grouping(detector: PiiDetector, text: str, fragment: str) -> None:
    assert _types(detector, text) == [("PHONE", fragment)]
    assert "phone" in find_pii_types(text)


@pytest.mark.parametrize(
    "text",
    ["арт. 8 916 12 34 567", "Заказ 2026-11-25, 9161234 шт", "сумма 8 916 12 34 567 руб"],
)
def test_unusual_grouping_without_plus7_or_keyword_is_not_phone(
    detector: PiiDetector, text: str
) -> None:
    assert all(t != "PHONE" for t, _ in _types(detector, text))


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("звоните 8/916/123/45/67 в любое время", "phone"),
        ("тел 8/916/123/45/67 г. Москва", "phone"),
        ("карта 4276/1600/1234/5675", "card"),
        ("счёт 40817/810/0/9991/0004312 в банке", "account"),
    ],
)
def test_guard_does_not_split_pii_written_with_slashes(text: str, kind: str) -> None:
    """«в» (как «В», вольт) и «г.» после номера не делают его списком размеров."""
    assert kind in find_pii_types(text)


@pytest.mark.parametrize("text", ["Кружка 425/660/1000 мл", "Объём 425/660/10/20 мл"])
def test_guard_still_splits_size_lists(text: str) -> None:
    assert "phone" not in find_pii_types(text)


@pytest.mark.parametrize(
    "text",
    [
        "Паспорт серия 4510, номер 123456",
        "ИНН 5497 0940 0950",
        "р/с 4081 7810 0999 1000 4313",
        "+7 916 12 345 67",
    ],
)
def test_new_formats_round_trip(service: Pseudonymizer, text: str) -> None:
    masked, _ = service.pseudonymize("n", text)
    assert not any(ch.isdigit() for ch in masked.replace("_1]", "]"))
    assert service.restore("n", masked) == text
