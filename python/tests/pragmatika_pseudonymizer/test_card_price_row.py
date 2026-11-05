"""Этап 116: ряд цен по тиражам не маскируется как карта, настоящие карты — по-прежнему."""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector

# 3050+2850+2620+2390 проходит Luhn — боевая строка «Награда органайзер»
PRICE_ROWS = [
    "Награда органайзер 3050 2850 2620 2390 2180",
    "3050 2850 2620 2390 2180 1990",
]
CARDS = [
    "4276 1600 1234 5675",
    "4276160012345675",
    "4276-1600-1234-5675",
    "карта 4276 1600 1234 5675 до 12/27",
    "номер карты: 5469 3800 1234 5673 спасибо",
    "Оплата картой Visa 4111 1111 1111 1111",
    # соседнее число (CVV, сумма, срок) ряд цен не делает
    "4276 1600 1234 5675 123",
    "4276 1600 1234 5675 1500 руб",
    "4276 1600 1234 5675 12/27",
    "Клиент оплатил заказ на прошлой неделе по реквизитам 4276 1600 1234 5675 — 1500 руб",
    "Клиент оплатил заказ на прошлой неделе и сообщил номер 4276 1600 1234 5675 CVV 123",
    # два соседних числа (CVV+год, сумма+число) — всё равно не гладкий ряд цен
    "4276 1600 1234 5675 123 2026",
    "4276 1600 1234 5675 1500 2000",
    "5000 4276 1600 1234 5675 1500",
    # 4 цены без соседей — не отличить от карты, маскируем (осторожная сторона)
    "Органайзер | 3050 2750 2620 2300 | шт",
]


def _types(detector: PiiDetector, text: str) -> set[str]:
    return {d.pii_type.value.lower() for d in detector.detect(text)}


@pytest.mark.parametrize("text", PRICE_ROWS)
def test_price_row_is_not_card(detector: PiiDetector, text: str) -> None:
    assert "card" not in _types(detector, text)


@pytest.mark.parametrize("text", CARDS)
def test_real_card_is_still_masked(detector: PiiDetector, text: str) -> None:
    assert "card" in _types(detector, text)


def test_price_row_next_to_card_keyword_is_masked(detector: PiiDetector) -> None:
    """Подсказка «карта» рядом сильнее формы ряда цен."""
    assert "card" in _types(detector, "номер карты 3050 2850 2620 2390 2180")
