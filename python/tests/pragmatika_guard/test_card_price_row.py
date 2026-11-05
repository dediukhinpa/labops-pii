"""Этап 116: вторая линия не отклоняет прайс с рядом цен, но видит настоящую карту."""

from labops_pii.guard.detector import find_pii_types


def test_price_row_is_not_card() -> None:
    assert "card" not in find_pii_types("Награда органайзер 3050 2850 2620 2390 2180")


def test_real_card_is_still_found() -> None:
    assert "card" in find_pii_types("4276 1600 1234 5675")
    assert "card" in find_pii_types("номер карты 3050 2850 2620 2390 2180")


def test_card_with_cvv_or_amount_is_found() -> None:
    assert "card" in find_pii_types("4276 1600 1234 5675 123")
    assert "card" in find_pii_types("4276 1600 1234 5675 1500 руб")
    assert "card" in find_pii_types("4276 1600 1234 5675 12/27")
