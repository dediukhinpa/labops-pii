"""Ряд «4242 4242 ...» не должен давать сверхлинейное время проверки карт."""

from __future__ import annotations

import time

from labops_pii.pii_patterns import PRICE_NEIGHBORS_MAX, find_card_spans, looks_like_price_row

# Длина тела, на которой прежний разбор соседей работал часами (предел текста сервиса)
LONG_ROW_REPEATS = 14_000
# С запасом для медленной машины; прежний код на 4 000 символах тратил 14 с
TIME_BUDGET_SECONDS = 5.0


def test_long_luhn_row_is_linear() -> None:
    text = "4242 " * LONG_ROW_REPEATS
    started = time.perf_counter()
    find_card_spans(text)
    assert time.perf_counter() - started < TIME_BUDGET_SECONDS


def test_price_row_neighbors_unchanged() -> None:
    # Поведение на обычном ряде цен прежнее: соседи слева и справа находятся
    row = "Тиражи: 3500 3250 3050 2850 2620 2390 2180 руб."
    start = row.index("3050")
    end = row.index("2180") + 4
    assert looks_like_price_row(row, start, end, " ")


def test_row_longer_than_neighbor_limit_is_masked_as_card() -> None:
    # Плавные соседи до предела, а дальше число, ломающее шаг: без предела ряд не считался
    # рядом цен, поэтому и с пределом карта должна находиться (fail closed)
    smooth = " ".join(str(4100 + 10 * i) for i in range(PRICE_NEIGHBORS_MAX))
    text = f"100 {smooth} 4242 4242 4242 4242"
    card_start = text.index("4242")
    assert (card_start, card_start + len("4242 4242 4242 4242")) in find_card_spans(text)
