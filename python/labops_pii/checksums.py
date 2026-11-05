"""Проверка контрольных сумм российских идентификаторов."""

from __future__ import annotations

INN10_WEIGHTS = (2, 4, 10, 3, 5, 9, 4, 6, 8)
INN12_WEIGHTS_1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
INN12_WEIGHTS_2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
INN_MODULO = 11
DIGIT_MODULO = 10
INN_LEN_ORG = 10
INN_LEN_PERSON = 12
OGRN_LEN = 13
OGRNIP_LEN = 15
OGRN_DIVISOR = 11
OGRNIP_DIVISOR = 13
SNILS_LEN = 11
SNILS_MIN_NUMBER = 1_001_998  # контрольная сумма считается только для номеров больше этого
SNILS_MODULO = 101
SNILS_SPECIAL_SUM = 100


def _weighted(digits: str, weights: tuple[int, ...]) -> int:
    """Считает взвешенную сумму цифр и возвращает контрольную цифру."""
    total = sum(int(d) * w for d, w in zip(digits, weights, strict=False))
    return total % INN_MODULO % DIGIT_MODULO


def is_valid_inn(value: str) -> bool:
    """Проверяет ИНН (10 цифр — юрлицо, 12 — физлицо/ИП) по контрольной сумме."""
    if not value.isdigit():
        return False
    if len(value) == INN_LEN_ORG:
        return _weighted(value[:9], INN10_WEIGHTS) == int(value[9])
    if len(value) == INN_LEN_PERSON:
        first = _weighted(value[:10], INN12_WEIGHTS_1) == int(value[10])
        second = _weighted(value[:11], INN12_WEIGHTS_2) == int(value[11])
        return first and second
    return False


def is_valid_ogrn(value: str) -> bool:
    """Проверяет ОГРН (13 цифр) по контрольной цифре."""
    if not value.isdigit() or len(value) != OGRN_LEN:
        return False
    return int(value[:-1]) % OGRN_DIVISOR % DIGIT_MODULO == int(value[-1])


def is_valid_ogrnip(value: str) -> bool:
    """Проверяет ОГРНИП (15 цифр) по контрольной цифре."""
    if not value.isdigit() or len(value) != OGRNIP_LEN:
        return False
    return int(value[:-1]) % OGRNIP_DIVISOR % DIGIT_MODULO == int(value[-1])


def is_valid_snils(value: str) -> bool:
    """Проверяет СНИЛС (11 цифр, без разделителей) по контрольному числу."""
    if not value.isdigit() or len(value) != SNILS_LEN:
        return False
    number, control = int(value[:9]), int(value[9:])
    if number <= SNILS_MIN_NUMBER:
        return True  # для малых номеров контрольное число не определено
    total = sum(int(d) * w for d, w in zip(value[:9], range(9, 0, -1), strict=True))
    if total < SNILS_SPECIAL_SUM:
        expected = total
    elif total <= SNILS_MODULO:
        expected = 0
    else:
        expected = total % SNILS_MODULO
        if expected >= SNILS_SPECIAL_SUM:
            expected = 0
    return expected == control
