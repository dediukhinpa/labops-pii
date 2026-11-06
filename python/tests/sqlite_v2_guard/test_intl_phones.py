"""R7-01: международные номера с кодом 1-2 цифры, короткими группами и префиксом 00."""

import pytest

from labops_pii.guard.detector import find_pii_types
from labops_pii.pii_patterns import PHONE_RE, normalize_text

# Формы из ревью R7: раньше уходили модели открытыми
PHONES = [
    "+48 123 456 789",
    "+34 612 345 678",
    "+32 475 123 456",
    "+33 6 12 34 56 78",
    "+45 12 34 56 78",
    "+86 13800138000",
    "+90 5321234567",
    "0086 138 0013 8000",
    "0049 30 12345678",
]
# Суммы и артикулы: телефоном быть не должны
NOT_PHONES = [
    "1 234 567,89 руб",
    "+1 234 567 руб",
    "12 345 678",
    "Арт. 123-456-789",
    "итого 12 345 678 руб",
    "цена 1 234 567.89 руб",
    "сумма +12 345 678 руб",
    "+12 345 000 000 руб",
    "№ 0012 3456 789",
    "00 123 456 789 шт",
    "0012 345 678",
    "размер 12 34 56 78 мм",
    "арт 12 34 56 78 90",
    "+3 15 20 25 30",
    "+20 000 000 000",
]


@pytest.mark.parametrize("phone", PHONES)
def test_phone_found(phone: str) -> None:
    assert PHONE_RE.search(normalize_text(f"тел: {phone}, доб. 5")) is not None
    assert "phone" in find_pii_types(f"Звоните {phone} завтра")


@pytest.mark.parametrize("text", NOT_PHONES)
def test_amount_or_article_not_phone(text: str) -> None:
    assert PHONE_RE.search(normalize_text(text)) is None
    assert "phone" not in find_pii_types(f"Позиция {text} в заказе")
