"""R6-04-02: международные телефоны (+код страны) и латинские ФИО рядом с меткой контакта."""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.pii_patterns import PHONE_RE, normalize_text
from labops_pii.service import Pseudonymizer
from tests.sqlite_v2_pseudonymizer.conftest import found

INTL_PHONES = [
    "+86 138 0013 8000",
    "+90 532 123 45 67",
    "+380 44 123 45 67",
    "+998 90 123 45 67",
    "+996 555 123 456",
    "+49 30 12345678",
    "+1 415 555 0132",
    "+1 (415) 555-0132",
    "+82 10 1234 5678",
    "(+44) 20 7946 0958",
    "+44 (0)20 7946 0958",
    "+971-4-123-4567",
    # R7-01: формы из ревью (код 1-2 цифры + 3-3-3, ряды коротких групп, слитный номер, 00)
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
# Не телефоны: допуски, температуры, суммы, размеры, артикулы с плюсом
NOT_PHONES = [
    "допуск +0.5 1.2 3.4 мм",
    "от +10 до +20 градусов",
    "+5 мм",
    "размер 2+3 4 5 6 7",
    "+12 30 40",
    "сталь 09Г2С +20 +40 +60",
    "итого +1 200 000 руб",
    # даты, размеры и суммы с плюсом (ревью R6): девять и больше цифр группами
    "+1 2024-01-15",
    "+1 15.01.2024",
    "размер +2 10 20 30 40",
    "+20 000 000 000",
    "+3 15 20 25 30",
    "итого +1 200 000 000 руб",
    # R7-01: суммы и артикулы, которые не должны начать маскироваться
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
]


@pytest.mark.parametrize("phone", INTL_PHONES)
def test_international_phone_matched(phone: str) -> None:
    assert PHONE_RE.search(normalize_text(f"тел: {phone}, доб. 5")) is not None


@pytest.mark.parametrize("text", NOT_PHONES)
def test_plus_numbers_are_not_phones(text: str) -> None:
    assert PHONE_RE.search(normalize_text(text)) is None


@pytest.mark.parametrize(
    ("phone", "key"),
    [
        ("+48 123 456 789", "48123456789"),
        ("+33 6 12 34 56 78", "33612345678"),
        ("0086 138 0013 8000", "8613800138000"),  # 00 == «+»: тот же ключ, что у «+86 …»
    ],
)
def test_intl_phone_masked_as_whole_number(
    detector: PiiDetector, phone: str, key: str
) -> None:
    hits = [d for d in detector.detect(f"Звоните {phone}, спросить менеджера")
            if d.pii_type.value == "PHONE"]
    assert [(f"Звоните {phone}"[d.start:d.end], d.key) for d in hits] == [(phone, key)]


def test_international_phone_masked_with_whole_number(detector: PiiDetector) -> None:
    text = "Li Wei, +86 138 0013 8000, price list"
    assert ("PHONE", "+86 138 0013 8000") in found(detector, text)


@pytest.mark.parametrize(
    "text",
    [
        "Contact: Li Wei, sales",
        "Contact person: John Smith",
        "Attn: Mehmet Yilmaz Ozkan",
        "Best regards,\nAnna Kowalska",
        "Manager: Sherzod Karimov",
    ],
)
def test_latin_name_after_contact_label_masked(detector: PiiDetector, text: str) -> None:
    persons = [frag for kind, frag in found(detector, text) if kind == "PERSON"]
    assert persons, text


@pytest.mark.parametrize(
    "text",
    [
        "Contact: Sales Department",
        "Manager: Head Office",
        "Contact us: Customer Support Team",
        "Best regards, Steel Trading Company",
        "contact: li wei",  # без заглавных - не имя
        "Attn: Accounts Payable",
        "Contact: Please Confirm",
        "Contact: Details Sheet",
        "Attn: Information Sheet",
        "Contact: Today Update",
        "Attn: Us Today",
    ],
)
def test_latin_label_without_name_not_masked(detector: PiiDetector, text: str) -> None:
    assert not [frag for kind, frag in found(detector, text) if kind == "PERSON"], text


# --- R7-02: повтор латинского ФИО без метки в том же тексте ----------------------

LATIN_REPEAT = "Contact: John Smith\nJohn Smith will ship; Smith confirmed"


def test_latin_name_repeats_masked_in_same_text(detector: PiiDetector) -> None:
    """Найденное после метки ФИО маскируется и дальше по тексту: полностью и по фамилии."""
    persons = [frag for kind, frag in found(detector, LATIN_REPEAT) if kind == "PERSON"]
    assert persons == ["John Smith", "John Smith", "Smith"]


@pytest.mark.parametrize(
    "text",
    [
        "Contact: John Smith\nSmithson Ltd ships; Smithsonian museum",  # часть другого слова
        "Contact: John Smith\nblacksmith and smith tools",  # другой регистр / внутри слова
        "Smith confirmed the order",  # метки нет: одиночная фамилия сама не находится
    ],
)
def test_latin_name_repeat_respects_word_boundaries(detector: PiiDetector, text: str) -> None:
    persons = [frag for kind, frag in found(detector, text) if kind == "PERSON"]
    assert persons == (["John Smith"] if text.startswith("Contact") else [])


def test_latin_name_repeat_service_roundtrip(service: Pseudonymizer) -> None:
    """Уровень сервиса: все формы -> один токен, в маскированном тексте ПДн нет, restore."""
    masked, _ = service.pseudonymize("t-lat", LATIN_REPEAT)
    assert "Smith" not in masked
    assert "John" not in masked
    assert masked.count("[PERSON_1]") == 3
    # /restore возвращает форму, встретившуюся первой (как и для кириллицы, см. README)
    assert service.restore("t-lat", masked) == LATIN_REPEAT.replace("; Smith", "; John Smith")
    assert service.check(masked) == []
