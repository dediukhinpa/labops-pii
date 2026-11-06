"""Этап 26: цифры любых систем счисления, ИП капсом, ники Telegram (R4-SEC-1, 10, 9)."""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.pii_patterns import normalize_text
from labops_pii.service import Pseudonymizer
from tests.sqlite_v2_pseudonymizer.conftest import found

VALID_INN12 = "500100732259"
PHONE = "+7 916 123-45-67"
# Начала блоков десятичных цифр Unicode (код нуля)
ZERO_BASES = {
    "arabic_indic": 0x0660,
    "ext_arabic_indic": 0x06F0,
    "devanagari": 0x0966,
    "bengali": 0x09E6,
    "thai": 0x0E50,
    "fullwidth": 0xFF10,
}


def to_script(text: str, base: int) -> str:
    """Заменяет ASCII-цифры цифрами другой системы счисления."""
    return "".join(chr(base + int(c)) if c.isdigit() else c for c in text)


# --- R4-SEC-1 -------------------------------------------------------------------------

@pytest.mark.parametrize("script", sorted(ZERO_BASES))
def test_normalize_folds_decimal_digits(script: str) -> None:
    src = to_script("0123456789", ZERO_BASES[script])
    assert normalize_text(src) == "0123456789"
    assert len(normalize_text(src)) == len(src)


@pytest.mark.parametrize("script", sorted(ZERO_BASES))
def test_phone_in_any_digits_masked(detector: PiiDetector, script: str) -> None:
    phone = to_script(PHONE, ZERO_BASES[script])
    text = f"Звоните {phone} после обеда"
    assert found(detector, text) == [("PHONE", phone)]


def test_mixed_digits_phone_masked(detector: PiiDetector) -> None:
    phone = "8 (९१६) 123-٤٥-６７"  # деванагари + ASCII + арабо-индийские + полноширинные
    assert found(detector, f"тел. {phone}") == [("PHONE", phone)]


@pytest.mark.parametrize("script", sorted(ZERO_BASES))
def test_inn_in_any_digits_masked(detector: PiiDetector, script: str) -> None:
    inn = to_script(VALID_INN12, ZERO_BASES[script])
    assert found(detector, f"ИНН {inn}") == [("INN", inn)]


def test_service_masks_exotic_digits_and_restores(service: Pseudonymizer) -> None:
    text = f"Позвоните на {to_script(PHONE, ZERO_BASES['arabic_indic'])}, ИНН "
    text += to_script(VALID_INN12, ZERO_BASES["devanagari"])
    masked, _ = service.pseudonymize("t", text)
    assert "[PHONE_1]" in masked and "[INN_1]" in masked
    assert not any(ord(c) > 0x7F and c.isdigit() for c in masked)
    assert service.restore("t", masked) == text


def test_exotic_digits_do_not_create_false_phone(detector: PiiDetector) -> None:
    text = "Артикул " + to_script("12345", ZERO_BASES["arabic_indic"]) + " в наличии"
    assert found(detector, text) == []


# --- R4-SEC-10 ------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ("Контрагент ИП ПЕТРОВ принял заказ", "ИП ПЕТРОВ"),
        ("Контрагент ИП ПЕТРОВ ИВАН ИВАНОВИЧ принял заказ", "ИП ПЕТРОВ ИВАН ИВАНОВИЧ"),
        ("Индивидуальный предприниматель ПЕТРОВ принял", "Индивидуальный предприниматель ПЕТРОВ"),
        ("ИП ПЕТРОВ И.И. принял заказ", "ИП ПЕТРОВ И.И."),
        (
            f"ИП ПЕТРОВ ИВАН ИВАНОВИЧ, ИНН {VALID_INN12}",
            f"ИП ПЕТРОВ ИВАН ИВАНОВИЧ, ИНН {VALID_INN12}",
        ),
        (f"ИП ПЕТРОВ ИНН {VALID_INN12}", f"ИП ПЕТРОВ ИНН {VALID_INN12}"),
    ],
)
def test_ip_caps_masked(detector: PiiDetector, text: str, masked: str) -> None:
    assert found(detector, text) == [("PERSON", masked)]


def test_ip_caps_same_key_as_normal_case(service: Pseudonymizer) -> None:
    first, _ = service.pseudonymize("t", "ИП Петров прислал счёт")
    second, _ = service.pseudonymize("t", "ИП ПЕТРОВ прислал счёт")
    assert first == second == "[PERSON_1] прислал счёт"


def test_single_caps_surname_after_ip_not_dropped(detector: PiiDetector) -> None:
    # Группа из одного слова без инициалов раньше отбрасывалась в _flush_caps_group
    assert [t for t, _ in found(detector, "поставщик ИП: ПЕТРОВ")] == ["PERSON"]


@pytest.mark.parametrize(
    "text",
    [
        "ООО РОМАШКА ТРЕЙД поставляет СТАЛЬ 09Г2С",
        "ГОСТ 5781-82 АРМАТУРА ГОРЯЧЕКАТАНАЯ",
        "DIN 933 БОЛТ ОЦИНКОВАННЫЙ",
        "ИП ООО РОМАШКА",
        "ИП ЗАКАЗЧИК ОПЛАТИЛ",
        "ИП ИНН 500100732259",
        "ТРУБА СТАЛЬНАЯ БЕСШОВНАЯ ПОСТАВКА",
        "СТАЛЬ ЛИСТОВАЯ ХОЛОДНОКАТАНАЯ, ЦЕМЕНТ М500",
        "ПОСТАВЩИК КОНТАКТ ЗАКАЗ",
    ],
)
def test_caps_headings_not_masked(detector: PiiDetector, text: str) -> None:
    assert not [t for t, _ in found(detector, text) if t == "PERSON"]


# --- R4-SEC-9 -------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ("Telegram: @ivanov_petr, пишите", "@ivanov_petr"),
        ("писать в @Ivanov_Petr.", "@Ivanov_Petr"),
        ("ссылка t.me/ivanov_petr", "t.me/ivanov_petr"),
        ("ссылка https://t.me/ivanov_petr?start=1 вот", "https://t.me/ivanov_petr"),
        ("ссылка T.ME/ivanov вот", "T.ME/ivanov"),
        ("инвайт https://t.me/+AbCdEf123456 вот", "https://t.me/+AbCdEf123456"),
    ],
)
def test_telegram_contact_masked(detector: PiiDetector, text: str, masked: str) -> None:
    assert found(detector, text) == [("CONTACT", masked)]


def test_nick_roundtrip_and_same_token(service: Pseudonymizer) -> None:
    text = "связь @ivanov_petr или @IVANOV_PETR"
    masked, _ = service.pseudonymize("t", text)
    assert masked == "связь [CONTACT_1] или [CONTACT_1]"
    assert service.restore("t", "[CONTACT_1]") == "@ivanov_petr"


@pytest.mark.parametrize(
    "text",
    [
        "Пишите на ivan.petrov@mail.ru, ответим",
        "user_name@example.com",
        "иван@пример.рф",
        "Артикул AB@12345 на складе",
        "код ЛМ@ABCDEFG1 в прайсе",
        "цена 5@100 шт",
        "ящик @example.com (домен)",
        "ник @abcd слишком короткий",
        "почта a@b.ru и @",
        "в t.met/abc и dt.me/xyz нет ссылки",
    ],
)
def test_nick_false_positives_none(detector: PiiDetector, text: str) -> None:
    assert not [t for t, _ in found(detector, text) if t == "CONTACT"]


def test_email_not_broken_by_nick_rule(detector: PiiDetector) -> None:
    text = "ivan_petrov@firma.ru и @ivan_petrov"
    assert found(detector, text) == [("EMAIL", "ivan_petrov@firma.ru"), ("CONTACT", "@ivan_petrov")]


def test_role_label_before_person_token_not_person(service: Pseudonymizer) -> None:
    """«Подписант: ФИО» после маскирования не даёт ложного PERSON на слове «Подписант»."""
    masked, _ = service.pseudonymize(
        "t-role", "Подписант: Дудорова Марина Евгеньевна\nДолжность: генеральный директор"
    )
    assert "Дудорова" not in masked
    assert "Подписант:" in masked
    # Вторая проверка маскированного текста (как в шлюзе ядра) ничего не находит.
    assert service.check(masked, "t-role") == []


@pytest.mark.parametrize(
    "text",
    [
        "Генеральный директор Дудорова Марина Евгеньевна",
        "директор Дудорова Марина Евгеньевна, подписант",
    ],
)
def test_surname_after_position_masked(detector: PiiDetector, text: str) -> None:
    """Фамилия после должности не теряется: NER брал только «Марина Евгеньевна»."""
    spans = [text[d.start:d.end] for d in detector.detect(text, set())]
    assert "Дудорова Марина Евгеньевна" in spans
