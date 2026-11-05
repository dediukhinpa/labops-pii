"""Этап 26 (R4-SEC-1): цифры любых систем счисления приводятся к ASCII до поиска."""

import pytest

from labops_pii.guard.detector import find_pii_types, scan_body
from labops_pii.pii_patterns import normalize_text

ZERO_BASES = {
    "arabic_indic": 0x0660,
    "ext_arabic_indic": 0x06F0,
    "devanagari": 0x0966,
    "bengali": 0x09E6,
    "thai": 0x0E50,
    "fullwidth": 0xFF10,
}
PHONE = "+7 916 123-45-67"
INN12 = "500100732259"
CARD = "4111 1111 1111 1111"


def to_script(text: str, base: int) -> str:
    return "".join(chr(base + int(c)) if c.isdigit() else c for c in text)


@pytest.mark.parametrize("script", sorted(ZERO_BASES))
def test_normalize_folds_decimal_digits(script: str) -> None:
    src = to_script("0123456789", ZERO_BASES[script])
    assert normalize_text(src) == "0123456789"


@pytest.mark.parametrize("script", sorted(ZERO_BASES))
def test_phone_inn_card_found_in_any_digits(script: str) -> None:
    base = ZERO_BASES[script]
    assert "phone" in find_pii_types("тел " + to_script(PHONE, base))
    assert "inn" in find_pii_types("ИНН " + to_script(INN12, base))
    assert "card" in find_pii_types("карта " + to_script(CARD, base))


def test_mixed_digit_systems_phone_found() -> None:
    assert "phone" in find_pii_types("8 (९१६) 123-٤٥-６७")


def test_exotic_digits_found_in_json_body() -> None:
    body = ('{"a": "позвони ' + to_script("8 916 123 45 67", ZERO_BASES["devanagari"]) + '"}')
    assert scan_body(body.encode(), require_json=True) == {"phone"}


def test_exotic_digits_do_not_invent_findings() -> None:
    assert find_pii_types("артикул " + to_script("12345", ZERO_BASES["thai"])) == set()
