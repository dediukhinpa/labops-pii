"""Этап 22: нормализация, общий корпус слоёв, окна поиска, обязательный JSON."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from tests.edge_guard.pii_corpus import NEGATIVE, POSITIVE
from labops_pii.guard.detector import (
    SCAN_OVERLAP,
    SCAN_WINDOW,
    TOKEN_TYPES,
    BodyNotJsonError,
    find_pii_types,
    scan_body,
)
from labops_pii.pii_patterns import is_luhn_valid, normalize_text

GUARD_DIR = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = GUARD_DIR / "scripts" / "check-pii-patterns.sh"
# Каталог проекта общего сервиса (каталог pseudonymizer/ исходной копии); не задан - сверка
# пропускается (guard ставится на edge без исходников сервиса)
CANON_ENV = "PSEUDONYMIZER_SRC"
STRICT_TYPES = {"phone", "card", "account", "email"}


def _canon_dir() -> Path:
    raw = os.environ.get(CANON_ENV, "")
    if not raw or not Path(raw).is_dir():
        pytest.skip(f"{CANON_ENV} не задан: сверка с каноном пропущена")
    return Path(raw)


@pytest.mark.parametrize(("text", "expected"), POSITIVE)
def test_corpus_positive_found(text: str, expected: str) -> None:
    assert expected in find_pii_types(text)


@pytest.mark.parametrize("text", NEGATIVE)
def test_corpus_negative_not_found(text: str) -> None:
    assert not find_pii_types(text) & STRICT_TYPES


def test_normalize_keeps_length() -> None:
    text = "８９１６ №5 8–916/12 3 … ＠"
    out = normalize_text(text)
    assert len(out) == len(text)
    assert out.startswith("8916 №5 8-916-12 3") and "@" in out


def test_luhn() -> None:
    assert is_luhn_valid("4111111111111111")
    assert not is_luhn_valid("4111111111111112")
    assert not is_luhn_valid("411111111111111")


def test_tokens_of_new_types_pass() -> None:
    assert find_pii_types("карта [CARD_1], счёт [ACCOUNT_2]") == set()


@pytest.mark.parametrize("offset", [-30, -12, -1, 0, 1, 12, 30])
def test_phone_at_window_boundary_found(offset: int) -> None:
    """Номер на границе окон поиска не теряется, где бы граница ни прошла."""
    phone = "+7 916 123-45-67"
    cut = SCAN_WINDOW + offset
    text = "а" * cut + " " + phone + " " + "б" * (SCAN_WINDOW // 2)
    assert "phone" in find_pii_types(text)
    assert SCAN_OVERLAP > len(phone) * 2


def test_phone_inside_long_digit_run_not_invented_by_windows() -> None:
    """Длинная цифровая строка без пробелов не даёт телефон из-за границы окна."""
    text = "1" * (SCAN_WINDOW * 2 + 5)
    assert "phone" not in find_pii_types(text)


# --- scan_body(require_json) ------------------------------------------------------------

def test_require_json_rejects_plain_text() -> None:
    with pytest.raises(BodyNotJsonError):
        scan_body(b"hello world", require_json=True)
    assert scan_body(b"hello world") == set()  # без требования поведение прежнее


def test_require_json_accepts_json_and_still_scans() -> None:
    body = json.dumps({"a": ["x", "позвони 8–916–123–45–67"]}).encode()
    assert scan_body(body, require_json=True) == {"phone"}


def test_require_json_accepts_bom_and_utf16() -> None:
    assert scan_body(b'\xef\xbb\xbf{"a": 1}', require_json=True) == set()
    assert scan_body('{"a": "b"}'.encode("utf-16"), require_json=True) == set()


@pytest.mark.parametrize(
    "text",
    [
        "Li Wei, +86 138 0013 8000",
        "tel +90 532 123 45 67",
        "+49 30 12345678",
        "(+44) 20 7946 0958",
        "+44 (0)20 7946 0958",
        "+971-4-123-4567",
    ],
)
def test_international_phone_found(text: str) -> None:
    """R6-04-02: номера вне РФ/BY с «+» и кодом страны не уходят к модели открытыми."""
    assert "phone" in find_pii_types(text)


@pytest.mark.parametrize(
    "text",
    [
        "допуск +0.5 1.2 3.4",
        "итого +10 200 000 руб",
        "+5 мм",
        "+1 2024-01-15",
        "размер +2 10 20 30 40",
        "+20 000 000 000",
        "+3 15 20 25 30",
    ],
)
def test_plus_numbers_are_not_international_phones(text: str) -> None:
    assert "phone" not in find_pii_types(text)


def test_token_types_cover_all_pseudonymizer_types() -> None:
    """Токены всех типов псевдонимизатора guard вырезает до поиска (канон один в пакете)."""
    from labops_pii.detector import PiiType

    assert {t.value for t in PiiType} <= set(TOKEN_TYPES)
