"""Ревью-9: перекрытие находок (R9-A4-03) и одно правило СНИЛС для двух слоёв (R9-A4-04)."""

from __future__ import annotations

import importlib
import random
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.pii_patterns import find_snils_spans, is_snils_checksum_valid
from labops_pii.service import Pseudonymizer
from labops_pii.store import SqliteReplacementStore

ROOT = Path(__file__).resolve().parents[3]
GUARD_ROOT = ROOT / "gateway" / "pii-guard"
# Записи словаря короче ФИО в тексте: только фамилия, только имя, «Фамилия Имя»; адрес-ник
# (часть e-mail) и запись, задевающая телефон (смесь типов).
R9_CONTACTS = ("Петров", "Иван", "Сидоров Олег", "petrov", "Вася 8 916")
RANDOM_SEED = 9
RANDOM_NUMBERS = 20_000
SNILS_DIGITS = 11
PRICE_ROWS = 300


@pytest.fixture(scope="module")
def r9_detector() -> PiiDetector:
    """Детектор со словарём контактов, записи которого короче ФИО в тексте."""
    return PiiDetector(contacts=R9_CONTACTS)


@pytest.fixture
def r9_service(r9_detector: PiiDetector, store: SqliteReplacementStore) -> Pseudonymizer:
    """Сервис поверх детектора со словарём R9_CONTACTS."""
    return Pseudonymizer(r9_detector, store)


# --- R9-A4-03: контакт из словаря не открывает остаток ФИО ----------------------------

OVERLAP_CASES = [
    # (текст, слова, которых не должно остаться в маске)
    ("Прошу согласовать: Петров Иван Сергеевич, отдел снабжения.", ("Иван", "Сергеевич")),
    ("Счёт подписал Иван Петров, бухгалтер.", ("Иван", "Петров")),
    ("Ответственный Сидоров Олег Петрович подтвердил поставку.", ("Олег", "Петрович")),
]


@pytest.mark.parametrize(("text", "secrets"), OVERLAP_CASES)
def test_dictionary_contact_does_not_unmask_rest_of_name(
    r9_service: Pseudonymizer, text: str, secrets: tuple[str, ...]
) -> None:
    out, entities = r9_service.pseudonymize("t-r9", text)
    for secret in secrets:
        assert secret not in out
    # объединение ФИО и контакта - одно ФИО: тип PERSON, восстановление побайтно
    assert [e.type for e in entities] == ["PERSON"]
    assert r9_service.restore("t-r9", out) == text


def test_merged_name_token_matches_detection_without_dictionary(
    r9_detector: PiiDetector, detector: PiiDetector
) -> None:
    """Со словарём ФИО маскируется тем же диапазоном и ключом, что без словаря (тот же токен)."""
    text = OVERLAP_CASES[0][0]
    with_dict = [(d.start, d.end, d.pii_type, d.key) for d in r9_detector.detect(text)]
    without = [(d.start, d.end, d.pii_type, d.key) for d in detector.detect(text)]
    assert with_dict == without


def test_merged_name_token_is_stable_in_thread(r9_service: Pseudonymizer) -> None:
    first, _ = r9_service.pseudonymize("t-r9", "Петров Иван Сергеевич прислал счёт")
    second, _ = r9_service.pseudonymize("t-r9", "Повторно звонил Петров Иван Сергеевич")
    third, _ = r9_service.pseudonymize("t-r9", "Передайте Петрову Ивану Сергеевичу оплату")
    assert first.startswith("[PERSON_1]")
    assert "[PERSON_1]" in second and "[PERSON_1]" in third
    assert "Иван" not in third and "Сергеевич" not in third


def test_contact_inside_email_keeps_email(r9_detector: PiiDetector) -> None:
    """Контакт внутри адреса: адрес важнее и покрывает контакт, находка прежняя."""
    text = "Пишите на petrov@mail.ru или petrov.ivan@mail.ru"
    found = [(d.pii_type.value, text[d.start:d.end], d.exact) for d in r9_detector.detect(text)]
    assert found == [("EMAIL", "petrov@mail.ru", False), ("EMAIL", "petrov.ivan@mail.ru", False)]


def test_contact_overlapping_phone_is_merged_exactly(r9_service: Pseudonymizer) -> None:
    """Смесь типов: маска - объединение, тип важнейшей находки, восстановление побайтно."""
    text = "Звонить: Вася 8 916 123-45-67, после обеда"
    out, entities = r9_service.pseudonymize("t-r9", text)
    assert out == "Звонить: [PHONE_1], после обеда"
    assert [e.type for e in entities] == ["PHONE"]
    assert r9_service.restore("t-r9", out) == text
    again, _ = r9_service.pseudonymize("t-r9", "Повторяю: Вася 8 916 123-45-67")
    assert again == "Повторяю: [PHONE_1]"


def test_adjacent_detections_are_not_glued(r9_detector: PiiDetector) -> None:
    text = "Петров, ivan@mail.ru"
    found = [(d.pii_type.value, text[d.start:d.end]) for d in r9_detector.detect(text)]
    assert ("EMAIL", "ivan@mail.ru") in found
    assert all(len(fragment) < len(text) for _, fragment in found)


# --- R9-A4-04: всё, что шлюз счёл бы СНИЛС, псевдонимизатор маскирует ---------------------

def _import_guard() -> ModuleType:
    """Детектор guard из того же пакета (раньше лежал в соседнем каталоге репозитория)."""
    return importlib.import_module("labops_pii.guard.detector")


def _snils_with_checksum(rng: random.Random) -> str:
    """Случайный 11-значный номер, у которого сходится контрольное число СНИЛС."""
    while True:
        digits = str(rng.randint(10 ** (SNILS_DIGITS - 1), 10**SNILS_DIGITS - 1))
        if is_snils_checksum_valid(digits):
            return digits


def _parity_inputs() -> Iterator[str]:
    """Набор входов: случайные номера, СНИЛС в разных записях, строки прайса с артикулами."""
    rng = random.Random(RANDOM_SEED)
    for _ in range(RANDOM_NUMBERS // 100):
        yield f"артикул {rng.randint(10 ** (SNILS_DIGITS - 1), 10**SNILS_DIGITS - 1)}"
    for _ in range(50):
        d = _snils_with_checksum(rng)
        yield f"Артикул {d}, 12 шт."
        yield f"СНИЛС {d[:3]}-{d[3:6]}-{d[6:9]} {d[9:]}"
        yield f"номер {d[:3]} {d[3:6]} {d[6:9]} {d[9:]}"
        yield f"код {d[:3]}-{d[3:6]}-{d[6:9]}{d[9:]};"
        yield f"прайс_{d}.xlsx"
    rows = [
        f"{i}\t{rng.randint(10 ** (SNILS_DIGITS - 1), 10**SNILS_DIGITS - 1)}\tТруба 57x3\t"
        f"{rng.randint(100, 9999)},00"
        for i in range(PRICE_ROWS)
    ]
    yield "Прайс-лист\n" + "\n".join(rows)


def test_snils_parity_guard_never_rejects_pseudonymized(
    service: Pseudonymizer,
) -> None:
    """Паритет слоёв: после псевдонимизации шлюз не находит СНИЛС ни в одном входе."""
    guard = _import_guard()
    rejected = []
    for index, text in enumerate(_parity_inputs()):
        out, _ = service.pseudonymize(f"t-parity-{index}", text)
        if "snils" in guard.find_pii_types(out):
            rejected.append(text)
        assert service.restore(f"t-parity-{index}", out) == text
    assert rejected == []


def test_snils_guard_rule_is_shared() -> None:
    """Шлюз берёт правило из общего модуля, а не держит свою копию."""
    guard = _import_guard()
    assert guard.find_snils_spans.__module__ == "labops_pii.pii_patterns"
    sample = "Артикул 31234567846, 12 шт."
    assert "snils" in guard.find_pii_types(sample)
    assert find_snils_spans(sample) == [(8, 19)]


def test_checksum_snils_without_keyword_is_masked(service: Pseudonymizer) -> None:
    text = "Артикул 31234567846, 12 шт."
    out, entities = service.pseudonymize("t-r9", text)
    assert out == "Артикул [SNILS_1], 12 шт."
    assert [e.type for e in entities] == ["SNILS"]
    assert service.restore("t-r9", out) == text


def test_phone_with_snils_checksum_stays_phone(detector: PiiDetector) -> None:
    """Номер телефона, у которого случайно сходится сумма СНИЛС, остаётся телефоном."""
    rng = random.Random(RANDOM_SEED)
    while True:
        tail = str(rng.randint(10**9, 10**10 - 1))
        if tail[0] in "3456789" and is_snils_checksum_valid("8" + tail):
            break
    text = f"Звоните: 8{tail}"
    assert [(d.pii_type.value, text[d.start:d.end]) for d in detector.detect(text)] == [
        ("PHONE", f"8{tail}")
    ]
