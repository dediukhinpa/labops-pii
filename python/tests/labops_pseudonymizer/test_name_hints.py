"""Правила ФИО: латиница, значения JSON-полей по ключу, строчные имена (вымышленные данные)."""

from __future__ import annotations

import json
import time

import pytest
from labops_pii import name_hints
from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer
from labops_pii.store import MemoryReplacementStore

from tests.labops_pseudonymizer.conftest import found

THREAD = "hints-thread"


def persons(detector: PiiDetector, text: str, known: tuple[str, ...] = ()) -> list[str]:
    """Фрагменты, найденные как ФИО."""
    return [
        text[d.start:d.end] for d in detector.detect(text, known) if d.pii_type.value == "PERSON"
    ]


# --- латиница ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Ivanov Ivan Petrovich, Moscow", ["Ivanov Ivan Petrovich"]),
        ("Resume of Sergey Kuznetsov, developer", ["Sergey Kuznetsov"]),
        ("Candidate Elena Sidorova works at a bank", ["Elena Sidorova"]),
        ("Sidorova Anna, Kotsiuba Ivan", ["Sidorova Anna", "Kotsiuba Ivan"]),
        ("IVANOV IVAN PETROVICH", ["IVANOV IVAN PETROVICH"]),
        ("Yulia Smirnova (Julia) and Dmitry Orlov", ["Yulia Smirnova", "Dmitry Orlov"]),
        ("Senior Developer Maria Ivanova", ["Maria Ivanova"]),
        ("Smith John", ["Smith John"]),
        ("Pyotr Ivanovich Kotsiuba", ["Pyotr Ivanovich Kotsiuba"]),
        ("Ekaterina Petrova and Yekaterina Petrova", ["Ekaterina Petrova", "Yekaterina Petrova"]),
    ],
)
def test_latin_names_found(detector: PiiDetector, text: str, expected: list[str]) -> None:
    assert persons(detector, text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Visual Studio Code and Open Source Software",
        "Product Manager Anna Developer",
        "Dear Anna",
        "Hello Anna, please call back",
        "Maria Python Developer",
        "Yesterday Anna went home",
        "Google Cloud Platform, Amazon Web Services, Docker Compose",
        "New York, Data Science, Machine Learning, Project Manager",
        "/home/ivan/Petrov Ivan/file.txt",
        "https://github.com/Ivan/Petrov",
        "user@example.com Ivan_Petrov Ivan.Petrov JohnSmith",
        "Alexa Skill Kit",
    ],
)
def test_latin_not_names(detector: PiiDetector, text: str) -> None:
    assert persons(detector, text) == []


def test_latin_name_repeat_masks_lone_surname(detector: PiiDetector) -> None:
    text = "Candidate Elena Sidorova. Later: Sidorova called, Elena agreed."
    assert persons(detector, text) == ["Elena Sidorova", "Sidorova", "Elena"]


def test_translit_variants_cover_spellings() -> None:
    variants = name_hints.LATIN_FIRST_NAMES
    for spelling in ("aleksandr", "alexander", "sergey", "sergei", "yuliya", "yulia", "evgeniy",
                     "evgeny", "dmitriy", "dmitry", "ekaterina", "anastasiya", "kseniya",
                     "mikhail", "vasiliy", "natalya", "pyotr", "john", "elena"):
        assert spelling in variants, spelling
    # неоднозначные английские слова в словарь не входят
    for word in ("will", "bill", "rose", "mark", "grace", "may", "jack", "max"):
        assert word not in variants, word


def test_latin_via_service_leaves_nothing_for_check(detector: PiiDetector) -> None:
    service = Pseudonymizer(detector, MemoryReplacementStore())
    text = "Candidate Elena Sidorova (Sidorova Anna), +7 902 123-45-67"
    masked, _ = service.pseudonymize(THREAD, text)
    assert "Sidorova" not in masked and "Elena" not in masked
    assert service.check(masked) == []
    assert service.restore(THREAD, masked) == text


# --- значения JSON-полей -------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"name": "Иванов Иван Иванович", "age": 30}', ["Иванов Иван Иванович"]),
        ('{"full_name": "Ivan Petrov"}', ["Ivan Petrov"]),
        ('{"first_name": "Иван", "last_name": "Петров"}', ["Иван", "Петров"]),
        ('{"fullName": "Сидорова Анна", "middleName": "Петровна"}', ["Сидорова Анна", "Петровна"]),
        ('{\\"contact_name\\": \\"Peter Gray\\"}', ["Peter Gray"]),
        ('{"ФИО": "Смирнов Пётр Андреевич", "имя": "Ольга"}', ["Смирнов Пётр Андреевич", "Ольга"]),
        ('{"author": "Kuznetsov A.", "contact": "Анна"}', ["Kuznetsov A.", "Анна"]),
        ("{'surname': 'Фролов'}", ["Фролов"]),
        ('{"name_ru": "Фролов Пётр"}', ["Фролов Пётр"]),
    ],
)
def test_json_field_values_are_persons(
    detector: PiiDetector, text: str, expected: list[str]
) -> None:
    assert persons(detector, text) == expected


@pytest.mark.parametrize(
    "text",
    [
        '{"name": "Python"}',
        '{"name": "hh_text_cache", "title": "Менеджер"}',
        '{"name": "12345", "candidate": "https://hh.example/resume/1", "fio": ""}',
        '{"contact": "user@example.com", "author": "a@b.c"}',
        '{"name": "Read", "description": "Иванов Иван"}',
        '{"title": "Анна", "value": "Иван Петров"}',
        '{"name": "Docker Compose"}',
        '{"name": "Senior Developer"}',
    ],
)
def test_json_field_values_not_persons(detector: PiiDetector, text: str) -> None:
    assert [p for p in persons(detector, text) if p not in ("Иван Петров", "Иванов Иван")] == []


def test_json_field_masked_value_keeps_json_valid(detector: PiiDetector) -> None:
    service = Pseudonymizer(detector, MemoryReplacementStore())
    raw = {"first_name": "Иван", "name": "Сидорова Анна", "age": 30, "tags": ["a", "b"]}
    masked, _ = service.pseudonymize(THREAD, json.dumps(raw, ensure_ascii=False))
    data = json.loads(masked)
    assert data["age"] == 30 and data["tags"] == ["a", "b"]
    assert data["first_name"].startswith("[PERSON_")
    assert data["name"].startswith("[PERSON_")
    assert "Иван" not in masked and "Сидорова" not in masked
    assert service.check(masked) == []


def test_json_field_key_normalization() -> None:
    assert name_hints.normalize_field_key("fullName") == "fullname"
    assert name_hints.normalize_field_key("Full-Name") == "fullname"
    assert name_hints.normalize_field_key("FIO_ru") == "fio"
    assert name_hints.normalize_field_key("nameEn") == "name"
    assert name_hints.normalize_field_key("filename") == "filename"


# --- строчные имена ------------------------------------------------------------------------

def test_lowercase_known_surname_in_thread(detector: PiiDetector) -> None:
    assert persons(detector, "найди сидоров по базе", ("сидоров",)) == ["сидоров"]
    assert persons(detector, "найди сидорова", ("сидоров",)) == ["сидорова"]


def test_lowercase_common_word_with_known_name_is_text(detector: PiiDetector) -> None:
    assert persons(detector, "надежда умирает последней", ("надежда",)) == []
    assert persons(detector, "Надежда пришла", ("надежда",)) == ["Надежда"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("петров Пётр", ["петров Пётр"]),
        ("Иван иванов работает", ["Иван иванов"]),
        ("позвони Пётр петрович", ["Пётр петрович"]),
    ],
)
def test_mixed_case_name_groups(detector: PiiDetector, text: str, expected: list[str]) -> None:
    assert persons(detector, text) == expected


def test_mixed_case_needs_full_name(detector: PiiDetector) -> None:
    # пара «имя + имя» не группа ФИО: строчное «иван» не склеивается с «Анна»
    assert persons(detector, "иван Анна") == ["Анна"]


# --- производительность на враждебных телах -----------------------------------------------

def _elapsed(func, text: str) -> float:  # type: ignore[no-untyped-def]
    started = time.perf_counter()
    func(text)
    return time.perf_counter() - started


@pytest.mark.parametrize(
    "make",
    [
        lambda n: "Ivan " * n,
        lambda n: "Aaa " * n,
        lambda n: "Senior Developer " * n,
        lambda n: "A" * n,
        lambda n: '"name": "' * n,
        lambda n: '{"fio": "' + "а " * n + '"}',
        lambda n: '\\"' * n,
        lambda n: ('{"name": "Иванов Иван", "k": 1}, ' * n),
        lambda n: "[" * n,
    ],
)
def test_name_hints_are_linear_on_hostile_bodies(make) -> None:  # type: ignore[no-untyped-def]
    def run(text: str) -> None:
        name_hints.find_latin_name_spans(text)
        name_hints.find_json_field_names(text)

    run(make(1000))  # прогрев
    small = _elapsed(run, make(15_000))
    large = _elapsed(run, make(60_000))
    # 4x по длине: линейный рост даёт около 4x, квадратичный - около 16x
    assert large < max(small * 9, 0.5)
    assert large < 5.0


def test_detector_on_70k_hostile_text_is_fast(detector: PiiDetector) -> None:
    text = ("Ivan Petrovich Sidorov " * 3000)[:70_000]
    started = time.perf_counter()
    detector.detect(text)
    assert time.perf_counter() - started < 20.0


def test_found_helper_still_reports_types(detector: PiiDetector) -> None:
    assert ("PERSON", "Elena Sidorova") in found(detector, "Elena Sidorova, +7 902 123-45-67")
