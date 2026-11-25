"""Матрица записи ФИО: форматы × контексты × фамилии, вымышленные данные (25.11.2026).

Прогон матрицы из 6 тыс. кейсов показал, что NER пропускал полное ФИО в обычных фразах
(«Позвоните Иванов Сергей Петрович завтра.», «Менеджер Петрова Анна Сергеевна, отдел»),
фамилию через дефис, капсом, строчными, после запятой, через NBSP, вне словаря
(«Пехтышева», «Головач», «Белых») и фамилию с одним инициалом. Здесь закреплено: ни одна
часть фамилии и имени не остаётся в маске, а restore возвращает текст побайтно.
"""

from __future__ import annotations

import re

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer

TOKEN_RE = re.compile(r"\[[A-Z]+_\d+(?:\|[a-z]+)?\]")

# (фамилия, имя, отчество): словарные, вне словаря, нарицательные, прилагательные, через дефис
PEOPLE = [
    ("Иванов", "Сергей", "Петрович"),
    ("Петрова", "Анна", "Сергеевна"),
    ("Ёлкин", "Пётр", "Фёдорович"),
    ("Салтыков-Щедрин", "Михаил", "Евграфович"),
    ("Шевчук", "Наталья", "Олеговна"),
    ("Пехтышева", "Юлия", "Андреевна"),
    ("Головач", "Дмитрий", "Ильич"),
    ("Белых", "Ирина", "Павловна"),
    ("Сидоренко", "Василий", "Тарасович"),
    ("Новикова-Прибой", "Мария", "Ильинична"),
]

CONTEXTS = [
    "{x}",
    "Позвоните {x} завтра.",
    "Менеджер {x}, отдел продаж",
    "Кому: {x}\nТема: счёт",
    "«{x}»",
    '{{"fio": "{x}"}}',
]


def _formats(f: str, i: str, o: str) -> list[tuple[str, list[str]]]:
    """Запись ФИО и слова, которых не должно остаться в маске."""
    return [
        (f"{f} {i} {o}", [f, i, o]),
        (f"{i} {o} {f}", [f, i, o]),
        (f"{f}, {i} {o}", [f, i, o]),
        (f"{f} {i} {o}", [f, i, o]),
        (f"{f}  {i}   {o}", [f, i, o]),
        (f"{f} {i} {o}".upper(), [f.upper(), i.upper(), o.upper()]),
        (f"{f} {i} {o}".lower(), [f.lower(), i.lower(), o.lower()]),
        (f"{f.upper()} {i[0]}.{o[0]}.", [f.upper()]),
        (f"{f} {i[0]}.{o[0]}.", [f]),
        (f"{i[0]}. {o[0]}. {f}", [f]),
    ]


CASES = [
    pytest.param(ctx.format(x=value), words, id=f"{value}|{ctx}")
    for f, i, o in PEOPLE
    for value, words in _formats(f, i, o)
    for ctx in CONTEXTS
]


@pytest.mark.parametrize(("text", "words"), CASES)
def test_full_name_masked_and_restored(
    service: Pseudonymizer, text: str, words: list[str]
) -> None:
    masked, _ = service.pseudonymize("m", text)
    left = TOKEN_RE.sub(" ", masked)
    assert [w for w in words if w in left] == [], masked
    assert service.restore("m", masked) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Позвоните Иванов Сергей завтра.", "Иванов Сергей"),
        ("Кузнецов Алексей: ок, согласовано", "Кузнецов Алексей"),
        ("Позвоните Пётр Ёлкин завтра.", "Пётр Ёлкин"),
        ("«Юлия Пехтышева»", "Юлия Пехтышева"),
        ("Позвоните Иванов С. завтра.", "Иванов С"),
        ("А. Кузнецов подписал акт.", "А. Кузнецов"),
        ("«О. Смирнова»", "О. Смирнова"),
        ("Д.И. Головач: ок", "Д.И. Головач"),
        ("САЛТЫКОВ-ЩЕДРИН М.Е.", "САЛТЫКОВ-ЩЕДРИН М.Е."),
        ("Менеджер Анна Сергеевна, отдел", "Анна Сергеевна"),
        ("Согласовать с Пехтышевой Юлией Андреевной.", "Пехтышевой Юлией Андреевной"),
    ],
)
def test_short_forms_found(detector: PiiDetector, text: str, expected: str) -> None:
    assert [text[d.start:d.end] for d in detector.detect(text)
            if d.pii_type.value == "PERSON"] == [expected]


@pytest.mark.parametrize(
    "text",
    [
        "ООО «Красная Роза Трейд»",
        "Альфа Групп Ирина",
        "Лада Веста",
        "школа имени Ивана Петрова",
        "г. Москва, П. 3",
        "В. Новгород",
        "С. Петербург",
        "Корпус Б. Строение 2",
        "Позвоните завтра, менеджер ответит.",
    ],
)
def test_not_a_person(detector: PiiDetector, text: str) -> None:
    assert [d for d in detector.detect(text) if d.pii_type.value == "PERSON"] == []
