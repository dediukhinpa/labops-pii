"""Опечатка расшифровки голоса с согласованным определением - не фамилия (25.11.2026)."""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.morph import typo_noun_parses


@pytest.fixture(scope="module")
def detector() -> PiiDetector:
    return PiiDetector(False, [])


def persons(detector: PiiDetector, text: str) -> list[str]:
    return [text[d.start:d.end] for d in detector.detect(text) if d.pii_type.value == "PERSON"]


@pytest.mark.parametrize(
    "text",
    [
        "наш Крутоголов сказал",  # фамилия вне словаря: окончание фамилии
        "передай нашему Крутоголову",
        "Это вашу Иванову я видел",  # словарная фамилия
        "вашу Белоусову",
        "Позвони Садачу завтра",  # без определения правило не срабатывает
        "наш Ковальчук приедет",
    ],
)
def test_names_after_modifier_still_masked(detector: PiiDetector, text: str) -> None:
    assert persons(detector, text)


@pytest.mark.parametrize(
    "text",
    [
        "Не разбираем вашу рутину в живую, а разбираем вашу Садачу в живую.",
        "Сделай эту Пумагу до вечера",  # «бумагу»: определение - указательное местоимение
        "Назначь новую Фстречу на завтра",  # «встречу»: определение - прилагательное
        "подготовь следующую Садачу",
    ],
)
def test_typo_after_agreeing_modifier_is_not_masked(detector: PiiDetector, text: str) -> None:
    assert persons(detector, text) == []


@pytest.mark.parametrize(
    "text",
    [
        "Позвони Кадару завтра",  # созвучно «катару», но определения нет - маскируем
        "Встреча с Танакой в пятницу",
        "Передай Бьянки отчёт",
    ],
)
def test_rare_surnames_sounding_like_nouns_stay_masked(detector: PiiDetector, text: str) -> None:
    assert persons(detector, text)


@pytest.mark.parametrize(
    ("word", "expected"),
    [("Садачу", True), ("Задачу", False), ("Крутоголов", False), ("Свежинина", False),
     ("Шмидта", False), ("Гурченко", False)],
)
def test_typo_noun_parses(word: str, expected: bool) -> None:
    assert bool(typo_noun_parses(word)) is expected
