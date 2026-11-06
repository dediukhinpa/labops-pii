"""Ревью-9: фамилия с инициалами, которую пропускает NER (R9-A4-12).

Natasha не видела ФИО во фразах вроде «Заказ у Петрова О.И. оформлен.», и фамилия вместе с
инициалами уходила в модель открытым текстом. Страховочное правило ловит фамилию рядом с
двумя инициалами по морфологии, без NER.
"""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector, PiiType
from labops_pii.service import Pseudonymizer
from labops_pii.tech_tokens import find_tech_spans


def _persons(detector: PiiDetector, text: str) -> list[str]:
    """Фрагменты текста, найденные как ФИО."""
    return [text[d.start:d.end] for d in detector.detect(text) if d.pii_type is PiiType.PERSON]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # До правки NER не находил здесь ничего
        ("Заказ у Петрова О.И. оформлен.", "Петрова О.И"),
        ("Заказ Петрова О.И. оформлен.", "Петрова О.И"),
        ("Заказ у Петрова О. И. оформлен.", "Петрова О. И"),
        # Фамилия, у которой главный разбор pymorphy не «фамилия»
        ("Счёт подписал Черных А.Б. вчера.", "Черных А.Б"),
        ("Счёт выставлен, ответственный — О.И. Петрова.", "О.И. Петрова"),
    ],
)
def test_surname_with_initials_is_masked_without_ner(
    detector: PiiDetector, text: str, expected: str
) -> None:
    """Фамилия и оба инициала скрыты (точку предложения может взять и находка NER)."""
    assert any(expected in chunk for chunk in _persons(detector, text))


def test_initials_do_not_glue_two_people(detector: PiiDetector) -> None:
    """«Петров А.Б. Сидоров»: инициалы уже отданы Петрову, Сидоров — отдельный человек.

    Проверяется само правило: NER на этой фразе склеивает обоих сам (так было и до правки).
    """
    text = "Согласовали Петров А.Б. Сидоров вчера."
    found = [text[d.start:d.end] for d in detector._detect_initialed_surnames(text, find_tech_spans(text))]
    assert found == ["Петров А.Б", "Сидоров"]


@pytest.mark.parametrize(
    "text",
    [
        "Согласовано О.И. и отправлено.",  # словарное слово без разбора «фамилия»
        "Шаблон подписи: Фамилия И.О.",
        "Позиция П. 3 прайса.",  # одна буква с точкой — не инициалы
    ],
)
def test_dictionary_words_near_initials_are_not_persons(
    detector: PiiDetector, text: str
) -> None:
    """Правило не превращает в ФИО словарные слова рядом с инициалами."""
    for chunk in _persons(detector, text):
        assert "Согласовано" not in chunk
        assert "Фамилия" not in chunk
        assert "Позиция" not in chunk


def test_leaking_phrase_round_trips(service: Pseudonymizer) -> None:
    """В модель не уходят ни фамилия, ни инициалы, а /restore возвращает исходный текст."""
    text = "Заказ у Петрова О.И. оформлен."
    masked, _ = service.pseudonymize("thread-r9-initials", text)
    assert "Петров" not in masked
    assert "О.И" not in masked
    assert service.restore("thread-r9-initials", masked) == text
