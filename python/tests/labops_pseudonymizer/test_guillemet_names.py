"""ФИО в кавычках без слов вокруг («ёлочки» и другие), вымышленные данные.

Дефект 1.1.1: Natasha не размечает «Белоусова Анна Сергеевна» в кавычках, если рядом нет
слова-подсказки, и ни один другой детектор это ФИО не подхватывал: оно уходило в модель, а
/check отвечал has_pii=false. Названия в кавычках («Ромашка», «Сбер Банк Онлайн») при этом
ФИО не становятся.
"""

from __future__ import annotations

import json

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer

from tests.labops_pseudonymizer.conftest import found

FULL = "Белоусова Анна Сергеевна"
OTHER = "Игорь Валентинович Крутоголов"

# (открывающая, закрывающая) кавычки: русские, немецкие, английские, прямые, одинарные «ёлочки»
QUOTE_PAIRS = [
    ("«", "»"),
    ("„", "“"),
    ("“", "”"),
    ("\"", "\""),
    ("‹", "›"),
    ("„", "”"),
]


def persons(detector: PiiDetector, text: str) -> list[str]:
    """Фрагменты, найденные как ФИО."""
    return [text[d.start:d.end] for d in detector.detect(text) if d.pii_type.value == "PERSON"]


@pytest.mark.parametrize(("left", "right"), QUOTE_PAIRS)
@pytest.mark.parametrize("name", [FULL, OTHER])
@pytest.mark.parametrize(
    "template",
    [
        "{q}",  # весь текст - только ФИО в кавычках
        "ФИО: {q}",
        "Кандидат {q}",
        "{q} в базе",
        "Встреча с {q}, Москва.",
        "Начало.\n{q}\nОпыт: 5 лет",
        "| 1 | {q} | Москва |",
        "{q}\n",
    ],
)
def test_quoted_full_name_is_found(
    detector: PiiDetector, left: str, right: str, name: str, template: str
) -> None:
    text = template.format(q=f"{left}{name}{right}")
    assert persons(detector, text) == [name]


@pytest.mark.parametrize(("left", "right"), QUOTE_PAIRS[:4])
def test_quoted_two_word_name_is_found(detector: PiiDetector, left: str, right: str) -> None:
    text = f"Автор {left}Белоусова Анна{right}, 35 лет"
    assert persons(detector, text) == ["Белоусова Анна"]


def test_oblique_case_in_guillemets(detector: PiiDetector) -> None:
    text = "Передать «Белоусовой Анне Сергеевне»"
    assert persons(detector, text) == ["Белоусовой Анне Сергеевне"]


def test_name_inside_json_string_with_escaped_quotes(detector: PiiDetector) -> None:
    body = json.dumps({"comment": f"ФИО: \"{FULL}\" принят", "n": 1}, ensure_ascii=False)
    assert persons(detector, body) == [FULL]
    body = json.dumps({"comment": f"ФИО: «{FULL}» принят"}, ensure_ascii=False)
    assert persons(detector, body) == [FULL]


def test_two_quoted_names_on_one_line(detector: PiiDetector) -> None:
    text = f"«{FULL}» и «{OTHER}»"
    assert persons(detector, text) == [FULL, OTHER]


@pytest.mark.parametrize(
    "text",
    [
        "«Ромашка»",
        "«Яндекс»",
        "«Сбер»",
        "Войти в «Яндекс Маркет»",
        "Приложение «Сбер Банк Онлайн»",
        "ООО «Красная Роза Трейд»",
        "ООО «Торговый Дом Ромашка»",
        "Фильм «Вторая Мировая Война»",
        "Программа «Мир Новых Технологий»",
        "АО «Альфа Групп Трейд»",
        "Газета «Белая Ночь»",
        "Услуга «Генеральный Директор Онлайн»",
        "Отдел «Продажи Москва Центр»",
        "Тариф «Максимум Плюс Бизнес»",
        "Город «Сергиев Посад Центр»",
        "Заголовок «Как Это Работает»",
    ],
)
def test_quoted_titles_are_not_persons(detector: PiiDetector, text: str) -> None:
    assert persons(detector, text) == []


def test_name_and_patronymic_inside_quoted_phrase_is_person(detector: PiiDetector) -> None:
    """Цитата целиком не ФИО, но «имя + отчество» внутри неё - человек (матрица 25.11.2026)."""
    assert persons(detector, "«Позвоните Анне Сергеевне завтра»") == ["Анне Сергеевне"]


def test_pseudonymize_masks_and_restores_quoted_name(service: Pseudonymizer) -> None:
    text = f"ФИО: «{FULL}»\nОпыт: 5 лет"
    masked, _ = service.pseudonymize("t1", text)
    assert "Белоусова" not in masked and "Анна" not in masked and "Сергеевна" not in masked
    assert masked.endswith("\nОпыт: 5 лет")  # слово следующей строки остаётся текстом
    assert service.restore("t1", masked) == text


def test_check_sees_quoted_name(service: Pseudonymizer) -> None:
    assert service.check(f"«{FULL}»") == ["PERSON"]
    assert service.check(f"ФИО: «{OTHER}»") == ["PERSON"]


def test_check_ignores_quoted_titles(service: Pseudonymizer) -> None:
    assert service.check("ООО «Красная Роза Трейд», приложение «Сбер Банк Онлайн»") == []


# --- попутно: слово следующей строки не уходит в токен ФИО ---------------------------------

def test_next_line_word_stays_outside_person(detector: PiiDetector) -> None:
    text = f"Резюме: {OTHER}\nОпыт: 5 лет"
    assert persons(detector, text) == [OTHER]


def test_next_line_word_stays_outside_person_after_pseudonymize(service: Pseudonymizer) -> None:
    masked, _ = service.pseudonymize("t2", f"Резюме: {OTHER}\nОпыт: 5 лет")
    assert masked == "Резюме: [PERSON_1]\nОпыт: 5 лет"


def test_name_split_over_lines_stays_whole(detector: PiiDetector) -> None:
    # перенос строки внутри ФИО (PDF, узкая колонка): отчество на следующей строке
    text = "Иванов Иван\nИванович"
    assert persons(detector, text) == [text]
