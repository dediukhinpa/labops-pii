"""ФИО не забирает слово-заголовок со следующей строки (вымышленные данные).

Дефект 1.2.0: в «Имя: Диана Арепьева\nБуллеты:» слово «Буллеты» (его нет в словаре) считалось
возможной фамилией и уходило под токен ФИО. Модель не видела имени спикера и сочиняла фамилию,
а в слайд при обратной подстановке попадало «Буллеты».
"""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer


def persons(detector: PiiDetector, text: str) -> list[str]:
    """Фрагменты, найденные как ФИО."""
    return [text[d.start:d.end] for d in detector.detect(text) if d.pii_type.value == "PERSON"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Имя: Диана Арепьева\nБуллеты:\n– 6 лет в операционке", ["Диана Арепьева"]),
        ("Спикер: Анна Белоусова\nТезисы: три пункта", ["Анна Белоусова"]),
        ("Анна Белоусова\nБуллеты\n– пункт", ["Анна Белоусова"]),
    ],
)
def test_next_line_label_is_not_part_of_name(
    detector: PiiDetector, text: str, expected: list[str]
) -> None:
    assert persons(detector, text) == expected


def test_patronymic_on_next_line_stays_in_name(detector: PiiDetector) -> None:
    assert persons(detector, "Подписал: Белоусова Анна\nСергеевна, директор") == [
        "Белоусова Анна\nСергеевна"
    ]


def test_restore_gives_name_without_next_line_word(service: Pseudonymizer) -> None:
    text = "Имя: Диана Арепьева\nБуллеты:\n– 6 лет"
    masked, _ = service.pseudonymize("t1", text)
    assert "Арепьева" not in masked
    assert "\nБуллеты:" in masked  # заголовок строки остаётся текстом, не уходит в токен
    assert service.restore("t1", masked) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Список людей по строке на каждого - каждый отдельно, а не один токен на весь список
        ("Иванов Иван\nПетров Пётр\nСидорова Анна",
         ["Иванов Иван", "Петров Пётр", "Сидорова Анна"]),
        # Вывод `uniq -c`: строка начинается с числа - новая строка, не продолжение ФИО
        ("Белоусова Анна\n      2 Смирнова Ольга", ["Белоусова Анна", "Смирнова Ольга"]),
        ("Менеджеры:\n      3 Иванов Иван\n      2 Петров Пётр", ["Иванов Иван", "Петров Пётр"]),
        ("– Белоусова Анна\n– Смирнова Ольга", ["Белоусова Анна", "Смирнова Ольга"]),
    ],
)
def test_each_line_of_a_name_list_is_its_own_name(
    detector: PiiDetector, text: str, expected: list[str]
) -> None:
    assert persons(detector, text) == expected


def test_name_split_by_line_break_stays_one_name(detector: PiiDetector) -> None:
    assert persons(detector, "Подписал Иван\nКрутоголов, директор") == ["Иван\nКрутоголов"]
