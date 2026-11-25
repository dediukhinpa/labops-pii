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
