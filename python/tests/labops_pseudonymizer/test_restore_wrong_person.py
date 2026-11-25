"""Restore не подставляет другого человека (ревью 25.11.2026), вымышленные данные.

Хуже утечки - подмена: модель пишет про одного человека, а пользователь видит другого или
обоих. Здесь закреплены три таких случая и граница точки после инициалов.
"""

from __future__ import annotations

import pytest

from labops_pii.morph import keys_compatible, person_key
from labops_pii.service import Pseudonymizer


def _roundtrip(service: Pseudonymizer, texts: list[str]) -> list[tuple[str, str]]:
    """Маскирует тексты подряд в одном треде; пары (маска, restore маски)."""
    out = []
    for text in texts:
        masked, _ = service.pseudonymize("w", text)
        out.append((masked, service.restore("w", masked)))
    return out


@pytest.mark.parametrize(
    ("together", "alone"),
    [
        ("Акт подписали Петров А.Б. Сидоров В.Г.", "Петров А.Б. в отпуске."),
        ("Иванов И.И. Петрову П.П. передал документы.", "Петрову П.П. перезвонить."),
        ("Присутствовали Иван Петров Анна Сидорова.", "Анна Сидорова заболела."),
    ],
)
def test_people_listed_together_get_own_tokens(
    service: Pseudonymizer, together: str, alone: str
) -> None:
    """Два человека подряд - два токена; одиночное упоминание восстанавливается одним."""
    (masked_together, back_together), (_, back_alone) = _roundtrip(service, [together, alone])
    assert "[PERSON_2]" in masked_together
    assert back_together == together
    assert back_alone == alone


def test_two_full_names_with_patronymics_in_a_row(service: Pseudonymizer) -> None:
    masked, _ = service.pseudonymize("w", "Анна Сергеевна Иванова Ольга Петровна Смирнова")
    assert masked == "[PERSON_1] [PERSON_2]"


def test_merged_key_is_never_fuzzy_matched() -> None:
    """Страховка в сопоставлении: ключ длиннее одного человека ни с кем не совместим."""
    merged = person_key("Петров А.Б. Сидоров В.Г.")
    assert not keys_compatible(merged, person_key("Петров А.Б."))
    assert keys_compatible(person_key("Алиев Рашид Мамед оглы"), person_key("Алиев Рашид"))
    assert keys_compatible(
        person_key("Бухгалтер Павлова Елена Сергеевна"), person_key("Павловой Елене")
    )


def test_alias_does_not_follow_token_widened_to_another_person(service: Pseudonymizer) -> None:
    """«Иванов И.» не превращается в «Иванов Пётр Сергеевич» после расширения токена."""
    texts = [
        "Звонил Иванов.",
        "Иванов И. перезвонит.",
        "Иванов Пётр Сергеевич подписал договор.",
        "Иванов И. перезвонит.",
    ]
    results = _roundtrip(service, texts)
    assert "Пётр" not in results[-1][1]
    assert "Пётр" not in results[1][1]
    # Полное ФИО с другим инициалом - отдельный человек
    assert results[2][0] != results[0][0].replace("Звонил ", "")


def test_feminine_accusative_surname_is_not_the_man(service: Pseudonymizer) -> None:
    """«на Иванову А.С.» (женщина) не получает токен «Иванов А.С.» (мужчина)."""
    results = _roundtrip(
        service,
        ["Иванов А.С. — менеджер.", "Иванова А.С. — бухгалтер.",
         "Пропуск выписали на Иванову А.С., она приедет"],
    )
    assert results[2][1] == "Пропуск выписали на Иванову А.С., она приедет"
    assert "[PERSON_1]" not in results[2][0]


@pytest.mark.parametrize(
    "texts",
    [
        ["Заказ у Петрова О.И. оформлен.", "Нет ответа от Петрова О.И."],
        ["Подписал Петров А.Б.", "Петров А.Б. в отпуске", "Петров А.Б.: на связи"],
        ["Петров А.Б: на связи", "Петров А.Б, перезвоните"],
    ],
)
def test_initial_dot_round_trips_in_every_mention(service: Pseudonymizer, texts: list[str]) -> None:
    """Точка после инициала - часть ФИО у всех детекторов: restore её не теряет и не добавляет."""
    for (masked, back), text in zip(_roundtrip(service, texts), texts, strict=True):
        assert back == text, masked


@pytest.mark.parametrize(
    "text",
    [
        "Петрова Александра подписала договор.",
        "Александра Петрова приехала.",
        "Петрова Александра, она бухгалтер.",
    ],
)
def test_feminine_subject_is_not_the_man(service: Pseudonymizer, text: str) -> None:
    """«Петрова Александра» + глагол женского рода - женщина, а не «Петров Александр».

    Без глагола форма остаётся неоднозначной (R9-A4-07): «Нет подписи Петрова Александра» -
    мужской родительный падеж, и это тот же человек.
    """
    (first, _), (genitive, _), (masked, back) = _roundtrip(
        service,
        ["Счёт подписал Петров Александр Иванович.", "Нет подписи Петрова Александра.", text],
    )
    assert first == "Счёт подписал [PERSON_1]."
    assert genitive == "Нет подписи [PERSON_1]."
    assert "[PERSON_1]" not in masked
    assert back == text
