"""Полное ФИО после одиночного имени не теряет отчество и фамилию при восстановлении.

Дефект 1.1.0: в треде уже был «Игорь»; затем «Игорь Валентинович Крутоголов» получал тот же
токен, а /restore возвращал оригинал первого упоминания - «Игорь». Модель получала от
пользователя полное ФИО, а в ответе агент видел только имя.
"""

from __future__ import annotations

import pytest

from labops_pii.service import Pseudonymizer

FULL = "Игорь Валентинович Крутоголов"


def test_full_name_after_first_name_restores_in_full(service: Pseudonymizer) -> None:
    short, _ = service.pseudonymize("t1", "Менеджер Игорь согласовал заказ.")
    full, _ = service.pseudonymize("t1", f"Кандидат {FULL}, 35 лет.")
    token = short.removeprefix("Менеджер ").split(" ")[0]
    assert full == f"Кандидат {token}, 35 лет."  # тот же человек: один токен
    assert service.restore("t1", token) == FULL


def test_full_name_after_surname_restores_in_full(service: Pseudonymizer) -> None:
    short, _ = service.pseudonymize("t1", "Передайте Крутоголову, что счёт оплачен.")
    full, _ = service.pseudonymize("t1", f"Подписал {FULL}.")
    assert "[PERSON_1]" in short and "[PERSON_1]" in full
    assert service.restore("t1", "[PERSON_1]") == FULL


def test_full_name_in_oblique_case_restores_in_nominative(service: Pseudonymizer) -> None:
    service.pseudonymize("t1", "Менеджер Игорь согласовал заказ.")
    masked, _ = service.pseudonymize(
        "t1", "Позвони Игорю Валентиновичу Крутоголову.", case_labels=True
    )
    assert masked == "Позвони [PERSON_1|datv]."
    assert service.restore("t1", "[PERSON_1]") == FULL
    assert service.restore("t1", "[PERSON_1|datv]") == "Игорю Валентиновичу Крутоголову"


def test_earlier_text_with_short_token_restores_to_fuller_name(service: Pseudonymizer) -> None:
    """Токен один на человека: ответ модели со старым токеном тоже получает полное ФИО."""
    short, _ = service.pseudonymize("t1", "Менеджер Игорь согласовал заказ.")
    service.pseudonymize("t1", f"Кандидат {FULL}.")
    assert service.restore("t1", short) == f"Менеджер {FULL} согласовал заказ."


def test_other_full_name_with_same_first_name_gets_own_token(service: Pseudonymizer) -> None:
    """После расширения до полного ФИО другой Игорь с другой фамилией - другой человек."""
    service.pseudonymize("t1", "Менеджер Игорь согласовал заказ.")
    service.pseudonymize("t1", f"Кандидат {FULL}.")
    other, entities = service.pseudonymize("t1", "Кандидат Игорь Петрович Сидоров.")
    assert [e.token for e in entities] == ["[PERSON_2]"]
    assert service.restore("t1", other) == "Кандидат Игорь Петрович Сидоров."
    assert service.restore("t1", "[PERSON_1]") == FULL


def test_shorter_mention_after_full_keeps_full_name(service: Pseudonymizer) -> None:
    service.pseudonymize("t1", f"Кандидат {FULL}.")
    short, _ = service.pseudonymize("t1", "Игорь прислал резюме.")
    assert short == "[PERSON_1] прислал резюме."
    assert service.restore("t1", "[PERSON_1]") == FULL


def test_same_request_other_full_name_does_not_hijack_widened_token(
    service: Pseudonymizer,
) -> None:
    """В одном тексте: «Игорь» расширен до полного ФИО, другой Игорь остаётся другим."""
    service.pseudonymize("t1", "Менеджер Игорь согласовал заказ.")
    out, entities = service.pseudonymize(
        "t1", f"Кандидаты: {FULL} и Игорь Петрович Сидоров."
    )
    assert [e.token for e in entities] == ["[PERSON_1]", "[PERSON_2]"]
    assert service.restore("t1", out) == f"Кандидаты: {FULL} и Игорь Петрович Сидоров."


def test_widening_is_rolled_back_with_failed_request(
    service: Pseudonymizer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сбой запроса после расширения оставляет прежний оригинал: пачка откатывается целиком."""
    service.pseudonymize("t1", "Менеджер Игорь согласовал заказ.")
    store = service._store  # noqa: SLF001 - ломаем запись второго ФИО запроса

    def failing_add(*_args: str) -> None:
        raise RuntimeError("сбой записи")

    monkeypatch.setattr(store, "add", failing_add)
    with pytest.raises(RuntimeError):
        service.pseudonymize("t1", f"Кандидаты: {FULL} и Петров Пётр Сергеевич.")
    monkeypatch.undo()
    assert service.restore("t1", "[PERSON_1]") == "Игорь"
    # прежний ключ на месте: «Игорь» снова находит свой токен
    again, _ = service.pseudonymize("t1", "Игорь позвонил.")
    assert again == "[PERSON_1] позвонил."
