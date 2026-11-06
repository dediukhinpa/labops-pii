"""Ревью-9: леммы фамилий от личных имён (R9-A4-06) и род фамилии на «-а» (R9-A4-07)."""

from __future__ import annotations

import pytest

from labops_pii.morph import keys_compatible, lemma, person_key
from labops_pii.service import Pseudonymizer

# Фамилии, у которых первый разбор pymorphy — личное имя во мн.ч. род.п. («Борис»)
SURNAMES_FROM_NAMES = (
    "Борисов", "Семенов", "Максимов", "Филиппов", "Владимиров", "Ефимов", "Гаврилов", "Абрамов",
)
# Частые мужские имена в паре «именительный / родительный»; часть из них у pymorphy имеет
# и женский разбор («Александра», «Дмитрия»), из-за чего ключ становился женским.
MALE_NAMES = (
    ("Иван", "Ивана"), ("Сергей", "Сергея"), ("Алексей", "Алексея"), ("Дмитрий", "Дмитрия"),
    ("Андрей", "Андрея"), ("Михаил", "Михаила"), ("Александр", "Александра"),
    ("Евгений", "Евгения"), ("Артём", "Артёма"), ("Олег", "Олега"), ("Николай", "Николая"),
    ("Владимир", "Владимира"), ("Павел", "Павла"), ("Юрий", "Юрия"), ("Максим", "Максима"),
    ("Никита", "Никиты"), ("Илья", "Ильи"), ("Кирилл", "Кирилла"), ("Роман", "Романа"),
    ("Виктор", "Виктора"), ("Антон", "Антона"), ("Денис", "Дениса"), ("Валерий", "Валерия"),
    ("Вячеслав", "Вячеслава"), ("Игорь", "Игоря"),
)


# --- R9-A4-06: лемма фамилии от личного имени -------------------------------------------------

@pytest.mark.parametrize("surname", SURNAMES_FROM_NAMES)
def test_surname_from_name_has_one_lemma(surname: str) -> None:
    base = surname.lower()
    forms = (surname, f"{surname}а", f"{surname}у", f"{surname}ым", f"{surname}е")
    assert {lemma(form) for form in forms} == {base}
    assert person_key(f"{surname} Олег") == person_key(f"{surname}а Олега")


@pytest.mark.parametrize("surname", SURNAMES_FROM_NAMES[:3])
def test_known_lemma_catches_surname_from_name(service: Pseudonymizer, surname: str) -> None:
    """Одинокая фамилия в косвенном падеже ловится по лемме треда и получает тот же токен."""
    thread = f"t-a406-{surname}"
    first, _ = service.pseudonymize(thread, f"Счёт подписал {surname} Олег Иванович, менеджер.")
    assert first == "Счёт подписал [PERSON_1], менеджер."
    out, _ = service.pseudonymize(thread, f"{surname}у отправил. Ок.")
    assert out == "[PERSON_1] отправил. Ок."


# --- R9-A4-07: мужчина в родительном падеже ---------------------------------------------------

@pytest.mark.parametrize(("nominative", "genitive"), MALE_NAMES)
def test_male_genitive_key_compatible_with_nominative(nominative: str, genitive: str) -> None:
    assert keys_compatible(person_key(f"Петров {nominative}"), person_key(f"Петрова {genitive}"))


def test_surname_after_preposition_is_male(service: Pseudonymizer) -> None:
    thread = "t-a407"
    service.pseudonymize(thread, "Счёт подписал Петров Олег Иванович, менеджер.")
    out, _ = service.pseudonymize(thread, "Нет ответа от Петрова.")
    assert out == "Нет ответа от [PERSON_1]."
    out, _ = service.pseudonymize(thread, "Спроси у Петрова про отгрузку")
    assert out == "Спроси у [PERSON_1] про отгрузку"


def test_female_forms_keep_gender(service: Pseudonymizer) -> None:
    """Прежнее поведение R3-ALG-14 сохраняется: без мужских признаков «-а» — женщина."""
    assert not keys_compatible(person_key("Иванов И."), person_key("Иванова И."))
    assert not keys_compatible(person_key("Петров Ю."), person_key("Петрова Юлия"))
    assert not keys_compatible(person_key("Петров В."), person_key("Петрова Валентина"))
    thread = "t-a407-f"
    service.pseudonymize(thread, "Счёт подписал Петров Олег Иванович.")
    out, _ = service.pseudonymize(thread, "Письмо от Петровой получено, подписала Петрова.")
    assert "[PERSON_1]" not in out
