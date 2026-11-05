"""Падежные метки «[PERSON_N|падеж]» в /restore: склонение ФИО, игнор у других типов."""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.service import ESCAPE_MARK, Pseudonymizer, TooManyTokensError
from labops_pii.store import ReplacementStore

THREAD = "cl"
CASES = ("nomn", "gent", "datv", "accs", "ablt", "loct")


def seeded(service: Pseudonymizer, person: str) -> Pseudonymizer:
    """Кладёт ФИО в тред как [PERSON_1], а телефон как [PHONE_1] (повторный вызов не дублирует)."""
    store = service._store
    if store.get_original(THREAD, "[PERSON_1]") is None:
        store.add(THREAD, "[PERSON_1]", "PERSON", f"k:{person}", person)
        store.add(THREAD, "[PHONE_1]", "PHONE", "k:phone", "+7 (902) 123-45-67")
    return service


def restore_case(service: Pseudonymizer, person: str, case: str) -> str:
    """Восстанавливает метку [PERSON_1|case] для ФИО person."""
    return seeded(service, person).restore(THREAD, f"[PERSON_1|{case}]")


def restore_cases(service: Pseudonymizer, person: str, cases: tuple[str, ...]) -> list[str]:
    """Результат restore одной метки для каждого падежа (ФИО кладётся один раз)."""
    return [restore_case(service, person, case) for case in cases]


@pytest.mark.parametrize(
    ("person", "expected"),
    [
        ("Иванов Пётр Сергеевич", [
            "Иванов Пётр Сергеевич", "Иванова Петра Сергеевича", "Иванову Петру Сергеевичу",
            "Иванова Петра Сергеевича", "Ивановым Петром Сергеевичем",
            "Иванове Петре Сергеевиче",
        ]),
        ("Петрова Ольга Ивановна", [
            "Петрова Ольга Ивановна", "Петровой Ольги Ивановны", "Петровой Ольге Ивановне",
            "Петрову Ольгу Ивановну", "Петровой Ольгой Ивановной", "Петровой Ольге Ивановне",
        ]),
    ],
)
def test_male_and_female_all_cases(
    service: Pseudonymizer, person: str, expected: list[str]
) -> None:
    got = restore_cases(service, person, CASES)
    assert got == expected


def test_oblique_original_is_reinflected(service: Pseudonymizer) -> None:
    assert restore_cases(service, "Петровой Ольге", ("datv", "nomn")) == [
        "Петровой Ольге", "Петрова Ольга",
    ]


def test_surname_with_initials_unchanged_initials(service: Pseudonymizer) -> None:
    assert restore_cases(service, "Сидоров А.В.", ("datv", "ablt")) == [
        "Сидорову А.В.", "Сидоровым А.В.",
    ]


def test_caps_preserved(service: Pseudonymizer) -> None:
    assert restore_case(service, "ИВАНОВ ИВАН", "datv") == "ИВАНОВУ ИВАНУ"


@pytest.mark.parametrize("person", ["Шевченко Тарас", "Дюма Александр"])
def test_indeclinable_surname_stays(service: Pseudonymizer, person: str) -> None:
    surname, name = person.split()
    assert restore_case(service, person, "datv") == f"{surname} {name}у"


def test_double_surname_each_part(service: Pseudonymizer) -> None:
    got = restore_case(service, "Соколов-Смирнов Иван", "datv")
    assert got == "Соколову-Смирнову Ивану"


def test_unparsed_word_stays(service: Pseudonymizer) -> None:
    assert restore_case(service, "Xyz Иван", "datv") == "Xyz Ивану"


def test_label_on_other_type_ignored(service: Pseudonymizer) -> None:
    seeded(service, "Иванов Пётр")
    assert service.restore(THREAD, "Звоните [PHONE_1|datv]") == "Звоните +7 (902) 123-45-67"


def test_unknown_number_left_as_is(service: Pseudonymizer) -> None:
    seeded(service, "Иванов Пётр")
    assert service.restore(THREAD, "[PERSON_7|datv]") == "[PERSON_7|datv]"


@pytest.mark.parametrize("label", ["[PERSON_1|дат]", "[PERSON_1|xyz]", "[PERSON_1|DATV]"])
def test_code_outside_set_untouched(service: Pseudonymizer, label: str) -> None:
    seeded(service, "Иванов Пётр")
    assert service.restore(THREAD, label) == label


def test_literal_label_in_input_escaped_and_restored_as_is(service: Pseudonymizer) -> None:
    text = "Модель пишет [PERSON_1|datv] и [PERSON_1]"
    masked, _ = service.pseudonymize(THREAD, text)
    assert f"[{ESCAPE_MARK}PERSON_1|datv]" in masked
    assert service.restore(THREAD, masked) == text


def test_literal_label_not_touched_even_when_token_exists(service: Pseudonymizer) -> None:
    masked, _ = service.pseudonymize(THREAD, "Иванов Пётр сказал: [PERSON_1|datv]")
    assert masked.startswith("[PERSON_1]")
    assert service.restore(THREAD, masked) == "Иванов Пётр сказал: [PERSON_1|datv]"


def test_mixed_simple_and_labelled(service: Pseudonymizer) -> None:
    seeded(service, "Петрова Ольга")
    text = "[PERSON_1] просила передать [PERSON_1|datv]: звонить [PHONE_1|datv] и [PHONE_1]"
    phone = "+7 (902) 123-45-67"
    assert service.restore(THREAD, text) == (
        f"Петрова Ольга просила передать Петровой Ольге: звонить {phone} и {phone}"
    )


def test_cases_of_one_token_count_once(detector: PiiDetector, store: ReplacementStore) -> None:
    limited = Pseudonymizer(detector, store, max_restore_tokens=1)
    seeded(limited, "Иванов Пётр")
    out = limited.restore(THREAD, "[PERSON_1] [PERSON_1|datv] [PERSON_1|ablt]")
    assert out == "Иванов Пётр Иванову Петру Ивановым Петром"
    with pytest.raises(TooManyTokensError):
        limited.restore(THREAD, "[PERSON_1|datv] [PHONE_1]")


def test_check_ignores_labels(service: Pseudonymizer) -> None:
    assert service.check("Передайте [PERSON_1|datv] и [PHONE_1|gent]") == []


@pytest.mark.parametrize(
    "original",
    ["Петрова О.И.", "Иванова", "Иванову", "ИВАНОВА А.А."],
)
def test_ambiguous_gender_surname_is_not_inflected(original: str) -> None:
    """Род по одной фамилии неоднозначен («Иванова» - и она, и его родительный): как есть."""
    from labops_pii.morph import inflect_person

    assert inflect_person(original, "datv") == original


@pytest.mark.parametrize(
    ("original", "expected"),
    [("Петров П.С.", "Петрову П.С."), ("Сидоров", "Сидорову")],
)
def test_unambiguous_surname_is_inflected(original: str, expected: str) -> None:
    """Фамилия, у которой все разборы одного рода, склоняется и без имени."""
    from labops_pii.morph import inflect_person

    assert inflect_person(original, "datv") == expected
