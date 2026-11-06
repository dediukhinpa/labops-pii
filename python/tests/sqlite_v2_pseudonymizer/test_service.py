"""Тесты сервиса: токены, падежи, стабильность, round-trip, изоляция тредов."""

from __future__ import annotations

import re

from labops_pii.service import Pseudonymizer

MANAGER_MSG = "позвони Петрову, +7 (902) 123-45-67"
SUPPLIER_LETTER = (
    "Здравствуйте, Мария Петровна!\n"
    "Просим выставить счёт на 200 мешков цемента М500. Наш закупщик Сидоров А.В., "
    "тел. 8-902-555-12-34, sidorov@buildco.ru. Оплату проведём по паспорту сделки.\n"
    "С уважением, ИП Кузнецов К.К. ИНН 500100732259"
)


def test_manager_message(service: Pseudonymizer) -> None:
    out, entities = service.pseudonymize("t1", MANAGER_MSG)
    assert out == "позвони [PERSON_1], [PHONE_1]"
    assert [(e.type, e.token) for e in entities] == [
        ("PERSON", "[PERSON_1]"),
        ("PHONE", "[PHONE_1]"),
    ]


def test_supplier_letter_round_trip(service: Pseudonymizer) -> None:
    out, entities = service.pseudonymize("t1", SUPPLIER_LETTER)
    for secret in ("Сидоров", "902", "sidorov@", "500100732259", "Кузнецов", "Мария"):
        assert secret not in out
    assert {e.type for e in entities} == {"PERSON", "PHONE", "EMAIL"}
    assert service.restore("t1", out) == SUPPLIER_LETTER


def test_case_forms_share_token(service: Pseudonymizer) -> None:
    first, _ = service.pseudonymize("t1", "Иванов Пётр прислал счёт")
    second, _ = service.pseudonymize("t1", "Передайте Иванову, что счёт оплачен")
    third, _ = service.pseudonymize("t1", "Письмо от Ивановой получено")
    assert first.startswith("[PERSON_1]")
    assert "[PERSON_1]" in second
    # «Ивановой» — женская форма: это не тот же человек, что мужчина «Иванов Пётр» (R3-ALG-14)
    assert "[PERSON_1]" not in third and "[PERSON_2]" in third


def test_known_surname_masked_even_if_ner_misses(service: Pseudonymizer) -> None:
    service.pseudonymize("t1", "Иванов Пётр прислал счёт")
    out, _ = service.pseudonymize("t1", "Иванов прислал счёт")  # NER одиночную фамилию теряет
    assert out == "[PERSON_1] прислал счёт"


def test_full_and_short_name_share_token(service: Pseudonymizer) -> None:
    a, _ = service.pseudonymize("t1", "Иван Сергеевич Кузнецов приедет завтра")
    b, _ = service.pseudonymize("t1", "Кузнецову отправлено письмо")
    assert a.startswith("[PERSON_1]")
    assert "[PERSON_1]" in b


def test_different_people_different_tokens(service: Pseudonymizer) -> None:
    out, _ = service.pseudonymize("t1", "Петров и Сидоров, а также Иван Козлов")
    assert "[PERSON_1]" in out and "[PERSON_2]" in out and "[PERSON_3]" in out


def test_phone_format_variants_share_token(service: Pseudonymizer) -> None:
    a, _ = service.pseudonymize("t1", "тел. +7 (902) 123-45-67")
    b, _ = service.pseudonymize("t1", "или 8 902 123 45 67")
    assert a.endswith("[PHONE_1]") and b.endswith("[PHONE_1]")


def test_tokens_stable_across_calls_and_thread_scoped(service: Pseudonymizer) -> None:
    a, _ = service.pseudonymize("t1", "a@x.ru")
    b, _ = service.pseudonymize("t1", "b@x.ru, a@x.ru")
    c, _ = service.pseudonymize("t2", "b@x.ru")
    assert a == "[EMAIL_1]"
    assert b == "[EMAIL_2], [EMAIL_1]"
    assert c == "[EMAIL_1]"


def test_restore_ignores_foreign_tokens(service: Pseudonymizer) -> None:
    service.pseudonymize("t1", "a@x.ru")
    service.pseudonymize("t2", "secret@y.ru")
    assert service.restore("t1", "Ответ: [EMAIL_1] и [EMAIL_7] и [PERSON_1]") == (
        "Ответ: a@x.ru и [EMAIL_7] и [PERSON_1]"
    )
    # токен t2 в треде t1 раскрыт быть не должен
    assert "secret" not in service.restore("t1", "[EMAIL_1]")


def test_ip_and_legal_entity(service: Pseudonymizer) -> None:
    text = "ООО «Ромашка» ИНН 7707083893 купило у ИП Орлов О.О. ИНН 500100732259"
    out, _ = service.pseudonymize("t1", text)
    assert out == "ООО «Ромашка» ИНН [INN_1] купило у [PERSON_1]"
    assert service.restore("t1", out) == text


def test_legal_flag_masks_org(legal_detector, store) -> None:  # noqa: ANN001
    svc = Pseudonymizer(legal_detector, store)
    out, entities = svc.pseudonymize("t1", "ООО «Ромашка», ИНН 7707083893")
    assert out == "[ORG_1], ИНН [INN_1]"
    assert {e.type for e in entities} == {"ORG", "INN"}


def test_idempotent_on_already_masked_text(service: Pseudonymizer) -> None:
    # токены выданы этим тредом ранее; метки, которых тред не выдавал, экранируются (R3-ALG-30)
    service.pseudonymize("t1", "Иванов Пётр Сергеевич, тел. +7 916 123-45-67")
    out, entities = service.pseudonymize("t1", "Позвони [PERSON_1] по [PHONE_1]")
    assert out == "Позвони [PERSON_1] по [PHONE_1]"
    assert entities == []


def test_check_lists_types(service: Pseudonymizer) -> None:
    assert service.check(SUPPLIER_LETTER) == ["EMAIL", "PERSON", "PHONE"]
    assert service.check("Цемент М500 | 420,00 | 1200 шт") == []


def test_token_format(service: Pseudonymizer) -> None:
    out, _ = service.pseudonymize("t1", "x@y.ru")
    assert re.fullmatch(r"\[[A-Z]+_\d+\]", out)


def test_ip_service_words_not_treated_as_names(service: Pseudonymizer) -> None:
    service.pseudonymize("t1", "ИП Орлов О.О. ИНН 500100732259")
    out, _ = service.pseudonymize("t1", "ИП и ИНН нужны для счёта")
    assert out == "ИП и ИНН нужны для счёта"


def test_inn_token_round_trip_in_tool_arguments(service: Pseudonymizer) -> None:
    """Токен ИНН из запроса возвращается настоящим ИНН в аргументах инструмента и в ответе."""
    text = "добавь поставщика ООО Ромашка, ИНН 7707083893"
    out, _ = service.pseudonymize("t-inn", text)
    assert out == "добавь поставщика ООО Ромашка, ИНН [INN_1]"
    assert service.restore("t-inn", '{"name":"ООО Ромашка","inn":"[INN_1]"}') == (
        '{"name":"ООО Ромашка","inn":"7707083893"}'
    )
    assert service.restore("t-inn", "Карточка: ИНН [INN_1]") == "Карточка: ИНН 7707083893"
    again, _ = service.pseudonymize("t-inn", "повтор: 7707083893")
    assert again == "повтор: [INN_1]"
    assert service.restore("t-other", "[INN_1]") == "[INN_1]"


def test_articles_10_to_12_digits_without_checksum_are_not_tokenized(
    service: Pseudonymizer,
) -> None:
    rows = [
        "Арт. 1234567890 | Болт М8 | 4,50",
        "Артикул 4510123456 | Гайка | 1 234 567,89",
        "Код 452000123456 | Шайба",
        "Штрихкод 4600000000002 | Саморез",
    ]
    for row in rows:
        out, entities = service.pseudonymize("t-art", row)
        assert out == row
        assert entities == []
