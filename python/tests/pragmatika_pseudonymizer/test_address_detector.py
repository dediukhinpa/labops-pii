"""Тип ADDRESS: детектор, токены, восстановление, выключатель (этап Г плана 152-ФЗ)."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from labops_pii.config import ConfigError, load_settings
from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer
from labops_pii.store import SqliteReplacementStore
from tests.pragmatika_pseudonymizer.conftest import found

# (текст, ожидаемый результат маскирования). Город («г. Москва,») остаётся открытым.
MASKED = [
    ("ул. Ленина, д. 5, кв. 12", "[ADDRESS_1]"),
    ("Доставка: г. Москва, ул. Ленина, д. 5, кв. 12.", "Доставка: г. Москва, [ADDRESS_1]."),
    ("Заберём на улице Ленина, д. 5", "Заберём на [ADDRESS_1]"),
    ("Везём по ул. Ленина, д. 5", "Везём по [ADDRESS_1]"),
    ("дом 5 по улице Ленина", "[ADDRESS_1]"),
    ("г. Москва, Ленина 5", "г. Москва, [ADDRESS_1]"),
    ("пр-т Мира, д. 10, корп. 2", "[ADDRESS_1]"),
    ("б-р Яна Райниса, д.2", "[ADDRESS_1]"),
    ("119019, ул. Арбат, д. 1", "[ADDRESS_1]"),
    ("119019, г. Москва, ул. Арбат, д. 1", "[ADDRESS_1], г. Москва, [ADDRESS_2]"),
    # улица по фамилии: ФИО-детектор её тоже видит, но токен должен быть один и ADDRESS
    ("ул. Ивана Франко, д. 4", "[ADDRESS_1]"),
    ("пр. Маршала Жукова, 7", "[ADDRESS_1]"),
]

# Тексты, которые адресом не являются: проверяются реальным детектором (не только шаблоном).
CLEAN = [
    "Артикул АБ-12 д.5 по ТУ",
    "Лист 10x20 мм, ГОСТ 12345-2014",
    "см. стр. 5 договора",
    "Труба d 20, д. 5 мм",
    "Светильник ул. LED 50W, 12 шт",
    "Примечание: пр. 10 штук в упаковке",
    "Итого 12000 руб, счёт 40702810400000012345",
    "Склад в г. Москва, Заказ 5.",
    "Доставка на улице Ленина возможна",
    "Партия 119019 отгружена",
]


@pytest.mark.parametrize(("text", "expected"), MASKED)
def test_address_masked(service: Pseudonymizer, text: str, expected: str) -> None:
    """Адрес заменён токеном, город не тронут, исходный текст возвращается restore."""
    masked, _ = service.pseudonymize("t", text)
    assert masked == expected
    assert service.restore("t", masked) == text


@pytest.mark.parametrize("text", CLEAN)
def test_not_address(detector: PiiDetector, text: str) -> None:
    """Артикулы, размеры, ГОСТ, количество и «ул.» в названии товара адресом не считаются."""
    assert [pair for pair in found(detector, text) if pair[0] == "ADDRESS"] == []


def test_street_named_after_person_is_not_person(detector: PiiDetector) -> None:
    """Название улицы по фамилии не порождает отдельный токен ФИО внутри адреса."""
    assert found(detector, "ул. Ленина, д. 5") == [("ADDRESS", "ул. Ленина, д. 5")]


def test_person_next_to_address_stays_person(service: Pseudonymizer) -> None:
    """Соседнее ФИО маскируется как раньше, адрес рядом - своим токеном."""
    masked, entities = service.pseudonymize(
        "t", "Иванов Пётр Сергеевич, ул. Ленина, д. 5, кв. 12"
    )
    assert masked == "[PERSON_1], [ADDRESS_1]"
    assert [e.type for e in entities] == ["PERSON", "ADDRESS"]


@pytest.mark.parametrize(
    "variant",
    [
        "ул. Ленина, д. 5, кв. 12",
        "улица Ленина дом 5 кв.12",
        "улице Ленина, д.5, квартира 12",
        "Ленина ул., 5, кв. 12",
        "дом 5, кв. 12 по улице Ленина",
    ],
)
def test_forms_of_one_address_share_token(service: Pseudonymizer, variant: str) -> None:
    """Сокращения, падеж ключевого слова и порядок слов не плодят токены одного адреса."""
    service.pseudonymize("t", "Адрес: ул. Ленина, д. 5, кв. 12")
    masked, _ = service.pseudonymize("t", variant)
    assert masked == "[ADDRESS_1]"


def test_other_house_other_token(service: Pseudonymizer) -> None:
    """Разные дома, квартиры и улицы - разные токены."""
    masked, _ = service.pseudonymize(
        "t", "ул. Ленина, д. 5; ул. Ленина, д. 6; ул. Ленина, д. 5, кв. 1; ул. Мира, д. 5"
    )
    assert masked == "[ADDRESS_1]; [ADDRESS_2]; [ADDRESS_3]; [ADDRESS_4]"


def test_adjective_street_in_other_case_shares_token(service: Pseudonymizer) -> None:
    """Прилагательное в названии улицы склоняется: ключ по лемме объединяет формы."""
    service.pseudonymize("t", "Тверская ул., д. 7")
    masked, _ = service.pseudonymize("t", "на ул. Тверской, д. 7")
    assert masked == "на [ADDRESS_1]"


def test_restore_inside_model_answer(service: Pseudonymizer) -> None:
    """Токен в ответе модели восстанавливается; падеж берётся из первого упоминания."""
    service.pseudonymize("t", "Отгрузка: на улицу Ленина, д. 5")
    # без предлога перед токеном ключевое слово встаёт в именительный падеж
    answer = "Поставщик подтвердил доставку по адресу [ADDRESS_1] на среду."
    assert service.restore("t", answer) == (
        "Поставщик подтвердил доставку по адресу улица Ленина, д. 5 на среду."
    )
    assert service.restore("t", "delivery_address: [ADDRESS_1]") == (
        "delivery_address: улица Ленина, д. 5"
    )
    # после предлога падеж первого упоминания остаётся (так же, как в исходном тексте)
    assert service.restore("t", "Отвезём на [ADDRESS_1].") == "Отвезём на улицу Ленина, д. 5."


def test_restore_is_isolated_by_thread(service: Pseudonymizer) -> None:
    """Токен адреса чужого треда не раскрывается."""
    service.pseudonymize("a", "ул. Ленина, д. 5")
    assert service.restore("b", "[ADDRESS_1]") == "[ADDRESS_1]"


def test_check_reports_address(service: Pseudonymizer) -> None:
    """/check видит адрес как тип ADDRESS."""
    assert service.check("Доставка: ул. Ленина, д. 5") == ["ADDRESS"]


def test_literal_token_in_input_is_escaped_and_restored(service: Pseudonymizer) -> None:
    """Буквальная метка [ADDRESS_1] во входе не превращается в адрес при restore."""
    masked, _ = service.pseudonymize("t", "метка [ADDRESS_1] и ул. Ленина, д. 5")
    assert service.restore("t", masked) == "метка [ADDRESS_1] и ул. Ленина, д. 5"


def test_switch_off_returns_old_behaviour(fernet_key: str) -> None:
    """mask_addresses=False: адрес не маскируется (откат), остальные типы работают."""
    off = PiiDetector(mask_addresses=False)
    service = Pseudonymizer(off, SqliteReplacementStore(":memory:", fernet_key))
    masked, _ = service.pseudonymize("t", "ул. Ленина, д. 5, тел. +7 (902) 123-45-67")
    assert "ул. Ленина, д. 5" in masked and "[PHONE_1]" in masked
    assert "ADDRESS" not in "".join(service.check("ул. Ленина, д. 5"))


def test_env_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    """PSEUDONYMIZER_ADDRESS_MASK: по умолчанию включено, off выключает, мусор - ошибка."""
    base = {
        "PSEUDONYMIZER_KEY": Fernet.generate_key().decode(),
        "PSEUDONYMIZER_API_TOKEN": "t",
    }
    assert load_settings(base).mask_addresses is True
    assert load_settings({**base, "PSEUDONYMIZER_ADDRESS_MASK": ""}).mask_addresses is True
    assert load_settings({**base, "PSEUDONYMIZER_ADDRESS_MASK": "on"}).mask_addresses is True
    for off in ("off", "false", "0", "No", " OFF "):
        assert load_settings({**base, "PSEUDONYMIZER_ADDRESS_MASK": off}).mask_addresses is False
    with pytest.raises(ConfigError):
        load_settings({**base, "PSEUDONYMIZER_ADDRESS_MASK": "of"})


@pytest.mark.parametrize(
    "text",
    [
        "Доставить на улицу Ленина, д. 5",
        "Склад на улице Ленина, д. 5, кв. 12.",
        "Выезд с улицы Ленина, д. 5",
        "Адрес: ул. Ленина, д. 5",
        "Адрес: улица Ленина, д. 5",
    ],
)
def test_round_trip_identity(service: Pseudonymizer, text: str) -> None:
    """restore(pseudonymize(x)) == x: подстановка падежа не ломает исходный текст."""
    masked, _ = service.pseudonymize("t", text)
    assert "ADDRESS" in masked
    assert service.restore("t", masked) == text


def test_street_word_to_nominative() -> None:
    """Склонение ключевого слова улицы: падежи, регистр, сокращения и чужое начало."""
    from labops_pii.inflect import address_street_word_nominative as nom

    assert nom("улицу Ленина, д. 5") == "улица Ленина, д. 5"
    assert nom("Улице Ленина, 5") == "Улица Ленина, 5"
    assert nom("проспекта Мира, 10") == "проспект Мира, 10"
    assert nom("набережную Фонтанки, 15") == "набережная Фонтанки, 15"
    assert nom("площади Революции, 2") == "площадь Революции, 2"
    # название-прилагательное согласуется, существительное и составное название - нет
    assert nom("улицу Складскую, д. 5") == "улица Складская, д. 5"
    assert nom("улице Тверской, 7") == "улица Тверская, 7"
    assert nom("проспекту Садовому 3") == "проспект Садовый 3"
    assert nom("улицы Красной Армии, д. 7") == "улица Красной Армии, д. 7"
    assert nom("улицу Ленина, д. 5") == "улица Ленина, д. 5"
    assert nom("улица Складская, д. 5") == "улица Складская, д. 5"
    assert nom("ул. Ленина, д. 5") == "ул. Ленина, д. 5"
    assert nom("дом 5 по улице Ленина") == "дом 5 по улице Ленина"
    assert nom("Ленина ул., 5") == "Ленина ул., 5"


def test_two_forms_of_one_address_restore_first_form(service: Pseudonymizer) -> None:
    """Известное ограничение: две формы одного адреса в треде возвращаются в первой форме."""
    masked, _ = service.pseudonymize("t", "пр-т Мира, д. 10; ещё к проспекту Мира, д. 10")
    assert masked == "[ADDRESS_1]; ещё к [ADDRESS_1]"
    assert service.restore("t", masked) == "пр-т Мира, д. 10; ещё к пр-т Мира, д. 10"
