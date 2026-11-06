"""Адрес в сценариях агентов: поле доставки в документах, карточки поставщиков, шорт-лист.

Ядро (core) читает город из полей карточки кодом и показывает адрес сотруднику только после
`/restore`, поэтому проверяется то, что видит модель (город открыт, дом закрыт) и что
возвращается после восстановления.
"""

from __future__ import annotations

import json

from labops_pii.service import Pseudonymizer


def test_supplier_card_city_stays_for_model(service: Pseudonymizer) -> None:
    """Карточка поставщика: город виден модели, улица и дом - токен; восстановление точное."""
    card = {
        "productionCity": "Казань",
        "address": "г. Казань, ул. Складская, 5",
        "legalAddress": "г. Москва, ул. Вавилова, 19",
    }
    masked = service.pseudonymize_batch("t", list(card.values()))
    assert [text for text, _ in masked] == [
        "Казань",
        "г. Казань, [ADDRESS_1]",
        "г. Москва, [ADDRESS_2]",
    ]
    restored = [service.restore("t", text) for text, _ in masked]
    assert restored == list(card.values())


def test_shortlist_city_with_address_in_brackets(service: Pseudonymizer) -> None:
    """Строка шорт-листа «Казань (ул. Складская, 5)»: город открыт, адрес токеном."""
    masked, _ = service.pseudonymize("t", "Казань (ул. Складская, 5)")
    assert masked == "Казань ([ADDRESS_1])"
    assert service.restore("t", masked) == "Казань (ул. Складская, 5)"


def test_documents_delivery_address_roundtrip(service: Pseudonymizer) -> None:
    """Адрес доставки из слов сотрудника: модель кладёт токен в поле, поле восстанавливается."""
    masked, _ = service.pseudonymize(
        "t", "Договор поставки, доставка на улицу Складскую, д. 5, цемент 200 мешков"
    )
    assert "Складскую" not in masked and "[ADDRESS_1]" in masked
    # модель вызывает инструмент: значение поля - токен; ядро восстанавливает аргументы
    arguments = json.dumps({"delivery_variant": "delivery", "delivery_address": "[ADDRESS_1]"})
    restored = json.loads(service.restore("t", arguments))
    assert restored["delivery_address"] == "улица Складская, д. 5"


def test_price_rows_and_requisites_unchanged(service: Pseudonymizer) -> None:
    """Строки прайса, реквизиты и размеры не превращаются в адрес."""
    rows = [
        "Цемент М500 Д0 50кг мешок | 420,00 | Holcim | 1200 шт | арт. 4510123",
        "Арматура А500С d12 11.7м | 61 500,00 руб/т | ГОСТ 34028-2016",
        "Кабель ВВГнг(А)-LS 3х2,5 | 78,40 руб/м | бухта 100 м",
        "Светильник уличный ул. исп. 5 | 1 250,00 | 40 шт",
        "Доставка до склада в г. Казань, 5 рабочих дней",
        "Счёт №12345 от 01.09.2026, д. 5 мм, стр. 3 спецификации",
    ]
    for row in rows:
        masked, entities = service.pseudonymize("t", row)
        assert not [e for e in entities if e.type == "ADDRESS"], row
        assert masked == row or "ADDRESS" not in masked


def test_external_query_check_flags_restored_address(service: Pseudonymizer) -> None:
    """Ядро проверяет восстановленный запрос во внешний поиск через /check: адрес = ПДн."""
    service.pseudonymize("t", "ул. Складская, д. 5")
    restored = service.restore("t", "поставщик цемента [ADDRESS_1]")
    assert "ADDRESS" in service.check(restored, "t")
