"""Ложные блокировки guard на названиях товаров: синтетические аналоги замера Прагматики.

Замер 05.11.26 на 75 752 реальных названиях БД Прагматики (сами строки в репо не кладутся):
морфология v0.6.0 добавляла 396 ложных блокировок, списки размеров давали телефон и карту,
торговая марка с инициалом - ФИО. Здесь по одному аналогу на каждую причину.
"""

from __future__ import annotations

import pytest
from labops_pii.guard import detector
from labops_pii.guard.names import NAME_TYPE

# Каждая строка блокировалась морфологией v0.6.0 (проверено); морфология убрана в 0.7.0, и
# старая переменная PII_GUARD_NAMES_MORPH=on больше ничего не включает
MORPH_PRODUCT_NAMES = (
    "Н-р тарелок «Гранд» 18 пр.",  # сокращение «Н-р» шло как инициал
    "Вода т.бут 0,5 л",  # «т.бут» - как инициал
    "Масло Иланг-иланг 10 мл",  # два «имени» без фамилии
    "Вино Марк де Шампань белое",  # имя плюс иностранные слова
    "Кофе флэт уайт 250 мл",  # строчные слова
    "Плёнка стрейч мини 20 мкм",  # строчные слова
)
SLASH_LISTS = (
    "Набор банок для сыпучих 450/750/1000 мл",  # был телефон 3-3-4
    "Кронштейн для SSD M.2 2280/2260/2242/2230",  # была карта 4-4-4-4
)
BRAND_WITH_INITIAL = "Пектин С.ПУДОВЪ яблочный /пакет/ 10г"
REAL_PII = (
    ("звони 8/916/123/45/67", "phone"),
    ("тел 916/123/45/67", "phone"),
    ("Пудов С.А. звонил вчера", NAME_TYPE),
    ("Передай Иванову Петру Сергеевичу", NAME_TYPE),
)


@pytest.fixture(autouse=True)
def _pragmatika_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LABOPS_PII_PROFILE", "pragmatika")
    monkeypatch.setenv("PII_GUARD_NAMES_MODE", "enforce")
    monkeypatch.setenv("PII_GUARD_ADDRESS_MODE", "enforce")


@pytest.mark.parametrize("text", MORPH_PRODUCT_NAMES)
def test_removed_morph_env_does_not_flag_product_names(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PII_GUARD_NAMES_MORPH", "on")
    assert NAME_TYPE not in detector.find_pii_types(text)


@pytest.mark.parametrize("text", SLASH_LISTS)
def test_size_lists_are_not_phone_or_card(text: str) -> None:
    assert not detector.find_pii_types(text) & {"phone", "card"}


def test_brand_with_glued_initial_is_not_a_name() -> None:
    assert NAME_TYPE not in detector.find_pii_types(BRAND_WITH_INITIAL)


@pytest.mark.parametrize(("text", "kind"), REAL_PII)
def test_real_pii_still_found(text: str, kind: str) -> None:
    assert kind in detector.find_pii_types(text)


ORG_INN = "7707083893"  # 10 цифр, контрольная сумма верна
PERSON_INN = "500100732259"  # 12 цифр, ИНН физлица или ИП


def test_org_inn_not_blocked_in_pragmatika() -> None:
    """pragmatika: guard_block_org_inn выкл., ИНН организации не блокируется (в т.ч. штрихкод)."""
    assert "inn" not in detector.find_pii_types(f"Поставщик ИНН {ORG_INN}")
    assert "inn" not in detector.find_pii_types(f"Макароны LA PASTA {ORG_INN} 250г")
    assert "inn" in detector.find_pii_types(f"ИП, ИНН {PERSON_INN}")


def test_org_inn_blocked_where_profile_asks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LABOPS_PII_PROFILE", "webapp_v2")
    assert "inn" in detector.find_pii_types(f"Поставщик ИНН {ORG_INN}")
