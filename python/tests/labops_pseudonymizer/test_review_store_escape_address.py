"""Таблица замен, экранирование меток и адреса: дефекты ревью 25.11.2026 (вымышленные данные)."""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.service import ESCAPE_MARK, Pseudonymizer
from labops_pii.store import MemoryReplacementStore


class _BatchFailure(RuntimeError):
    """Сбой посреди пачки записей."""


def test_memory_rollback_undoes_operations_in_reverse_order() -> None:
    """Расширение освободило ключ, новый токен той же пачки его занял, затем сбой."""
    store = MemoryReplacementStore()
    store.add("t", "[PERSON_1]", "PERSON", "игорь", "Игорь")
    with pytest.raises(_BatchFailure), store.batch():
        store.widen("t", "[PERSON_1]", "PERSON", "игорь крутоголов", "Игорь Крутоголов")
        store.add("t", "[PERSON_2]", "PERSON", "игорь", "Игорь")
        raise _BatchFailure
    assert store.find_token("t", "PERSON", "игорь") == "[PERSON_1]"
    assert store.get_original("t", "[PERSON_1]") == "Игорь"
    assert store.list_keys("t", "PERSON") == [("игорь", "[PERSON_1]")]


@pytest.mark.parametrize(
    "text",
    [
        f"Ссылка [{ESCAPE_MARK}PERSON_1] и Иванов Иван",
        f"[{ESCAPE_MARK}{ESCAPE_MARK}PHONE_2|datv] и [{ESCAPE_MARK}EMAIL_3]",
    ],
)
def test_already_escaped_label_round_trips(service: Pseudonymizer, text: str) -> None:
    """Экранированная метка во входе экранируется ещё раз: модель не видит её токеном."""
    masked, _ = service.pseudonymize("e", text)
    assert f"[{ESCAPE_MARK}{ESCAPE_MARK}" in masked
    assert service.restore("e", masked) == text


@pytest.fixture(scope="module")
def address_service() -> Pseudonymizer:
    """Сервис с маскированием адресов (в наборе labops оно выключено)."""
    return Pseudonymizer(PiiDetector(mask_addresses=True), MemoryReplacementStore())


def test_street_type_distinguishes_addresses(address_service: Pseudonymizer) -> None:
    """«ул. Мира, д. 5» и «пр-т Мира, д. 5» - разные адреса, restore каждого - свой."""
    texts = ["Склад: ул. Мира, д. 5.", "Офис: пр-т Мира, д. 5.", "Шоурум: пер. Мира, д. 5."]
    masked = [address_service.pseudonymize("a1", t)[0] for t in texts]
    assert len(set(masked)) == len(texts)
    assert [address_service.restore("a1", m) for m in masked] == texts


def test_address_without_type_joins_the_single_typed_one(address_service: Pseudonymizer) -> None:
    first, _ = address_service.pseudonymize("a2", "Склад: ул. Мира, д. 5.")
    bare, _ = address_service.pseudonymize("a2", "Адрес: Мира 5.")
    assert first.removeprefix("Склад: ") == bare.removeprefix("Адрес: ")
    address_service.pseudonymize("a2", "Офис: пр-т Мира, д. 5.")
    # два адреса с типом: адрес без типа неоднозначен и получает свой токен
    third, _ = address_service.pseudonymize("a2", "по адресу: Мира 5, кв. 1")
    assert "[ADDRESS_3]" in third


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("Адрес: пр-т Мира 15к2", "пр-т Мира 15к2"),
        ("мкр. Солнечный, 5, кв. 8", "мкр. Солнечный, 5, кв. 8"),
        ("наб. реки Фонтанки, д. 90", "наб. реки Фонтанки, д. 90"),
        ("ул. Ленина, 15к2, кв. 3", "ул. Ленина, 15к2, кв. 3"),
    ],
)
def test_address_forms_found(text: str, fragment: str) -> None:
    detector = PiiDetector(mask_addresses=True)
    assert [text[d.start:d.end] for d in detector.detect(text)] == [fragment]


@pytest.mark.parametrize("text", ["Корпус 15к2 отгружен", "Модель ул. Серия 15к2"])
def test_house_with_building_is_not_address_without_street(text: str) -> None:
    assert PiiDetector(mask_addresses=True).detect(text) == []


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("Адрес: Moscow, Tverskaya st. 7", "Tverskaya st. 7"),
        ("ul. Tverskaya, 7, apt. 12", "ul. Tverskaya, 7, apt. 12"),
        ("Nevsky prospekt 28", "Nevsky prospekt 28"),
        ("Адрес: 221 Baker Street, London", "221 Baker Street"),
    ],
)
def test_latin_address_forms_found(text: str, fragment: str) -> None:
    detector = PiiDetector(mask_addresses=True)
    assert [text[d.start:d.end] for d in detector.detect(text)] == [fragment]


@pytest.mark.parametrize(
    "text",
    ["Python 3 support", "Wall Street Journal 2024", "Chapter 7 Road map", "Moscow 7"],
)
def test_latin_text_without_street_is_not_address(text: str) -> None:
    assert PiiDetector(mask_addresses=True).detect(text) == []


def test_latin_addresses_on_different_streets_do_not_share_token(
    address_service: Pseudonymizer,
) -> None:
    """Латинские слова входят в ключ: «Tverskaya st. 7» и «Lenina st. 7» - разные адреса."""
    texts = ["Склад: Tverskaya st. 7", "Офис: Lenina st. 7"]
    masked = [address_service.pseudonymize("a3", t)[0] for t in texts]
    assert masked[0] != masked[1].replace("Офис", "Склад")
    assert [address_service.restore("a3", m) for m in masked] == texts
