"""Склонение подписанта договора в родительный падеж (формула «в лице ...»)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from labops_pii.inflect import (
    inflect_person_genitive,
    inflect_position_genitive,
    signatory_genitive,
)


@pytest.mark.parametrize(
    ("full_name", "expected"),
    [
        ("Дудорова Марина Евгеньевна", "Дудоровой Марины Евгеньевны"),
        ("Дудоров Пётр Алексеевич", "Дудорова Петра Алексеевича"),
        ("Смирнова-Петрова Анна Игоревна", "Смирновой-Петровой Анны Игоревны"),
        ("Ткаченко Игорь Ильич", "Ткаченко Игоря Ильича"),
        ("Шевчук Мария Ивановна", "Шевчук Марии Ивановны"),
        ("Достоевский Фёдор Михайлович", "Достоевского Фёдора Михайловича"),
        ("Толстая Любовь Сергеевна", "Толстой Любови Сергеевны"),
        ("Марина Евгеньевна Дудорова", "Марины Евгеньевны Дудоровой"),
        ("ДУДОРОВА Марина Евгеньевна", "ДУДОРОВОЙ Марины Евгеньевны"),
    ],
)
def test_person_genitive(full_name: str, expected: str) -> None:
    assert inflect_person_genitive(full_name) == expected


@pytest.mark.parametrize(
    "full_name",
    [
        "Иванов И. И.",  # по инициалам пол не понять
        "Иванов",  # одно слово
        "[PERSON_1]",  # токен вместо ФИО
        "Иванов Иван Иванович Петров Сидор",  # слишком много слов
    ],
)
def test_person_genitive_unknown_is_none(full_name: str) -> None:
    assert inflect_person_genitive(full_name) is None


@pytest.mark.parametrize(
    ("position", "expected"),
    [
        ("Генеральный директор", "генерального директора"),
        ("Директор по продажам", "директора по продажам"),
        ("Директор филиала", "директора филиала"),
        ("Индивидуальный предприниматель", "индивидуального предпринимателя"),
        ("Управляющий", "управляющего"),
        ("Главный бухгалтер", "главного бухгалтера"),
    ],
)
def test_position_genitive(position: str, expected: str) -> None:
    assert inflect_position_genitive(position) == expected


def test_position_without_head_is_none() -> None:
    assert inflect_position_genitive("ООО") is None
    assert inflect_position_genitive("по доверенности") is None


def test_signatory_genitive() -> None:
    assert (
        signatory_genitive("Генеральный директор", "Дудорова Марина Евгеньевна")
        == "генерального директора Дудоровой Марины Евгеньевны"
    )
    assert signatory_genitive("Генеральный директор", "Иванов И. И.") is None


def test_endpoint(client: TestClient) -> None:
    resp = client.post(
        "/inflect_signatory",
        json={"position": "Генеральный директор", "full_name": "Дудорова Марина Евгеньевна"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"text": "генерального директора Дудоровой Марины Евгеньевны"}
    unknown = client.post(
        "/inflect_signatory", json={"position": "Директор", "full_name": "Иванов И. И."}
    )
    assert unknown.json() == {"text": None}


def test_endpoint_rejects_long_fields(client: TestClient) -> None:
    resp = client.post("/inflect_signatory", json={"position": "а" * 201, "full_name": "x"})
    assert resp.status_code == 422
