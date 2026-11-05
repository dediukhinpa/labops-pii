"""Падежные метки во входе /pseudonymize: `case_labels=true` у ФИО в косвенном падеже."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from labops_pii.morph import person_case
from labops_pii.service import LABEL_RE, Pseudonymizer

THREAD = "in-labels"


def mask(service: Pseudonymizer, text: str, labels: bool = True) -> str:
    """Текст после маскирования в общем треде."""
    return service.pseudonymize(THREAD, text, labels)[0]


@pytest.mark.parametrize(
    ("person", "case"),
    [
        ("Кузнецову Олегу Игоревичу", "datv"),
        ("Кузнецова Олега Игоревича", None),  # муж. родительный совпадает с винительным
        ("Кузнецовым Олегом Игоревичем", "ablt"),
        ("Кузнецовой Ольгой Игоревной", "ablt"),
        ("Кузнецову Ольгу Игоревну", "accs"),
        ("Кузнецов Олег Игоревич", None),  # именительный: метки нет
        ("Иванову", None),  # муж. дат. / жен. вин.
        ("Иванова", None),  # жен. им. / муж. род.
        ("Петрова О.И.", None),  # только фамилия + инициалы
        ("Петровой Ольге Ивановне", None),  # дат. / предл.
        ("Иванову Петру", "datv"),  # имя снимает неоднозначность фамилии
        ("ИВАНОВУ ПЕТРУ", "datv"),
        ("Олегу Игоревичу", "datv"),
        ("Шевченко Олегу", "datv"),  # несклоняемая фамилия не мешает
    ],
)
def test_person_case(person: str, case: str | None) -> None:
    assert person_case(person) == case


def test_oblique_person_gets_label(service: Pseudonymizer) -> None:
    out = mask(service, "Договор подписан с Кузнецову Олегу Игоревичу.")
    assert "[PERSON_1|datv]" in out
    assert "Кузнецов" not in out


def test_nominative_has_no_label(service: Pseudonymizer) -> None:
    assert mask(service, "Кузнецов Олег Игоревич приедет завтра") == "[PERSON_1] приедет завтра"


def test_ambiguous_form_has_no_label(service: Pseudonymizer) -> None:
    assert mask(service, "Позвони Иванову.") == "Позвони [PERSON_1]."


def test_numbering_does_not_depend_on_labels(service: Pseudonymizer) -> None:
    labelled = mask(service, "Кузнецову Олегу Игоревичу и Кузнецов Олег Игоревич")
    assert labelled == "[PERSON_1|datv] и [PERSON_1]"
    # Тот же тред без флага: та же нумерация, голые токены
    assert mask(service, "Кузнецову Олегу Игоревичу", labels=False) == "[PERSON_1]"


def test_same_numbers_as_without_flag(detector, fernet_key: str) -> None:
    from labops_pii.store import MemoryReplacementStore

    text = "Кузнецову Олегу Игоревичу, Петровой Ольге, Сидорова Ивана, +7 916 123-45-67."
    plain = Pseudonymizer(detector, MemoryReplacementStore())
    labelled = Pseudonymizer(detector, MemoryReplacementStore())
    bare, ents = plain.pseudonymize("t", text)
    out, ents_labelled = labelled.pseudonymize("t", text, True)
    assert re.sub(r"\|[a-z]{4}\]", "]", out) == bare
    assert ents_labelled == ents


def test_only_person_is_labelled(service: Pseudonymizer) -> None:
    out = mask(service, "Звони +7 (916) 123-45-67, почта a.b@mail.ru")
    assert "|" not in out


def test_labelled_text_restores_to_inflected_original(service: Pseudonymizer) -> None:
    out = mask(service, "Передай Кузнецову Олегу Игоревичу")
    assert service.restore(THREAD, out) == "Передай Кузнецову Олегу Игоревичу"


def test_literal_label_in_input_still_escaped(service: Pseudonymizer) -> None:
    out = mask(service, "вот [PERSON_1|datv] и Кузнецову Олегу Игоревичу")
    assert "[​PERSON_1|datv]" in out
    assert out.endswith("[PERSON_2|datv]") or out.endswith("[PERSON_1|datv]")
    assert service.restore(THREAD, out).startswith("вот [PERSON_1|datv] и ")


def test_check_ignores_labels_from_input(service: Pseudonymizer) -> None:
    assert service.check("Передайте [PERSON_1|datv] и [PERSON_2|ablt]") == []
    out = mask(service, "Передай Кузнецову Олегу Игоревичу")
    assert service.check(out) == []
    assert LABEL_RE.search(out)


def test_http_flag_and_entities_are_bare(client: TestClient) -> None:
    body = {"thread_id": "h", "text": "Передай Кузнецову Олегу Игоревичу", "case_labels": True}
    data = client.post("/pseudonymize", json=body).json()
    assert data["text"] == "Передай [PERSON_1|datv]"
    assert data["entities"] == [{"type": "PERSON", "token": "[PERSON_1]"}]


def test_http_batch_flag(client: TestClient) -> None:
    texts = ["Кузнецову Олегу Игоревичу", "Кузнецов Олег Игоревич"]
    base = {"thread_id": "hb", "texts": texts}
    on = client.post("/pseudonymize_batch", json={**base, "case_labels": True}).json()
    assert [i["text"] for i in on["items"]] == ["[PERSON_1|datv]", "[PERSON_1]"]
    assert all(i["entities"][0]["token"] == "[PERSON_1]" for i in on["items"])
    off = client.post("/pseudonymize_batch", json={**base, "thread_id": "hb2"}).json()
    assert [i["text"] for i in off["items"]] == ["[PERSON_1]", "[PERSON_1]"]


def test_http_false_equals_absent(client: TestClient) -> None:
    text = "Передай Кузнецову Олегу Игоревичу"
    absent = client.post("/pseudonymize", json={"thread_id": "a", "text": text}).json()
    off = client.post(
        "/pseudonymize", json={"thread_id": "b", "text": text, "case_labels": False}
    ).json()
    assert absent == off


def test_restore_and_check_unchanged(client: TestClient) -> None:
    masked = client.post(
        "/pseudonymize",
        json={"thread_id": "r", "text": "Передай Кузнецову Олегу Игоревичу", "case_labels": True},
    ).json()["text"]
    restored = client.post("/restore", json={"thread_id": "r", "text": masked}).json()
    assert restored["text"] == "Передай Кузнецову Олегу Игоревичу"
    check = client.post("/check", json={"text": masked, "thread_id": "r"}).json()
    assert check == {"has_pii": False, "types": []}
