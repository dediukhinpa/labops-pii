"""Тесты HTTP API, отсутствия ПДн в ответах и логах."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from tests.sqlite_v2_pseudonymizer.conftest import make_client

LETTER = "Позвони Петрову, +7 (902) 123-45-67, почта petrov@firma.ru"


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_pseudonymize_response_has_no_originals(client: TestClient) -> None:
    resp = client.post("/pseudonymize", json={"thread_id": "t1", "text": LETTER})
    assert resp.status_code == 200
    body = resp.json()
    assert body["text"] == "Позвони [PERSON_1], [PHONE_1], почта [EMAIL_1]"
    assert body["entities"] == [
        {"type": "PERSON", "token": "[PERSON_1]"},
        {"type": "PHONE", "token": "[PHONE_1]"},
        {"type": "EMAIL", "token": "[EMAIL_1]"},
    ]
    raw = resp.text
    for secret in ("Петров", "902", "petrov@firma"):
        assert secret not in raw


def test_restore_round_trip(client: TestClient) -> None:
    masked = client.post("/pseudonymize", json={"thread_id": "t1", "text": LETTER}).json()["text"]
    restored = client.post("/restore", json={"thread_id": "t1", "text": masked}).json()["text"]
    assert restored == LETTER


def test_restore_foreign_thread_unchanged(client: TestClient) -> None:
    client.post("/pseudonymize", json={"thread_id": "t1", "text": LETTER})
    out = client.post("/restore", json={"thread_id": "t2", "text": "[PHONE_1]"}).json()["text"]
    assert out == "[PHONE_1]"


def test_check(client: TestClient) -> None:
    assert client.post("/check", json={"text": LETTER}).json() == {
        "has_pii": True,
        "types": ["EMAIL", "PERSON", "PHONE"],
    }
    assert client.post("/check", json={"text": "Цемент М500 | 420,00"}).json() == {
        "has_pii": False,
        "types": [],
    }


def test_check_does_not_store(client: TestClient) -> None:
    client.post("/check", json={"text": "a@x.ru"})
    out = client.post("/pseudonymize", json={"thread_id": "t1", "text": "b@x.ru"}).json()
    assert out["text"] == "[EMAIL_1]"


def test_validation_errors(client: TestClient) -> None:
    assert client.post("/pseudonymize", json={"text": "x"}).status_code == 422
    assert client.post("/pseudonymize", json={"thread_id": "", "text": "x"}).status_code == 422


def test_no_pii_in_logs(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        masked = client.post("/pseudonymize", json={"thread_id": "t1", "text": LETTER}).json()
        client.post("/restore", json={"thread_id": "t1", "text": masked["text"]})
        client.post("/check", json={"text": LETTER})
    logged = caplog.text
    assert "pseudonymize" in logged  # логирование реально работает
    for secret in ("Петров", "902", "123-45-67", "petrov@firma"):
        assert secret not in logged


def test_key_not_in_logs(
    fernet_key: str, caplog: pytest.LogCaptureFixture, detector, store, monkeypatch  # noqa: ANN001
) -> None:
    with caplog.at_level(logging.DEBUG):
        make_client(detector, monkeypatch, store, key=fernet_key)
    assert fernet_key not in caplog.text


def test_too_long_text_rejected_422_without_echo(
    detector, store, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Текст длиннее предела: 422 с понятным сообщением, сам текст в ответ не попадает (S-03)."""
    local = make_client(detector, monkeypatch, store, key=fernet_key, max_text_chars=50)
    secret = "Секретный текст " * 10
    for path, payload in (
        ("/pseudonymize", {"thread_id": "t", "text": secret}),
        ("/check", {"text": secret}),
    ):
        resp = local.post(path, json=payload)
        assert resp.status_code == 422
        assert "limit is 50" in resp.json()["detail"]
        assert "Секретный" not in resp.text
    ok = local.post("/check", json={"text": "x" * 50})
    assert ok.status_code == 200
