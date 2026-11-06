"""Этап 26 (R4-SEC-3): API требует Authorization: Bearer из PSEUDONYMIZER_API_TOKEN."""

from __future__ import annotations

import logging

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import labops_pii.api as api
from labops_pii.__main__ import main
from labops_pii.config import ENV_API_TOKEN, ENV_KEY, ConfigError, Settings, load_settings
from labops_pii.detector import PiiDetector
from tests.sqlite_v2_pseudonymizer.conftest import API_TOKEN, make_client

ENDPOINTS = (
    ("/pseudonymize", {"thread_id": "t", "text": "Иванов Иван"}),
    ("/restore", {"thread_id": "t", "text": "[PERSON_1]"}),
    ("/check", {"text": "x"}),
    ("/inflect_signatory", {"position": "Директор", "full_name": "Иванов Иван Иванович"}),
)


@pytest.fixture
def bare(detector: PiiDetector, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Клиент без заголовка авторизации."""
    return make_client(detector, monkeypatch, headers=None)


@pytest.mark.parametrize(("path", "payload"), ENDPOINTS)
def test_missing_header_401(bare: TestClient, path: str, payload: dict) -> None:
    resp = bare.post(path, json=payload)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert API_TOKEN not in resp.text


@pytest.mark.parametrize(("path", "payload"), ENDPOINTS)
@pytest.mark.parametrize(
    "header",
    [
        "Bearer wrong-token",
        "Bearer ",
        "Bearer",
        API_TOKEN,  # без схемы
        f"Basic {API_TOKEN}",
        f"Bearer {API_TOKEN}x",
        f"Bearer {API_TOKEN[:-1]}",
        "Bearer é".encode("latin-1"),  # не-ASCII: сравнение не должно падать 500
    ],
)
def test_wrong_header_401(bare: TestClient, path: str, payload: dict, header: str | bytes) -> None:
    resp = bare.post(path, json=payload, headers={"Authorization": header})
    assert resp.status_code == 401


def test_correct_token_passes_and_scheme_case_insensitive(bare: TestClient) -> None:
    for scheme in ("Bearer", "bearer", "BEARER"):
        resp = bare.post(
            "/check", json={"text": "x"}, headers={"Authorization": f"{scheme} {API_TOKEN}"}
        )
        assert resp.status_code == 200


def test_auth_checked_before_body_validation(bare: TestClient) -> None:
    resp = bare.post("/pseudonymize", json={"nonsense": 1})
    assert resp.status_code == 401  # не 422: без токена структуру запроса не раскрываем


def test_health_open_without_token(bare: TestClient) -> None:
    assert bare.get("/health").status_code == 200


def test_rejected_requests_do_not_take_slot(
    detector: PiiDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client(
        detector, monkeypatch, headers=None, max_concurrency=1, busy_timeout_seconds=0.05
    )
    for _ in range(5):
        assert client.post("/check", json={"text": "x"}).status_code == 401
    ok = client.post(
        "/check", json={"text": "x"}, headers={"Authorization": f"Bearer {API_TOKEN}"}
    )
    assert ok.status_code == 200


def test_failures_logged_without_token(
    bare: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        bare.post("/check", json={"text": "x"}, headers={"Authorization": "Bearer secret-guess"})
    assert "unauthorized" in caplog.text
    assert "secret-guess" not in caplog.text and API_TOKEN not in caplog.text


def test_create_app_refuses_empty_token(fernet_key: str) -> None:
    for empty in ("", "   "):
        settings = Settings(
            key=fernet_key, db_path=":memory:", api_token=empty  # type: ignore[arg-type]
        )
        with pytest.raises(ConfigError):
            api.create_app(settings)


def test_load_settings_requires_token() -> None:
    key = Fernet.generate_key().decode()
    with pytest.raises(ConfigError, match=ENV_API_TOKEN):
        load_settings({ENV_KEY: key})
    with pytest.raises(ConfigError):
        load_settings({ENV_KEY: key, ENV_API_TOKEN: "  "})
    assert load_settings({ENV_KEY: key, ENV_API_TOKEN: API_TOKEN}).api_token == API_TOKEN
    # автономные утилиты без HTTP (rekey) токен не требуют
    assert load_settings({ENV_KEY: key}, require_api_token=False).api_token == ""


def test_token_not_in_settings_repr() -> None:
    settings = Settings(key="k", api_token=API_TOKEN)
    assert API_TOKEN not in repr(settings)


def test_main_exits_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_KEY, Fernet.generate_key().decode())
    monkeypatch.delenv(ENV_API_TOKEN, raising=False)
    assert main() == 1
