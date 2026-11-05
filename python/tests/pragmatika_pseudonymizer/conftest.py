"""Общие фикстуры: детекторы создаются один раз (загрузка модели Natasha дорогая)."""

from __future__ import annotations

import os

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from labops_pii.api import create_app
from labops_pii.config import Settings
from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer
from labops_pii.store import SqliteReplacementStore

CONTACTS = ["Вася Рабочий", "Дядя Коля"]
# Тестовый общий секрет API (R4-SEC-3) и заголовок, который клиент обязан слать
API_TOKEN = "test-api-token-0123456789abcdef"
AUTH_HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}


def make_client(
    detector: object,
    monkeypatch: pytest.MonkeyPatch,
    store: SqliteReplacementStore | None = None,
    *,
    key: str | None = None,
    headers: dict[str, str] | None = AUTH_HEADERS,
    **overrides: object,
) -> TestClient:
    """Клиент поверх приложения: детектор подменяется (модель не грузится), хранилище в памяти.

    Args:
        detector: Детектор, который вернёт PiiDetector внутри приложения.
        monkeypatch: Фикстура для подмены PiiDetector.
        store: Хранилище; по умолчанию SQLite в памяти.
        key: Ключ Fernet; по умолчанию свежий.
        headers: Заголовки клиента; None — без авторизации.
        **overrides: Поля Settings, переопределяющие значения по умолчанию.
    """
    import labops_pii.api as api

    key = key or Fernet.generate_key().decode()
    monkeypatch.setattr(api, "PiiDetector", lambda *_a, **_k: detector)
    fields = {"key": key, "db_path": ":memory:", "api_token": API_TOKEN, **overrides}
    settings = Settings(**fields)  # type: ignore[arg-type]
    app = create_app(settings, store or SqliteReplacementStore(":memory:", key))
    return TestClient(app, headers=headers)


def found(detector: PiiDetector, text: str) -> list[tuple[str, str]]:
    """Пары (тип, фрагмент) всех находок детектора."""
    return [(d.pii_type.value, text[d.start:d.end]) for d in detector.detect(text)]


@pytest.fixture(scope="session")
def detector() -> PiiDetector:
    """Детектор по умолчанию (названия организаций не маскируются, реквизиты - всегда)."""
    return PiiDetector()


@pytest.fixture(scope="session")
def legal_detector() -> PiiDetector:
    """Детектор с включённой маскировкой названий организаций и словарём контактов."""
    return PiiDetector(mask_legal_entity_requisites=True, contacts=CONTACTS)


@pytest.fixture(scope="session")
def contacts_detector() -> PiiDetector:
    """Детектор со словарём контактов."""
    return PiiDetector(contacts=CONTACTS)


@pytest.fixture
def fernet_key() -> str:
    """Свежий ключ Fernet."""
    return Fernet.generate_key().decode()


@pytest.fixture
def store(fernet_key: str) -> SqliteReplacementStore:
    """SQLite в памяти."""
    return SqliteReplacementStore(":memory:", fernet_key)


@pytest.fixture
def service(detector: PiiDetector, store: SqliteReplacementStore) -> Pseudonymizer:
    """Сервис с детектором по умолчанию."""
    return Pseudonymizer(detector, store)


@pytest.fixture
def client(
    detector: PiiDetector, store: SqliteReplacementStore, fernet_key: str, monkeypatch
) -> TestClient:
    """HTTP-клиент поверх приложения (детектор подменяем на общий, чтобы не грузить модель)."""
    return make_client(detector, monkeypatch, store, key=fernet_key)


# Набор воспроизводит поведение исходной копии: профиль задаётся при сборе тестов, до создания
# детекторов и настроек (запускать набор отдельным процессом, см. tools/run_tests.sh)
os.environ["LABOPS_PII_PROFILE"] = "pragmatika"
