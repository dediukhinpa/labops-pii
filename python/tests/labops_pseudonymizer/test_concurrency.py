"""R3-MEM-14: параллельность сервиса ограничена, лишние запросы получают 503."""

from __future__ import annotations

import threading
import time

import pytest
from cryptography.fernet import Fernet

from labops_pii.config import (
    BUSY_TIMEOUT_SECONDS,
    CLIENT_TIMEOUT_SECONDS,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_MAX_TEXT_CHARS,
    ENV_API_TOKEN,
    ENV_KEY,
    ENV_MAX_CONCURRENCY,
    WORST_SECONDS_PER_CHAR,
    ConfigError,
    load_settings,
)
from tests.labops_pseudonymizer.conftest import API_TOKEN, make_client

HTTP_BUSY = 503


class SlowDetector:
    """Детектор, считающий одновременные вызовы."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def detect(self, text: str, known=None) -> list:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.delay)
        with self._lock:
            self.active -= 1
        return []


def test_default_and_env_setting() -> None:
    key = Fernet.generate_key().decode()
    base = {ENV_KEY: key, ENV_API_TOKEN: API_TOKEN}
    assert load_settings(base).max_concurrency == DEFAULT_MAX_CONCURRENCY
    assert load_settings({**base, ENV_MAX_CONCURRENCY: "1"}).max_concurrency == 1
    with pytest.raises(ConfigError):
        load_settings({**base, ENV_MAX_CONCURRENCY: "0"})


def test_concurrency_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    det = SlowDetector(0.05)
    client = make_client(det, monkeypatch, max_concurrency=1, busy_timeout_seconds=10.0)
    codes: list[int] = []

    def call() -> None:
        codes.append(client.post("/check", json={"text": "x"}).status_code)

    threads = [threading.Thread(target=call) for _ in range(5)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert det.max_active == 1 and codes == [200] * 5


def test_overload_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    det = SlowDetector(0.5)
    client = make_client(det, monkeypatch, max_concurrency=1, busy_timeout_seconds=0.05)
    codes: list[int] = []

    def call() -> None:
        codes.append(client.post("/check", json={"text": "x"}).status_code)

    threads = [threading.Thread(target=call) for _ in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert HTTP_BUSY in codes and 200 in codes


def test_busy_wait_plus_worst_processing_fits_client_timeout() -> None:
    """Ожидание слота и худшая обработка вместе короче таймаута клиента.

    Иначе клиент бросает запрос по таймауту и повторяет, а сервер доделывает первый.
    """
    worst_processing = DEFAULT_MAX_TEXT_CHARS * WORST_SECONDS_PER_CHAR
    assert BUSY_TIMEOUT_SECONDS + worst_processing < CLIENT_TIMEOUT_SECONDS
    assert BUSY_TIMEOUT_SECONDS <= 4.0
