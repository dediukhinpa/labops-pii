"""Токен и предел тела проверяются до чтения тела (пункт 27 аудита производительности)."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from labops_pii.body_guard import BodyGuardMiddleware
from labops_pii.config import DEFAULT_MAX_BATCH_ITEMS, DEFAULT_MAX_TEXT_CHARS, max_body_bytes
from tests.sqlite_v2_pseudonymizer.conftest import AUTH_HEADERS, make_client

LIMIT = max_body_bytes(DEFAULT_MAX_TEXT_CHARS, DEFAULT_MAX_BATCH_ITEMS)
CHUNK = b"x" * 65_536
# Сколько кусков отдаёт «бесконечное» тело в ASGI-тестах: заведомо больше предела
ENDLESS_CHUNKS = LIMIT // len(CHUNK) * 4
SMALL_LIMIT = 100


@pytest.fixture
def client(detector: object, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_client(detector, monkeypatch)


def endless_body() -> Iterator[bytes]:
    """Тело без Content-Length (chunked), заведомо больше предела."""
    for _ in range(ENDLESS_CHUNKS):
        yield CHUNK


def test_normal_request_passes(client: TestClient) -> None:
    resp = client.post("/check", json={"text": "привет"})
    assert resp.status_code == 200


def test_text_over_char_limit_still_422(client: TestClient) -> None:
    """Предел тела не заменяет прежний 422 для слишком длинного текста."""
    resp = client.post("/check", json={"text": "я" * (DEFAULT_MAX_TEXT_CHARS + 1)})
    assert resp.status_code == 422


def test_batch_over_item_limit_still_413_with_old_detail(client: TestClient) -> None:
    texts = [""] * (DEFAULT_MAX_BATCH_ITEMS + 1)
    resp = client.post("/pseudonymize_batch", json={"thread_id": "t", "texts": texts})
    assert resp.status_code == 413
    assert "batch is too large" in resp.json()["detail"]


def test_declared_length_over_limit_is_413(client: TestClient) -> None:
    resp = client.post("/pseudonymize", content=b"x" * (LIMIT + 1))
    assert resp.status_code == 413
    assert "limit" in resp.json()["detail"]


def test_streamed_body_over_limit_is_413(client: TestClient) -> None:
    resp = client.post("/restore", content=endless_body())
    assert resp.status_code == 413


def test_wrong_token_with_huge_body_is_401(
    detector: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = make_client(detector, monkeypatch, headers={"Authorization": "Bearer wrong"})
    resp = bare.post("/pseudonymize", content=b"x" * (LIMIT + 1))
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert resp.json() == {"detail": "unauthorized"}


def test_health_is_not_guarded(detector: object, monkeypatch: pytest.MonkeyPatch) -> None:
    bare = make_client(detector, monkeypatch, headers=None)
    assert bare.get("/health").status_code == 200


async def _run(
    middleware: BodyGuardMiddleware, headers: list[tuple[bytes, bytes]], chunks: int
) -> tuple[list[dict], int]:
    """Прогоняет запрос через middleware; возвращает ответ и число прочитанных кусков тела."""
    sent: list[dict] = []
    served = 0

    async def receive() -> dict:
        nonlocal served
        served += 1
        return {"type": "http.request", "body": CHUNK, "more_body": served < chunks}

    async def send(message: dict) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/x", "headers": headers}
    await middleware(scope, receive, send)
    return sent, served


async def _reading_app(scope: dict, receive: object, send: object) -> None:
    """Приложение, читающее тело до конца (как request.json())."""
    while (await receive())["more_body"]:  # type: ignore[operator]
        pass


def _guard(authorize: object) -> BodyGuardMiddleware:
    return BodyGuardMiddleware(
        _reading_app,
        max_body_bytes=SMALL_LIMIT,
        authorize=authorize,  # type: ignore[arg-type]
        guarded_paths=("/x",),
    )


def test_unauthorized_request_does_not_read_body() -> None:
    sent, served = asyncio.run(_run(_guard(lambda _h: False), [], ENDLESS_CHUNKS))
    assert sent[0]["status"] == 401
    assert served == 0


def test_reading_stops_at_the_limit() -> None:
    sent, served = asyncio.run(_run(_guard(lambda _h: True), [], ENDLESS_CHUNKS))
    assert sent[0]["status"] == 413
    # Первый же кусок (64 КБ) больше предела в 100 байт: дальше тело не читается
    assert served == 1


def test_declared_length_rejected_without_reading() -> None:
    headers = [(b"content-length", str(SMALL_LIMIT + 1).encode())]
    sent, served = asyncio.run(_run(_guard(lambda _h: True), headers, 1))
    assert sent[0]["status"] == 413
    assert served == 0


def test_garbage_content_length_falls_back_to_counter() -> None:
    headers = [(b"content-length", b"abc")]
    sent, _ = asyncio.run(_run(_guard(lambda _h: True), headers, ENDLESS_CHUNKS))
    assert sent[0]["status"] == 413
