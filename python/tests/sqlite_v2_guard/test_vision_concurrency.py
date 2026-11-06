"""Предел одновременных запросов маршрута зрения: ожидание, 429 по таймауту, освобождение."""

import asyncio
import json

import httpx
import pytest

from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.litellm.vision_route import (
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_QUEUE_TIMEOUT_SECONDS,
    VISION_ROUTE_PATH,
    VisionLimits,
)
from tests.sqlite_v2_guard.test_vision_route import _body

# Короткое ожидание очереди в тестах (секунды)
SHORT_QUEUE_SECONDS = 1
HTTP_RATE_LIMITED = 429


async def _stream(data: bytes):
    yield data


def _gated_client(
    gate: asyncio.Event, limits: VisionLimits, fail: bool = False
) -> httpx.AsyncClient:
    """Клиент к шлюзу, апстрим которого отвечает только после gate (держит слот)."""

    async def handler(_: httpx.Request) -> httpx.Response:
        await gate.wait()
        if fail:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    app = create_app(
        "http://upstream", transport=httpx.MockTransport(handler), vision_enabled=True,
        vision_limits=limits,
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


async def _post(client: httpx.AsyncClient) -> httpx.Response:
    return await client.post(VISION_ROUTE_PATH, content=json.dumps(_body()))


def test_defaults() -> None:
    limits = VisionLimits.from_env({})
    assert limits.max_concurrent == DEFAULT_MAX_CONCURRENT == 2
    assert limits.queue_timeout_seconds == DEFAULT_QUEUE_TIMEOUT_SECONDS == 20


@pytest.mark.parametrize(
    "env",
    [
        {"VISION_MAX_CONCURRENT": "0"},
        {"VISION_MAX_CONCURRENT": "99"},
        {"VISION_MAX_CONCURRENT": "two"},
        {"VISION_QUEUE_TIMEOUT_SECONDS": "0"},
        {"VISION_QUEUE_TIMEOUT_SECONDS": "-5"},
        {"VISION_QUEUE_TIMEOUT_SECONDS": "9999"},
    ],
)
def test_invalid_concurrency_env_fails_startup(env: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        VisionLimits.from_env(env)


async def test_extra_request_gets_429_after_queue_timeout() -> None:
    gate = asyncio.Event()
    limits = VisionLimits(max_concurrent=1, queue_timeout_seconds=SHORT_QUEUE_SECONDS)
    async with _gated_client(gate, limits) as c:
        first = asyncio.create_task(_post(c))
        await asyncio.sleep(0.2)
        second = await _post(c)
        assert second.status_code == HTTP_RATE_LIMITED
        assert second.headers["retry-after"]
        assert second.json()["error"]["type"] == "rate_limit_error"
        assert second.json()["code"] == "vision_busy"
        gate.set()
        assert (await first).status_code == 200


async def test_extra_request_waits_and_succeeds_when_slot_frees() -> None:
    gate = asyncio.Event()
    limits = VisionLimits(max_concurrent=1, queue_timeout_seconds=10)
    async with _gated_client(gate, limits) as c:
        first = asyncio.create_task(_post(c))
        await asyncio.sleep(0.2)
        second = asyncio.create_task(_post(c))
        await asyncio.sleep(0.2)
        assert not second.done()
        gate.set()
        assert (await first).status_code == 200
        assert (await second).status_code == 200


async def test_slot_released_after_upstream_error() -> None:
    gate = asyncio.Event()
    gate.set()
    limits = VisionLimits(max_concurrent=1, queue_timeout_seconds=SHORT_QUEUE_SECONDS)
    async with _gated_client(gate, limits, fail=True) as c:
        for _ in range(3):
            assert (await _post(c)).status_code == 502


async def test_slot_released_after_rejected_request() -> None:
    gate = asyncio.Event()
    gate.set()
    limits = VisionLimits(max_concurrent=1, queue_timeout_seconds=SHORT_QUEUE_SECONDS)
    async with _gated_client(gate, limits) as c:
        for _ in range(3):
            bad = await c.post(VISION_ROUTE_PATH, content=b"not json")
            assert bad.status_code == 403
        assert (await _post(c)).status_code == 200
