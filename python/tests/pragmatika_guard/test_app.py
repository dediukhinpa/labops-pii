"""Тесты прокси: блокировка, пропуск, поток, fail closed, отсутствие утечки в логи."""

import asyncio
import json
import logging

import httpx
import pytest

from labops_pii.guard.litellm.app import create_app

PHONE = "+7 916 123 45 67"


async def _stream_gen(data: bytes):
    yield data


def _stream(data: bytes):
    """Тело ответа как поток (как у реального транспорта)."""
    return _stream_gen(data)


def _client(handler: httpx.MockTransport, monkeypatch: pytest.MonkeyPatch | None = None):
    app = create_app("http://upstream", transport=handler)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


def _ok_transport(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=_stream(b'{"ok": true}'), headers={"x-test": "1"})

    return httpx.MockTransport(handler)


async def test_clean_request_proxied() -> None:
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        body = {"messages": [{"role": "user", "content": "Клиент [PERSON_1], заказ 5 шт"}]}
        r = await c.post("/v1/messages?beta=true", json=body, headers={"x-api-key": "k"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert r.headers["x-test"] == "1"
    assert len(seen) == 1
    assert seen[0].url.path == "/v1/messages"
    assert seen[0].url.query == b"beta=true"
    assert seen[0].headers["x-api-key"] == "k"
    assert json.loads(seen[0].content) == body


async def test_pii_blocked_without_value_and_not_forwarded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    seen: list[httpx.Request] = []
    caplog.set_level(logging.DEBUG)
    async with _client(_ok_transport(seen)) as c:
        r = await c.post("/v1/messages", json={"content": f"позвони {PHONE}"})
    assert r.status_code == 422
    assert r.json()["pii_types"] == ["phone"]
    assert "916" not in r.text
    assert seen == []
    assert "916" not in caplog.text
    assert "позвони" not in caplog.text


async def test_stream_passthrough() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        async def gen():
            yield b"event: a\n\n"
            yield b"event: b\n\n"

        return httpx.Response(
            200, content=gen(), headers={"content-type": "text/event-stream"}
        )

    async with _client(httpx.MockTransport(handler)) as c:
        r = await c.post("/v1/messages", json={"stream": True, "x": "ok"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.content == b"event: a\n\nevent: b\n\n"


async def test_upstream_error_status_passed() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=_stream(b'{"error": "limit"}'))

    async with _client(httpx.MockTransport(handler)) as c:
        r = await c.post("/v1/messages", json={"x": "ok"})
    assert r.status_code == 429


async def test_upstream_down_fail_closed() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    async with _client(httpx.MockTransport(handler)) as c:
        r = await c.post("/v1/messages", json={"x": "ok"})
    assert r.status_code == 502


async def test_scan_failure_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def boom(_: bytes, max_bytes: int) -> set[str]:
        raise RuntimeError("boom")

    monkeypatch.setattr("labops_pii.guard.litellm.app.scan_body", boom)
    async with _client(_ok_transport(seen)) as c:
        r = await c.post("/v1/messages", json={"x": "ok"})
    assert r.status_code == 503
    assert seen == []


async def test_too_large_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_BODY_BYTES", "100")
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.post("/v1/messages", content=b"x" * 500)
    assert r.status_code == 413
    assert seen == []


async def test_healthz_local() -> None:
    async with _client(_ok_transport([])) as c:
        r = await c.get("/_guard/healthz")
    assert r.json() == {"status": "ok"}


BODY_ABOVE_OLD_SCAN_LIMIT = 9 * 1024 * 1024  # прежний зашитый предел сканирования 8 МиБ


async def test_raised_body_limit_also_raises_scan_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Предел сканирования выводится из MAX_BODY_BYTES: поднятый предел тела работает."""
    monkeypatch.setenv("MAX_BODY_BYTES", str(16 * 1024 * 1024))
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        # JSON-строка нужного размера: не-JSON тела шлюз теперь отклоняет (R3-SEC-11)
        payload = b'"' + b"x" * BODY_ABOVE_OLD_SCAN_LIMIT + b'"'
        r = await c.post("/v1/messages", content=payload)
    assert r.status_code == 200
    assert len(seen) == 1 and len(seen[0].content) == len(payload)


async def test_scan_uses_configured_body_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Детектору передаётся ровно настроенный предел тела."""
    monkeypatch.setenv("MAX_BODY_BYTES", "4096")
    limits: list[int] = []

    def spy(body: bytes, max_bytes: int, require_json: bool = False) -> set[str]:
        limits.append(max_bytes)
        return set()

    monkeypatch.setattr("labops_pii.guard.litellm.app.scan_body", spy)
    async with _client(_ok_transport([])) as c:
        await c.post("/v1/messages", json={"a": "x"})
    assert limits == [4096]


async def test_detector_limit_error_is_413(monkeypatch: pytest.MonkeyPatch) -> None:
    """Отказ детектора по размеру: 413, в апстрим не уходит (fail closed, S-04)."""
    from labops_pii.guard.detector import BodyTooLargeError

    def too_large(body: bytes, max_bytes: int, require_json: bool = False) -> set[str]:
        raise BodyTooLargeError("body exceeds scan limit")

    monkeypatch.setattr("labops_pii.guard.litellm.app.scan_body", too_large)
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.post("/v1/messages", json={"a": "x" * 200})
    assert r.status_code == 413
    assert seen == []


@pytest.mark.parametrize("value", ["0", "-5", "8m", ""])
def test_invalid_body_limit_refuses_to_start(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """Противоречивая настройка не запускается: без предела проверка тела бессмысленна."""
    monkeypatch.setenv("MAX_BODY_BYTES", value)
    with pytest.raises(ValueError, match="MAX_BODY_BYTES"):
        create_app("http://upstream")


async def test_client_disconnect_cancels_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    """Клиент ушёл, пока LiteLLM думает: запрос к апстриму отменяется (R3-NET-9)."""
    monkeypatch.setattr("labops_pii.guard.litellm.app.DISCONNECT_POLL_SECONDS", 0.05)
    state = {"started": False, "cancelled": False}

    async def handler(req: httpx.Request) -> httpx.Response:
        state["started"] = True
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise
        return httpx.Response(200)

    app = create_app("http://upstream", transport=httpx.MockTransport(handler))
    body = json.dumps({"x": "ok"}).encode()
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict] = []

    async def receive() -> dict:
        if messages:
            return messages.pop(0)
        # Соединение «закрывается» после того, как апстрим начал работу.
        # is_disconnected опрашивает receive с нулевым таймаутом: ждать внутри нельзя.
        if not state["started"]:
            await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/v1/messages", "raw_path": b"/v1/messages",
        "query_string": b"", "headers": [(b"content-length", str(len(body)).encode())],
        "scheme": "http", "server": ("guard", 80), "client": ("c", 1), "http_version": "1.1",
    }
    await asyncio.wait_for(app(scope, receive, send), timeout=5)
    assert state["cancelled"] is True
    assert sent[0]["status"] == 499


# --- R3-SEC-11 / R3-SEC-15: не-JSON и сжатые тела, адрес, цикл событий ---

async def test_non_json_body_rejected() -> None:
    """Тело не JSON (форма, multipart, сырой текст) не пропускается в апстрим."""
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.post(
            "/v1/messages", content=b"prompt=hello", headers={"content-type": "text/plain"}
        )
    assert r.status_code == 415
    assert seen == []


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate", "gzip, br"])
async def test_content_encoding_rejected(encoding: str) -> None:
    """Сжатое тело прочитать нельзя, поэтому оно не уходит в апстрим."""
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.post(
            "/v1/messages", content=b'{"a": 1}', headers={"content-encoding": encoding}
        )
    assert r.status_code == 415
    assert seen == []


async def test_identity_content_encoding_allowed() -> None:
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.post("/v1/messages", json={"a": 1}, headers={"content-encoding": "identity"})
    assert r.status_code == 200


async def test_bodyless_get_still_proxied() -> None:
    """Запрос без тела (список моделей) проходит: JSON требуется только у тела."""
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.get("/v1/models")
    assert r.status_code == 200
    assert len(seen) == 1


@pytest.mark.parametrize(
    "target",
    [
        "/v1/files/%2B79161234567",  # телефон в пути, закодирован
        "/v1/messages?email=ivan%40example.ru",  # почта в строке запроса
        "/v1/files/иван@пример.рф",  # Unicode
        "/v1/messages?tel=8%20916%20123%2045%2067",
    ],
)
async def test_pii_in_address_rejected(target: str) -> None:
    """ПДн в пути и строке запроса (в том числе Unicode и %-кодирование) блокируются."""
    seen: list[httpx.Request] = []
    async with _client(_ok_transport(seen)) as c:
        r = await c.get(target)
    assert r.status_code == 422
    assert seen == []


async def test_scan_does_not_block_event_loop() -> None:
    """Проверка тяжёлого тела идёт в потоке окнами: цикл событий отвечает во время неё."""
    import time

    loop = asyncio.get_running_loop()
    worst_gap = 0.0
    stop = False

    async def heartbeat() -> None:
        nonlocal worst_gap
        last = loop.time()
        while not stop:
            await asyncio.sleep(0.01)
            now = loop.time()
            worst_gap = max(worst_gap, now - last)
            last = now

    payload = json.dumps({"content": "7 " * (3 * 1024 * 1024)}).encode()
    seen: list[httpx.Request] = []
    beat = asyncio.create_task(heartbeat())
    started = time.perf_counter()
    async with _client(_ok_transport(seen)) as c:
        r = await c.post("/v1/messages", content=payload)
    elapsed = time.perf_counter() - started
    stop = True
    await beat
    assert r.status_code == 200
    # Пока тело проверяется (секунды), цикл не простаивает дольше доли секунды
    assert elapsed > worst_gap * 3
    assert worst_gap < 0.5


# --- R5-PY-8: предел запросов в полёте и освобождение кусков тела ---

def _gate_transport(state: dict) -> httpx.MockTransport:
    """Апстрим, который считает одновременные запросы и ждёт сигнала теста."""

    async def handler(req: httpx.Request) -> httpx.Response:
        state["active"] += 1
        state["peak"] = max(state["peak"], state["active"])
        try:
            await state["release"].wait()
        finally:
            state["active"] -= 1
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    return httpx.MockTransport(handler)


async def test_inflight_limit_not_exceeded_and_overflow_gets_503() -> None:
    """Сверх предела запрос ждёт слот, а по таймауту получает 503 с понятным кодом."""
    state = {"active": 0, "peak": 0, "release": asyncio.Event()}
    limit = 2
    app = create_app(
        "http://upstream", transport=_gate_transport(state),
        max_inflight=limit, slot_wait_seconds=0.2,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        tasks = [
            asyncio.create_task(c.post("/v1/messages", json={"x": f"ok {i}"})) for i in range(5)
        ]
        await asyncio.sleep(0.6)  # лишние запросы выдержали таймаут ожидания слота
        state["release"].set()
        results = await asyncio.gather(*tasks)
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 200, 503, 503, 503]
    assert state["peak"] == limit
    busy = next(r for r in results if r.status_code == 503)
    assert busy.json()["error"]["type"] == "overloaded_error"
    assert busy.json()["code"] == "guard_busy"
    assert busy.headers["retry-after"] == "5"


async def test_waiting_request_gets_slot_when_freed() -> None:
    """Ожидающий запрос в пределах таймаута проходит, когда слот освободился."""
    state = {"active": 0, "peak": 0, "release": asyncio.Event()}
    app = create_app(
        "http://upstream", transport=_gate_transport(state),
        max_inflight=1, slot_wait_seconds=5.0,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        tasks = [asyncio.create_task(c.post("/v1/messages", json={"x": "ok"})) for _ in range(3)]
        await asyncio.sleep(0.2)
        assert state["peak"] == 1
        state["release"].set()
        results = await asyncio.gather(*tasks)
    assert [r.status_code for r in results] == [200, 200, 200]
    assert state["peak"] == 1


@pytest.mark.parametrize("scenario", ["upstream_down", "pii", "scan_failure", "too_large"])
async def test_failure_frees_slot(scenario: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Любой отказ (апстрим, ПДн, сбой проверки, размер) освобождает единственный слот."""
    mode = {"fail": True}

    def handler(req: httpx.Request) -> httpx.Response:
        if scenario == "upstream_down" and mode["fail"]:
            raise httpx.ConnectError("down")
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    if scenario == "scan_failure":
        def boom(*_: object, **__: object) -> set[str]:
            raise RuntimeError("boom")

        monkeypatch.setattr("labops_pii.guard.litellm.app.scan_body", boom)
    if scenario == "too_large":
        monkeypatch.setenv("MAX_BODY_BYTES", "100")
    app = create_app(
        "http://upstream", transport=httpx.MockTransport(handler),
        max_inflight=1, slot_wait_seconds=0.3,
    )
    bad_body = {"pii": f"тел {PHONE}"} if scenario == "pii" else {"x": "ok" * 100}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        first = await c.post("/v1/messages", json=bad_body)
        assert first.status_code in (422, 502, 503, 413)
        assert first.json()["error"]["type"] != "overloaded_error"
        # Второй запрос тоже должен получить ответ по существу, а не 503 «занято»
        for _ in range(3):
            again = await c.post("/v1/messages", json=bad_body)
            assert again.status_code == first.status_code
            assert again.json()["error"]["type"] != "overloaded_error"
        monkeypatch.undo()
        mode["fail"] = False
        ok = await c.post("/v1/messages", json={"x": "ok"})
    assert ok.status_code == 200


async def test_chunks_not_alive_while_waiting_upstream() -> None:
    """Список кусков тела не держится в памяти, пока апстрим думает (R5-PY-8)."""
    import gc

    total = 0
    alive: list[int] = []
    parts_ref: list[list[bytes]] = [[]]  # собственный список теста не считается

    async def handler(req: httpx.Request) -> httpx.Response:
        found = [
            o for o in gc.get_objects()
            if type(o) is list and o is not parts_ref[0] and len(o) > 1
            and all(type(x) is bytes for x in o)
            and sum(len(x) for x in o) == total
        ]
        alive.append(len(found))
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    # Один JSON, разрезанный на несколько ASGI-сообщений: куски копятся в списке
    payload = json.dumps({"x": "ключ " * 20000}, ensure_ascii=False).encode()
    step = len(payload) // 4 + 1
    parts = [payload[i:i + step] for i in range(0, len(payload), step)]
    assert len(parts) > 1
    total = len(payload)
    parts_ref[0] = parts

    async def stream_body():
        for part in parts:
            yield part

    app = create_app("http://upstream", transport=httpx.MockTransport(handler))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        r = await c.post(
            "/v1/messages", content=stream_body(), headers={"content-type": "application/json"}
        )
    assert r.status_code == 200
    assert alive == [0]
