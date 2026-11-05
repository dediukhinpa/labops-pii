"""Режим PII_GUARD_NAMES_MODE (off / log_only / enforce) на всех маршрутах guard."""

from __future__ import annotations

import io
import json

import httpx
import pytest

from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.detector import find_pii_types, scan_body
from labops_pii.guard.litellm.jsonlog import configure_logging
from labops_pii.guard.policy import split_findings
from labops_pii.guard.names import NamesMode
from labops_pii.guard.litellm.vision_route import check_vision_request
from labops_pii.guard.litellm.webpage_route import check_webpage_request
from tests.pragmatika_guard.test_vision_route import _body as vision_body

MODE_ENV = "PII_GUARD_NAMES_MODE"
FIO = "Иванов Иван Иванович"
PHONE = "+7 916 123 45 67"


async def _stream(data: bytes):
    yield data


def _client(seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    app = create_app(
        "http://upstream", transport=httpx.MockTransport(handler), vision_enabled=True,
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


@pytest.fixture(autouse=True)
def _clean_cache() -> None:
    from labops_pii.guard.detector import _STRING_CACHE

    _STRING_CACHE.clear()


def test_default_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Без PII_GUARD_NAMES_MODE ФИО не ищутся (log_only прежнего профиля теперь в env)."""
    monkeypatch.delenv(MODE_ENV, raising=False)
    assert find_pii_types(f"Контакт {FIO}") == set()


def test_log_only_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "log_only")
    found = find_pii_types(f"Контакт {FIO}")
    assert found == {"name"}
    split = split_findings(found)
    assert not split.blocking and split.observed == {"name"}


def test_off_does_not_search(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "off")
    assert find_pii_types(f"Контакт {FIO}") == set()


def test_phone_blocks_in_every_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    for mode in NamesMode:
        monkeypatch.setenv(MODE_ENV, mode.value)
        assert split_findings(find_pii_types(f"{PHONE} {FIO}")).blocking >= {"phone"}


def test_cache_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Кэш строк не отдаёт ответ прежнего режима (длинная строка попадает в кэш)."""
    text = "Передайте документы. " * 5 + FIO
    body = json.dumps({"x": text}).encode()
    monkeypatch.setenv(MODE_ENV, "log_only")
    assert "name" in scan_body(body)
    monkeypatch.setenv(MODE_ENV, "off")
    assert "name" not in scan_body(body)


async def test_chat_log_only_forwards_and_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "log_only")
    stream = io.StringIO()
    configure_logging(stream=stream)
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"content": f"контакт {FIO}"})
    assert r.status_code == 200 and len(seen) == 1
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    observed = [x for x in records if x["event"] == "pii_guard_observed"]
    assert len(observed) == 1 and observed[0]["pii_types"] == ["name"]
    assert FIO.split()[0] not in stream.getvalue()  # значения в журнал не попадают


async def test_chat_enforce_blocks_like_phone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "enforce")
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"content": f"контакт {FIO}"})
    assert r.status_code == 422
    assert r.json()["pii_types"] == ["name"]
    assert not seen and FIO not in r.text


async def test_chat_enforce_name_and_phone_together(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "enforce")
    async with _client([]) as c:
        r = await c.post("/v1/messages", json={"content": f"{FIO} {PHONE}"})
    assert r.status_code == 422 and r.json()["pii_types"] == ["name", "phone"]


async def test_chat_log_only_still_blocks_phone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "log_only")
    async with _client([]) as c:
        r = await c.post("/v1/messages", json={"content": f"{FIO} {PHONE}"})
    assert r.status_code == 422 and r.json()["pii_types"] == ["phone"]


async def test_name_in_query_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    async with _client([]) as c:
        monkeypatch.setenv(MODE_ENV, "log_only")
        assert (await c.post(f"/v1/messages?who={FIO}", json={"x": "ok"})).status_code == 200
        monkeypatch.setenv(MODE_ENV, "enforce")
        assert (await c.post(f"/v1/messages?who={FIO}", json={"x": "ok"})).status_code == 422


async def test_vision_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    body = vision_body()
    body["messages"][0]["content"][1]["text"] = f"Что на фото? Заказчик {FIO}"
    monkeypatch.setenv(MODE_ENV, "log_only")
    async with _client([]) as c:
        assert (await c.post("/vision/v1/messages", json=body)).status_code == 200
        monkeypatch.setenv(MODE_ENV, "enforce")
        r = await c.post("/vision/v1/messages", json=body)
    assert r.status_code == 422 and r.json()["pii_types"] == ["name"]


def test_vision_verdict_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    body = vision_body()
    body["messages"][0]["content"][1]["text"] = f"Заказчик {FIO}"
    raw = json.dumps(body).encode()
    monkeypatch.setenv(MODE_ENV, "log_only")
    verdict = check_vision_request("POST", "", "", raw)
    assert verdict.reason is None and verdict.observed_types == {"name"}
    monkeypatch.setenv(MODE_ENV, "enforce")
    verdict = check_vision_request("POST", "", "", raw)
    assert verdict.reason == "pii" and verdict.pii_types == {"name"}


def test_webpage_never_blocks_names_even_in_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """Решение 28.10: на маршруте публичных страниц ПДн не причина отказа."""
    from tests.pragmatika_guard.test_webpage_route import _body as webpage_body

    monkeypatch.setenv(MODE_ENV, "enforce")
    body = json.dumps(webpage_body(f"Директор {FIO}")).encode()
    verdict = check_webpage_request("POST", "", "", body)
    assert verdict.reason is None and "name" in verdict.pii_types


def test_search_instruction_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Проверка текста fetch-запроса: ФИО блокирует только в enforce."""
    from labops_pii.guard.litellm.search_route import _fetch_text_ok

    text = f"Выпиши цены у {FIO}"
    monkeypatch.setenv(MODE_ENV, "log_only")
    assert _fetch_text_ok(text, ["example.com"], False) is True
    monkeypatch.setenv(MODE_ENV, "enforce")
    assert _fetch_text_ok(text, ["example.com"], False) is False


def test_invalid_mode_stops_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "maybe")
    with pytest.raises(ValueError, match=MODE_ENV):
        create_app("http://upstream")
