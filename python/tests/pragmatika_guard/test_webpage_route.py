"""Тесты маршрута страниц сайтов: ФИО/телефон/почта проходят, ИНН/СНИЛС/карта и форма - нет."""

import json
import logging
from typing import Any

import httpx
import pytest

from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.detector import find_pii_types
from labops_pii.guard.litellm.webpage_route import (
    WEBPAGE_MAX_BODY_BYTES,
    WEBPAGE_ROUTE_PATH,
    check_webpage_request,
    is_webpage_namespace,
    parse_webpage_models,
)

INSTRUCTION = "Достань город и контакты поставщика из текста страницы."
CONTACTS = "Директор Иванов Пётр Сергеевич, тел. +7 (495) 123-45-67, sales@example.ru"
INN_TEXT = "реквизиты: ИНН 500100732259"
SNILS_TEXT = "СНИЛС 112-233-445 95"
CARD_TEXT = "оплата на карту 4111 1111 1111 1111"


def _body(text: str = CONTACTS, **over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "model": "agent-main",
        "max_tokens": 400,
        "system": INSTRUCTION,
        "messages": [{"role": "user", "content": f"Страница:\n{text}"}],
    }
    data.update(over)
    return data


async def _stream(data: bytes):
    yield data


def _client(
    seen: list[httpx.Request], enabled: bool = True
) -> httpx.AsyncClient:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    app = create_app(
        "http://upstream", transport=httpx.MockTransport(handler), webpage_enabled=enabled
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


def test_fixtures_are_really_detected_on_main_route() -> None:
    """Страховка тестов: фикстуры - действительно находки детектора, а не пустой текст."""
    assert {"phone", "email"} <= find_pii_types(CONTACTS)
    assert "inn" in find_pii_types(INN_TEXT)
    assert "snils" in find_pii_types(SNILS_TEXT)
    assert "card" in find_pii_types(CARD_TEXT)


async def test_person_phone_email_pass_and_forwarded() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(
            WEBPAGE_ROUTE_PATH, json=_body(),
            headers={"x-api-key": "k", "anthropic-version": "1", "anthropic-beta": "x"},
        )
    assert r.status_code == 200
    assert len(seen) == 1
    assert seen[0].url.path == "/v1/messages"
    assert "anthropic-beta" not in seen[0].headers
    assert json.loads(seen[0].content) == _body()


@pytest.mark.parametrize("text", [INN_TEXT, SNILS_TEXT, CARD_TEXT])
async def test_any_pii_type_passes(text: str) -> None:
    """Решение владельца 28.10: на маршруте публичных страниц ПДн не причина отказа."""
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(WEBPAGE_ROUTE_PATH, json=_body(f"{CONTACTS}\n{text}"))
    assert r.status_code == 200
    assert len(seen) == 1


async def test_pii_in_system_passes() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(WEBPAGE_ROUTE_PATH, json=_body(system=INN_TEXT))
    assert r.status_code == 200
    assert len(seen) == 1


def test_verdict_lists_found_types_for_log() -> None:
    verdict = check_webpage_request(
        "POST", "", "", json.dumps(_body(f"{CONTACTS}\n{INN_TEXT}")).encode()
    )
    assert verdict.reason is None
    assert {"phone", "email", "inn"} <= verdict.pii_types


@pytest.mark.parametrize(
    "over",
    [
        {"tools": []},
        {"tools": [{"name": "web_search"}]},
        {"tool_choice": {"type": "auto"}},
        {"stream": True},
        {"model": "claude-opus"},
        {"model": None},
        {"metadata": {"a": 1}},
        {"max_tokens": 10**6},
        {"messages": []},
        {"messages": [{"role": "assistant", "content": "x"}]},
        {"messages": [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]},
        {"messages": [{"role": "user", "content": [{"type": "image", "source": {}}]}]},
        {"system": [{"type": "text", "text": "x", "cache_control": {}}]},
        {"system": [{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "a": 1}}]},
        {"system": [{"type": "text", "text": "x", "cache_control": "ephemeral"}]},
    ],
)
async def test_bad_form_rejected_403(over: dict[str, Any]) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(WEBPAGE_ROUTE_PATH, json=_body(**over))
    assert r.status_code == 403
    assert r.json()["code"] == "webpage_route_form"
    assert seen == []


async def test_ephemeral_cache_control_passes() -> None:
    """Тело в том виде, как его шлёт ядро: блоки system и сообщения с меткой кэша промпта."""
    mark = {"type": "ephemeral"}
    data = _body(
        system=[{"type": "text", "text": INSTRUCTION, "cache_control": mark}],
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": f"Страница:\n{CONTACTS}", "cache_control": mark}
                ],
            }
        ],
    )
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(WEBPAGE_ROUTE_PATH, json=data)
    assert r.status_code == 200
    assert len(seen) == 1


async def test_method_query_encoding_and_garbage_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        assert (await c.get(WEBPAGE_ROUTE_PATH)).status_code == 403
        assert (await c.post(WEBPAGE_ROUTE_PATH + "?a=1", json=_body())).status_code == 403
        gz = await c.post(
            WEBPAGE_ROUTE_PATH, content=b"{}", headers={"content-encoding": "gzip"}
        )
        assert gz.status_code == 403
        assert (await c.post(WEBPAGE_ROUTE_PATH, content=b"not json")).status_code == 403
        assert (await c.post(WEBPAGE_ROUTE_PATH, content=b"[1]")).status_code == 403
    assert seen == []


async def test_oversize_body_rejected() -> None:
    seen: list[httpx.Request] = []
    big = _body("а" * WEBPAGE_MAX_BODY_BYTES)
    async with _client(seen) as c:
        r = await c.post(WEBPAGE_ROUTE_PATH, json=big)
    assert r.status_code == 403
    assert seen == []


async def test_disabled_flag_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEBPAGE_ROUTE_ENABLED", raising=False)
    seen: list[httpx.Request] = []
    app = create_app(
        "http://upstream",
        transport=httpx.MockTransport(
            lambda req: seen.append(req) or httpx.Response(200, content=_stream(b"{}"))
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        assert (await c.post(WEBPAGE_ROUTE_PATH, json=_body())).status_code == 404
        assert (await c.post("/webpage/other", json=_body())).status_code == 403
    assert seen == []


async def test_env_flag_enables_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBPAGE_ROUTE_ENABLED", "1")
    seen: list[httpx.Request] = []
    app = create_app(
        "http://upstream",
        transport=httpx.MockTransport(
            lambda req: seen.append(req) or httpx.Response(200, content=_stream(b"{}"))
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        assert (await c.post(WEBPAGE_ROUTE_PATH, json=_body())).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/webpage/",
        "/webpage/v1/other",
        "/WEBPAGE/v1/messages",
        "/webpage//v1/messages",
        "/webpage/v1/%2e/messages",
        "/%77ebpage/v1/messages",
        "/webpage%2Fv1/messages",
        "/%252fwebpage/v1/messages",
    ],
)
async def test_path_bypass_forbidden_before_body(path: str) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(path, json=_body())
    assert r.status_code == 403
    assert seen == []


def test_namespace_helper() -> None:
    assert is_webpage_namespace("/webpage/v1/messages")
    assert is_webpage_namespace("//WEBPAGE/x")
    assert not is_webpage_namespace("/v1/messages")
    assert not is_webpage_namespace("/v1/webpage/x")


def test_default_model_is_agent_main() -> None:
    assert parse_webpage_models(None) == frozenset({"agent-main"})
    assert parse_webpage_models("a, b") == frozenset({"a", "b"})
    assert check_webpage_request(
        "POST", "", "", json.dumps(_body(model="a")).encode(), parse_webpage_models("a")
    ).reason is None
    assert check_webpage_request(
        "POST", "", "", json.dumps(_body(model="a")).encode()
    ).reason == "params"


async def test_main_route_unchanged_for_pii() -> None:
    """Основной маршрут по-прежнему отклоняет телефон и почту."""
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"messages": [{"role": "user", "content": CONTACTS}]})
    assert r.status_code == 422
    assert seen == []


async def test_logs_have_no_content(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        await c.post(WEBPAGE_ROUTE_PATH, json=_body())
        await c.post(WEBPAGE_ROUTE_PATH, json=_body(f"{CONTACTS}\n{INN_TEXT}"))
    assert "500100732259" not in caplog.text
    assert "Иванов" not in caplog.text
    assert "sales@example.ru" not in caplog.text
    assert "webpage_request" in caplog.text
