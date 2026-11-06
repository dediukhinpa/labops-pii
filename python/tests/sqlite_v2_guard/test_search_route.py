"""Тесты маршрута поиска: форма запроса вместо фильтра ПДн, обходы пути, флаг."""

import json
import logging
from typing import Any

import httpx
import pytest

from labops_pii.errors import ConfigError
from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.litellm.search_route import (
    SEARCH_CONTINUATION_MAX_BODY_BYTES,
    SEARCH_MAX_BODY_BYTES,
    SEARCH_ROUTE_PATH,
    check_search_form,
    is_search_namespace,
)

PII_TEXT = "найди ООО по ИНН 7707083893, директор Иванов Иван Иванович, +7 916 123 45 67"
TOOL = {"type": "web_search_20260209", "name": "web_search", "max_uses": 3}
# Модель тела по умолчанию и самое длинное допустимое имя (граница 128 символов)
DEFAULT_MODEL = "agent-main"
LONGEST_MODEL = "m" * 128


@pytest.fixture(autouse=True)
def _allowed_models(monkeypatch: pytest.MonkeyPatch) -> None:
    """Включённый маршрут поиска требует списка моделей; тесты формы работают с этим списком."""
    monkeypatch.setenv("SEARCH_ALLOWED_MODELS", f"{DEFAULT_MODEL},{LONGEST_MODEL}")


async def _stream(data: bytes):
    """Тело ответа как поток (как у реального транспорта)."""
    yield data


def _body(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "model": "agent-main",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": PII_TEXT}],
        "tools": [dict(TOOL)],
    }
    data.update(over)
    return data


def _transport(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    return httpx.MockTransport(handler)


def _client(seen: list[httpx.Request], enabled: bool = True) -> httpx.AsyncClient:
    app = create_app("http://upstream", transport=_transport(seen), search_enabled=enabled)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


async def test_valid_form_with_pii_forwarded_to_v1_messages() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(
            SEARCH_ROUTE_PATH, json=_body(), headers={"x-api-key": "k", "anthropic-version": "1"}
        )
    assert r.status_code == 200
    assert len(seen) == 1
    assert seen[0].url.path == "/v1/messages"
    assert seen[0].url.query == b""
    assert seen[0].headers["x-api-key"] == "k"
    assert json.loads(seen[0].content) == _body()


async def test_list_content_and_tool_choice_allowed() -> None:
    seen: list[httpx.Request] = []
    body = _body(
        messages=[{"role": "user", "content": [{"type": "text", "text": PII_TEXT}]}],
        tool_choice={"type": "tool", "name": "web_search"},
    )
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=body)
    assert r.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        _body(messages=[{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]),
        _body(messages=[{"role": "assistant", "content": "a"}]),
        _body(messages=[]),
        _body(tools=[{"type": "bash_20250124", "name": "bash"}]),
        _body(tools=[dict(TOOL), {"name": "custom", "input_schema": {}}]),
        _body(tools=[]),
        _body(tools=None),
        _body(stream=True),
        _body(stream=False),
        _body(extra_key=1),
        _body(metadata={"user_id": "x"}),
        _body(tool_choice={"type": "tool", "name": "other"}),
        _body(tool_choice="auto"),
        _body(max_tokens="1024"),
    ],
    ids=lambda b: json.dumps(b, ensure_ascii=False)[:60],
)
async def test_bad_form_rejected_403(body: dict[str, Any]) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=body)
    assert r.status_code == 403
    assert r.json()["code"] == "search_route_form"
    assert seen == []


async def test_oversize_rejected() -> None:
    seen: list[httpx.Request] = []
    big = _body(messages=[{"role": "user", "content": "я" * SEARCH_MAX_BODY_BYTES}])
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=big)
    assert r.status_code == 403
    assert seen == []


async def test_non_object_and_garbage_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        for raw in (b"[]", b"not json", b"", b'"str"'):
            r = await c.post(SEARCH_ROUTE_PATH, content=raw)
            assert r.status_code == 403
    assert seen == []


async def test_get_query_and_encoding_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        assert (await c.get(SEARCH_ROUTE_PATH)).status_code == 403
        assert (await c.put(SEARCH_ROUTE_PATH, json=_body())).status_code == 403
        r = await c.post(SEARCH_ROUTE_PATH + "?beta=true", json=_body())
        assert r.status_code == 403
        r = await c.post(
            SEARCH_ROUTE_PATH, json=_body(), headers={"content-encoding": "gzip"}
        )
        assert r.status_code == 403
    assert seen == []


@pytest.mark.parametrize(
    "path",
    [
        "/search/v1/chat/completions",
        "/search/v1/messages/extra",
        "/search/v1/messages/",
        "/search",
        "/search/",
        "/SEARCH/v1/messages",
        "/Search/v1/messages",
        "/search//v1/messages",
        "/search/v1/%2e/messages",
        "/%73earch/v1/messages",
        "/search%2Fv1/messages",
        "/%2fsearch/v1/messages",
        "/%252fsearch/v1/messages",
        "/search/v1/../v1/chat/completions",
    ],
)
async def test_path_bypass_forbidden_before_body(path: str) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(path, json=_body())
    assert r.status_code == 403
    assert seen == []


async def test_namespace_helper() -> None:
    assert is_search_namespace("/search/v1/messages")
    assert is_search_namespace("//SEARCH/x")
    assert not is_search_namespace("/v1/messages")
    assert not is_search_namespace("/v1/search/x")


async def test_main_route_still_rejects_pii() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"messages": [{"role": "user", "content": PII_TEXT}]})
        assert r.status_code == 422
        r = await c.post("/v1/messages", json=_body())
        assert r.status_code == 422
    assert seen == []


async def test_disabled_flag_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SEARCH_ROUTE_ENABLED", raising=False)
    seen: list[httpx.Request] = []
    app = create_app("http://upstream", transport=_transport(seen))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        assert (await c.post(SEARCH_ROUTE_PATH, json=_body())).status_code == 404
        assert (await c.post("/search/other", json=_body())).status_code == 403
    assert seen == []


async def test_env_flag_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEARCH_ROUTE_ENABLED", "1")
    seen: list[httpx.Request] = []
    app = create_app("http://upstream", transport=_transport(seen))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        assert (await c.post(SEARCH_ROUTE_PATH, json=_body())).status_code == 200


async def test_logs_have_no_body(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        await c.post(SEARCH_ROUTE_PATH, json=_body(stream=True))
        await c.post(SEARCH_ROUTE_PATH, json=_body())
    assert "7707083893" not in caplog.text
    assert "Иванов" not in caplog.text


def test_check_search_form_pure() -> None:
    ok = json.dumps(_body()).encode()
    assert check_search_form("POST", "", "", ok) is None
    assert check_search_form("POST", "", "identity", ok) is None
    assert check_search_form("GET", "", "", ok) == "method"
    assert check_search_form("POST", "a=1", "", ok) == "query_string"
    assert check_search_form("POST", "", "br", ok) == "content_encoding"


@pytest.mark.parametrize("raw", [b"//search/v1/messages", b"/search/./v1/messages"])
async def test_raw_asgi_path_bypass_forbidden(raw: bytes) -> None:
    """httpx сам нормализует такие пути, поэтому шлём сырой ASGI-запрос."""
    seen: list[httpx.Request] = []
    app = create_app("http://upstream", transport=_transport(seen), search_enabled=True)
    payload = json.dumps(_body()).encode()
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": raw.decode(), "raw_path": raw, "query_string": b"",
        "headers": [(b"content-type", b"application/json")], "server": ("guard", 80),
        "client": ("127.0.0.1", 1),
    }
    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 403
    assert seen == []


def _assistant(*blocks: dict[str, Any]) -> dict[str, Any]:
    return {"role": "assistant", "content": list(blocks)}


_SERVER_BLOCKS = [
    {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {"query": "q"}},
    {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": []},
    {"type": "text", "text": "промежуточный текст"},
]


def _continuation(**over: Any) -> dict[str, Any]:
    msgs = [{"role": "user", "content": PII_TEXT}, _assistant(*_SERVER_BLOCKS)]
    return _body(messages=msgs, **over)


async def test_continuation_allowed_and_forwarded() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=_continuation())
    assert r.status_code == 200
    assert seen[0].url.path == "/v1/messages"


async def test_large_continuation_within_limit_allowed() -> None:
    seen: list[httpx.Request] = []
    # Большой encrypted_content - единственный легитимный источник объёма в продолжении
    blocks = [{"type": "web_search_tool_result", "tool_use_id": "s", "content": [
        {"type": "web_search_result", "url": "u", "title": "t",
         "encrypted_content": "A" * 20000, "page_age": None}]}]
    body = _body(messages=[{"role": "user", "content": "q"}, _assistant(*blocks)])
    assert SEARCH_MAX_BODY_BYTES < len(json.dumps(body).encode()) < 262144
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=body)
    assert r.status_code == 200


@pytest.mark.parametrize(
    "messages",
    [
        [{"role": "user", "content": "q"}, _assistant({"type": "tool_use", "id": "t",
                                                       "name": "x", "input": {}})],
        [{"role": "user", "content": "q"}, _assistant({"type": "thinking", "thinking": "..."})],
        [{"role": "user", "content": "q"}, {"role": "assistant", "content": "строка"}],
        [{"role": "user", "content": "q"}, _assistant()],
        [{"role": "user", "content": "q"}, _assistant(*_SERVER_BLOCKS),
         _assistant(*_SERVER_BLOCKS)],
        [{"role": "user", "content": "q"}, _assistant(*_SERVER_BLOCKS),
         {"role": "user", "content": "q2"}],
        [_assistant(*_SERVER_BLOCKS), {"role": "user", "content": "q"}],
    ],
)
async def test_bad_continuation_rejected(messages: list[dict[str, Any]]) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=_body(messages=messages))
    assert r.status_code == 403
    assert seen == []


async def test_continuation_over_limit_rejected() -> None:
    seen: list[httpx.Request] = []
    blocks = [{"type": "text", "text": "a" * SEARCH_CONTINUATION_MAX_BODY_BYTES}]
    body = _body(messages=[{"role": "user", "content": "q"}, _assistant(*blocks)])
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=body)
    assert r.status_code == 403
    assert seen == []


async def test_first_request_over_4k_rejected_even_if_below_continuation_limit() -> None:
    seen: list[httpx.Request] = []
    body = _body(messages=[{"role": "user", "content": "a" * 10000}])
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=body)
    assert r.status_code == 403
    assert seen == []


async def test_continuation_stream_and_extra_keys_still_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        for extra in ({"stream": True}, {"x": 1}):
            r = await c.post(SEARCH_ROUTE_PATH, json=_continuation(**extra))
            assert r.status_code == 403
        bad = _continuation(tools=[{"type": "bash_20250124", "name": "bash"}])
        assert (await c.post(SEARCH_ROUTE_PATH, json=bad)).status_code == 403
    assert seen == []


# ---- F1: предел 4 КиБ для user/system и allowlist блоков assistant при продолжении ----

# Форма ответа API: серверный вызов, результат поиска и текст с цитатой
_REAL_BLOCKS: list[dict[str, Any]] = [
    {"type": "text", "text": "Ищу.", "citations": None},
    {"type": "server_tool_use", "id": "srvtoolu_01A", "name": "web_search",
     "input": {"query": "ООО Ромашка ИНН"}, "caller": {"type": "direct"}},
    {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_01A", "content": [
        {"type": "web_search_result", "url": "https://example.com/a", "title": "Заголовок",
         "encrypted_content": "EqgfCioIARgB" * 500, "page_age": "April 30, 2025"},
        {"type": "web_search_result", "url": "https://example.com/b", "title": "Б",
         "encrypted_content": "Zm9v", "page_age": None},
    ]},
    {"type": "text", "text": "Итог", "citations": [
        {"type": "web_search_result_location", "url": "https://example.com/a",
         "title": "Заголовок", "cited_text": "фрагмент", "encrypted_index": "Eo8BCioI"},
    ]},
]
_BIG = "я" * 3000  # 6000 байт UTF-8


def _cont(assistant_blocks: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    msgs = [{"role": "user", "content": "q"}, _assistant(*assistant_blocks)]
    return _body(messages=msgs, **over)


async def _status(body: dict[str, Any], headers: dict[str, str] | None = None) -> int:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(SEARCH_ROUTE_PATH, json=body, headers=headers or {})
    return r.status_code


async def test_real_api_continuation_allowed() -> None:
    assert await _status(_cont(_REAL_BLOCKS)) == 200


async def test_result_error_object_allowed() -> None:
    err = {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
           "content": {"type": "web_search_tool_result_error", "error_code": "max_uses_exceeded"}}
    assert await _status(_cont([err])) == 200


@pytest.mark.parametrize(
    "body",
    [
        _body(messages=[{"role": "user", "content": _BIG},
                        _assistant(*_SERVER_BLOCKS)]),
        _body(messages=[{"role": "user", "content": [{"type": "text", "text": _BIG}]},
                        _assistant(*_SERVER_BLOCKS)]),
        _body(system=_BIG, messages=[{"role": "user", "content": "q"},
                                     _assistant(*_SERVER_BLOCKS)]),
        _body(system=[{"type": "text", "text": _BIG}],
              messages=[{"role": "user", "content": "q"}, _assistant(*_SERVER_BLOCKS)]),
        _body(messages=[{"role": "user", "content": [
            {"type": "text", "text": "я" * 1500}, {"type": "text", "text": "я" * 1500}]},
            _assistant(*_SERVER_BLOCKS)]),
    ],
    ids=["user_str", "user_blocks", "system_str", "system_blocks", "user_sum"],
)
async def test_user_and_system_capped_in_continuation(body: dict[str, Any]) -> None:
    assert await _status(body) == 403


@pytest.mark.parametrize(
    "blocks",
    [
        [{"type": "server_tool_use", "id": "s", "name": "bash", "input": {"query": "q"}}],
        [{"type": "server_tool_use", "id": "s", "name": "web_search",
          "input": {"query": "я" * 1000}}],
        [{"type": "server_tool_use", "id": "s", "name": "web_search", "input": {"x": "y"}}],
        [{"type": "server_tool_use", "id": "s", "name": "web_search", "input": {"query": "q"},
          "extra": "ПДн"}],
        [{"type": "server_tool_use", "id": "s", "name": "web_search", "input": {"query": "q"},
          "caller": {"type": "x", "note": "ПДн"}}],
        [{"type": "web_search_tool_result", "tool_use_id": "s", "content": [],
          "extra": "ПДн"}],
        [{"type": "web_search_tool_result", "tool_use_id": "s", "content": [
            {"type": "web_search_result", "url": "u", "title": "t", "encrypted_content": "e",
             "extra": "ПДн"}]}],
        [{"type": "web_search_tool_result", "tool_use_id": "s", "content": [
            {"type": "other", "url": "u"}]}],
        [{"type": "web_search_tool_result", "tool_use_id": "s",
          "content": {"type": "web_search_tool_result_error", "error_code": "x", "m": "ПДн"}}],
        [{"type": "web_search_tool_result", "tool_use_id": "s", "content": "строка"}],
        [{"type": "text", "text": "я" * 8193}],
        [{"type": "text", "text": "t", "extra": "ПДн"}],
        [{"type": "text", "text": "t", "citations": [
            {"type": "web_search_result_location", "url": "u", "title": "t",
             "cited_text": "я" * 1025, "encrypted_index": "e"}]}],
        [{"type": "text", "text": "t", "citations": [
            {"type": "web_search_result_location", "url": "u", "title": "t",
             "cited_text": "c", "encrypted_index": "e", "extra": "ПДн"}]}],
        [{"type": "text", "text": "t", "citations": [{"type": "char_location"}]}],
        [{"type": "text", "text": "я" * 8000}] * 8,
    ],
    ids=lambda b: json.dumps(b, ensure_ascii=False)[:50],
)
async def test_assistant_blocks_allowlist(blocks: list[dict[str, Any]]) -> None:
    assert await _status(_cont(blocks)) == 403


async def test_total_limit_for_encrypted_content_kept() -> None:
    ok = {"type": "web_search_tool_result", "tool_use_id": "s", "content": [
        {"type": "web_search_result", "url": "u", "title": "t",
         "encrypted_content": "A" * 200000, "page_age": None}]}
    assert await _status(_cont([ok])) == 200
    ok["content"][0]["encrypted_content"] = "A" * SEARCH_CONTINUATION_MAX_BODY_BYTES
    assert await _status(_cont([ok])) == 403


# ---- F2: ужесточение tools и скалярных параметров, заголовок anthropic-beta ----

@pytest.mark.parametrize(
    "tool",
    [
        {**TOOL, "extra": "ПДн"},
        {**TOOL, "name": "other"},
        {"type": "web_search_20260209"},
        {**TOOL, "max_uses": 0},
        {**TOOL, "max_uses": 11},
        {**TOOL, "max_uses": True},
        {**TOOL, "max_uses": "3"},
        {**TOOL, "max_uses": 2.5},
        {**TOOL, "allowed_domains": ["я" * 4000]},
    ],
    ids=lambda t: json.dumps(t, ensure_ascii=False)[:60],
)
async def test_tool_allowlist(tool: dict[str, Any]) -> None:
    assert await _status(_body(tools=[tool])) == 403


async def test_tool_full_allowed() -> None:
    tool = {**TOOL, "max_uses": 10, "user_location": {"type": "approximate", "city": "Moscow"},
            "allowed_domains": ["example.com"], "blocked_domains": ["bad.example"]}
    assert await _status(_body(tools=[tool])) == 200


@pytest.mark.parametrize(
    "over",
    [
        {"max_tokens": 0}, {"max_tokens": 8193}, {"max_tokens": True}, {"max_tokens": 1.5},
        {"temperature": -0.1}, {"temperature": 1.1}, {"temperature": "0.5"},
        {"temperature": True}, {"model": "m" * 129}, {"model": 5},
    ],
    ids=lambda o: json.dumps(o),
)
async def test_scalar_params_rejected(over: dict[str, Any]) -> None:
    assert await _status(_body(**over)) == 403


async def test_scalar_params_boundaries_allowed() -> None:
    assert await _status(_body(max_tokens=8192, temperature=0, model=LONGEST_MODEL)) == 200
    assert await _status(_body(max_tokens=1, temperature=1.0)) == 200


async def test_allowed_models_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEARCH_ALLOWED_MODELS", "agent-main, agent-fast")
    assert await _status(_body(model="agent-fast")) == 200
    assert await _status(_body(model="claude-opus-x")) == 403
    body = _body()
    del body["model"]
    assert await _status(body) == 403


@pytest.mark.parametrize("raw", [None, "", " , "])
def test_enabled_route_without_models_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, raw: str | None
) -> None:
    # Пустой список при включённом маршруте раньше пропускал любую модель (fail open)
    if raw is None:
        monkeypatch.delenv("SEARCH_ALLOWED_MODELS", raising=False)
    else:
        monkeypatch.setenv("SEARCH_ALLOWED_MODELS", raw)
    with pytest.raises(ConfigError, match="SEARCH_ALLOWED_MODELS"):
        create_app("http://upstream", search_enabled=True)
    monkeypatch.setenv("SEARCH_ROUTE_ENABLED", "1")
    with pytest.raises(ConfigError, match="SEARCH_ALLOWED_MODELS"):
        create_app("http://upstream")


def test_disabled_route_without_models_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SEARCH_ALLOWED_MODELS", raising=False)
    monkeypatch.delenv("SEARCH_ROUTE_ENABLED", raising=False)
    assert create_app("http://upstream") is not None


async def test_anthropic_beta_not_forwarded_on_search_route() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(
            SEARCH_ROUTE_PATH, json=_body(),
            headers={"anthropic-beta": "files-api-2025-04-14", "anthropic-version": "1"},
        )
    assert r.status_code == 200
    assert "anthropic-beta" not in seen[0].headers
    assert seen[0].headers["anthropic-version"] == "1"
