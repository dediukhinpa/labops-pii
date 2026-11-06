"""Режим прокси для CLI-песочницы на edge: апстримы, токены, thinking, режимы block/log."""

import json

import httpx
import pytest

from labops_pii.guard.edge.app import PII_REJECTED_CODE, create_app
from labops_pii.guard.edge.config import GuardMode, parse_mode, parse_upstreams, split_upstream_path
from labops_pii.guard.detector import find_pii_types, scan_body
from tests.edge_guard.helpers import UPSTREAMS

PHONE = "+7 902 123-45-67"


async def _gen(data: bytes):
    yield data


def _recording(seen: list[httpx.Request], status: int = 200) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(status, content=_gen(b'{"ok": true}'))

    return httpx.MockTransport(handler)


def _client(transport: httpx.MockTransport, mode: GuardMode = GuardMode.BLOCK) -> httpx.AsyncClient:
    app = create_app(UPSTREAMS, transport=transport, mode=mode)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


# --- токены-заменители ----------------------------------------------------------------

@pytest.mark.parametrize(
    "token",
    ["[PHONE_1]", "[INN_12]", "[PERSON_1|datv]", "[PERSON_3|gent]", "[ORG_2|ablt]",
     "[EMAIL_1|nomn]", "[PERSON_1|accs]", "[PERSON_1|loct]",
     "⟦PII:PHONE:0a1b2c3d⟧", "⟦PII:INN:12345678⟧"],
)
def test_tokens_are_not_pii(token: str) -> None:
    assert find_pii_types(f"позвонить {token} завтра") == set()


@pytest.mark.parametrize(
    "text",
    [
        # Код падежа вне закрытого набора: не токен, содержимое проверяется как текст
        "[PERSON_1|дат]89021234567",
        "[PHONE_1|xx 8 902 123 45 67]",
        # Номер токена длиннее шести цифр не вырезается (иначе оболочка прятала бы ИНН)
        "[INN_500100732259]",
        # Старый формат: только 8 hex и известный вид
        "⟦PII:PHONE:89021234567⟧",
        "⟦PII:OTHER:0a1b2c3d⟧ +7 902 123-45-67",
    ],
)
def test_lookalike_tokens_are_scanned(text: str) -> None:
    assert find_pii_types(text)


# --- настройки ----------------------------------------------------------------------

def test_default_upstream_is_anthropic() -> None:
    routes = parse_upstreams(None)
    assert list(routes) == ["anthropic"]
    assert routes["anthropic"].base_url == "https://api.anthropic.com"


@pytest.mark.parametrize(
    "raw",
    [
        "anthropic=http://api.anthropic.com",  # открытый http наружу
        "Bad=https://x.example",
        "a=https://x.example,a=https://y.example",
        "a=https://x.example?k=1",
        "a=https://user:pw@x.example",
        "a=ftp://x.example",
        "a=https://x.example,,b=https://y.example",
        "novalue",
    ],
)
def test_invalid_upstreams_refused(raw: str) -> None:
    with pytest.raises(ValueError, match="PII_GUARD_UPSTREAMS"):
        parse_upstreams(raw)


def test_mode_parsing() -> None:
    assert parse_mode(None) is GuardMode.BLOCK
    assert parse_mode("LOG") is GuardMode.LOG
    with pytest.raises(ValueError, match="PII_GUARD_MODE"):
        parse_mode("off")


def test_split_upstream_path() -> None:
    assert split_upstream_path("/u/anthropic/v1/messages") == ("anthropic", "/v1/messages")
    assert split_upstream_path("/v1/messages") is None
    assert split_upstream_path("/u/anthropic") is None
    assert split_upstream_path("/u/Bad/v1") is None


# --- маршрутизация --------------------------------------------------------------------

async def test_path_of_upstream_with_base_path_is_joined() -> None:
    seen: list[httpx.Request] = []
    async with _client(_recording(seen)) as c:
        r = await c.post("/u/deepseek/v1/messages?beta=true", json={"x": "ok"})
    assert r.status_code == 200
    assert str(seen[0].url) == "http://127.0.0.1:9/anthropic/v1/messages?beta=true"


@pytest.mark.parametrize(
    "target",
    ["/v1/messages", "/u/nope/v1/messages", "/u/anthropic/../x", "/u/anthr%6Fpic/v1/messages"],
)
async def test_unknown_routes_not_forwarded(target: str) -> None:
    seen: list[httpx.Request] = []
    async with _client(_recording(seen)) as c:
        r = await c.post(target, json={"x": "ok"})
    assert r.status_code == 404
    assert r.json()["type"] == "error"
    assert seen == []


def test_dot_segments_detected() -> None:
    from labops_pii.guard.edge.app import _has_dot_segment

    assert _has_dot_segment("/v1/../x") and _has_dot_segment("/v1/./x")
    assert not _has_dot_segment("/v1/messages/count_tokens")


async def test_count_tokens_scanned_too() -> None:
    seen: list[httpx.Request] = []
    async with _client(_recording(seen)) as c:
        r = await c.post("/u/anthropic/v1/messages/count_tokens", json={"m": f"тел {PHONE}"})
    assert r.status_code == 422
    assert seen == []


# --- пересылка как есть -----------------------------------------------------------------

def _thinking_body() -> bytes:
    """Тело с блоком thinking (подпись) и нестандартными пробелами: менять нельзя."""
    body = {
        "model": "claude-sonnet",
        "metadata": {"user_id": "u"},
        "messages": [
            {"role": "user", "content": "Клиент [PERSON_1|datv], заказ 5 шт"},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "думаю о [PERSON_1]",
                     "signature": "EqoBCkgIBRABGAIiQL+/zz09/Abc=="},
                    {"type": "text", "text": "Готово"},
                ],
            },
        ],
        "stream": True,
    }
    return json.dumps(body, ensure_ascii=False, indent=1).encode()


async def test_body_and_auth_headers_forwarded_unchanged() -> None:
    seen: list[httpx.Request] = []
    raw = _thinking_body()
    headers = {
        "authorization": "Bearer oauth-token-value",
        "x-api-key": "api-key-value",
        "anthropic-beta": "oauth-2025-04-20",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    async with _client(_recording(seen)) as c:
        r = await c.post("/u/anthropic/v1/messages?beta=true", content=raw, headers=headers)
    assert r.status_code == 200
    assert seen[0].content == raw
    for key, value in headers.items():
        assert seen[0].headers[key] == value


async def test_pii_inside_thinking_is_rejected() -> None:
    seen: list[httpx.Request] = []
    body = {"messages": [{"role": "assistant", "content": [
        {"type": "thinking", "thinking": f"номер {PHONE}", "signature": "c2ln"}]}]}
    async with _client(_recording(seen)) as c:
        r = await c.post("/u/anthropic/v1/messages", json=body)
    assert r.status_code == 422
    assert seen == []


async def test_sse_stream_passed_by_chunks() -> None:
    events = [b"event: message_start\ndata: {}\n\n", b"event: content_block_delta\ndata: {}\n\n"]

    def handler(req: httpx.Request) -> httpx.Response:
        async def gen():
            for event in events:
                yield event

        return httpx.Response(200, content=gen(), headers={"content-type": "text/event-stream"})

    async with _client(httpx.MockTransport(handler)) as c:
        async with c.stream("POST", "/u/anthropic/v1/messages", json={"stream": True}) as r:
            chunks = [chunk async for chunk in r.aiter_raw()]
    assert b"".join(chunks) == b"".join(events)
    assert r.headers["content-type"] == "text/event-stream"


# --- отказ и режимы ---------------------------------------------------------------------

async def test_rejection_has_marker_and_no_retry() -> None:
    async with _client(_recording([])) as c:
        r = await c.post("/u/anthropic/v1/messages", json={"m": f"тел {PHONE}"})
    assert r.status_code == 422
    payload = r.json()
    assert payload["type"] == "error"
    assert payload["error"]["type"] == "invalid_request_error"
    assert payload["error"]["message"].startswith(PII_REJECTED_CODE)
    assert payload["code"] == PII_REJECTED_CODE
    assert payload["pii_types"] == ["phone"]
    assert r.headers["x-should-retry"] == "false"
    assert "902" not in r.text


async def test_scan_failure_is_503_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: object) -> set[str]:
        raise RuntimeError("boom")

    monkeypatch.setattr("labops_pii.guard.edge.app.scan_body", boom)
    seen: list[httpx.Request] = []
    for mode in (GuardMode.BLOCK, GuardMode.LOG):
        async with _client(_recording(seen), mode) as c:
            r = await c.post("/u/anthropic/v1/messages", json={"x": "ok"})
        assert r.status_code == 503
        assert r.headers["x-should-retry"] == "false"
    assert seen == []


async def test_log_mode_forwards_finding() -> None:
    seen: list[httpx.Request] = []
    async with _client(_recording(seen), GuardMode.LOG) as c:
        r = await c.post("/u/anthropic/v1/messages", json={"m": f"тел {PHONE}"})
    assert r.status_code == 200
    assert len(seen) == 1


def test_mode_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PII_GUARD_MODE", "bogus")
    with pytest.raises(ValueError, match="PII_GUARD_MODE"):
        create_app(UPSTREAMS)


def test_scan_body_on_thinking_body_is_clean() -> None:
    assert scan_body(_thinking_body(), require_json=True) == set()


# --- почта аккаунта подписки в контексте CLI ------------------------------------------

ACCOUNT_CONTEXT = (
    "# userEmail\nThe user's email address is owner.account@example.com. Use it only to "
    "identify the user, such as for authorship."
)


def _context_body(extra: str = "") -> bytes:
    content = [{"type": "text", "text": ACCOUNT_CONTEXT + extra}, {"type": "text", "text": "hi"}]
    return json.dumps({"messages": [{"role": "user", "content": content}]}).encode()


def test_account_email_template_exempt_only_when_allowed() -> None:
    assert scan_body(_context_body(), require_json=True, allow_account_email=True) == set()
    assert scan_body(_context_body(), require_json=True) == {"email"}


@pytest.mark.parametrize(
    "smuggled",
    [
        "+79161234567,500100732259,4242424242424242,ivan@mail.ru",
        "4242424242424242",
        "ivan@mail.ru,+79161234567",
    ],
)
def test_account_email_template_does_not_hide_other_pii(smuggled: str) -> None:
    # Вместо почты в шаблон вписаны телефон, ИНН и карта: вырезаться должен только один адрес
    text = f"The user's email address is {smuggled}. Use it only to identify the user"
    body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode()
    assert scan_body(body, require_json=True, allow_account_email=True)


def test_other_email_next_to_template_still_found() -> None:
    body = _context_body(" Клиент: ivan@firma.ru")
    assert scan_body(body, require_json=True, allow_account_email=True) == {"email"}


def test_account_email_exempt_per_upstream() -> None:
    routes = parse_upstreams("anthropic=https://api.anthropic.com,deepseek=https://d.example")
    assert routes["anthropic"].allow_account_email
    assert not routes["deepseek"].allow_account_email
    none = parse_upstreams("anthropic=https://api.anthropic.com", "")
    assert not none["anthropic"].allow_account_email
    with pytest.raises(ValueError, match="PII_GUARD_ACCOUNT_EMAIL_UPSTREAMS"):
        parse_upstreams(None, "nope")


async def test_account_email_routing_in_app() -> None:
    seen: list[httpx.Request] = []
    routes = parse_upstreams(
        "anthropic=http://127.0.0.1:9,deepseek=http://127.0.0.1:9/anthropic"
    )
    app = create_app(routes, transport=_recording(seen))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        ok = await c.post("/u/anthropic/v1/messages", content=_context_body())
        bad = await c.post("/u/deepseek/v1/messages", content=_context_body())
    assert (ok.status_code, bad.status_code) == (200, 422)
    assert len(seen) == 1


async def test_api_hello_head_is_forwarded() -> None:
    seen: list[httpx.Request] = []
    async with _client(_recording(seen)) as c:
        r = await c.head("/u/anthropic/api/hello")
    assert r.status_code == 200
    assert seen[0].method == "HEAD" and seen[0].url.path == "/api/hello"
