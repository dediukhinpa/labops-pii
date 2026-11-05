"""Тесты маршрута поиска для серверного web_fetch: форма инструмента, адреса и текст."""

import json
from typing import Any

import pytest

from labops_pii.guard.litellm.search_route import (
    FETCH_MAX_CONTENT_TOKENS_LIMIT,
    FETCH_MAX_DOMAINS,
    FETCH_MAX_URLS,
    FETCH_MAX_USES_LIMIT,
    check_search_form,
)

FETCH_TOOL = {
    "type": "web_fetch_20260209",
    "name": "web_fetch",
    "allowed_domains": ["good.com"],
    "max_uses": 2,
    "max_content_tokens": 20000,
}
INSTRUCTION = "Прочитай страницу и найди город, контакты, цены и сроки поставки."
USER_TEXT = f"{INSTRUCTION} https://good.com/ https://good.com/contacts"


def _check(**over: Any) -> str | None:
    data: dict[str, Any] = {
        "model": "agent-main",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": USER_TEXT}],
        "tools": [dict(FETCH_TOOL)],
    }
    data.update(over)
    return check_search_form("POST", "", "", json.dumps(data).encode())


def _tool(**over: Any) -> list[dict[str, Any]]:
    tool = dict(FETCH_TOOL)
    tool.update(over)
    return [tool]


def _user(text: str) -> list[dict[str, Any]]:
    return [{"role": "user", "content": text}]


def test_valid_fetch_passes() -> None:
    assert _check() is None


def test_valid_fetch_list_content_and_tool_choice() -> None:
    blocks = [{"type": "text", "text": INSTRUCTION}, {"type": "text", "text": "https://good.com/"}]
    assert _check(
        messages=[{"role": "user", "content": blocks}],
        tool_choice={"type": "tool", "name": "web_fetch"},
    ) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://good.com",
        "http://good.com/",
        "HTTPS://GOOD.COM/About-Us/",
        "https://www.good.com/contacts",
        "https://a.b.good.com/x_y.html",
        "https://good.com/%D0%BA%D0%BE%D0%BD%D1%82%D0%B0%D0%BA%D1%82%D1%8B",
    ],
)
def test_allowed_urls_and_subdomains(url: str) -> None:
    assert _check(messages=_user(f"{INSTRUCTION} {url}")) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com/",
        "https://evil.com/?a.good.com",
        "https://evil.com/good.com",
        "https://evil.com#.good.com",
        "https://good.com.evil.com/",
        "https://evilgood.com/",
        "https://good.com@evil.com/",
        "https://evil.com@good.com/",
        "https://user:pw@good.com/",
        "https://good.com:8443/",
        "https://good.com:443/",
        "https://good.com/?token=abc",
        "https://good.com/#frag",
        "https://good.com\\@evil.com/",
        "https://good.com./",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://good.com%2eevil.com/",
        "https://*.good.com/",
        "https://хорошо.рф/",
        "ftp://good.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "//good.com/",
        "https://good.com/" + "a" * 300,
        "https://",
    ],
)
def test_urls_outside_domains_or_unsafe_rejected(url: str) -> None:
    assert _check(messages=_user(f"{INSTRUCTION} {url}")) == "fetch_url"


def test_one_bad_url_among_good_rejected() -> None:
    text = f"{INSTRUCTION} https://good.com/ https://evil.com/"
    assert _check(messages=_user(text)) == "fetch_url"


def test_no_url_rejected() -> None:
    assert _check(messages=_user(INSTRUCTION)) == "fetch_url"


def test_too_many_urls_rejected() -> None:
    urls = " ".join(f"https://good.com/p{i}" for i in range(FETCH_MAX_URLS + 1))
    assert _check(messages=_user(f"{INSTRUCTION} {urls}")) == "fetch_url"


@pytest.mark.parametrize(
    "text",
    [
        "Найди ИНН 500100732259 https://good.com/",
        "Позвони +7 916 123 45 67 https://good.com/",
        "Напиши ivan@mail.ru https://good.com/",
        "Карта 4111 1111 1111 1111 https://good.com/",
        "Директор Иванов https://good.com/ ИНН 500100732259",
    ],
)
def test_pii_in_message_rejected(text: str) -> None:
    assert _check(messages=_user(text)) == "fetch_url"


@pytest.mark.parametrize(
    "text",
    [
        "Загляни на evil.com https://good.com/",
        "Прочитай www.evil.com и https://good.com/",
        "Прочитай https://good.com/ и ещё evil.org/x",
    ],
)
def test_domain_like_words_in_instruction_rejected(text: str) -> None:
    assert _check(messages=_user(text)) == "fetch_url"


def test_instruction_size_limit() -> None:
    assert _check(messages=_user("а" * 2000 + " https://good.com/")) == "fetch_url"


def test_system_with_pii_or_url_rejected() -> None:
    assert _check(system="Контакт: ivan@mail.ru") == "fetch_url"
    assert _check(system="Читай https://good.com/") == "fetch_url"
    assert _check(system="Ты извлекаешь контакты компании.") is None


def test_continuation_not_supported_for_fetch() -> None:
    assistant = {
        "role": "assistant",
        "content": [
            {
                "type": "server_tool_use", "id": "srvtoolu_1", "name": "web_fetch",
                "input": {"url": "https://good.com/"},
            },
            {
                "type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_1",
                "content": {"type": "web_fetch_tool_result_error", "error_code": "unavailable"},
            },
        ],
    }
    assert _check(messages=_user(USER_TEXT) + [assistant]) == "messages"


def test_fetch_blocks_not_allowed_in_search_continuation() -> None:
    """Блоки web_fetch в продолжении поискового запроса - отказ."""
    search_tool = [{"type": "web_search_20260209", "name": "web_search", "max_uses": 3}]
    assistant = {
        "role": "assistant",
        "content": [
            {
                "type": "server_tool_use", "id": "srvtoolu_1", "name": "web_fetch",
                "input": {"url": "https://good.com/"},
            },
        ],
    }
    assert _check(tools=search_tool, messages=_user("найди") + [assistant]) == "messages"
    result = {
        "role": "assistant",
        "content": [
            {
                "type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_1",
                "content": {"type": "web_fetch_tool_result_error", "error_code": "unavailable"},
            },
        ],
    }
    assert _check(tools=search_tool, messages=_user("найди") + [result]) == "messages"


@pytest.mark.parametrize(
    "tools",
    [
        _tool(allowed_domains=[]),
        _tool(allowed_domains="good.com"),
        _tool(allowed_domains=[1]),
        _tool(allowed_domains=["good.com", None]),
        _tool(allowed_domains=[f"d{i}.com" for i in range(FETCH_MAX_DOMAINS + 1)]),
        _tool(allowed_domains=["https://good.com"]),
        _tool(allowed_domains=["good.com/path"]),
        _tool(allowed_domains=["good.com:8443"]),
        _tool(allowed_domains=["*.good.com"]),
        _tool(allowed_domains=["Good.com"]),
        _tool(allowed_domains=[".good.com"]),
        _tool(allowed_domains=["good.com."]),
        _tool(allowed_domains=["127.0.0.1"]),
        _tool(allowed_domains=["localhost"]),
        _tool(allowed_domains=["good"]),
        _tool(allowed_domains=["good..com"]),
        _tool(allowed_domains=["хорошо.рф"]),
        _tool(allowed_domains=[""]),
        _tool(allowed_domains=["example.ru\n"]),
        _tool(allowed_domains=["good.com\n"]),
        _tool(allowed_domains=["\u0662good.com"]),
        _tool(allowed_domains=["good.\u212a\u212a"]),
        _tool(max_uses=FETCH_MAX_USES_LIMIT + 1),
        _tool(max_uses=0),
        _tool(max_uses=True),
        _tool(max_uses="2"),
        _tool(max_content_tokens=FETCH_MAX_CONTENT_TOKENS_LIMIT + 1),
        _tool(max_content_tokens=0),
        _tool(max_content_tokens=1.5),
        _tool(blocked_domains=["evil.com"]),
        _tool(citations={"enabled": True}),
        _tool(url_sources={"client_tool_results": {"type": "none"}}),
        _tool(use_cache=False),
        _tool(user_location={"type": "approximate"}),
        _tool(type="web_search_20260209"),
        _tool(type="web_fetch_"),
        _tool(type="web_fetch_latest"),
        _tool(type="web_fetch_20260209\n"),
        _tool(type="web_fetch_\u0662\u0660\u0662\u0666\u0660\u0662\u0660\u0669"),
        _tool(type="code_execution_20250825"),
        _tool(name="web_search"),
    ],
)
def test_bad_fetch_tool_rejected(tools: list[dict[str, Any]]) -> None:
    assert _check(tools=tools) in {"tools", "fetch_url"}
    assert _check(tools=tools) is not None


@pytest.mark.parametrize("missing", ["allowed_domains", "max_uses", "max_content_tokens"])
def test_missing_required_fetch_param_rejected(missing: str) -> None:
    tool = dict(FETCH_TOOL)
    del tool[missing]
    assert _check(tools=[tool]) == "tools"


def test_boundary_values_pass() -> None:
    tools = _tool(
        max_uses=FETCH_MAX_USES_LIMIT,
        max_content_tokens=FETCH_MAX_CONTENT_TOKENS_LIMIT,
        allowed_domains=[f"d{i}.com" for i in range(FETCH_MAX_DOMAINS)],
    )
    assert _check(tools=tools, messages=_user(f"{INSTRUCTION} https://d0.com/")) is None


def test_search_and_fetch_together_rejected() -> None:
    search = {"type": "web_search_20260209", "name": "web_search", "max_uses": 3}
    assert _check(tools=[search, dict(FETCH_TOOL)]) == "tools"
    assert _check(tools=[dict(FETCH_TOOL), search]) == "tools"
    assert _check(tools=[dict(FETCH_TOOL), dict(FETCH_TOOL)]) == "tools"


def test_tool_choice_must_name_fetch() -> None:
    assert _check(tool_choice={"type": "tool", "name": "web_search"}) == "tool_choice"
    assert _check(tool_choice={"type": "tool", "name": "web_fetch"}) is None


def test_search_with_fetch_only_keys_rejected() -> None:
    """Ключи fetch на поисковом инструменте по-прежнему недопустимы."""
    search = {
        "type": "web_search_20260209", "name": "web_search", "max_content_tokens": 10,
    }
    assert _check(tools=[search], messages=_user("найди")) == "tools"


def test_search_query_keeps_pii_allowed() -> None:
    """Для поиска ПДн в запросе по-прежнему допустимы (решение владельца)."""
    search = [{"type": "web_search_20260209", "name": "web_search", "max_uses": 3}]
    assert _check(tools=search, messages=_user("ИНН 500100732259 ivan@mail.ru")) is None
