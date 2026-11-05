"""Детектор адресов и режим PII_GUARD_ADDRESS_MODE (off / log_only / enforce), этап 187 Г."""

from __future__ import annotations

import io
import json
import time

import httpx
import pytest

from labops_pii.guard.address import AddressMode, parse_address_mode
from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.detector import find_pii_types, scan_body
from labops_pii.guard.litellm.jsonlog import configure_logging
from labops_pii.guard.metrics import METRICS
from labops_pii.guard.policy import split_findings
from labops_pii.guard.litellm.vision_route import check_vision_request
from labops_pii.guard.litellm.webpage_route import check_webpage_request
from tests.pragmatika_guard.test_vision_route import _body as vision_body

MODE_ENV = "PII_GUARD_ADDRESS_MODE"
NAMES_ENV = "PII_GUARD_NAMES_MODE"
ADDR = "г. Москва, ул. Ленина, д. 5, кв. 12"
ADDR_WITH_INDEX = "119019, ул. Арбат, д. 1"
PHONE = "+7 916 123 45 67"
# Линейность: потолок времени на ~1 МБ текста (запас на медленный CI, квадрат дал бы минуты)
LINEAR_TEXT_CHARS = 1_000_000
LINEAR_MAX_SECONDS = 20.0


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
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    from labops_pii.guard.detector import _STRING_CACHE

    _STRING_CACHE.clear()
    METRICS.reset()
    monkeypatch.setenv(NAMES_ENV, "off")  # имена не мешают проверке адресов


# --- Детектор ---------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    ADDR,
    ADDR_WITH_INDEX,
    "Доставка: улица Ленина 5",
    "по адресу: Ленина 5",
    "119019, г. Москва, ул. Арбат, 1",
    "дом 5 по улице Ленина",
    "Ленина ул., д. 5",
    "ул.Садовая,д.10",
])
def test_address_found(text: str) -> None:
    assert find_pii_types(text) == {"address"}


@pytest.mark.parametrize("text", [
    "Артикул АБ-12 д.5",
    "Размер 10x20",
    "ГОСТ 12345-2014",
    "см. стр. 5 договора",
    "Болт д. 5 мм",
    "Цена 1500 руб., скидка 15%",
    "Счёт на оплату № 15 от 01.02.2026",
    "Улица и дом - это адрес",
    "ул. Ленина",  # без номера дома адрес не определён
    "Итого 12 345,67 руб.",
    "",
])
def test_not_address(text: str) -> None:
    assert "address" not in find_pii_types(text)


def test_address_tokens_are_not_pii() -> None:
    """Токены псевдонимизатора [ADDRESS_n] ПДн не считаются, в том числе рядом с улицей."""
    assert find_pii_types("Отправить на [ADDRESS_1] завтра") == set()
    assert find_pii_types("ул. [ADDRESS_1], д. [ADDRESS_2]") == set()
    assert find_pii_types("[ADDRESS_12] и [PERSON_3]") == set()


def test_token_does_not_hide_real_address() -> None:
    assert "address" in find_pii_types(f"[ADDRESS_1] и {ADDR}")


def test_address_in_scan_body_strings_and_cache() -> None:
    text = "Передайте документы. " * 5 + ADDR  # длиннее порога кэша строк
    body = json.dumps({"x": text}).encode()
    assert scan_body(body) == {"address"}
    assert scan_body(body) == {"address"}  # из кэша


def test_address_found_after_unicode_escape() -> None:
    raw = ('{"x": "' + "".join(f"\\u{ord(c):04x}" for c in "ул. Ленина, д. 5") + '"}').encode()
    assert "address" in scan_body(raw)


def test_address_linear_on_long_inputs() -> None:
    samples = [
        "ул. " * (LINEAR_TEXT_CHARS // 4),
        "д. 5 " * (LINEAR_TEXT_CHARS // 5),
        "Ленина " * (LINEAR_TEXT_CHARS // 7),
        "1" * LINEAR_TEXT_CHARS,
        "119019, " * (LINEAR_TEXT_CHARS // 8),
        "г. Москва, " * (LINEAR_TEXT_CHARS // 11),
        ("ул. Ленина, " + "а" * 40 + " ") * (LINEAR_TEXT_CHARS // 54),
    ]
    for sample in samples:
        started = time.perf_counter()
        find_pii_types(sample)
        assert time.perf_counter() - started < LINEAR_MAX_SECONDS


def test_address_found_in_long_text_windows() -> None:
    """Адрес в хвосте текста длиннее окна сканирования всё равно находится."""
    filler = "обычный текст без цифр " * 20_000
    assert "address" in find_pii_types(filler + ADDR)
    assert "address" in find_pii_types(ADDR + " " + filler)


# --- Режимы -----------------------------------------------------------------------

def test_default_is_log_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(MODE_ENV, raising=False)
    found = find_pii_types(ADDR)
    assert found == {"address"}
    split = split_findings(found)
    assert not split.blocking and split.observed == {"address"}


def test_off_does_not_search(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "off")
    assert find_pii_types(ADDR) == set()


def test_parse_mode() -> None:
    assert parse_address_mode(None) is AddressMode.LOG_ONLY
    assert parse_address_mode("  ") is AddressMode.LOG_ONLY
    assert parse_address_mode(" ENFORCE ") is AddressMode.ENFORCE
    with pytest.raises(ValueError, match=MODE_ENV):
        parse_address_mode("on")


def test_modes_independent_of_names(monkeypatch: pytest.MonkeyPatch) -> None:
    found = {"name", "address"}
    monkeypatch.setenv(NAMES_ENV, "enforce")
    monkeypatch.setenv(MODE_ENV, "log_only")
    split = split_findings(found)
    assert split.blocking == {"name"} and split.observed == {"address"}
    monkeypatch.setenv(NAMES_ENV, "log_only")
    monkeypatch.setenv(MODE_ENV, "enforce")
    split = split_findings(found)
    assert split.blocking == {"address"} and split.observed == {"name"}


def test_phone_blocks_in_every_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    for mode in AddressMode:
        monkeypatch.setenv(MODE_ENV, mode.value)
        assert split_findings(find_pii_types(f"{PHONE} {ADDR}")).blocking >= {"phone"}


def test_cache_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"x": "Передайте документы. " * 5 + ADDR}).encode()
    monkeypatch.setenv(MODE_ENV, "log_only")
    assert "address" in scan_body(body)
    monkeypatch.setenv(MODE_ENV, "off")
    assert "address" not in scan_body(body)


def test_invalid_mode_stops_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "maybe")
    with pytest.raises(ValueError, match=MODE_ENV):
        create_app("http://upstream")


def test_invalid_mode_in_detector_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "maybe")
    assert split_findings(find_pii_types(ADDR)).blocking == {"address"}


# --- Маршруты ---------------------------------------------------------------------

async def test_chat_log_only_forwards_logs_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "log_only")
    stream = io.StringIO()
    configure_logging(stream=stream)
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"content": f"доставить {ADDR}"})
    assert r.status_code == 200 and len(seen) == 1
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    observed = [x for x in records if x["event"] == "pii_guard_observed"]
    assert len(observed) == 1 and observed[0]["pii_types"] == ["address"]
    assert "Ленина" not in stream.getvalue()  # значения в журнал не попадают
    assert METRICS.snapshot("pii_guard_findings_total")["address"] == 1
    assert METRICS.snapshot("pii_guard_denied_total")["address"] == 0


async def test_chat_enforce_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "enforce")
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"content": f"доставить {ADDR}"})
    assert r.status_code == 422 and r.json()["pii_types"] == ["address"]
    assert not seen and "Ленина" not in r.text
    assert METRICS.snapshot("pii_guard_denied_total")["address"] == 1


async def test_chat_off_forwards_silently(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "off")
    stream = io.StringIO()
    configure_logging(stream=stream)
    async with _client([]) as c:
        r = await c.post("/v1/messages", json={"content": ADDR})
    assert r.status_code == 200 and "pii_guard_observed" not in stream.getvalue()


async def test_address_in_query_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    async with _client([]) as c:
        monkeypatch.setenv(MODE_ENV, "log_only")
        r = await c.post("/v1/messages?to=ул. Ленина, д. 5", json={"x": "ok"})
        assert r.status_code == 200
        monkeypatch.setenv(MODE_ENV, "enforce")
        r = await c.post("/v1/messages?to=ул. Ленина, д. 5", json={"x": "ok"})
        assert r.status_code == 422


async def test_vision_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    body = vision_body()
    body["messages"][0]["content"][1]["text"] = f"Что на фото? Склад {ADDR}"
    monkeypatch.setenv(MODE_ENV, "log_only")
    async with _client([]) as c:
        assert (await c.post("/vision/v1/messages", json=body)).status_code == 200
        monkeypatch.setenv(MODE_ENV, "enforce")
        r = await c.post("/vision/v1/messages", json=body)
    assert r.status_code == 422 and r.json()["pii_types"] == ["address"]


def test_vision_verdict_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    body = vision_body()
    body["messages"][0]["content"][1]["text"] = f"Склад {ADDR}"
    raw = json.dumps(body).encode()
    monkeypatch.setenv(MODE_ENV, "log_only")
    verdict = check_vision_request("POST", "", "", raw)
    assert verdict.reason is None and verdict.observed_types == {"address"}
    monkeypatch.setenv(MODE_ENV, "enforce")
    verdict = check_vision_request("POST", "", "", raw)
    assert verdict.reason == "pii" and verdict.pii_types == {"address"}


def test_webpage_never_blocks_address_even_in_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """Решение 28.10: на маршруте публичных страниц ПДн не причина отказа."""
    from tests.pragmatika_guard.test_webpage_route import _body as webpage_body

    monkeypatch.setenv(MODE_ENV, "enforce")
    body = json.dumps(webpage_body(f"Офис: {ADDR}")).encode()
    verdict = check_webpage_request("POST", "", "", body)
    assert verdict.reason is None and "address" in verdict.pii_types


def test_search_instruction_follows_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from labops_pii.guard.litellm.search_route import _fetch_text_ok

    text = f"Выпиши цены со склада {ADDR}"
    monkeypatch.setenv(MODE_ENV, "log_only")
    assert _fetch_text_ok(text, ["example.com"], False) is True
    monkeypatch.setenv(MODE_ENV, "enforce")
    assert _fetch_text_ok(text, ["example.com"], False) is False


def test_address_on_chunk_boundary() -> None:
    """Адрес, разрезанный границей куска сканирования, находится благодаря перекрытию."""
    from labops_pii.guard.detector import ADDRESS_SCAN_CHUNK

    for shift in range(-len(ADDR), 1, 7):
        text = "а " * ((ADDRESS_SCAN_CHUNK + shift) // 2) + ADDR + " конец"
        assert "address" in find_pii_types(text)
