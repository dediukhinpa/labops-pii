"""Тесты JSON-логов pii-guard: формат, коды отказов, трассировка, отсутствие ПДн в логе."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from labops_pii.guard.edge import jsonlog
from labops_pii.guard.edge.app import create_app
from labops_pii.guard.edge.jsonlog import EVENT_SEVERITY, JsonFormatter, JsonLogMiddleware
from tests.edge_guard.helpers import MESSAGES, UPSTREAMS
from tests.edge_guard.pii_corpus import INN12

ALLOWED_KEYS = {
    "ts", "level", "severity", "event", "request_id", "code", "route", "upstream", "status",
    "duration_ms", "service", "exc_type", "msg",
}
SEVERITY_VALUES = {"info", "warning", "serious", "critical"}
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
REQUEST_ID = "0123456789abcdef0123456789abcdef"
# Данные пользователя, которые не должны оказаться в логе
FIO = "Иванов Иван Иванович"
PHONE = "+7 (902) 123-45-67"
EMAIL = "ivanov@firma.ru"
PII_FRAGMENTS = (FIO, "Иванов", PHONE, "902", "123-45-67", "1234567", EMAIL, "ivanov", "firma",
                 INN12)


class LogSink:
    """Перехватывает вывод JSON-обработчика в строку."""

    def __init__(self) -> None:
        self.stream = io.StringIO()

    @property
    def raw(self) -> str:
        """Весь вывод."""
        return self.stream.getvalue()

    def records(self) -> list[dict[str, Any]]:
        """Разобранные JSON-строки; каждая строка обязана быть валидным JSON."""
        return [json.loads(line) for line in self.raw.splitlines() if line.strip()]

    def events(self, name: str) -> list[dict[str, Any]]:
        """Записи с данным событием."""
        return [r for r in self.records() if r["event"] == name]


@pytest.fixture
def sink() -> Iterator[LogSink]:
    """Подключает JSON-форматтер к корневому логгеру на время теста."""
    out = LogSink()
    handler = logging.StreamHandler(out.stream)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield out
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


async def _stream_gen(data: bytes):
    yield data


def _ok_transport(status: int = 200) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=_stream_gen(b'{"ok": true}'))

    return httpx.MockTransport(handler)


def _client(transport: httpx.MockTransport) -> httpx.AsyncClient:
    app = create_app(UPSTREAMS, transport=transport)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


def _check_record(record: dict[str, Any]) -> None:
    assert set(record) <= ALLOWED_KEYS, set(record) - ALLOWED_KEYS
    assert TS_RE.fullmatch(record["ts"])
    assert record["severity"] in SEVERITY_VALUES
    assert record["service"] == "pii-guard"


async def test_success_logged_as_http_request(sink: LogSink) -> None:
    async with _client(_ok_transport()) as c:
        r = await c.post(
            MESSAGES, json={"x": f"клиент {FIO}"}, headers={"x-request-id": REQUEST_ID}
        )
    assert r.status_code == 200
    (rec,) = sink.events("http_request")
    _check_record(rec)
    assert (rec["level"], rec["severity"], rec["status"]) == ("info", "info", 200)
    assert rec["route"] == "/v1/messages"
    assert rec["request_id"] == REQUEST_ID
    assert isinstance(rec["duration_ms"], float)
    assert FIO not in sink.raw


async def test_pii_denied_logs_code_without_value(sink: LogSink) -> None:
    """Репродукция: до правки отказ не давал события pii_guard_denied с кодом категории."""
    async with _client(_ok_transport()) as c:
        r = await c.post(
            MESSAGES, json={"content": f"позвони {PHONE}"},
            headers={"x-request-id": REQUEST_ID},
        )
    assert r.status_code == 422
    (rec,) = sink.events("pii_guard_denied")
    _check_record(rec)
    assert (rec["level"], rec["severity"], rec["status"]) == ("warning", "warning", 422)
    assert rec["code"] == "phone"
    assert rec["request_id"] == REQUEST_ID
    assert rec["route"] == "/v1/messages"
    assert not sink.events("http_request")


async def test_several_categories_in_code(sink: LogSink) -> None:
    async with _client(_ok_transport()) as c:
        await c.post(MESSAGES, json={"a": PHONE, "b": EMAIL, "c": f"ИНН {INN12}"})
    (rec,) = sink.events("pii_guard_denied")
    assert set(rec["code"].split("+")) == {"phone", "email", "inn"}


async def test_pii_never_in_logs(sink: LogSink) -> None:
    """Телефон, ФИО, email и ИНН в теле, пути и query не попадают в лог ни в каком виде."""
    body = {"messages": [{"role": "user", "content": f"{FIO} {PHONE} {EMAIL} ИНН {INN12}"}]}
    async with _client(_ok_transport()) as c:
        await c.post(MESSAGES, json=body)
        await c.post(f"/u/anthropic/v1/messages/{PHONE}/{EMAIL}", json={"x": "ok"})
        await c.post(f"/u/anthropic/v1/messages?name={FIO}&p={PHONE}", json={"x": "ok"})
        await c.post(MESSAGES, content=f"не json {FIO} {PHONE}".encode())
        await c.post(MESSAGES, json={"x": FIO}, headers={"content-encoding": "gzip"})
    assert sink.records()
    for record in sink.records():
        _check_record(record)
    for fragment in PII_FRAGMENTS:
        assert fragment not in sink.raw, fragment
    # Тело не логируется: ни ключей запроса, ни текста сообщений
    for key in ('"role"', '"user"', '"messages"', '"content":', "ИНН"):
        assert key not in sink.raw, key


async def test_arbitrary_path_is_unmatched(sink: LogSink) -> None:
    async with _client(_ok_transport()) as c:
        await c.post(f"/u/anthropic/v1/secret-{PHONE}", json={"x": "ok"})
    (rec,) = [r for r in sink.records() if "route" in r]
    assert rec["route"] == "unmatched"
    assert "secret" not in sink.raw


@pytest.mark.parametrize("bad", ["short", "bad id with spaces!!", "a" * 65, "id;drop--table"])
async def test_invalid_request_id_dropped(sink: LogSink, bad: str) -> None:
    async with _client(_ok_transport()) as c:
        await c.post(MESSAGES, json={"x": "ok"}, headers={"x-request-id": bad})
    (rec,) = sink.events("http_request")
    assert "request_id" not in rec
    assert bad not in sink.raw


async def test_scan_failure_logged_as_failed(
    sink: LogSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> set[str]:
        raise RuntimeError(f"секрет {PHONE}")

    monkeypatch.setattr("labops_pii.guard.edge.app.scan_body", boom)
    async with _client(_ok_transport()) as c:
        r = await c.post(MESSAGES, json={"x": "ok"})
    assert r.status_code == 503
    (rec,) = sink.events("pii_guard_failed")
    _check_record(rec)
    assert (rec["level"], rec["severity"], rec["code"]) == ("error", "serious", "scan_failure")
    assert rec["exc_type"] == "RuntimeError"
    assert "секрет" not in sink.raw and "902" not in sink.raw


async def test_upstream_down_logged_as_failed(sink: LogSink) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    async with _client(httpx.MockTransport(handler)) as c:
        r = await c.post(MESSAGES, json={"x": "ok"})
    assert r.status_code == 502
    (rec,) = sink.events("pii_guard_failed")
    assert (rec["code"], rec["exc_type"], rec["status"]) == (
        "upstream_failure", "ConnectError", 502,
    )


async def test_upstream_5xx_is_failed_and_4xx_is_request(sink: LogSink) -> None:
    async with _client(_ok_transport(529)) as c:
        await c.post(MESSAGES, json={"x": "ok"})
    async with _client(_ok_transport(429)) as c:
        await c.post(MESSAGES, json={"x": "ok"})
    (failed,) = sink.events("pii_guard_failed")
    assert (failed["code"], failed["status"]) == ("upstream_5xx", 529)
    (plain,) = sink.events("http_request_rejected")
    assert plain["status"] == 429


async def test_technical_denials_have_codes(
    sink: LogSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAX_BODY_BYTES", "100")
    async with _client(_ok_transport()) as c:
        await c.post(MESSAGES, content=b"x" * 500)
        await c.post(MESSAGES, json={"x": 1}, headers={"content-encoding": "gzip"})
        await c.post("/v1/messages", json={"x": 1})
        await c.post("/u/nope/v1/messages", json={"x": 1})
    codes = [r["code"] for r in sink.events("pii_guard_denied")]
    assert codes == ["body_too_large", "content_encoding", "unknown_route", "unknown_upstream"]


async def test_error_response_unchanged(sink: LogSink) -> None:
    async with _client(_ok_transport()) as c:
        r = await c.post(MESSAGES, json={"content": PHONE})
    assert r.status_code == 422
    assert r.json()["pii_types"] == ["phone"]


def test_service_started_event(sink: LogSink) -> None:
    with TestClient(create_app(UPSTREAMS, transport=_ok_transport())):
        pass
    (rec,) = sink.events("service_started")
    _check_record(rec)
    assert rec["severity"] == "info"


def test_unhandled_exception_logged_with_exc_type_only(sink: LogSink) -> None:
    async def broken(scope: Any, receive: Any, send: Any) -> None:
        raise ValueError(f"упало на {PHONE}")

    middleware = JsonLogMiddleware(broken)
    scope = {"type": "http", "path": MESSAGES, "headers": []}
    with pytest.raises(ValueError):
        asyncio.run(middleware(scope, None, None))  # type: ignore[arg-type]
    (rec,) = sink.events("pii_guard_failed")
    assert rec["exc_type"] == "ValueError" and rec["code"] == "unhandled_error"
    assert "упало" not in sink.raw and "902" not in sink.raw


def test_plain_log_has_template_without_args(sink: LogSink) -> None:
    logging.getLogger("pii_guard").warning("сбой для %s", PHONE)
    (rec,) = sink.records()
    _check_record(rec)
    assert rec["event"] == "log" and rec["msg"] == "сбой для %s"
    assert "902" not in sink.raw


def test_configure_logging_is_idempotent_and_writes_to_stream() -> None:
    root = logging.getLogger()
    saved = list(root.handlers)
    saved_level = root.level
    out = io.StringIO()
    try:
        jsonlog.configure_logging(logging.INFO, out)
        jsonlog.configure_logging(logging.INFO, out)
        ours = [h for h in root.handlers if isinstance(h, jsonlog._GuardJsonHandler)]
        assert len(ours) == 1
        logging.getLogger("pii_guard").info("привет")
        assert json.loads(out.getvalue())["msg"] == "привет"
    finally:
        root.handlers[:] = saved
        root.setLevel(saved_level)


def test_event_severity_shape_and_parity() -> None:
    assert set(EVENT_SEVERITY.values()) <= SEVERITY_VALUES
    assert EVENT_SEVERITY == {
        "pii_guard_denied": "warning", "pii_guard_observed": "warning",
        "pii_guard_failed": "serious",
        "service_started": "info", "http_request": "info",
        "http_request_rejected": "warning",
    }
    source = Path(jsonlog.__file__).read_text(encoding="utf-8")
    assert dict(re.findall(r'^    "(\w+)": "(\w+)",$', source, flags=re.M)) == EVENT_SEVERITY



async def test_upstream_name_and_route_without_prefix(sink: LogSink) -> None:
    async with _client(_ok_transport()) as c:
        await c.post("/u/deepseek/v1/messages/count_tokens", json={"x": "ok"})
    (rec,) = sink.events("http_request")
    assert (rec["route"], rec["upstream"]) == ("/v1/messages/count_tokens", "deepseek")


async def test_auth_headers_never_logged(sink: LogSink) -> None:
    secret_bearer = "sk-ant-oat01-SECRETVALUE-xyz"
    secret_key = "sk-ant-api03-OTHERSECRET"
    async with _client(_ok_transport()) as c:
        await c.post(
            MESSAGES, json={"x": "ok"},
            headers={"authorization": f"Bearer {secret_bearer}", "x-api-key": secret_key},
        )
        await c.post(
            MESSAGES, json={"x": PHONE},
            headers={"authorization": f"Bearer {secret_bearer}", "x-api-key": secret_key},
        )
    assert "SECRET" not in sink.raw and "Bearer" not in sink.raw


async def test_log_mode_records_types_and_passes(sink: LogSink) -> None:
    from labops_pii.guard.edge.config import GuardMode

    app = create_app(UPSTREAMS, transport=_ok_transport(), mode=GuardMode.LOG)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        r = await c.post(MESSAGES, json={"content": f"{PHONE} {EMAIL}"})
    assert r.status_code == 200
    (rec,) = sink.events("pii_guard_observed")
    _check_record(rec)
    assert (rec["code"], rec["status"], rec["severity"]) == ("email+phone", 200, "warning")
    for fragment in PII_FRAGMENTS:
        assert fragment not in sink.raw, fragment
