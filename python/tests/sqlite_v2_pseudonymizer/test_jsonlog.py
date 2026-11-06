"""Тесты JSON-логов: формат, traceparent, шаблон маршрута, классы, отсутствие ПДн."""

from __future__ import annotations

import ast
import asyncio
import io
import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import labops_pii
from labops_pii import jsonlog
from labops_pii.jsonlog import EVENT_SEVERITY, JsonFormatter, JsonLogMiddleware
from labops_pii.service import Pseudonymizer
from tests.pragmatika_pseudonymizer.conftest import AUTH_HEADERS, make_client

ALLOWED_KEYS = {
    "ts", "level", "severity", "event", "trace_id", "route", "status", "duration_ms",
    "msg", "exc_type", "code", "service",
}
SEVERITY_VALUES = {"info", "warning", "serious", "critical"}
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
# Данные пользователя, которые не должны оказаться в логе
FIO = "Иванов Иван Иванович"
PHONE = "+7 (902) 123-45-67"
EMAIL = "ivanov@firma.ru"
SECRET_TEXT = f"Позвони {FIO}, {PHONE}, почта {EMAIL}"
SOURCE_DIR = Path(labops_pii.__file__).parent


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
    root.setLevel(logging.INFO)
    try:
        yield out
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


def mini_app(failure_events: dict[str, str] | None = None) -> FastAPI:
    """Приложение с path-параметром и падающим обработчиком."""
    app = FastAPI()

    @app.get("/items/{item_id}")
    def item(item_id: str) -> dict[str, str]:
        logging.getLogger("t").info("внутри обработчика %s", item_id)
        return {"id": item_id}

    @app.get("/teapot")
    def teapot() -> None:
        raise HTTPException(418, "x")

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError(f"секрет {FIO}")

    @app.get("/unavailable")
    def unavailable() -> None:
        raise HTTPException(503, "busy")

    app.add_middleware(JsonLogMiddleware, failure_events=failure_events)
    return app


def test_record_format_and_keys(sink: LogSink) -> None:
    with TestClient(mini_app()) as client:
        client.get("/items/42", headers={"traceparent": TRACEPARENT})
    record = sink.events("http_request")[0]
    assert set(record) <= ALLOWED_KEYS
    assert {"ts", "level", "severity", "event", "route", "status", "duration_ms"} <= set(record)
    assert TS_RE.fullmatch(record["ts"])
    assert (record["level"], record["severity"], record["status"]) == ("info", "info", 200)
    assert isinstance(record["duration_ms"], (int, float)) and record["duration_ms"] >= 0
    assert all("\n" not in line for line in sink.raw.splitlines())


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (TRACEPARENT, TRACE_ID),
        (f"00-{TRACE_ID}-00f067aa0ba902b7-01-extra", TRACE_ID),
        ("garbage", None),
        (f"00-{TRACE_ID[:-1]}-00f067aa0ba902b7-01", None),
        (f"00-{'0' * 32}-00f067aa0ba902b7-01", None),
        (f"ff-{TRACE_ID}-00f067aa0ba902b7-01", None),
        (f"00-{TRACE_ID.upper()}-00f067aa0ba902b7-01", None),
        (None, None),
    ],
)
def test_traceparent(sink: LogSink, header: str | None, expected: str | None) -> None:
    headers = {} if header is None else {"traceparent": header}
    with TestClient(mini_app()) as client:
        client.get("/items/1", headers=headers)
    record = sink.events("http_request")[0]
    if expected is None:
        assert "trace_id" not in record
    else:
        assert record["trace_id"] == expected


def test_trace_id_reaches_plain_log_records(sink: LogSink) -> None:
    with TestClient(mini_app()) as client:
        client.get("/items/1", headers={"traceparent": TRACEPARENT})
    inner = sink.events("log")[0]
    assert inner["trace_id"] == TRACE_ID
    assert inner["msg"] == "внутри обработчика %s"


def test_route_is_template_not_actual_path(sink: LogSink) -> None:
    with TestClient(mini_app()) as client:
        client.get("/items/secret-value-777")
        client.get("/no/such/place")
    routes = [r["route"] for r in sink.events("http_request")]
    assert routes == ["/items/{item_id}"]
    assert sink.events("http_request_rejected")[0]["route"] == "unmatched"
    assert "secret-value-777" not in sink.raw and "/no/such/place" not in sink.raw


def test_status_classes(sink: LogSink) -> None:
    with TestClient(mini_app(), raise_server_exceptions=False) as client:
        client.get("/items/1")
        client.get("/teapot")
        client.get("/unavailable")
    ok, rejected, failed = (
        sink.events("http_request")[0],
        sink.events("http_request_rejected")[0],
        sink.events("http_request_failed")[0],
    )
    assert (ok["status"], ok["severity"], ok["level"]) == (200, "info", "info")
    assert (rejected["status"], rejected["severity"], rejected["level"]) == (
        418, "warning", "warning",
    )
    assert (failed["status"], failed["severity"], failed["level"]) == (503, "serious", "error")


def test_unhandled_exception_logs_type_only(sink: LogSink) -> None:
    with TestClient(mini_app(), raise_server_exceptions=False) as client:
        resp = client.get("/boom")
    assert resp.status_code == 500
    failed = sink.events("http_request_failed")[0]
    assert (failed["status"], failed["exc_type"], failed["route"]) == (500, "RuntimeError", "/boom")
    assert FIO not in sink.raw and "секрет" not in sink.raw


def test_formatter_drops_args_and_exception_text(sink: LogSink) -> None:
    logger = logging.getLogger("t.fmt")
    logger.warning("не открылся: %s", FIO)
    try:
        raise ValueError(PHONE)
    except ValueError:
        logger.exception("сбой")
    assert FIO not in sink.raw and PHONE not in sink.raw
    first, second = sink.records()
    assert (first["event"], first["msg"], first["severity"]) == (
        "log", "не открылся: %s", "warning",
    )
    assert (second["level"], second["severity"], second["exc_type"]) == (
        "error", "serious", "ValueError",
    )
    assert "Traceback" not in sink.raw


def test_pii_never_logged_for_real_app(
    detector: object, monkeypatch: pytest.MonkeyPatch, sink: LogSink
) -> None:
    client = make_client(detector, monkeypatch)
    query = f"?fio={FIO}&phone={PHONE}&mail={EMAIL}"
    client.post(
        "/pseudonymize" + query, json={"thread_id": "t-" + FIO, "text": SECRET_TEXT}
    )
    client.post("/check" + query, json={"text": SECRET_TEXT})
    client.post("/restore" + query, json={"thread_id": "t", "text": SECRET_TEXT})
    client.get("/health" + query)
    client.post("/pseudonymize" + query, json={"text": SECRET_TEXT})  # 422 валидации
    client.post("/check" + query, json={"text": SECRET_TEXT}, headers={"Authorization": "Bearer x"})
    for secret in (FIO, "Иванов", PHONE, "902", EMAIL, "firma.ru", "fio=", "?"):
        assert secret not in sink.raw, secret
    assert len(sink.events("http_request")) >= 3


def test_every_request_logged_once_including_guard_rejections(
    detector: object, monkeypatch: pytest.MonkeyPatch, sink: LogSink
) -> None:
    client = make_client(detector, monkeypatch, headers=None)
    client.post("/check", json={"text": "x"})  # 401 от BodyGuard, маршрут не найден
    http_events = [r for r in sink.records() if r["event"].startswith("http_request")]
    assert [(r["event"], r["status"], r["route"]) for r in http_events] == [
        ("http_request_rejected", 401, "unmatched"),
    ]


def test_restore_route_uses_dedicated_event(
    detector: object, monkeypatch: pytest.MonkeyPatch, sink: LogSink
) -> None:
    client = make_client(detector, monkeypatch)
    crash = TestClient(client.app, headers=AUTH_HEADERS, raise_server_exceptions=False)

    def broken(*_a: object, **_k: object) -> str:
        raise RuntimeError(SECRET_TEXT)

    monkeypatch.setattr(Pseudonymizer, "restore", broken)
    assert crash.post("/restore", json={"thread_id": "t", "text": "x"}).status_code == 500
    event = sink.events("pseudonymizer_restore_failed")[0]
    assert (event["severity"], event["level"], event["status"], event["route"]) == (
        "critical", "critical", 500, "/restore",
    )
    assert event["code"] == "RuntimeError" and event["exc_type"] == "RuntimeError"

    def busy(*_a: object, **_k: object) -> str:
        raise HTTPException(503, "busy")

    monkeypatch.setattr(Pseudonymizer, "restore", busy)
    crash.post("/restore", json={"thread_id": "t", "text": "x"})
    assert sink.events("pseudonymizer_restore_failed")[1]["code"] == "http_503"
    assert not sink.events("http_request_failed")
    assert SECRET_TEXT not in sink.raw and FIO not in sink.raw


def test_other_route_failure_stays_generic(sink: LogSink) -> None:
    with TestClient(mini_app({"/other": "pseudonymizer_restore_failed"}),
                    raise_server_exceptions=False) as client:
        client.get("/boom")
    assert sink.events("http_request_failed") and not sink.events("pseudonymizer_restore_failed")


def test_lifespan_events(sink: LogSink) -> None:
    from labops_pii.api import create_app
    from labops_pii.config import Settings
    from tests.pragmatika_pseudonymizer.conftest import API_TOKEN

    settings = Settings(
        key=_key(), db_path=":memory:", api_token=API_TOKEN  # type: ignore[arg-type]
    )
    with TestClient(create_app(settings)):
        assert [r["event"] for r in sink.records()] == ["service_started"]
    assert [r["event"] for r in sink.records()] == ["service_started", "service_stopped"]
    assert {r["severity"] for r in sink.records()} == {"info"}


def _key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


def test_middleware_does_not_read_or_buffer_body() -> None:
    """Middleware пересылает receive/send как есть: тело не читается и не накапливается."""
    receive_calls = 0
    order: list[str] = []

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.request", "body": b"x", "more_body": False}

    async def inner(scope: Any, recv: Any, send: Any) -> None:
        assert recv is receive  # тот же объект: middleware его не оборачивает
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"a", "more_body": True})
        order.append("inner-after-first-chunk")
        await send({"type": "http.response.body", "body": b"b", "more_body": False})

    async def send(message: dict[str, Any]) -> None:
        order.append(f"out:{message['type']}:{message.get('body', b'').decode()}")

    scope = {"type": "http", "headers": [], "method": "POST", "path": "/x"}
    asyncio.run(JsonLogMiddleware(inner)(scope, receive, send))
    assert receive_calls == 0
    # первый кусок ушёл наружу до того, как приложение отдало второй (без буферизации)
    assert order.index("out:http.response.body:a") < order.index("inner-after-first-chunk")


def test_non_http_scope_passes_through() -> None:
    seen: list[str] = []

    async def inner(scope: Any, recv: Any, send: Any) -> None:
        seen.append(scope["type"])

    middleware = JsonLogMiddleware(inner)
    asyncio.run(middleware({"type": "lifespan"}, None, None))  # type: ignore[arg-type]
    assert seen == ["lifespan"]


def test_event_severity_shape() -> None:
    assert set(EVENT_SEVERITY.values()) <= SEVERITY_VALUES
    assert set(EVENT_SEVERITY) == {
        "service_started", "service_stopped", "http_request", "http_request_rejected",
        "http_request_failed", "pseudonymizer_restore_failed",
    }
    source = Path(jsonlog.__file__).read_text(encoding="utf-8")
    lines = re.findall(r'^    "(\w+)": "(\w+)",$', source, flags=re.M)
    assert dict(lines) == EVENT_SEVERITY


def test_logger_calls_use_static_messages() -> None:
    """Первый аргумент logger.* - строковая константа (никаких f-строк и склейки данных)."""
    levels = {"debug", "info", "warning", "error", "critical", "exception"}
    checked = 0
    for path in SOURCE_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in levels
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "logger"
                and node.args
            ):
                checked += 1
                first = node.args[0]
                assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
                    f"{path.name}:{node.lineno}: сообщение лога должно быть статической строкой"
                )
    assert checked > 5


# Безопасные вызовы-аргументы log_info_formatted: хэш треда и длина (число, не текст).
SAFE_FORMAT_ARG_CALLS = {"thread_hash", "len"}


def _is_log_info_formatted_call(node: ast.AST) -> bool:
    """Вызов log_info_formatted(...) по имени или как атрибут модуля (jsonlog.log_...)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (isinstance(func, ast.Name) and func.id == "log_info_formatted") or (
        isinstance(func, ast.Attribute) and func.attr == "log_info_formatted"
    )


def _is_safe_format_arg(arg: ast.expr) -> bool:
    """Аргумент вида thread_hash(...) / len(...) / числовая константа (не bool)."""
    if isinstance(arg, ast.Constant):
        return isinstance(arg.value, (int, float)) and not isinstance(arg.value, bool)
    return (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Name)
        and arg.func.id in SAFE_FORMAT_ARG_CALLS
    )


def _format_call_violation(node: ast.Call) -> str | None:
    """Причина нарушения для вызова log_info_formatted или None, если вызов безопасен."""
    if node.keywords or any(isinstance(arg, ast.Starred) for arg in node.args):
        return "ключевые и *-аргументы не допускаются"
    if len(node.args) < 2:
        return "нужны логгер и статический шаблон"
    template = node.args[1]
    if not (isinstance(template, ast.Constant) and isinstance(template.value, str)):
        return "шаблон должен быть статической строкой"
    if not all(_is_safe_format_arg(arg) for arg in node.args[2:]):
        return "аргументы только thread_hash(...), len(...) или числовые константы"
    return None


def test_log_info_formatted_calls_use_static_template_and_safe_args() -> None:
    """log_info_formatted: статический шаблон, аргументы - хэш треда, длина или число."""
    checked = 0
    for path in SOURCE_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if _is_log_info_formatted_call(node):
                assert isinstance(node, ast.Call)
                checked += 1
                violation = _format_call_violation(node)
                assert violation is None, f"{path.name}:{node.lineno}: {violation}"
    assert checked >= 1


@pytest.mark.parametrize(
    ("source", "safe"),
    [
        ('log_info_formatted(logger, "t=%s n=%d", thread_hash(t), len(x))', True),
        ('log_info_formatted(logger, "n=%d", 3)', True),
        ('log_info_formatted(logger, f"t={t}")', False),
        ('log_info_formatted(logger, "t=" + t)', False),
        ('log_info_formatted(logger, "t=%s", thread_id)', False),
        ('log_info_formatted(logger, "t=%s", text[:5])', False),
        ('log_info_formatted(logger, "t=%s", str(thread_hash(t)))', False),
        ('log_info_formatted(logger, "t=%s", True)', False),
        ('log_info_formatted(logger, "t=%s", *args)', False),
        ('jsonlog.log_info_formatted(logger, "t=%s", name)', False),
    ],
)
def test_log_info_formatted_checker_rejects_unsafe_calls(source: str, safe: bool) -> None:
    """Сам детектор ловит небезопасные вызовы (иначе тест выше ничего не охраняет)."""
    node = ast.parse(source).body[0].value  # type: ignore[attr-defined]
    assert _is_log_info_formatted_call(node)
    assert (_format_call_violation(node) is None) is safe


def test_formatted_message_has_args_and_thread_hash(sink: LogSink) -> None:
    """Сообщение приходит с подставленными аргументами, thread - хэш, а не сам id."""
    thread = "thread-секрет-42"
    jsonlog.log_info_formatted(
        logging.getLogger("t.fmt2"), "pseudonymize: thread=%s найдено=%d",
        jsonlog.thread_hash(thread), 3,
    )
    (record,) = sink.records()
    assert record["msg"] == f"pseudonymize: thread={jsonlog.thread_hash(thread)} найдено=3"
    assert "%s" not in record["msg"] and thread not in sink.raw
