"""JSON-логи сервиса: форматтер, ASGI-middleware запросов и настройка корневого логгера.

Одна запись - одна JSON-строка. Тексты запросов, тела, имена файлов и query-строки в лог не
попадают никогда: путь пишется только как шаблон маршрута (`/v1/parse`), а у обычных записей
`logging` в `msg` идёт шаблон сообщения ДО подстановки аргументов (аргументы не пишутся).

Модуль намеренно не зависит от остального кода сервиса (сервисы - отдельные образы, общий код
не шарится; в соседнем сервисе лежит такая же копия).
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import logging
import re
import sys
import time
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from datetime import datetime, timezone
from typing import Any, TextIO

SERVICE_NAME = "pseudonymizer"
HTTP_LOGGER_NAME = f"{SERVICE_NAME}.http"

EVENT_LOG = "log"
EVENT_HTTP_REQUEST = "http_request"
EVENT_HTTP_REJECTED = "http_request_rejected"
EVENT_HTTP_FAILED = "http_request_failed"
EVENT_SERVICE_STARTED = "service_started"
EVENT_SERVICE_STOPPED = "service_stopped"
EVENT_RESTORE_FAILED = "pseudonymizer_restore_failed"

# Класс события; значения общие для сервисов LabOps
# (тест разбирает строки ниже, поэтому формат строго `    "событие": "класс",`).
EVENT_SEVERITY: dict[str, str] = {
    "service_started": "info",
    "service_stopped": "info",
    "http_request": "info",
    "http_request_rejected": "warning",
    "http_request_failed": "serious",
    "pseudonymizer_restore_failed": "critical",
}

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_SERIOUS = "serious"

UNMATCHED_ROUTE = "unmatched"
HTTP_REJECT_FROM = 400
HTTP_FAILED_FROM = 500
HTTP_INTERNAL_ERROR = 500
# Нестандартный код «клиент закрыл соединение» (как HTTP_CLIENT_CLOSED в api.py)
HTTP_CLIENT_CLOSED = 499
# Страховочный предел длины шаблона сообщения: шаблоны статические и короткие
MAX_MSG_CHARS = 300
MS_IN_SECOND = 1000.0
DURATION_DIGITS = 1
TRACEPARENT_HEADER = b"traceparent"
TRACEPARENT_RE = re.compile(r"[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}(?:-.*)?")
TRACE_ID_ZERO = "0" * 32
TRACEPARENT_BAD_VERSION = "ff"

LEVEL_NAMES: dict[int, str] = {
    logging.DEBUG: "info",
    logging.INFO: "info",
    logging.WARNING: "warning",
    logging.ERROR: "error",
    logging.CRITICAL: "critical",
}

# Поля, которые форматтер берёт из `extra` записи (остальное в лог не попадает)
EXTRA_FIELDS = ("trace_id", "route", "status", "duration_ms", "code", "exc_type")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# trace_id текущего запроса: старые записи logger.* внутри обработчика тоже получают его
_trace_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "pseudonymizer_trace_id", default=None
)


def parse_traceparent(value: str | None) -> str | None:
    """Достаёт trace_id (32 hex) из заголовка W3C `traceparent`.

    Args:
        value: Значение заголовка или None.

    Returns:
        trace_id или None, если заголовка нет или он невалиден.
    """
    if not value:
        return None
    match = TRACEPARENT_RE.fullmatch(value.strip())
    if match is None or value.strip().startswith(TRACEPARENT_BAD_VERSION + "-"):
        return None
    trace_id = match.group(1)
    return None if trace_id == TRACE_ID_ZERO else trace_id


def _level_severity(levelno: int) -> str:
    """Класс по уровню записи, у которой нет события из таблицы."""
    if levelno >= logging.ERROR:
        return SEVERITY_SERIOUS
    if levelno >= logging.WARNING:
        return SEVERITY_WARNING
    return SEVERITY_INFO


def severity_of(event: str, levelno: int) -> str:
    """Класс события: из таблицы, иначе по уровню записи."""
    return EVENT_SEVERITY.get(event) or _level_severity(levelno)


def _format_ts(created: float) -> str:
    """Время записи: ISO UTC с миллисекундами и суффиксом Z."""
    moment = datetime.fromtimestamp(created, tz=timezone.utc)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


THREAD_HASH_CHARS = 12


def thread_hash(thread_id: str) -> str:
    """Короткий необратимый хэш идентификатора треда для логов (сам id в лог не пишется)."""
    return hashlib.sha256(thread_id.encode("utf-8")).hexdigest()[:THREAD_HASH_CHARS]


def log_info_formatted(log: logging.Logger, template: str, *args: object) -> None:
    """Пишет info с уже подставленными аргументами.

    Форматтер аргументы не пишет (защита от ПДн), поэтому сообщение собирается до передачи
    в логгер. Вызывать ТОЛЬКО с безопасными аргументами: числа, хэши, коды - не тексты.
    """
    log.info(template % args)


class JsonFormatter(logging.Formatter):
    """Пишет запись одной JSON-строкой с фиксированным белым списком полей."""

    def format(self, record: logging.LogRecord) -> str:
        """Собирает JSON-строку; аргументы сообщения и текст исключения не пишутся."""
        event = getattr(record, "event", None)
        payload: dict[str, Any] = {
            "ts": _format_ts(record.created),
            "level": LEVEL_NAMES.get(record.levelno, "info"),
            "severity": severity_of(event or EVENT_LOG, record.levelno),
            "event": event or EVENT_LOG,
            "service": SERVICE_NAME,
        }
        extras = {name: getattr(record, name, None) for name in EXTRA_FIELDS}
        if extras["trace_id"] is None:
            extras["trace_id"] = _trace_var.get()
        if extras["exc_type"] is None and record.exc_info and record.exc_info[0] is not None:
            extras["exc_type"] = record.exc_info[0].__name__
        for name, value in extras.items():
            if value is not None:
                payload[name] = value
        # msg - шаблон до подстановки args; у событий с явным именем он не нужен
        if event is None and isinstance(record.msg, str):
            payload["msg"] = record.msg[:MAX_MSG_CHARS]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: int = logging.INFO, stream: TextIO | None = None) -> None:
    """Заменяет обработчики корневого логгера одним JSON-обработчиком.

    Args:
        level: Уровень корневого логгера.
        stream: Поток вывода; по умолчанию stderr.
    """
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for old in list(root.handlers):
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(level)


def log_event(
    logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any
) -> None:
    """Пишет именованное событие; `fields` - только поля из EXTRA_FIELDS."""
    logger.log(level, event, extra={"event": event, **fields})


class JsonLogMiddleware:
    """Чистый ASGI-middleware: одно событие на запрос после ответа.

    Тело запроса и ответа не читается и не буферизуется: `receive` передаётся как есть, а
    `send` лишь подсматривает код статуса.

    Args:
        app: Следующее приложение ASGI.
        failure_events: Шаблон маршрута -> событие, которое пишется вместо
            `http_request_failed` при 5xx/исключении; такое событие получает поле `code`.
    """

    def __init__(self, app: ASGIApp, failure_events: Mapping[str, str] | None = None) -> None:
        self._app = app
        self._failure_events = dict(failure_events or {})
        self._logger = logging.getLogger(HTTP_LOGGER_NAME)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        started = time.perf_counter()
        raw = next((v for k, v in scope["headers"] if k == TRACEPARENT_HEADER), None)
        trace_id = parse_traceparent(raw.decode("latin-1") if raw is not None else None)
        token = _trace_var.set(trace_id)
        status: int | None = None
        exc_type: str | None = None
        cancelled = False

        async def spy_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self._app(scope, receive, spy_send)
        except asyncio.CancelledError:
            cancelled = True
            raise
        except Exception as exc:
            exc_type = type(exc).__name__
            status = HTTP_INTERNAL_ERROR
            raise
        finally:
            if cancelled and status is None:
                status = HTTP_CLIENT_CLOSED
            duration = round((time.perf_counter() - started) * MS_IN_SECOND, DURATION_DIGITS)
            self._emit(scope, trace_id, status or HTTP_INTERNAL_ERROR, duration, exc_type)
            _trace_var.reset(token)

    def _emit(
        self, scope: Scope, trace_id: str | None, status: int, duration: float, exc_type: str | None
    ) -> None:
        """Пишет итоговое событие запроса."""
        route_obj = scope.get("route")
        route = getattr(route_obj, "path", None)
        route = route if isinstance(route, str) else UNMATCHED_ROUTE
        fields: dict[str, Any] = {
            "trace_id": trace_id, "route": route, "status": status, "duration_ms": duration,
        }
        if exc_type is not None:
            fields["exc_type"] = exc_type
        if status >= HTTP_FAILED_FROM:
            special = self._failure_events.get(route)
            if special is not None:
                fields["code"] = exc_type or f"http_{status}"
                log_event(self._logger, special, logging.CRITICAL, **fields)
            else:
                log_event(self._logger, EVENT_HTTP_FAILED, logging.ERROR, **fields)
        elif status >= HTTP_REJECT_FROM:
            log_event(self._logger, EVENT_HTTP_REJECTED, logging.WARNING, **fields)
        else:
            log_event(self._logger, EVENT_HTTP_REQUEST, logging.INFO, **fields)
